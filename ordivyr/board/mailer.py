"""Transactional email: a durable outbox + pluggable transports. Invites, password resets, payment/suspension notices and security notices all go through here.

  * Outbox rows are written INSIDE the business transaction (an invite exists <=> its email is queued), the body is sealed with the vault (it may hold a one-time token) and wiped once sent/failed.
  * `mail_tick()` (Board's loop, any number of processes) claims a row with a conditional UPDATE (no double send), retries with backoff (1m, 5m, 30m, 2h, 12h), then marks it failed and raises an alert.
  * SMTPTransport REQUIRES STARTTLS (or implicit TLS) before authenticating; a server that does not offer it is refused, never downgraded. `FileTransport` writes .eml files (dev/test, and the
    safe default for demos: nothing leaves the machine).
  * Header injection: addresses and subjects containing CR/LF/NUL are rejected before anything is built.
Nothing here sends to a real recipient unless the operator configures an SMTP transport; tests use a loopback sink.
"""
from __future__ import annotations
import email.message, email.utils, json, os, re, secrets, smtplib, ssl, time
from pathlib import Path
from .errors import Invalid

BACKOFF = (60, 300, 1800, 7200, 43200)
ADDR = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")

TEMPLATES = {
    "invite": ("You're invited to {org} on ORDIVYR Board", "{inviter} invited you to join {org} as {role}.\n\nAccept: {url}/#/accept?token={token}\n\nThis link works once and expires {expires}. If you did not expect it, ignore this email."),
    "password_reset": ("Reset your ORDIVYR Board password", "Someone (hopefully you) asked to reset the password for this account.\n\nReset: {url}/#/reset?token={token}\n\nThe link works once and expires {expires}. If this was not you, ignore this email: your password has not changed."),
    "mfa_enabled": ("Two-step verification was turned on", "Two-step verification is now enabled for your ORDIVYR Board account. If you did not do this, reset your password immediately."),
    "account_guarded": ("Unusual sign-in attempts on your account", "We saw repeated failed sign-ins from networks you do not normally use and are refusing sign-ins from new networks for a while. Your usual network still works. You can restore access with a code from your authenticator app at {url}/#/unlock."),
}


def check_addr(a):
    a = str(a or "").strip()
    if not ADDR.fullmatch(a) or any(ch in a for ch in "\r\n\0"): raise Invalid("invalid email address")
    return a


def clean_header(v):
    v = str(v)
    if any(ch in v for ch in "\r\n\0"): raise Invalid("illegal characters in header")
    return v[:200]


def build(from_addr, to, subject, body, msgid=None):
    m = email.message.EmailMessage(); m["From"] = clean_header(from_addr); m["To"] = check_addr(to); m["Subject"] = clean_header(subject); m["Date"] = email.utils.formatdate(localtime=False)
    m["Message-ID"] = msgid or email.utils.make_msgid(domain="board.invalid"); m["Auto-Submitted"] = "auto-generated"; m.set_content(body); return m


class FileTransport:
    name = "file"
    def __init__(self, directory, from_addr="board@localhost"): self.dir = Path(directory); self.dir.mkdir(parents=True, exist_ok=True); os.chmod(self.dir, 0o700); self.from_addr = from_addr
    def send(self, to, subject, body):
        m = build(self.from_addr, to, subject, body); f = self.dir / f"{int(time.time() * 1000)}-{secrets.token_hex(3)}.eml"
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, bytes(m)); os.close(fd); return str(f)


class SMTPTransport:
    name = "smtp"
    def __init__(self, host, port=587, user=None, password=None, from_addr="board@localhost", mode="starttls", timeout=20, ca_file=None, allow_plaintext=False):
        if mode not in ("starttls", "tls", "plain"): raise ValueError("mode")
        if mode == "plain" and not allow_plaintext: raise Invalid("plaintext SMTP refused (set allow_plaintext only for a loopback sink)")
        self.host, self.port, self.user, self.password, self.from_addr, self.mode, self.timeout, self.ca = host, int(port), user, password, from_addr, mode, timeout, ca_file
    def _ctx(self): return ssl.create_default_context(cafile=self.ca)
    def send(self, to, subject, body):
        m = build(self.from_addr, to, subject, body)
        s = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=self._ctx()) if self.mode == "tls" else smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        try:
            s.ehlo()
            if self.mode == "starttls":
                if not s.has_extn("starttls"): raise smtplib.SMTPNotSupportedError("server does not offer STARTTLS: refusing to send or authenticate in the clear")
                s.starttls(context=self._ctx()); s.ehlo()
            if self.user:
                if self.mode == "plain": raise smtplib.SMTPException("refusing to authenticate over plaintext")
                s.login(self.user, self.password)
            s.send_message(m); return m["Message-ID"]
        finally:
            try: s.quit()
            except Exception: pass


class MailMixin:
    mailer = None                    # set by the operator: FileTransport(...) / SMTPTransport(...)
    public_url = os.environ.get("BOARD_PUBLIC_URL", "https://board.example.com")

    @property
    def mail_enabled(self): return self.mailer is not None

    def _mail(self, c, to, kind, ctx, org=None, dedupe=None):
        """Queue an email inside the caller's transaction `c`. Silently skips invalid addresses (never raises into a business flow)."""
        try: to = check_addr(to)
        except Invalid: return None
        subj, body = TEMPLATES[kind]; ctx = {"url": self.public_url.rstrip("/"), **ctx}
        try: subject, text = subj.format(**ctx), body.format(**ctx)
        except KeyError: return None
        mid = "mail-" + secrets.token_hex(8); now = self.clock()
        if dedupe and c.execute("SELECT 1 FROM outbox WHERE dedupe=?", (dedupe,)).fetchone(): return None
        c.execute("INSERT INTO outbox(id,org,to_addr,kind,subject,body,status,next_attempt,created,dedupe) VALUES(?,?,?,?,?,?,?,?,?,?)", (mid, org, to, kind, clean_header(subject), self.vault.seal(text.encode(), f"mail|{mid}"), "queued", now, now, dedupe))
        return mid

    def _org_admin_emails(self, c, org): return [r["email"] for r in c.execute("SELECT u.email FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.org=? AND m.role='admin' AND u.status='active'", (org,)).fetchall()]

    def mail_tick(self, now=None, limit=50):
        """Send due mail. Safe from any number of processes. -> {"sent": n, "failed": n, "retry": n}"""
        out = {"sent": 0, "failed": 0, "retry": 0}
        if self.mailer is None: return out
        now = now or self.clock(); limit = max(1, min(int(limit), 200)); self._scan_alerts_for_mail(now)
        with self.db.tx() as c: c.execute("UPDATE outbox SET status='queued', sending_since=NULL, next_attempt=? WHERE status='sending' AND sending_since<?", (now, now - 600))
        for r in self.db.c().execute("SELECT * FROM outbox WHERE status='queued' AND next_attempt<=? ORDER BY created LIMIT ?", (now, limit)).fetchall():
            with self.db.tx() as c:
                if not c.execute("UPDATE outbox SET status='sending', sending_since=?, attempts=attempts+1 WHERE id=? AND status='queued'", (now, r["id"])).rowcount: continue
            try:
                body = self.vault.open(r["body"], f"mail|{r['id']}").decode(); self.mailer.send(r["to_addr"], r["subject"], body); ok, err = True, None
            except Exception as e: ok, err = False, f"{type(e).__name__}: {str(e)[:150]}"
            n = r["attempts"] + 1
            with self.db.tx() as c:
                if ok: c.execute("UPDATE outbox SET status='sent', sending_since=NULL, sent_at=?, body=NULL, last_error=NULL WHERE id=?", (now, r["id"])); out["sent"] += 1
                elif n > len(BACKOFF): c.execute("UPDATE outbox SET status='failed', sending_since=NULL, body=NULL, last_error=? WHERE id=?", (err, r["id"])); c.execute("INSERT INTO alerts(ts,org,kind,detail) VALUES(?,?,?,?)", (now, r["org"], "mail_failed", json.dumps({"kind": r["kind"], "error": err}))); out["failed"] += 1
                else: c.execute("UPDATE outbox SET status='queued', sending_since=NULL, next_attempt=?, last_error=? WHERE id=?", (now + BACKOFF[n - 1], err, r["id"])); out["retry"] += 1
        return out

    def _scan_alerts_for_mail(self, now):
        """Reserved: no alert kinds are mailed in the open-source Board (account mail only)."""
        return

    def outbox_of(self, p, limit=50):
        self._need(p, "admin")
        limit = max(1, min(int(limit), 500))
        return [dict(id=r["id"], to=r["to_addr"], kind=r["kind"], subject=r["subject"], status=r["status"], attempts=r["attempts"], created=r["created"], sent_at=r["sent_at"], error=r["last_error"])
                for r in self.db.c().execute("SELECT * FROM outbox WHERE org=? AND kind!='marker' ORDER BY created DESC LIMIT ?", (p.org, limit)).fetchall()]
