"""Phase 3 customer email: durable outbox, retries, no double send, STARTTLS-or-nothing, header-injection refusal, tokens that exist only in the recipient's mail. A LOOPBACK sink stands in for SMTP: nothing leaves the machine."""
import email, re, socketserver, threading, time
import pytest
from ordivyr.board import auth as A, mailer as M
from ordivyr.board.accounts import AuthFailed
from ordivyr.board.errors import Invalid
from ordivyr.tests.board_support import World
from ordivyr.tests.test_board_accounts import human as _human, PW


def _human_admin(w, a, em):
    m, w.board.mailer = w.board.mailer, None
    try: return _human(w, a, em, role="admin")
    finally: w.board.mailer = m


def human(w, a, em):
    m, w.board.mailer = w.board.mailer, None                      # create the account without mail (the helper reads the invite token from the API response)
    try: return _human(w, a, em)
    finally: w.board.mailer = m


class Sink:
    def __init__(self, offer_starttls=False, fail_first=0):
        self.msgs = []; self.fail = fail_first; self.offer = offer_starttls; self.cmds = []; sink = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                w = lambda s: self.wfile.write((s + "\r\n").encode()); w("220 sink ESMTP"); data = False; buf = []; frm = to = None
                while True:
                    line = self.rfile.readline()
                    if not line: return
                    t = line.decode(errors="replace").rstrip("\r\n")
                    if data:
                        if t == ".": data = False; sink.msgs.append(("\n".join(buf), frm, list(to))); w("250 queued"); buf = []
                        else: buf.append(t[1:] if t.startswith("..") else t)
                        continue
                    u = t.upper(); sink.cmds.append(u.split()[0] if u else "")
                    if u.startswith("EHLO"): w("250-sink"); w("250 STARTTLS") if sink.offer else w("250 SIZE 100000")
                    elif u.startswith("HELO"): w("250 sink")
                    elif u.startswith("MAIL"): frm, to = t, []; w("250 ok")
                    elif u.startswith("RCPT"): to.append(t); w("250 ok")
                    elif u == "DATA":
                        if sink.fail > 0: sink.fail -= 1; w("451 try later"); continue
                        data = True; w("354 go")
                    elif u == "QUIT": w("221 bye"); return
                    elif u.startswith("AUTH"): w("235 ok")
                    else: w("250 ok")
        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H); self.srv.daemon_threads = True; self.port = self.srv.server_address[1]; threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self): self.srv.shutdown(); self.srv.server_close()
    def transport(self, **kw): return M.SMTPTransport("127.0.0.1", self.port, mode="plain", allow_plaintext=True, from_addr="board@example.test", **kw)
    def bodies(self): return [email.message_from_string(m[0]).get_payload(decode=True).decode() for m in self.msgs]


@pytest.fixture
def sink():
    s = Sink(); yield s; s.close()


@pytest.fixture
def w(tmp_path, monkeypatch, sink):
    x = World(tmp_path, {}, monkeypatch); x.board.mailer = sink.transport(); x.board.public_url = "https://board.test"; yield x; x.close()


def token_in(body, kind): return re.search(r"token=(" + kind + r"_[A-Za-z0-9_\-]+)", body).group(1)


def test_invite_token_exists_only_in_the_email_and_works_once(w, sink):
    a = w.org("acme"); r = w.board.invite_user(a, "new@corp.com", "member")
    assert r["emailed"] and "invite" not in r and "ordi_" not in str(r)                                           # not even the inviting admin sees the token
    assert w.board.mail_tick()["sent"] == 1; body = sink.bodies()[0]; tok = token_in(body, "ordi")
    assert "https://board.test/#/accept?token=" in body and "new@corp.com" in sink.msgs[0][2][0]
    assert w.board.accept_invite(tok, PW, "New")["org"] == "acme"
    with pytest.raises(Exception): w.board.accept_invite(tok, PW, "Again")
    row = w.board.db.c().execute("SELECT status, body FROM outbox WHERE kind='invite'").fetchone(); assert row["status"] == "sent" and row["body"] is None      # the secret body is wiped once delivered


def test_outbox_body_is_sealed_at_rest(w):
    a = w.org("acme"); w.board.invite_user(a, "x@corp.com", "member"); raw = w.board.db.c().execute("SELECT body FROM outbox").fetchone()[0]
    raw = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode(); assert b"ordi_" not in raw and b"accept" not in raw


def test_forgot_password_is_uniform_rate_limited_and_token_only_by_email(w, sink):
    a = w.org("acme"); human(w, a, "u@corp.com")
    r1 = w.board.request_password_reset("u@corp.com"); r2 = w.board.request_password_reset("ghost@corp.com"); r3 = w.board.request_password_reset("not-an-email")
    assert r1 == r2 == r3 and "token" not in str(r1)                                                               # identical answers: no account enumeration
    assert w.board.mail_tick()["sent"] == 1 and sink.msgs[0][2][0].find("u@corp.com") >= 0                         # mail only for the real account
    tok = token_in(sink.bodies()[0], "ordr"); w.board.reset_password(tok, "brand new passphrase 77"); assert w.board.login("u@corp.com", "brand new passphrase 77")["session"]
    with pytest.raises(Exception): w.board.reset_password(tok, "another passphrase 88 xx")                         # single use
    for _ in range(5): w.board.request_password_reset("u@corp.com")
    assert w.board.db.c().execute("SELECT COUNT(*) FROM invites WHERE email='u@corp.com' AND role='_reset'").fetchone()[0] == 3     # 3 per hour per account


def test_header_injection_and_bad_addresses_are_refused():
    for bad in ("a@b.com\r\nBcc: evil@x.io", "a@b.com\nX: y", "a b@c.com", "a@b", "", None, "a@b.com\0"):
        with pytest.raises(Invalid): M.check_addr(bad)
    with pytest.raises(Invalid): M.build("board@x.io", "a@b.co", "Subject\r\nBcc: e@x.io", "hi")
    with pytest.raises(Invalid): M.clean_header("x\ny")


def test_retries_back_off_then_fail_loudly_and_never_double_send(w, sink, monkeypatch):
    a = w.org("acme"); w.board.invite_user(a, "x@corp.com", "member"); sink.fail = 2; t0 = time.time()
    assert w.board.mail_tick(t0)["retry"] == 1 and w.board.mail_tick(t0 + 10)["sent"] == 0                         # not due yet
    assert w.board.mail_tick(t0 + 61)["retry"] == 1 and w.board.mail_tick(t0 + 61 + 301)["sent"] == 1 and len(sink.msgs) == 1
    w.board.invite_user(a, "y@corp.com", "member"); sink.fail = 99; now = t0 + 1000
    for _ in range(8): w.board.mail_tick(now); now += 50000
    r = w.board.db.c().execute("SELECT status, attempts, body FROM outbox WHERE to_addr='y@corp.com'").fetchone(); assert r["status"] == "failed" and r["attempts"] == 6 and r["body"] is None
    assert w.board.db.c().execute("SELECT COUNT(*) FROM alerts WHERE kind='mail_failed'").fetchone()[0] == 1
    sink.fail = 0; sink.msgs.clear()
    for i in range(6): w.board.invite_user(a, f"z{i}@corp.com", "member")
    others = [w.reborn() for _ in range(3)]
    for o in others: o.mailer = sink.transport()
    ts = [threading.Thread(target=lambda b=b: b.mail_tick(), args=()) for b in [w.board] + others]; [t.start() for t in ts]; [t.join() for t in ts]
    assert len(sink.msgs) == 6 and len({m[2][0] for m in sink.msgs}) == 6                                          # 4 racing processes, every mail delivered exactly once


def test_stale_sending_mail_is_recovered_after_worker_crash(w, sink):
    a = w.org("acme"); r = w.board.invite_user(a, "crashed@corp.com", "member")
    with w.board.db.tx() as c:
        c.execute("UPDATE outbox SET status='sending', sending_since=?, attempts=1 WHERE to_addr='crashed@corp.com'", (time.time() - 700,))
    assert w.board.mail_tick()["sent"] == 1
    row = w.board.db.c().execute("SELECT status, sending_since FROM outbox WHERE to_addr='crashed@corp.com'").fetchone()
    assert row["status"] == "sent" and row["sending_since"] is None and len(sink.msgs) == 1


def test_smtp_requires_starttls_or_sends_nothing(tmp_path, monkeypatch):
    s = Sink(offer_starttls=False)
    try:
        w = World(tmp_path, {}, monkeypatch); w.board.mailer = M.SMTPTransport("127.0.0.1", s.port, mode="starttls", from_addr="board@example.test"); a = w.org("acme"); w.board.invite_user(a, "x@corp.com", "member")
        r = w.board.mail_tick(); assert r == {"sent": 0, "failed": 0, "retry": 1} and not s.msgs and "DATA" not in s.cmds           # server never offered STARTTLS: refused, not downgraded
        assert "STARTTLS" in w.board.db.c().execute("SELECT last_error FROM outbox").fetchone()[0]
        w.close()
    finally: s.close()
    with pytest.raises(Invalid): M.SMTPTransport("h", mode="plain")                                                # plaintext needs an explicit dev opt-in
    with pytest.raises(Exception): M.SMTPTransport("127.0.0.1", 1, user="u", password="p", mode="plain", allow_plaintext=True).send("a@b.co", "s", "b")   # and never authenticates in the clear


def test_security_notices_mfa_enabled_and_account_guard(w, sink):
    a = w.org("acme"); human(w, a, "v@corp.com"); w.board.login("v@corp.com", PW, ip="198.51.100.7")
    p = w.board.principal(w.board.login("v@corp.com", PW, ip="198.51.100.7")["session"]); sec = w.board.mfa_begin(p)["secret"]; time.sleep(0); w.board.clock = w.board.db.clock = lambda: time.time() + 31
    w.board.mfa_confirm(p, A.totp_now(sec, time.time() + 31)); w.board.mail_tick(); assert any("Two-step verification is now enabled" in b for b in sink.bodies())
    for i in range(20):
        try: w.board.login("v@corp.com", "bad-password-1234", ip=f"203.0.{i}.9")
        except AuthFailed: pass
    for i in range(20, 24):
        try: w.board.login("v@corp.com", "bad-password-1234", ip=f"203.0.{i}.9")
        except AuthFailed: pass
    w.board.mail_tick(time.time() + 40); assert sum("repeated failed sign-ins" in b for b in sink.bodies()) == 1       # told once, not once per attempt


def test_file_transport_is_private_and_header_safe(tmp_path):
    t = M.FileTransport(tmp_path / "eml"); f = t.send("a@b.co", "Hello", "body"); import os
    assert oct(os.stat(f).st_mode & 0o777) == "0o600" and oct(os.stat(tmp_path / "eml").st_mode & 0o777) == "0o700"
    with pytest.raises(Invalid): t.send("a@b.co\r\nBcc: e@x.io", "s", "b")
