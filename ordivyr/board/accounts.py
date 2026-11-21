"""Customer identity for Board: users, sessions, MFA, invites, memberships, password reset, OIDC SSO, API-key lifecycle. A mixin over `Board` (needs self.db, self.clock, self.vault, self._need, self.principal hooks).

Principles
  * The API stays bearer-only (no cookies -> no CSRF). A session is an opaque random token (`ords_...`); only its hash is stored; it is re-validated against the live membership on EVERY request, so removing
    a member, changing a role or suspending an org takes effect immediately.
  * Failures are uniform ("invalid credentials"); unknown users cost the same time as wrong passwords; lockout is per ACCOUNT in the database (works across processes) on top of the per-IP limiter.
  * Every single-use value (invite, reset token, TOTP step, recovery code, SSO nonce, rotated key) is consumed with a conditional UPDATE or under a cross-process lock, never read-then-write.
  * SSO can create `member`/`viewer` only. Admin is always a deliberate human decision inside the org.
"""
from __future__ import annotations
import ipaddress, time
import json, secrets, time
from . import auth as A
from .errors import BoardError, Invalid, NotFound, Forbidden, Conflict, QuotaError, Unavailable

SESSION_TTL, SESSION_IDLE, MFA_TTL, ENROL_TTL = 12 * 3600, 2 * 3600, 300, 900
LOCK_AFTER, TOUCH_EVERY = 5, 60.0
GUARD_AFTER, HARD_LOCK_MAX, KNOWN_DAYS, IP_DECAY, GUARD_DECAY = 15, 3600, 30, 900, 6 * 3600     # hard lock never exceeds one hour
HUMAN_ROLES = ("admin", "member", "viewer")


class AuthFailed(BoardError):
    status = 401; code = "invalid_credentials"
    def __init__(self, msg="invalid credentials", **ctx): super().__init__(msg, **ctx)


def _email(e):
    e = str(e or "").strip().lower()
    if not (3 <= len(e) <= 254) or e.count("@") != 1 or any(c.isspace() for c in e) or e.startswith("@") or e.endswith("@") or "." not in e.split("@")[1]: raise Invalid("a valid email address is required")
    return e


class AccountsMixin:
    # ------------------------------------------------------------------ sessions
    def _new_session(self, uid, org, kind, ttl, ip=None, c=None):
        tok = A.opaque_token("ords_"); sid = "s-" + secrets.token_hex(5); now = self.clock()
        def go(c): c.execute("INSERT INTO sessions(h,id,user_id,org,kind,created,expires,last_used,ip) VALUES(?,?,?,?,?,?,?,?,?)", (A.hash_token(tok), sid, uid, org, kind, now, now + ttl, now, (ip or "")[:64]))
        if c is not None: go(c)
        else:
            with self.db.tx() as t: go(t)
        return tok, sid

    def _session_principal(self, token):
        from .service import P
        now = self.clock(); c = self.db.c()
        s = c.execute("SELECT * FROM sessions WHERE h=? AND revoked IS NULL", (A.hash_token(token),)).fetchone()
        if s is None or s["expires"] < now or s["kind"] == "mfa": return None
        if s["kind"] == "full" and now - s["last_used"] > SESSION_IDLE: return None
        u = c.execute("SELECT status FROM users WHERE id=?", (s["user_id"],)).fetchone()
        if u is None or u["status"] != "active": return None
        m = c.execute("SELECT * FROM memberships WHERE org=? AND user_id=?", (s["org"], s["user_id"])).fetchone()
        o = c.execute("SELECT status FROM orgs WHERE id=?", (s["org"],)).fetchone()
        if m is None or o is None or o["status"] != "active": return None
        if now - s["last_used"] > TOUCH_EVERY:
            with self.db.tx() as t: t.execute("UPDATE sessions SET last_used=? WHERE h=?", (now, s["h"]))          # throttled: one write per minute, not per request
        return P(m["role"] if s["kind"] == "full" else "enrol", s["org"], m["project"], s["id"], s["user_id"])

    def logout(self, p):
        with self.db.tx() as c:
            c.execute("UPDATE sessions SET revoked=? WHERE id=? AND revoked IS NULL", (self.clock(), p.kid)); self.db.audit(p.actor, "auth.logout", p.org, None, {}, c)
        return {"ok": True}

    def sessions(self, p):
        self._human(p)
        return [dict(id=r["id"], kind=r["kind"], created=r["created"], last_used=r["last_used"], expires=r["expires"], ip=r["ip"], current=r["id"] == p.kid)
                for r in self.db.c().execute("SELECT * FROM sessions WHERE user_id=? AND org=? AND revoked IS NULL AND expires>? AND kind!='mfa' ORDER BY created DESC", (p.user, p.org, self.clock())).fetchall()]

    def revoke_session(self, p, sid):
        self._human(p)
        with self.db.tx() as c:
            if not c.execute("UPDATE sessions SET revoked=? WHERE id=? AND user_id=? AND revoked IS NULL", (self.clock(), sid, p.user)).rowcount: raise NotFound("session")
            self.db.audit(p.actor, "auth.session.revoke", p.org, None, {"session": sid}, c)
        return {"revoked": sid}

    def _revoke_user_sessions(self, c, uid, org=None, keep=None):
        q = "UPDATE sessions SET revoked=? WHERE user_id=? AND revoked IS NULL"; a = [self.clock(), uid]
        if org: q += " AND org=?"; a.append(org)
        if keep: q += " AND id!=?"; a.append(keep)
        c.execute(q, a)

    def _human(self, p):
        if not p.user or p.role not in HUMAN_ROLES + ("enrol",): raise Forbidden("this action needs a signed-in user session")

    # ------------------------------------------------------------------ password + lockout
    # Throttling model (replaces the old per-account 24 h lock, which let anyone who knew an email lock its owner out):
    #   * per (account, network prefix): 5 failures -> THAT prefix is blocked 15 min, doubling, hard cap 1 h. The victim, on another network, is unaffected.
    #   * account-wide guard against IP rotation: failures from prefixes this account has never logged in from are counted together; at GUARD_AFTER the account is "guarded" - unknown prefixes are refused for
    #     15/30/60 min (hard cap 1 h) while prefixes with a successful login in the last KNOWN_DAYS keep working. So an attacker can neither lock the owner out nor out-run the limiter by rotating addresses.
    #   * restoration: a valid TOTP/recovery code (`unlock_account`, throttled on its own) or a password reset (email proof) lifts the guard.
    def _ipk(self, ip):
        if not ip: return "?"
        try:
            a = ipaddress.ip_address(str(ip).split("%")[0])
            return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 56}", strict=False))
        except ValueError: return "?"

    def _throttle_row(self, c, uid, ipk): return c.execute("SELECT * FROM auth_throttle WHERE user_id=? AND ipk=?", (uid, ipk)).fetchone()

    def _blocked(self, uid, ip):
        """True when this (account, network) may not even attempt a credential right now."""
        now = self.clock(); k = self._ipk(ip); c = self.db.c()
        r = self._throttle_row(c, uid, k)
        if r and r["locked_until"] and r["locked_until"] > now: return True
        g = self._throttle_row(c, uid, "*")
        if g and g["locked_until"] and g["locked_until"] > now:
            return not (r and r["last_ok"] and now - r["last_ok"] < KNOWN_DAYS * 86400)
        return False

    def _upsert(self, c, uid, ipk, **kw):
        if self._throttle_row(c, uid, ipk) is None: c.execute("INSERT INTO auth_throttle(user_id, ipk, failed) VALUES(?,?,0)", (uid, ipk))
        sets = ", ".join(f"{k}=?" for k in kw); c.execute(f"UPDATE auth_throttle SET {sets} WHERE user_id=? AND ipk=?", (*kw.values(), uid, ipk))

    def _fail(self, uid, why, org=None, ip=None, bucket=None):
        k = bucket or self._ipk(ip)
        with self.db.xlock("user:" + uid), self.db.tx() as c:
            now = self.clock(); r = self._throttle_row(c, uid, k)
            n = 1 if (r is None or not r["last_fail"] or now - r["last_fail"] > IP_DECAY) else r["failed"] + 1
            lock = now + min(900 * 2 ** max(0, n - LOCK_AFTER), HARD_LOCK_MAX) if n >= LOCK_AFTER else (r["locked_until"] if r else None)
            self._upsert(c, uid, k, failed=n, last_fail=now, locked_until=lock)
            known = bool(r and r["last_ok"] and now - r["last_ok"] < KNOWN_DAYS * 86400); guard = None; g = None
            if not known and k not in ("U",):
                g = self._throttle_row(c, uid, "*"); gn = 1 if (g is None or not g["last_fail"] or now - g["last_fail"] > GUARD_DECAY) else g["failed"] + 1
                guard = now + min(900 * 2 ** max(0, gn - GUARD_AFTER), HARD_LOCK_MAX) if gn >= GUARD_AFTER else (g["locked_until"] if g else None)
                self._upsert(c, uid, "*", failed=gn, last_fail=now, locked_until=guard)
            if guard and guard > now and self.mail_enabled and not (g and g["locked_until"] and g["locked_until"] > now):                # the guard just engaged: tell the owner, once per hour
                em = c.execute("SELECT email FROM users WHERE id=?", (uid,)).fetchone()
                if em: self._mail(c, em["email"], "account_guarded", {}, None, dedupe=f"guard:{uid}:{int(now // 3600)}")
            orgs = [org] if org else [m["org"] for m in c.execute("SELECT org FROM memberships WHERE user_id=?", (uid,)).fetchall()] or [None]      # visible in every org the account belongs to
            for o in orgs: self.db.audit(f"user:{uid}", "auth.fail", o, None, {"why": why, "failures": n, "ip_blocked": bool(lock and lock > now), "account_guarded": bool(guard and guard > now), "ip": ip}, c)

    def _ok(self, c, uid, ip=None):
        now = self.clock(); self._upsert(c, uid, self._ipk(ip), failed=0, locked_until=None, last_ok=now, last_fail=None)
        c.execute("UPDATE users SET failed=0, locked_until=NULL, last_login=? WHERE id=?", (now, uid))

    def _clear_throttle(self, c, uid, keep_known=True):
        c.execute("UPDATE auth_throttle SET failed=0, locked_until=NULL, last_fail=NULL WHERE user_id=?", (uid,)) if keep_known else c.execute("DELETE FROM auth_throttle WHERE user_id=?", (uid,))

    def unlock_account(self, email, code, ip=None):
        """Lift the account-wide guard and this network's block with a valid second factor. Throttled on its own (5 wrong codes -> 15 min -> ... 1 h, from any network); uniform failure."""
        try: email = _email(email)
        except Invalid: A.burn_password_time(code); raise AuthFailed()
        u = self._user_by_email(email)
        if u is None or u["status"] != "active" or not u["mfa_enabled"]: A.burn_password_time(code); raise AuthFailed()
        uid = u["id"]; now = self.clock(); r = self._throttle_row(self.db.c(), uid, "U")
        if r and r["locked_until"] and r["locked_until"] > now: A.burn_password_time(code); raise AuthFailed()
        self._verify_second_factor(uid, code, None, ip, bucket="U", honour_lock=False)
        with self.db.xlock("user:" + uid), self.db.tx() as c:
            self._clear_throttle(c, uid); self._upsert(c, uid, "U", failed=0, locked_until=None)
            for o in [m["org"] for m in c.execute("SELECT org FROM memberships WHERE user_id=?", (uid,)).fetchall()] or [None]: self.db.audit(f"user:{uid}", "auth.unlock", o, None, {"ip": ip}, c)
        return {"ok": True}

    def _user_by_email(self, email): return self.db.c().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    def _check_password(self, u, password, org=None, ip=None):
        """-> True or raises AuthFailed. Same cost and same message for unknown user, locked account, SSO-only account and wrong password."""
        if u is None or not u["pw_hash"] or u["status"] != "active" or self._blocked(u["id"], ip):
            A.burn_password_time(password)
            if u is not None and u["status"] == "active" and u["pw_hash"]: self.db.audit(f"user:{u['id']}", "auth.locked_attempt", org, None, {"ip": ip})
            raise AuthFailed()
        if not A.verify_password(password if isinstance(password, str) else "", u["pw_hash"]): self._fail(u["id"], "password", org, ip); raise AuthFailed()
        return True

    def change_password(self, p, old, new):
        self._human(p); u = self.db.c().execute("SELECT * FROM users WHERE id=?", (p.user,)).fetchone(); self._check_password(u, old, p.org); A.check_password_policy(new, u["email"])
        with self.db.xlock("user:" + p.user), self.db.tx() as c:
            c.execute("UPDATE users SET pw_hash=? WHERE id=?", (A.hash_password(new), p.user)); self._revoke_user_sessions(c, p.user, keep=p.kid); self.db.audit(p.actor, "auth.password.change", p.org, None, {}, c)
        return {"ok": True}

    # ------------------------------------------------------------------ login
    def _memberships(self, uid): return self.db.c().execute("SELECT m.*, o.status ostatus, o.require_mfa FROM memberships m JOIN orgs o ON o.id=m.org WHERE m.user_id=? AND o.status='active'", (uid,)).fetchall()

    def login(self, email, password, org=None, code=None, ip=None):
        """-> {"session": tok, ...} | {"mfa_required": True, "mfa_token": tok} | {"choose_org": [...]} | {"mfa_enrol_required": True, "session": limited}"""
        try: email = _email(email)
        except Invalid: A.burn_password_time(password); raise AuthFailed()
        u = self._user_by_email(email); self._check_password(u, password, org, ip)
        ms = self._memberships(u["id"])
        if org is not None: ms = [m for m in ms if m["org"] == org]
        if not ms: raise AuthFailed()                                                                       # no membership in the requested org: indistinguishable from a bad password
        if len(ms) > 1: return {"choose_org": sorted(m["org"] for m in ms)}
        m = ms[0]
        sso = self.db.c().execute("SELECT enforce FROM sso_providers WHERE org=?", (m["org"],)).fetchone()
        if sso and sso["enforce"]: raise Forbidden("this organization requires single sign-on", sso_required=True)
        if u["mfa_enabled"]:
            if code is None:
                tok, _ = self._new_session(u["id"], m["org"], "mfa", MFA_TTL, ip); return {"mfa_required": True, "mfa_token": tok}
            self._verify_second_factor(u["id"], code, m["org"], ip)
        elif m["require_mfa"]:
            tok, sid = self._new_session(u["id"], m["org"], "enrol", ENROL_TTL, ip)
            with self.db.tx() as c: self.db.audit(f"user:{u['id']}", "auth.login.enrol_only", m["org"], None, {"session": sid}, c)
            return {"mfa_enrol_required": True, "session": tok, "expires_in": ENROL_TTL}
        return self._finish_login(u["id"], m, ip, "password")

    def login_mfa(self, mfa_token, code, ip=None):
        now = self.clock(); s = self.db.c().execute("SELECT * FROM sessions WHERE h=? AND kind='mfa' AND revoked IS NULL", (A.hash_token(mfa_token),)).fetchone()
        if s is None or s["expires"] < now: A.burn_password_time(code); raise AuthFailed()
        self._verify_second_factor(s["user_id"], code, s["org"], ip)
        with self.db.tx() as c:
            if not c.execute("UPDATE sessions SET revoked=? WHERE h=? AND revoked IS NULL", (now, s["h"])).rowcount: raise AuthFailed()     # an MFA token is single-use
        m = self.db.c().execute("SELECT m.*, o.require_mfa FROM memberships m JOIN orgs o ON o.id=m.org WHERE m.org=? AND m.user_id=?", (s["org"], s["user_id"])).fetchone()
        if m is None: raise AuthFailed()
        return self._finish_login(s["user_id"], m, ip, "password+mfa")

    def _finish_login(self, uid, m, ip, how):
        with self.db.xlock("user:" + uid), self.db.tx() as c:
            self._ok(c, uid, ip); tok, sid = self._new_session(uid, m["org"], "full", SESSION_TTL, ip, c); self.db.audit(f"user:{uid}", "auth.login", m["org"], None, {"how": how, "session": sid, "ip": ip}, c)
        return {"session": tok, "org": m["org"], "role": m["role"], "expires_in": SESSION_TTL}

    def _verify_second_factor(self, uid, code, org=None, ip=None, bucket=None, honour_lock=True):
        """TOTP (each 30 s step usable ONCE) or a recovery code (usable once). Counts failures toward lockout. Raises AuthFailed."""
        with self.db.xlock("user:" + uid):
            u = self.db.c().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if u is None or u["status"] != "active" or (honour_lock and self._blocked(uid, ip)): A.burn_password_time(code); raise AuthFailed()
            code = str(code or "").strip()
            sec = self.vault.open(u["mfa_secret"], f"mfa|{uid}").decode() if u["mfa_secret"] else None
            step = A.totp_verify(sec, code, self.clock(), u["mfa_counter"]) if sec else None
            if step is not None:
                with self.db.tx() as c:
                    if c.execute("UPDATE users SET mfa_counter=? WHERE id=? AND mfa_counter<?", (step, uid, step)).rowcount: return True       # conditional UPDATE: a replayed code loses the race
            else:
                rec = json.loads(u["recovery"] or "[]"); hh = A.hash_recovery(code)
                if hh in rec:
                    rec.remove(hh)
                    with self.db.tx() as c:
                        if c.execute("UPDATE users SET recovery=? WHERE id=? AND recovery=?", (json.dumps(rec), uid, u["recovery"])).rowcount:
                            self.db.audit(f"user:{uid}", "auth.recovery_code_used", org, None, {"left": len(rec)}, c); return True
        self._fail(uid, "mfa", org, ip, bucket=bucket); raise AuthFailed()

    # ------------------------------------------------------------------ MFA enrolment
    def mfa_begin(self, p):
        self._human(p)
        with self.db.xlock("user:" + p.user), self.db.tx() as c:
            u = c.execute("SELECT * FROM users WHERE id=?", (p.user,)).fetchone()
            if u["mfa_enabled"]: raise Conflict("MFA is already enabled; disable it first")
            sec = A.totp_secret(); c.execute("UPDATE users SET mfa_secret=? WHERE id=?", (self.vault.seal(sec, f"mfa|{p.user}"), p.user)); self.db.audit(p.actor, "auth.mfa.begin", p.org, None, {}, c)
        return {"secret": sec, "otpauth_uri": A.otpauth_uri(sec, u["email"])}

    def mfa_confirm(self, p, code):
        self._human(p)
        with self.db.xlock("user:" + p.user):
            u = self.db.c().execute("SELECT * FROM users WHERE id=?", (p.user,)).fetchone()
            if u["mfa_enabled"] or not u["mfa_secret"]: raise Conflict("start enrolment first")
            step = A.totp_verify(self.vault.open(u["mfa_secret"], f"mfa|{p.user}").decode(), code, self.clock())
            if step is None: self._fail(p.user, "mfa_confirm", p.org); raise AuthFailed("that code is not valid")
            codes = A.new_recovery_codes()
            with self.db.tx() as c:
                c.execute("UPDATE users SET mfa_enabled=1, mfa_counter=?, recovery=? WHERE id=?", (step, json.dumps([A.hash_recovery(x) for x in codes]), p.user))
                self._revoke_user_sessions(c, p.user, keep=p.kid if p.role != "enrol" else None); self.db.audit(p.actor, "auth.mfa.enable", p.org, None, {}, c)
                if self.mail_enabled: self._mail(c, c.execute("SELECT email FROM users WHERE id=?", (p.user,)).fetchone()["email"], "mfa_enabled", {}, p.org)
                out = {"recovery_codes": codes}
                if p.role == "enrol": c.execute("UPDATE sessions SET revoked=? WHERE id=?", (self.clock(), p.kid)); tok, sid = self._new_session(p.user, p.org, "full", SESSION_TTL, None, c); out["session"] = tok       # upgrade: limited -> full
        return out

    def mfa_disable(self, p, password, code):
        self._human(p)
        if p.role == "enrol": raise Forbidden("finish enrolment first")
        if self.db.c().execute("SELECT require_mfa FROM orgs WHERE id=?", (p.org,)).fetchone()["require_mfa"]: raise Forbidden("this organization requires MFA")
        u = self.db.c().execute("SELECT * FROM users WHERE id=?", (p.user,)).fetchone(); self._check_password(u, password, p.org); self._verify_second_factor(p.user, code, p.org)
        with self.db.tx() as c:
            c.execute("UPDATE users SET mfa_enabled=0, mfa_secret=NULL, recovery=NULL, mfa_counter=-1 WHERE id=?", (p.user,)); self._revoke_user_sessions(c, p.user, keep=p.kid); self.db.audit(p.actor, "auth.mfa.disable", p.org, None, {}, c)
        return {"ok": True}

    def set_require_mfa(self, p, on):
        self._need(p, "admin")
        with self.db.tx() as c: c.execute("UPDATE orgs SET require_mfa=? WHERE id=?", (1 if on else 0, p.org)); self.db.audit(p.actor, "org.require_mfa", p.org, None, {"on": bool(on)}, c)
        return {"require_mfa": bool(on)}

    # ------------------------------------------------------------------ invites, members, password reset
    def invite_user(self, p, email, role, project=None, ttl_s=7 * 86400):
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot invite users")
        email = _email(email)
        if role not in HUMAN_ROLES: raise Invalid("role must be admin|member|viewer")
        if project is not None:
            self._scope(p, project, "admin")
            if role == "admin": raise Invalid("admin is org-wide")
        ttl_s = max(60, min(int(ttl_s), 30 * 86400)); now = self.clock()
        with self.db.xlock("org:" + p.org), self.db.tx() as c:
            u = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if u and c.execute("SELECT 1 FROM memberships WHERE org=? AND user_id=?", (p.org, u["id"])).fetchone(): raise Conflict("already a member")
            if c.execute("SELECT COUNT(*) FROM invites WHERE org=? AND used IS NULL AND expires>?", (p.org, now)).fetchone()[0] >= 200: raise QuotaError("too many pending invites")
            tok = A.opaque_token("ordi_"); hh = A.hash_token(tok)
            c.execute("INSERT INTO invites(h,id,org,email,role,project,created,expires,made_by) VALUES(?,?,?,?,?,?,?,?,?)", (hh, hh[:12], p.org, email, role, project, now, now + ttl_s, p.actor))
            self.db.audit(p.actor, "invite.create", p.org, project, {"email": email, "role": role, "invite": hh[:12]}, c)
            if self.mail_enabled: self._mail(c, email, "invite", {"org": p.org, "inviter": p.actor, "role": role, "token": tok, "expires": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(now + ttl_s))}, p.org)
        if self.mail_enabled: return {"id": hh[:12], "email": email, "role": role, "expires": now + ttl_s, "emailed": True}        # the token exists only in the email to its recipient: not even the inviting admin sees it
        return {"invite": tok, "id": hh[:12], "email": email, "role": role, "expires": now + ttl_s}      # no mailer configured: delivered out-of-band by the admin

    def invites(self, p):
        self._need(p, "admin")
        return [dict(id=r["id"], email=r["email"], role=r["role"], project=r["project"], expires=r["expires"], used=r["used"]) for r in
                self.db.c().execute("SELECT * FROM invites WHERE org=? AND role!='_reset' ORDER BY created DESC LIMIT 200", (p.org,)).fetchall()]

    def revoke_invite(self, p, iid):
        self._need(p, "admin")
        with self.db.tx() as c:
            if not c.execute("UPDATE invites SET used=? WHERE id=? AND org=? AND used IS NULL", (self.clock(), iid, p.org)).rowcount: raise NotFound("invite")
            self.db.audit(p.actor, "invite.revoke", p.org, None, {"invite": iid}, c)
        return {"revoked": iid}

    def accept_invite(self, token, password, name="", ip=None):
        now = self.clock(); hh = A.hash_token(token); inv = self.db.c().execute("SELECT * FROM invites WHERE h=? AND used IS NULL AND expires>? AND role!='_reset'", (hh, now)).fetchone()
        if inv is None: A.burn_password_time(password); raise AuthFailed("invite is invalid, used or expired")
        if self.db.c().execute("SELECT status FROM orgs WHERE id=?", (inv["org"],)).fetchone()["status"] != "active": raise AuthFailed("invite is invalid, used or expired")
        u = self._user_by_email(inv["email"])
        if u is not None: self._check_password(u, password, inv["org"], ip)           # an existing account must prove itself: an invite never takes over or silently attaches an account
        else: A.check_password_policy(password, inv["email"])
        with self.db.xlock("email:" + inv["email"]), self.db.tx() as c:
            if not c.execute("UPDATE invites SET used=? WHERE h=? AND used IS NULL AND expires>?", (now, hh, now)).rowcount: raise AuthFailed("invite is invalid, used or expired")     # single-use under races
            u = c.execute("SELECT * FROM users WHERE email=?", (inv["email"],)).fetchone()
            if u is None:
                uid = "u-" + secrets.token_hex(6); c.execute("INSERT INTO users(id,email,name,pw_hash,created) VALUES(?,?,?,?,?)", (uid, inv["email"], str(name)[:80], A.hash_password(password), now))
            else: uid = u["id"]
            if c.execute("SELECT 1 FROM memberships WHERE org=? AND user_id=?", (inv["org"], uid)).fetchone(): raise Conflict("already a member")
            c.execute("INSERT INTO memberships(org,user_id,role,project,created) VALUES(?,?,?,?,?)", (inv["org"], uid, inv["role"], inv["project"], now))
            self.db.audit(f"user:{uid}", "invite.accept", inv["org"], inv["project"], {"role": inv["role"], "invite": inv["id"]}, c)
        return {"user": uid, "org": inv["org"], "role": inv["role"]}

    def members(self, p):
        self._need(p, "admin")
        return [dict(user=r["id"], email=r["email"], name=r["name"], role=r["role"], project=r["project"], mfa=bool(r["mfa_enabled"]), status=r["status"], last_login=r["last_login"]) for r in
                self.db.c().execute("SELECT u.*, m.role, m.project FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org=? ORDER BY u.email", (p.org,)).fetchall()]

    def set_member(self, p, uid, role, project=None):
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot manage members")
        if role not in HUMAN_ROLES or (role == "admin" and project): raise Invalid("bad role/project")
        if project is not None: self._scope(p, project, "admin")
        with self.db.xlock("members:" + p.org), self.db.tx() as c:
            m = c.execute("SELECT * FROM memberships WHERE org=? AND user_id=?", (p.org, uid)).fetchone()
            if m is None: raise NotFound("member")
            if m["role"] == "admin" and role != "admin" and c.execute("SELECT COUNT(*) FROM memberships WHERE org=? AND role='admin'", (p.org,)).fetchone()[0] <= 1: raise Conflict("an organization needs at least one admin")
            c.execute("UPDATE memberships SET role=?, project=? WHERE org=? AND user_id=?", (role, project, p.org, uid)); self.db.audit(p.actor, "member.set", p.org, project, {"user": uid, "role": role}, c)
        return {"user": uid, "role": role, "project": project}

    def remove_member(self, p, uid):
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot manage members")
        with self.db.xlock("members:" + p.org), self.db.tx() as c:
            m = c.execute("SELECT * FROM memberships WHERE org=? AND user_id=?", (p.org, uid)).fetchone()
            if m is None: raise NotFound("member")
            if m["role"] == "admin" and c.execute("SELECT COUNT(*) FROM memberships WHERE org=? AND role='admin'", (p.org,)).fetchone()[0] <= 1: raise Conflict("an organization needs at least one admin")
            c.execute("DELETE FROM memberships WHERE org=? AND user_id=?", (p.org, uid)); self._revoke_user_sessions(c, uid, org=p.org); self.db.audit(p.actor, "member.remove", p.org, None, {"user": uid}, c)
        return {"removed": uid}

    def issue_password_reset(self, p, uid, ttl_s=3600):
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot reset passwords")
        now = self.clock()
        with self.db.tx() as c:
            u = c.execute("SELECT u.* FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.org=? AND u.id=?", (p.org, uid)).fetchone()
            if u is None: raise NotFound("member")
            memberships = c.execute("SELECT COUNT(*) FROM memberships WHERE user_id=?", (uid,)).fetchone()[0]
            if not self.mail_enabled and memberships != 1: raise Unavailable("cross-organization password recovery requires configured transactional email")
            tok = A.opaque_token("ordr_"); hh = A.hash_token(tok)
            c.execute("INSERT INTO invites(h,id,org,email,role,created,expires,made_by) VALUES(?,?,?,?,?,?,?,?)", (hh, hh[:12], p.org, u["email"], "_reset", now, now + min(int(ttl_s), 86400), p.actor))
            self.db.audit(p.actor, "auth.reset.issue", p.org, None, {"user": uid}, c)
            if self.mail_enabled: self._mail(c, u["email"], "password_reset", {"token": tok, "expires": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(now + min(int(ttl_s), 86400)))}, p.org)
        if self.mail_enabled: return {"emailed": True, "expires": now + min(int(ttl_s), 86400)}
        return {"reset_token": tok, "expires": now + min(int(ttl_s), 86400)}

    def request_password_reset(self, email, ip=None):
        """Self-service "forgot password". ALWAYS the same answer (no account enumeration). Needs a mailer: the token only ever travels by email. 3 requests/hour/account."""
        out = {"ok": True, "message": "If that address has an account, a reset link is on its way."}
        try: email = _email(email)
        except Invalid: A.burn_password_time("x"); return out
        if not self.mail_enabled: A.burn_password_time("x"); return out
        u = self._user_by_email(email); now = self.clock()
        if u is None or u["status"] != "active" or not u["pw_hash"]: A.burn_password_time("x"); return out
        with self.db.xlock("user:" + u["id"]), self.db.tx() as c:
            if c.execute("SELECT COUNT(*) FROM invites WHERE email=? AND role='_reset' AND created>?", (email, now - 3600)).fetchone()[0] >= 3: return out
            tok = A.opaque_token("ordr_"); hh = A.hash_token(tok); org = (c.execute("SELECT org FROM memberships WHERE user_id=? LIMIT 1", (u["id"],)).fetchone() or {"org": None})["org"]
            c.execute("INSERT INTO invites(h,id,org,email,role,created,expires,made_by) VALUES(?,?,?,?,?,?,?,?)", (hh, hh[:12], org, email, "_reset", now, now + 3600, "self"))
            self.db.audit(f"user:{u['id']}", "auth.reset.request", org, None, {"ip": ip}, c)
            self._mail(c, email, "password_reset", {"token": tok, "expires": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(now + 3600))}, org)
        return out

    def reset_password(self, token, new_password, ip=None):
        now = self.clock(); hh = A.hash_token(token); r = self.db.c().execute("SELECT * FROM invites WHERE h=? AND role='_reset' AND used IS NULL AND expires>?", (hh, now)).fetchone()
        if r is None: A.burn_password_time(new_password); raise AuthFailed("reset token is invalid, used or expired")
        A.check_password_policy(new_password, r["email"])
        with self.db.tx() as c:
            if not c.execute("UPDATE invites SET used=? WHERE h=? AND used IS NULL AND expires>?", (now, hh, now)).rowcount: raise AuthFailed("reset token is invalid, used or expired")
            u = c.execute("SELECT id FROM users WHERE email=?", (r["email"],)).fetchone()
            c.execute("UPDATE users SET pw_hash=?, failed=0, locked_until=NULL WHERE id=?", (A.hash_password(new_password), u["id"])); self._clear_throttle(c, u["id"]); self._revoke_user_sessions(c, u["id"])      # MFA stays: a reset never downgrades the account
            self.db.audit(f"user:{u['id']}", "auth.reset.use", r["org"], None, {"ip": ip}, c)
        return {"ok": True}

    # ------------------------------------------------------------------ OIDC SSO (foundation: ID-token validation + JIT provisioning; the browser redirect dance lives in the IdP client, not here)
    def set_sso(self, p, issuer, client_id, alg, jwks, domains, default_role="member", enforce=False):
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot configure SSO")
        if default_role not in ("member", "viewer"): raise Invalid("SSO can only provision member or viewer")
        if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains): raise Invalid("domains must be a list of strings")
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list): raise Invalid("jwks must be an object with a keys list")
        if not isinstance(issuer, str) or not isinstance(client_id, str): raise Invalid("issuer and client_id must be strings")
        domains = [d.lower().strip() for d in domains if d.strip()]
        if not domains: raise Invalid("allowed email domains are required (an IdP must never be able to claim arbitrary addresses)")
        if alg not in ("RS256", "ES256", "EdDSA"): raise Invalid("alg must be RS256, ES256 or EdDSA")
        if not str(issuer).startswith("https://") or not client_id: raise Invalid("issuer must be https and client_id is required")
        keys = (jwks or {}).get("keys") or []
        if not keys: raise Invalid("jwks.keys is required")
        try:
            for k in keys: A._jwk_key(k)
        except Exception as e: raise Invalid(f"bad jwks: {e}")
        with self.db.tx() as c:
            c.execute("DELETE FROM sso_providers WHERE org=?", (p.org,))
            c.execute("INSERT INTO sso_providers(org,issuer,client_id,alg,jwks,domains,default_role,enforce,created) VALUES(?,?,?,?,?,?,?,?,?)", (p.org, issuer, client_id, alg, json.dumps(jwks), json.dumps(domains), default_role, 1 if enforce else 0, self.clock()))
            self.db.audit(p.actor, "sso.configure", p.org, None, {"issuer": issuer, "domains": domains, "enforce": bool(enforce), "default_role": default_role}, c)
        return {"org": p.org, "issuer": issuer, "domains": domains, "enforce": bool(enforce)}

    def sso_config(self, p):
        self._need(p, "admin"); r = self.db.c().execute("SELECT * FROM sso_providers WHERE org=?", (p.org,)).fetchone()
        return None if r is None else {"issuer": r["issuer"], "client_id": r["client_id"], "alg": r["alg"], "domains": json.loads(r["domains"]), "default_role": r["default_role"], "enforce": bool(r["enforce"])}

    def sso_begin(self, org):
        if self.db.c().execute("SELECT 1 FROM sso_providers WHERE org=?", (org,)).fetchone() is None: raise AuthFailed("single sign-on is not configured")
        n = secrets.token_urlsafe(24); now = self.clock()
        with self.db.tx() as c:
            c.execute("DELETE FROM sso_nonces WHERE expires<?", (now - 3600,)); c.execute("INSERT INTO sso_nonces(nonce,org,expires) VALUES(?,?,?)", (n, org, now + 600))
        return {"nonce": n, "ttl_s": 600}

    def sso_login(self, org, id_token, nonce, ip=None):
        now = self.clock(); r = self.db.c().execute("SELECT * FROM sso_providers WHERE org=?", (org,)).fetchone()
        if r is None or self.db.c().execute("SELECT status FROM orgs WHERE id=?", (org,)).fetchone()["status"] != "active": raise AuthFailed()
        with self.db.tx() as c:
            if not c.execute("UPDATE sso_nonces SET used=? WHERE nonce=? AND org=? AND used IS NULL AND expires>?", (now, str(nonce), org, now)).rowcount: raise AuthFailed()      # nonce is single-use: a captured token cannot be replayed
        try: claims = A.verify_id_token(id_token, json.loads(r["jwks"]), r["alg"], r["issuer"], r["client_id"], nonce=nonce, now=now, allowed_domains=json.loads(r["domains"]))
        except A.AuthError as e:
            with self.db.tx() as c: self.db.audit("sso", "sso.reject", org, None, {"why": str(e)[:120], "ip": ip}, c)
            raise AuthFailed()
        email = claims["email"].lower()
        with self.db.xlock("email:" + email), self.db.tx() as c:
            u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if u is None:
                uid = "u-" + secrets.token_hex(6); c.execute("INSERT INTO users(id,email,name,pw_hash,created) VALUES(?,?,?,?,?)", (uid, email, str(claims.get("name") or "")[:80], None, now)); u = {"id": uid, "status": "active"}
            if u["status"] != "active": raise AuthFailed()
            m = c.execute("SELECT * FROM memberships WHERE org=? AND user_id=?", (org, u["id"])).fetchone()
            if m is None:
                c.execute("INSERT INTO memberships(org,user_id,role,created) VALUES(?,?,?,?)", (org, u["id"], r["default_role"], now)); m = {"role": r["default_role"], "org": org}
                self.db.audit("sso", "sso.provision", org, None, {"user": u["id"], "role": r["default_role"]}, c)
            self._ok(c, u["id"], ip); tok, sid = self._new_session(u["id"], org, "full", SESSION_TTL, ip, c); self.db.audit(f"user:{u['id']}", "auth.login", org, None, {"how": "sso", "session": sid, "ip": ip}, c)
        return {"session": tok, "org": org, "role": m["role"], "expires_in": SESSION_TTL}

    # ------------------------------------------------------------------ API-key lifecycle
    def keys(self, p):
        self._need(p, "admin")
        return [dict(kid=r["kid"], role=r["role"], project=r["project"], label=r["label"], created=r["created"], expires=r["expires"], revoked=r["revoked"], last_used=r["last_used"], created_by=r["created_by"], rotated_to=r["rotated_to"])
                for r in self.db.c().execute("SELECT * FROM keys WHERE org=? AND role!='worker' ORDER BY created DESC LIMIT 500", (p.org,)).fetchall()]

    def rotate_key(self, p, kid, grace_s=3600):
        """New key with the same role/project/label; the old one keeps working for `grace_s` (default 1 h, max 7 d) then expires. A key can be rotated ONCE (rotated_to is the guard)."""
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot rotate keys")
        grace_s = max(0, min(int(grace_s), 7 * 86400)); now = self.clock()
        with self.db.xlock("key:" + str(kid)), self.db.tx() as c:
            k = c.execute("SELECT * FROM keys WHERE kid=? AND org=? AND role!='worker' AND revoked IS NULL", (kid, p.org)).fetchone()
            if k is None or (k["expires"] and k["expires"] < now): raise NotFound("key")
            if k["rotated_to"]: raise Conflict("key was already rotated", rotated_to=k["rotated_to"])
            ttl = (k["expires"] - now) if k["expires"] else None
            tok, nk = self.db.issue_key(k["role"], k["org"], k["project"], k["label"] or "", ttl, actor=p.actor, c=c)
            c.execute("UPDATE keys SET rotated_to=?, expires=? WHERE kid=?", (nk, min(k["expires"] or 1e18, now + grace_s), kid)); self.db.audit(p.actor, "key.rotate", p.org, k["project"], {"old": kid, "new": nk, "grace_s": grace_s}, c)
        return {"key": tok, "kid": nk, "role": k["role"], "project": k["project"], "old_kid": kid, "old_expires": now + grace_s}

    def _touch_key(self, r):
        now = self.clock()
        if now - (r["last_used"] or 0) > TOUCH_EVERY:
            with self.db.tx() as c: c.execute("UPDATE keys SET last_used=? WHERE kid=?", (now, r["kid"]))
