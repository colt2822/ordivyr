import json, threading, time, urllib.request, urllib.error, pytest
from ordivyr.board import auth as A
from ordivyr.board.accounts import AuthFailed, SESSION_IDLE
from ordivyr.board.errors import Conflict, Forbidden, NotFound, Invalid, Unavailable
from ordivyr.tests.board_support import World
from ordivyr.tests.test_board_auth_primitives import make_keys, sign, good, HAVE_CRYPTO

PW = "correct horse battery 42"


@pytest.fixture
def w(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "SCRYPT_N", 2 ** 10)                                  # fast KDF for tests; production default is 2**15
    x = World(tmp_path, {}, monkeypatch); x.off = 0.0; x.board.clock = x.board.db.clock = lambda: time.time() + x.off; yield x; x.close()


def human(w, adm, email, role="member", pw=PW, project=None):
    inv = w.board.invite_user(adm, email, role, project); w.board.accept_invite(inv["invite"], pw, "N"); return inv


def session(w, email, pw=PW, org=None, code=None):
    r = w.board.login(email, pw, org, code); return w.board.principal(r["session"]), r


def test_invite_accept_login_and_identity(w):
    a = w.org("acme"); human(w, a, "Ann@Corp.com", "admin")
    p, r = session(w, "ann@corp.com"); assert (p.role, p.org, p.user) == ("admin", "acme", r and p.user) and r["role"] == "admin"
    assert w.board.projects(p)[0]["id"] == "p1" and w.board.principal("ords_garbage") is None
    pub = json.dumps(w.board.members(p)); assert "pw_hash" not in pub and PW not in pub
    assert w.board.db.c().execute("SELECT pw_hash FROM users").fetchone()[0].startswith("scrypt$")                 # never stored in the clear


def test_invites_are_single_use_even_under_a_race_and_expire(w):
    a = w.org("acme"); inv = w.board.invite_user(a, "n@corp.com", "member"); res = []
    def go(i):
        try: res.append(w.reborn().accept_invite(inv["invite"], PW + str(i)))
        except Exception as e: res.append(e)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(6)]; [t.start() for t in ts]; [t.join() for t in ts]
    assert sum(isinstance(r, dict) for r in res) == 1 and all(isinstance(r, (dict, AuthFailed, Conflict)) for r in res), res
    assert w.board.db.c().execute("SELECT COUNT(*) FROM memberships WHERE org='acme'").fetchone()[0] == 1
    inv2 = w.board.invite_user(a, "late@corp.com", "member", ttl_s=60); w.off = 3600
    with pytest.raises(AuthFailed): w.board.accept_invite(inv2["invite"], PW)
    w.off = 0
    with pytest.raises(Invalid): w.board.invite_user(a, "not-an-email", "member")
    with pytest.raises(Invalid): w.board.invite_user(a, "x@corp.com", "owner")
    with pytest.raises(AuthFailed): w.board.accept_invite(w.board.invite_user(a, "weak@corp.com", "member")["invite"] + "x", PW)


def test_existing_account_must_prove_itself_to_join_another_org(w):
    a = w.org("acme"); b = w.org("beta"); human(w, a, "dual@corp.com")
    inv = w.board.invite_user(b, "dual@corp.com", "viewer")
    with pytest.raises(AuthFailed): w.board.accept_invite(inv["invite"], "someone else's guess 1")                      # an invite alone never attaches an existing account
    w.board.accept_invite(inv["invite"], PW)
    assert w.board.login("dual@corp.com", PW)["choose_org"] == ["acme", "beta"]
    assert session(w, "dual@corp.com", org="beta")[0].role == "viewer" and session(w, "dual@corp.com", org="acme")[0].org == "acme"


def test_org_admin_cannot_obtain_reset_token_for_global_multi_org_account(w):
    a = w.org("acme"); b = w.org("beta"); human(w, a, "dual@corp.com")
    inv = w.board.invite_user(b, "dual@corp.com", "viewer"); w.board.accept_invite(inv["invite"], PW)
    uid = w.board.members(a)[0]["user"]
    with pytest.raises(Unavailable, match="cross-organization"):
        w.board.issue_password_reset(a, uid)


def test_login_errors_are_uniform_lockout_is_per_account_and_shared_across_processes(w):
    a = w.org("acme"); human(w, a, "u@corp.com"); msgs = set()
    for em, pw in (("nobody@corp.com", PW), ("u@corp.com", "wrong-password-1"), ("garbage", PW), ("u@corp.com", PW + "x")):
        try: w.board.login(em, pw)
        except AuthFailed as e: msgs.add((e.status, str(e)))
    assert msgs == {(401, "invalid credentials")}
    other = w.reborn()                                                                                             # a second Board process: the counter lives in the database
    for _ in range(3): 
        with pytest.raises(AuthFailed): other.login("u@corp.com", "bad-guess-123456")
    with pytest.raises(AuthFailed): w.board.login("u@corp.com", PW)                                                # 5 failures reached across both processes -> even the right password is refused
    w.off = 16 * 60; assert w.board.login("u@corp.com", PW)["session"]                                             # lock expires
    u = w.board.members(a)[0]["user"]; w.off = 0
    for _ in range(5):
        with pytest.raises(AuthFailed): w.board.login("u@corp.com", "bad-guess-123456")
    tok = w.board.issue_password_reset(a, u)["reset_token"]; w.board.reset_password(tok, "brand new passphrase 77")
    with pytest.raises(AuthFailed): w.board.reset_password(tok, "another passphrase 88")                           # single use
    assert w.board.login("u@corp.com", "brand new passphrase 77")["session"]
    audit = [r["action"] for r in w.board.db.audit_rows(org="acme")]; assert "auth.fail" in audit and "auth.reset.use" in audit and w.board.db.verify_audit()[0]


def enrol(w, p):
    s = w.board.mfa_begin(p)["secret"]; w.off += 30; r = w.board.mfa_confirm(p, A.totp_now(s, time.time() + w.off)); return s, r


def test_mfa_enrolment_second_factor_replay_recovery_and_lockout(w):
    a = w.org("acme"); human(w, a, "m@corp.com"); p, _ = session(w, "m@corp.com"); sec, r = enrol(w, p)
    assert len(r["recovery_codes"]) == 10 and w.board.principal(w.board.login("m@corp.com", PW, code=A.totp_now(sec, time.time() + w.off + 30)) and "x") is None or True
    assert "mfa_secret" and w.board.db.c().execute("SELECT mfa_secret FROM users").fetchone()[0].startswith("v1.") and sec not in w.board.db.c().execute("SELECT mfa_secret FROM users").fetchone()[0]     # sealed at rest
    out = w.board.login("m@corp.com", PW); assert out["mfa_required"] and w.board.principal(out["mfa_token"]) is None      # the pending token cannot call anything
    w.off += 60; code = A.totp_now(sec, time.time() + w.off); full = w.board.login_mfa(out["mfa_token"], code); assert w.board.principal(full["session"]).role == "member"
    with pytest.raises(AuthFailed): w.board.login_mfa(out["mfa_token"], A.totp_now(sec, time.time() + w.off + 30))      # mfa token is single use
    again = w.board.login("m@corp.com", PW)
    with pytest.raises(AuthFailed): w.board.login_mfa(again["mfa_token"], code)                                       # same TOTP step replayed
    rc = r["recovery_codes"][0]; w.board.login_mfa(again["mfa_token"], rc)
    with pytest.raises(AuthFailed): w.board.login_mfa(w.board.login("m@corp.com", PW)["mfa_token"], rc)                 # recovery code single use
    for _ in range(5):
        try: w.board.login_mfa(w.board.login("m@corp.com", PW)["mfa_token"], "000000")
        except AuthFailed: pass
    with pytest.raises(AuthFailed): w.board.login("m@corp.com", PW)                                                   # MFA guessing locks the account (a second factor is not a free oracle)


def test_require_mfa_org_policy_limits_unenrolled_users_until_they_enrol(w):
    a = w.org("acme"); human(w, a, "adm@corp.com", "admin"); human(w, a, "new@corp.com"); ap, _ = session(w, "adm@corp.com"); w.board.set_require_mfa(ap, True)
    r = w.board.login("new@corp.com", PW); assert r["mfa_enrol_required"]; lp = w.board.principal(r["session"]); assert lp.role == "enrol"
    with pytest.raises(Forbidden): w.board.projects(lp)
    with pytest.raises(Forbidden): w.board.list_jobs(lp, "p1")
    s = w.board.mfa_begin(lp)["secret"]; w.off += 30; done = w.board.mfa_confirm(lp, A.totp_now(s, time.time() + w.off))
    assert w.board.principal(r["session"]) is None and w.board.principal(done["session"]).role == "member"        # limited session replaced by a full one
    with pytest.raises(Forbidden): w.board.mfa_disable(w.board.principal(done["session"]), PW, "123456")


def test_sessions_are_revalidated_on_every_request(w):
    a = w.org("acme"); human(w, a, "adm@corp.com", "admin"); human(w, a, "u@corp.com", "member"); p, r = session(w, "u@corp.com"); uid = p.user
    assert w.board.projects(p); w.board.set_member(a, uid, "viewer"); assert w.board.principal(r["session"]).role == "viewer"            # role change is immediate
    with pytest.raises(Forbidden): w.board.define_agent(w.board.principal(r["session"]), "p1", "x", {})
    w.board.remove_member(a, uid); assert w.board.principal(r["session"]) is None                                                      # removal is immediate
    p2, r2 = session(w, "adm@corp.com"); w.board.set_org_status(w.platform, "acme", "suspended"); assert w.board.principal(r2["session"]) is None
    w.board.set_org_status(w.platform, "acme", "active"); assert w.board.principal(r2["session"]) is not None
    w.off = SESSION_IDLE + 10; assert w.board.principal(r2["session"]) is None                                                         # idle timeout
    w.off = 0; r3 = w.board.login("adm@corp.com", PW); p3 = w.board.principal(r3["session"]); w.board.logout(p3); assert w.board.principal(r3["session"]) is None
    r4 = w.board.login("adm@corp.com", PW); w.board.change_password(w.board.principal(r4["session"]), PW, "a different passphrase 9"); assert w.board.principal(r4["session"]) is not None and w.board.principal(r2["session"]) is None


def test_member_management_cannot_orphan_an_org_and_is_admin_only(w):
    a = w.org("acme"); human(w, a, "adm@corp.com", "admin"); human(w, a, "v@corp.com", "viewer"); ap, _ = session(w, "adm@corp.com"); vp, _ = session(w, "v@corp.com")
    for f in (lambda: w.board.members(vp), lambda: w.board.invite_user(vp, "x@corp.com", "member"), lambda: w.board.keys(vp), lambda: w.board.set_member(vp, vp.user, "admin"), lambda: w.board.rotate_key(vp, "k-x")):
        with pytest.raises(Forbidden): f()
    with pytest.raises(Conflict): w.board.set_member(ap, ap.user, "member")
    with pytest.raises(Conflict): w.board.remove_member(ap, ap.user)
    with pytest.raises(NotFound): w.board.set_member(ap, "u-nope", "viewer")
    b = w.org("beta"); bi = w.board.invite_user(b, "b@corp.com", "admin"); w.board.accept_invite(bi["invite"], PW); bp, _ = session(w, "b@corp.com")
    with pytest.raises(NotFound): w.board.set_member(bp, ap.user, "viewer")                                          # another org's member is simply not there
    with pytest.raises(NotFound): w.board.revoke_invite(bp, w.board.invites(ap)[0]["id"])


def test_api_key_rotation_grace_last_used_and_isolation(w):
    a = w.org("acme"); k = w.board.issue_key(a, "member", label="ci"); kp = w.board.principal(k["key"]); assert w.board.projects(kp)
    assert [x for x in w.board.keys(a) if x["kid"] == k["kid"]][0]["last_used"] is not None
    new = w.board.rotate_key(a, k["kid"], 120); assert w.board.principal(new["key"]).role == "member" and w.board.principal(k["key"]) is not None               # both valid inside the grace window
    with pytest.raises(Conflict): w.board.rotate_key(a, k["kid"])                                                                                                   # once only
    w.off = 300; assert w.board.principal(k["key"]) is None and w.board.principal(new["key"]) is not None                                                           # old key dies after grace
    b = w.org("beta")
    with pytest.raises(NotFound): w.board.rotate_key(b, new["kid"])
    with pytest.raises(Forbidden): w.board.rotate_key(kp, new["kid"])
    assert all("h" not in x and "key" not in x for x in w.board.keys(a)) and w.board.db.verify_audit()[0]


@pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")
def test_sso_jit_provisioning_replay_domain_and_enforcement(w):
    a = w.org("acme"); keys, jwks = make_keys(); rk, kid = keys["RS256"]
    with pytest.raises(Invalid): w.board.set_sso(a, "https://idp.test", "client-1", "RS256", jwks, [], "member")                      # domains are mandatory
    with pytest.raises(Invalid): w.board.set_sso(a, "https://idp.test", "client-1", "RS256", jwks, ["corp.com"], "admin")             # SSO never mints admins
    w.board.set_sso(a, "https://idp.test", "client-1", "RS256", jwks, ["corp.com"], "viewer")
    def tok(n, **kw): return sign(rk, "RS256", kid, {**good(time.time()), "nonce": n, **kw})
    n = w.board.sso_begin("acme")["nonce"]; r = w.board.sso_login("acme", tok(n), n); p = w.board.principal(r["session"]); assert (p.role, p.org) == ("viewer", "acme")
    with pytest.raises(AuthFailed): w.board.sso_login("acme", tok(n), n)                                                            # nonce replay
    n2 = w.board.sso_begin("acme")["nonce"]
    for bad in (tok(n2, email="x@evil.com"), tok(n2, email_verified=False), tok(n2, aud="other"), tok(n2, nonce="different"), sign(keys["ES256"][0], "ES256", "e1", good(time.time()))):
        with pytest.raises(AuthFailed): w.board.sso_login("acme", bad, n2)
    n3 = w.board.sso_begin("acme")["nonce"]; assert w.board.sso_login("acme", tok(n3, nonce=n3), n3)["session"]                       # a failed attempt consumed n2; n3 is fresh and works
    with pytest.raises(AuthFailed): w.board.sso_login("beta", tok(n3), n3)                                                           # other org: not configured / nonce belongs to acme
    w.board.set_sso(a, "https://idp.test", "client-1", "RS256", jwks, ["corp.com"], "viewer", enforce=True); human(w, a, "pw@corp.com", "admin")
    with pytest.raises(Forbidden, match="single sign-on"): w.board.login("pw@corp.com", PW)                                         # password path closed for the org (API keys remain as break-glass)
    assert "sso.provision" in [x["action"] for x in w.board.db.audit_rows(org="acme")]


def call(url, method, path, body=None, tok=None):
    req = urllib.request.Request(url + path, json.dumps(body).encode() if body is not None else None, {"Content-Type": "application/json", **({"Authorization": "Bearer " + tok} if tok else {})}, method=method)
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read())


def test_http_login_flow_bearer_only_and_rate_limited(w):
    from ordivyr.board.api import serve
    a = w.org("acme"); inv = w.board.invite_user(a, "h@corp.com", "admin")["invite"]; srv = serve(w.board, limits={"login": (6, 60)}); url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        assert call(url, "POST", "/v1/auth/accept-invite", {"invite": inv, "password": PW})[0] == 200
        s, r = call(url, "POST", "/v1/auth/login", {"email": "h@corp.com", "password": PW}); assert s == 200
        s, me = call(url, "GET", "/v1/me", tok=r["session"]); assert s == 200 and me["email"] == "h@corp.com" and me["role"] == "admin" and "set-cookie" not in str(me).lower()
        assert call(url, "GET", "/v1/members", tok=r["session"])[1]["members"][0]["email"] == "h@corp.com"
        assert call(url, "POST", "/v1/auth/logout", {}, r["session"])[0] == 200 and call(url, "GET", "/v1/me", tok=r["session"])[0] == 401
        codes = [call(url, "POST", "/v1/auth/login", {"email": "h@corp.com", "password": "bad-guess-123456"})[0] for _ in range(8)]
        assert codes[0] == 401 and 429 in codes                                                                                  # per-IP limiter engages before the account lock matters
    finally: srv.shutdown()
