"""Adversarial suite (mission item 8). Every test is an attack with a stated expectation; run it on BOTH backends (BOARD_TEST_PG_DSN): SQLite's global write lock hides every race here."""
import json, os, threading, time, urllib.request, urllib.error, pytest
from ordivyr.board import auth as A, service as S
from ordivyr.board.accounts import AuthFailed
from ordivyr.board.api import serve
from ordivyr.board.errors import Conflict, Forbidden, Invalid, NotFound, QuotaError
from ordivyr.tests.board_support import World, wait_for

PW = "correct horse battery 42"


@pytest.fixture
def w(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "SCRYPT_N", 2 ** 10)
    x = World(tmp_path, {"hello": [("say", "hi")], "slow": [("sleep", 1.0), ("say", "ok")]}, monkeypatch); x.off = 0.0; yield x; x.close()


def human(w, adm, email, role="member", project=None):
    inv = w.board.invite_user(adm, email, role, project); w.board.accept_invite(inv["invite"], PW)


def race(n, fn, boards=None):
    out, errs = [], []
    def go(i):
        try: out.append(fn(i))
        except Exception as e: errs.append(e)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]; [t.start() for t in ts]; [t.join() for t in ts]; return out, errs


def http(url, method, path, tok=None, body=None, raw=None, headers=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url + path, data, {"Content-Type": "application/json", **({"Authorization": "Bearer " + tok} if tok else {}), **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req) as r: return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e: return e.code, e.read(), dict(e.headers)


# ============================================================ 1. tenant isolation: every object type, over HTTP, by id
def test_cross_tenant_matrix_every_route_returns_404_never_403_or_data(w):
    a = w.org("acme"); b = w.org("beta"); w.agent(a, "p1", "ag"); w.agent(b, "p1", "bag"); from ordivyr.board import runtime_adapter as RA
    wk = w.board.register_worker(a, "ordivyr", RA.capabilities(1, ("stub",))); jid = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]
    sid = w.board.create_schedule(a, "p1", "s", "x", "ag", every="every 2 hours")["id"]; w.board.memory(a, "p1", "put", "project", "k", "ACME-MEM"); w.board.put_secret(a, "sec", "ACME-SECRET")
    kid = w.board.issue_key(a, "member")["kid"]; inv = w.board.invite_user(a, "i@a.com", "member")
    human(w, a, "m@a.com"); uid = [m["user"] for m in w.board.members(a) if m["email"] == "m@a.com"][0]
    bk = w.board.issue_key(b, "admin")["key"]; srv = serve(w.board); url = f"http://127.0.0.1:{srv.server_address[1]}"; ACME = ("ACME-MEM", "ACME-SECRET", "acme", "i@a.com", "m@a.com", jid, sid)
    try:
        probes = [("GET", f"/v1/projects/p1/jobs/{jid}"), ("GET", f"/v1/projects/p1/jobs/{jid}/events"), ("GET", f"/v1/projects/p1/jobs/{jid}/timings"), ("POST", f"/v1/projects/p1/jobs/{jid}/cancel"), ("POST", f"/v1/projects/p1/jobs/{jid}/retry"), ("POST", f"/v1/projects/p1/jobs/{jid}/approve"),
                  ("POST", f"/v1/projects/p1/schedules/{sid}/disable"), ("GET", "/v1/projects/p1/memory/project/k"), ("DELETE", f"/v1/keys/{kid}"), ("POST", f"/v1/keys/{kid}/rotate"),
                  ("PUT", f"/v1/members/{uid}"), ("DELETE", f"/v1/members/{uid}"), ("POST", f"/v1/members/{uid}/reset-password"), ("DELETE", f"/v1/invites/{inv['id']}"),
                  ("POST", f"/v1/workers/{wk['worker']}/revoke"), ("POST", f"/v1/workers/{wk['worker']}/drain"), ("DELETE", "/v1/secrets/sec"), ("POST", "/v1/hosted/h-x/stop")]
        for m, path in probes:
            s, raw, _ = http(url, m, path, bk, {"role": "admin", "slots": 1, "resolution": "retry"} if m in ("PUT", "POST") else None)
            assert s == 404 or (path.endswith("/memory/project/k") and s == 200 and b'"found": false' in raw), (m, path, s, raw[:120]); assert not any(x.encode() in raw for x in ACME), (m, path)
        for path in ("/v1/projects/p1/jobs", "/v1/projects/p1/agents", "/v1/projects/p1/schedules", "/v1/projects/p1/teams"):
            s, raw, _ = http(url, "GET", path, bk); assert s in (200, 404) and not any(x.encode() in raw for x in ACME), path
        for path in ("/v1/members", "/v1/invites", "/v1/keys", "/v1/secrets", "/v1/workers", "/v1/audit", "/v1/usage", "/v1/spending", "/v1/alerts", "/v1/health", "/v1/hosted"):
            s, raw, _ = http(url, "GET", path, bk); assert s == 200 and not any(x.encode() in raw for x in ACME[:5] + ("\"org\": \"acme\"",)), (path, [x for x in ACME[:5] + ("\"org\": \"acme\"",) if x.encode() in raw], raw[:600])
        assert w.board.get_job(a, "p1", jid)["status"] in ("queued", "claimed", "running", "completed") and w.board.secrets_list(a)               # nothing of acme's was changed by beta
        pk = w.board.issue_key(b, "admin")["key"]
        assert http(url, "GET", "/v1/projects/p1/jobs/" + jid, pk)[0] == 404 and b"ACME-MEM" not in http(url, "GET", "/v1/projects/p1/memory/project/k", pk)[1]
    finally: srv.shutdown()


def test_same_user_in_two_orgs_cannot_cross_with_one_session(w):
    a = w.org("acme"); b = w.org("beta"); w.agent(a, "p1", "ag"); human(w, a, "dual@x.com", "admin"); inv = w.board.invite_user(b, "dual@x.com", "admin"); w.board.accept_invite(inv["invite"], PW)
    pa = w.board.principal(w.board.login("dual@x.com", PW, org="acme")["session"]); pb = w.board.principal(w.board.login("dual@x.com", PW, org="beta")["session"])
    assert (pa.org, pb.org) == ("acme", "beta") and w.board.agents(pa, "p1") and w.board.agents(pb, "p1") == []
    with pytest.raises(NotFound): w.board.get_job(pb, "p1", "j-anything")
    assert pa.user == pb.user and w.board.put_secret(pa, "k", "A") and w.board.secrets_list(pb) == []


def test_project_scoped_keys_and_members_are_boxed_in(w):
    a = w.org("acme", projects=("p1", "p2")); w.agent(a, "p1", "ag"); w.agent(a, "p2", "ag"); k = w.board.issue_key(a, "member", project="p1"); pk = w.board.principal(k["key"])
    with pytest.raises(NotFound): w.board.list_jobs(pk, "p2")
    for f in (lambda: w.board.issue_key(pk, "member"), lambda: w.board.create_project(pk, "p3"), lambda: w.board.put_secret(pk, "k", "v"), lambda: w.board.invite_user(pk, "x@y.com", "member"), lambda: w.board.set_spend_limit(pk, 1),
              lambda: w.board.provision_worker(pk, "x"), lambda: w.board.rotate_key(pk, k["kid"]), lambda: w.board.set_member(pk, "u-x", "viewer"), lambda: w.board.register_worker(pk, "ordivyr", {})):
        with pytest.raises(Forbidden): f()
    human(w, a, "scoped@x.com", "member", project="p1"); sp = w.board.principal(w.board.login("scoped@x.com", PW)["session"]); assert sp.project == "p1"
    with pytest.raises(NotFound): w.board.list_jobs(sp, "p2")
    assert w.board.agents(sp, "p1") and w.board.projects(sp) is not None


def test_role_escalation_attempts(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); human(w, a, "mem@x.com", "member"); human(w, a, "view@x.com", "viewer"); m = w.board.principal(w.board.login("mem@x.com", PW)["session"]); v = w.board.principal(w.board.login("view@x.com", PW)["session"])
    for f in (lambda: w.board.define_agent(m, "p1", "evil", {"system": "x", "permissions": {"terminal": "full"}}), lambda: w.board.submit_job(m, "p1", "x", agent={"system": "x", "permissions": {"write": True}}),
              lambda: w.board.submit_job(m, "p1", "x", agent_id="ag", validators=[{"name": "v", "cmd": "id"}]), lambda: w.board.issue_key(m, "admin"), lambda: w.board.set_member(m, m.user, "admin"), lambda: w.board.invite_user(m, "x@y.com", "admin"),
              lambda: w.board.submit_job(v, "p1", "x", agent_id="ag"), lambda: w.board.create_schedule(v, "p1", "n", "p", "ag", every="every 2 hours"), lambda: w.board.memory(v, "p1", "put", "project", "k", "v"), lambda: w.board.put_secret(m, "k", "v"),
              lambda: w.board.set_org_status(m, "acme", "suspended"), lambda: w.board.create_org(m, "newco"), lambda: w.board.kill(m, True), lambda: w.board.set_plan(m, "acme", "scale"), lambda: w.board.rotate_master_key(m)):
        with pytest.raises(Forbidden): f()
    with pytest.raises(Forbidden): w.board.spending_state(w.platform)                                                                 # platform key: operator, not a customer-data reader
    with pytest.raises(Forbidden): w.board.list_jobs(w.platform, "p1")


# ============================================================ 2. injection / traversal / mass assignment
EVIL = ["'; DROP TABLE jobs;--", "\" OR 1=1 --", "../../etc/passwd", "a\x00b", "%00", "x' UNION SELECT key FROM keys --", "${jndi:ldap://x}", "{{7*7}}", "‮\u0000", "a" * 5000, "../" * 40, "\n\r"]


def test_hostile_strings_in_every_identifier_field_are_inert(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); n_orgs = w.board.db.c().execute("SELECT COUNT(*) FROM orgs").fetchone()[0]
    for e in EVIL:
        for f in (lambda: w.board.create_project(a, e), lambda: w.board.define_agent(a, "p1", e, {"system": "x"}), lambda: w.board.create_org(w.platform, e), lambda: w.board.memory(a, "p1", "put", e, "k", "v"), lambda: w.board.memory(a, "p1", "put", "project", e, "v"),
                  lambda: w.board.put_secret(a, e, "v"), lambda: w.board.submit_job(a, e, "x", agent_id="ag"), lambda: w.board.submit_job(a, "p1", "x", agent_id=e), lambda: w.board.submit_job(a, "p1", "x", agent_id="ag", workspace=e),
                  lambda: w.board.get_job(a, "p1", e), lambda: w.board.invite_user(a, e, "member"), lambda: w.board.login(e, e), lambda: w.board.fire_hook(e, e)):
            try: f()
            except (S.BoardError, AuthFailed): pass
    assert w.board.db.c().execute("SELECT COUNT(*) FROM orgs").fetchone()[0] == n_orgs
    c = w.board.db.c(); assert c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0 and c.execute("SELECT COUNT(*) FROM keys").fetchone()[0] >= 2 and w.board.db.verify_audit()[0]            # tables intact, nothing executed
    assert {r["id"] for r in c.execute("SELECT id FROM orgs").fetchall()} == {"acme"} and {r["id"] for r in c.execute("SELECT id FROM projects").fetchall()} == {"p1"}


def test_tenant_ids_can_never_collide_with_internal_sentinels(w):
    for bad in ("~no-such-tenant~", "~no-projects~", "a:b", "org:p1", "", ".", "-x", "x" * 65, "a/b", "a b"):
        with pytest.raises(Invalid): w.board.create_org(w.platform, bad)
    a = w.org("acme")
    for bad in ("~no-such-tenant~", "~no-projects~", "p:1", "../x"):
        with pytest.raises(Invalid): w.board.create_project(a, bad)
    assert S.tenant_of("acme", "p1") == "acme:p1" and all(not t.startswith("~") for t in w.board.tenants_for({"org": "acme", "project": None}) or [])
    from ordivyr.board import runtime_adapter as RA
    r = w.board.register_worker(a, "ordivyr", RA.capabilities(1, ())); wp = w.board.worker_principal(r["token"]); assert w.board.tenants_for(wp) == ["acme:p1"]
    b = w.board.create_org(w.platform, "emptyco", "e"); bp = w.board.principal(b["admin_key"]); rb = w.board.register_worker(bp, "ordivyr", RA.capabilities(1, ()))
    assert w.board.tenants_for(w.board.worker_principal(rb["token"])) == ["~no-projects~"]                                          # an org with no projects serves nothing, not "everything"


def test_http_hardening_headers_body_limits_and_no_leaks(w):
    a = w.org("acme"); k = w.board.issue_key(a, "admin")["key"]; srv = serve(w.board); url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        s, raw, h = http(url, "GET", "/v1/me", k); lc = {x.lower(): v for x, v in h.items()}
        assert "access-control-allow-origin" not in lc and lc["x-content-type-options"] == "nosniff" and "frame-ancestors 'none'" in lc["content-security-policy"] and lc["cache-control"] == "no-store"
        assert http(url, "POST", "/v1/projects", k, raw=b"x" * 300_000, headers={"Content-Length": "300000"})[0] in (413, 422) and http(url, "POST", "/v1/projects", k, raw=b"{not json")[0] == 422 and http(url, "POST", "/v1/projects", k, raw=b"[1]")[0] == 422
        assert http(url, "GET", "/v1/me", "ordb_" + "x" * 40)[0] == 401 and http(url, "GET", "/v1/me", headers={"Authorization": "Basic abc"})[0] == 401 and http(url, "GET", "/v1/me?token=" + k)[0] == 401      # tokens are not accepted in the URL
        assert http(url, "GET", "/v1/me", "ords_" + "y" * 40)[0] == 401 and http(url, "PATCH", "/v1/me", k)[0] in (404, 405, 501)
        s, raw, _ = http(url, "POST", "/v1/projects/p1/jobs", k, {"prompt": "x", "agent_id": "ag", "org": "beta", "project": "p9", "spec": {}}); assert s == 422 and b"unknown fields" in raw                 # mass assignment of org/project/spec refused
        s, raw, _ = http(url, "GET", "/v1/projects/p1/jobs/%27%3BDROP", k); assert s == 404 and b"Traceback" not in raw and b"sqlite" not in raw.lower() and b"psycopg" not in raw.lower()
        assert http(url, "GET", "/healthz")[0] == 200 and b"acme" not in http(url, "GET", "/readyz")[1]
    finally: srv.shutdown()


# ============================================================ 3. concurrency: every limit and every single-use value
def test_totp_code_replay_race_exactly_one_login_wins(w):
    a = w.org("acme"); human(w, a, "m@x.com"); p = w.board.principal(w.board.login("m@x.com", PW)["session"]); sec = w.board.mfa_begin(p)["secret"]; w.off += 30; w.board.mfa_confirm(p, A.totp_now(sec, time.time() + w.off))
    w.off += 90; code = A.totp_now(sec, time.time() + w.off); w.board.clock = w.board.db.clock = lambda: time.time() + w.off; others = [w.reborn() for _ in range(3)]
    for o in others: o.clock = o.db.clock = w.board.clock
    toks = [b.login("m@x.com", PW)["mfa_token"] for b in (w.board, *others) for _ in range(2)]; boards = [b for b in (w.board, *others) for _ in range(2)]
    out, errs = race(8, lambda i: boards[i].login_mfa(toks[i], code))
    assert len(out) == 1 and all(isinstance(e, AuthFailed) for e in errs), (len(out), errs)


def test_mfa_guessing_across_processes_locks_the_account_within_bounds(w):
    a = w.org("acme"); human(w, a, "m@x.com"); p = w.board.principal(w.board.login("m@x.com", PW)["session"]); sec = w.board.mfa_begin(p)["secret"]; w.off += 30; w.board.mfa_confirm(p, A.totp_now(sec, time.time() + w.off))
    w.board.clock = w.board.db.clock = lambda: time.time() + w.off; boards = [w.board, w.reborn(), w.reborn()]
    for o in boards: o.clock = o.db.clock = w.board.clock
    toks = [boards[i % 3].login("m@x.com", PW)["mfa_token"] for i in range(5)]                                                         # 5 pending MFA tokens (the max an attacker gets before the lock)
    out, errs = race(5, lambda i: boards[i % 3].login_mfa(toks[i], "%06d" % (i + 7)))
    assert not out and w.board.db.c().execute("SELECT failed FROM auth_throttle WHERE ipk=? AND user_id=(SELECT id FROM users WHERE email='m@x.com')", ("?",)).fetchone()[0] == 5
    w.off += 60
    with pytest.raises(AuthFailed): w.board.login_mfa(toks[0], A.totp_now(sec, time.time() + w.off))      # locked: not even the right code works
    with pytest.raises(AuthFailed): w.board.login("m@x.com", PW)


def test_recovery_code_and_reset_token_and_key_rotation_are_single_use_under_races(w):
    a = w.org("acme"); human(w, a, "m@x.com", "admin"); p = w.board.principal(w.board.login("m@x.com", PW)["session"]); sec = w.board.mfa_begin(p)["secret"]; w.off += 30; rc = w.board.mfa_confirm(p, A.totp_now(sec, time.time() + w.off))["recovery_codes"][0]
    w.board.clock = w.board.db.clock = lambda: time.time() + w.off; toks = [w.board.login("m@x.com", PW)["mfa_token"] for _ in range(4)]
    out, errs = race(4, lambda i: w.reborn().login_mfa(toks[i], rc)); assert len(out) == 1 and len(errs) == 3                              # one recovery code, four simultaneous uses
    uid = p.user; rt = w.board.issue_password_reset(a, uid)["reset_token"]; out, errs = race(5, lambda i: w.reborn().reset_password(rt, f"new passphrase number {i}")); assert len(out) == 1 and len(errs) == 4
    kid = w.board.issue_key(a, "member")["kid"]; out, errs = race(6, lambda i: w.reborn().rotate_key(a, kid)); assert len(out) == 1 and all(isinstance(e, Conflict) for e in errs)
    assert w.board.db.c().execute("SELECT COUNT(*) FROM keys WHERE rotated_to IS NOT NULL").fetchone()[0] == 1


def test_resource_limits_hold_under_concurrent_creation(w, monkeypatch):
    monkeypatch.setitem(S.PLANS["team"], "max_projects", 4); monkeypatch.setitem(S.PLANS["team"], "max_workers", 3)
    a = w.org("acme", projects=("p1",)); from ordivyr.board import runtime_adapter as RA; boards = [w.board] + [w.reborn() for _ in range(2)]; pr = [b.principal(w.board.issue_key(a, "admin")["key"]) for b in boards]
    out, errs = race(12, lambda i: boards[i % 3].create_project(pr[i % 3], f"x{i}")); assert len(out) == 3 and all(isinstance(e, QuotaError) for e in errs) and len(w.board.projects(a)) == 4
    out, errs = race(9, lambda i: boards[i % 3].register_worker(pr[i % 3], "ordivyr", RA.capabilities(1, ()))); assert len(out) == 3 and all(isinstance(e, QuotaError) for e in errs)
    out, errs = race(3, lambda i: w.reborn().create_project(a, "same")); assert len(out) <= 1


def test_delegation_caps_and_budget_cannot_be_raced_past(w, monkeypatch):
    monkeypatch.setitem(S.PLANS["team"], "max_fanout", 3); monkeypatch.setitem(S.PLANS["team"], "max_descendants", 100)
    a = w.org("acme"); w.agent(a, "p1", "kid"); w.agent(a, "p1", "boss", permissions={"delegate": ["kid"]}); from ordivyr.board import runtime_adapter as RA
    w.board.register_worker(a, "ordivyr", RA.capabilities(2, ("stub",)))
    jid = w.board.submit_job(a, "p1", "[[hello]]", agent_id="boss", limits={"budget_usd": 0.9})["job_id"]; tid = w.board.db.c().execute("SELECT tid FROM jobs WHERE job_id=?", (jid,)).fetchone()[0]
    t = w.board.store.claim("probe", "n", 120, ["board.ordivyr"], ["acme:p1"]); fence = t["fence"]; boards = [w.board, w.reborn(), w.reborn()]
    out, errs = race(12, lambda i: boards[i % 3].w_delegate(tid, fence, {"agent": "kid", "prompt": f"c{i}", "key": f"k{i}", "limits": {"budget_usd": 0.4}}))
    kids = w.board.db.c().execute("SELECT budget FROM jobs WHERE parent=?", (jid,)).fetchall()
    assert len(out) == 2 and len(kids) == 2 and sum(r[0] for r in kids) <= 0.9 + 1e-9, (len(out), [r[0] for r in kids], [repr(e)[:80] for e in errs][:3])     # 0.4 + 0.4 fit in 0.9; a third cannot (and fan-out 3 is not the binding limit)
    with pytest.raises(PermissionError): w.board.w_delegate(tid, fence, {"agent": "boss", "prompt": "self-escalate"})                       # not on the delegation list
    kid_rows = w.board.db.c().execute("SELECT org, project FROM jobs WHERE parent=?", (jid,)).fetchall()
    assert kid_rows and all((r["org"], r["project"]) == ("acme", "p1") for r in kid_rows)                                                   # a forged org/project in the request body is never honoured


def test_webhook_cooldown_and_daily_limit_cannot_be_raced(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); from ordivyr.board import runtime_adapter as RA; w.board.register_worker(a, "ordivyr", RA.capabilities(1, ("stub",)))
    s = w.board.create_schedule(a, "p1", "h", "go", "ag", webhook=True, max_per_day=50); _, _, sid, tok = s["hook_path"].split("/")[1:]
    out, errs = race(8, lambda i: w.reborn().fire_hook(sid, tok)); assert len(out) == 1 and all(isinstance(e, QuotaError) for e in errs), (len(out), errs)      # cooldown check-then-act
    for bad in ("0" * 20, tok[:-1] + ("y" if tok[-1] == "x" else "x"), "", tok.upper()):
        with pytest.raises(NotFound): w.board.fire_hook(sid, bad)
    with pytest.raises(NotFound): w.board.fire_hook("s-nope", tok)


def test_last_admin_cannot_be_removed_by_two_admins_demoting_each_other(w):
    a = w.org("acme"); human(w, a, "a1@x.com", "admin"); human(w, a, "a2@x.com", "admin"); ids = {m["email"]: m["user"] for m in w.board.members(a)}
    p1 = w.board.principal(w.board.login("a1@x.com", PW)["session"]); p2 = w.board.principal(w.board.login("a2@x.com", PW)["session"]); boards = [w.board, w.reborn()]
    pp = [boards[0].principal(w.board.login("a1@x.com", PW)["session"]), boards[1].principal(w.board.login("a2@x.com", PW)["session"])]
    # the org has 3 admins here (the creating key's admin is a key, not a member): demote until one member-admin is left, concurrently
    out, errs = race(2, lambda i: boards[i].set_member(pp[i], ids[("a2@x.com", "a1@x.com")[i]], "viewer"))
    assert w.board.db.c().execute("SELECT COUNT(*) FROM memberships WHERE org='acme' AND role='admin'").fetchone()[0] >= 1 and len(out) + len(errs) == 2


# ============================================================ 4. audit chain
def test_audit_chain_detects_edit_delete_reorder_and_survives_concurrent_writers(w):
    a = w.org("acme"); boards = [w.board] + [w.reborn() for _ in range(3)]; ps = [b.principal(w.board.issue_key(a, "admin")["key"]) for b in boards]
    race(40, lambda i: boards[i % 4].put_secret(ps[i % 4], f"s{i}", "v")); assert w.board.db.verify_audit() == (True, None)               # 4 writers, one chain
    c = w.board.db.c(); rows = [r[0] for r in c.execute("SELECT id FROM audit ORDER BY id").fetchall()]; mid = rows[len(rows) // 2]
    def tamper(sql, args=()):
        with w.board.db.tx() as t: t.execute(sql, args)
    orig = c.execute("SELECT detail FROM audit WHERE id=?", (mid,)).fetchone()[0]
    tamper("UPDATE audit SET detail=? WHERE id=?", ('{"forged":1}', mid)); ok, bad = w.board.db.verify_audit(); assert not ok and bad == mid
    tamper("UPDATE audit SET detail=? WHERE id=?", (orig, mid)); assert w.board.db.verify_audit()[0]
    row = dict(c.execute("SELECT * FROM audit WHERE id=?", (mid,)).fetchone()); tamper("DELETE FROM audit WHERE id=?", (mid,)); ok, bad = w.board.db.verify_audit(); assert not ok
    tamper("INSERT INTO audit(id,ts,actor,org,project,action,detail,prev,h) VALUES(?,?,?,?,?,?,?,?,?)", (mid, row["ts"], row["actor"], row["org"], row["project"], row["action"], row["detail"], row["prev"], row["h"])); assert w.board.db.verify_audit()[0]
    tamper("UPDATE audit SET actor='someone-else' WHERE id=?", (mid,)); assert not w.board.db.verify_audit()[0]


def test_nothing_secret_ever_reaches_the_audit_log_or_access_log(w):
    a = w.org("acme"); logs = []; srv = serve(w.board, access_log=logs.append); url = f"http://127.0.0.1:{srv.server_address[1]}"; ak = w.board.issue_key(a, "admin")["key"]
    try:
        http(url, "PUT", "/v1/secrets/sk", ak, {"value": "TOPSECRETVALUE-9f3"}); inv = http(url, "POST", "/v1/invites", ak, {"email": "z@x.com", "role": "member"}); tok = json.loads(inv[1])["invite"]
        http(url, "POST", "/v1/auth/accept-invite", None, {"invite": tok, "password": "my own passphrase 12345"}); lr = http(url, "POST", "/v1/auth/login", None, {"email": "z@x.com", "password": "my own passphrase 12345"}); ses = json.loads(lr[1])["session"]
        http(url, "POST", "/v1/auth/login", None, {"email": "z@x.com", "password": "WRONG-PASSWORD-ATTEMPT-1"})
        w.agent(a, "p1", "ag"); s = w.board.create_schedule(a, "p1", "h", "go", "ag", webhook=True); hook = s["hook_path"].split("/")[-1]; http(url, "POST", s["hook_path"], None, {})
    finally: srv.shutdown()
    blob = json.dumps(w.board.db.audit_rows(org="acme")) + json.dumps(w.board.db.audit_rows(org=None)) + json.dumps(logs)
    for needle in ("TOPSECRETVALUE", tok, ses, ak, hook, "my own passphrase", "WRONG-PASSWORD", "scrypt$"): assert needle not in blob, needle


# ============================================================ 5. credentials and token confusion
def test_token_classes_cannot_be_used_across_surfaces(w):
    from ordivyr.board.coordinator import BoardRemote
    from ordivyr.board import runtime_adapter as RA
    a = w.org("acme"); ak = w.board.issue_key(a, "admin")["key"]; wt = w.board.register_worker(a, "ordivyr", RA.capabilities(1, ()))["token"]; ptok = (w.tmp / "board" / "platform.token").read_text().strip(); srv = serve(w.board); url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        assert http(url, "GET", "/v1/projects", wt)[0] == 403 and http(url, "GET", "/v1/projects", ptok)[0] == 403                          # worker/platform keys do not read customer data
        for tk in (ak, ptok, "ords_x"):
            with pytest.raises(Exception): BoardRemote(w.url, tk).claim_many_wait("w", "n", 5, None, 1, wait_s=0)                           # customer/platform/session tokens do not open the lease API
        assert BoardRemote(w.url, wt).claim_many_wait("w", "n", 5, None, 1, wait_s=0) == []
        with pytest.raises(Exception): BoardRemote(w.url, wt).node_report("n", 1, 1.0, 1.0)                                                  # workers cannot zero a node
        w.board.revoke_worker(a, [x["id"] for x in w.board.workers(a)][0])
        with pytest.raises(Exception): BoardRemote(w.url, wt).claim_many_wait("w", "n", 5, None, 1, wait_s=0)                              # revoked worker token is dead at once
        k2 = w.board.issue_key(a, "admin"); assert http(url, "GET", "/v1/me", k2["key"])[0] == 200; w.board.revoke_key(a, k2["kid"]); assert http(url, "GET", "/v1/me", k2["key"])[0] == 401
        w.board.set_org_status(w.platform, "acme", "suspended"); assert http(url, "GET", "/v1/me", ak)[0] == 401                               # suspension kills every credential of the org
    finally: srv.shutdown()


def test_expired_keys_and_sessions_and_kill_switch(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); k = w.board.issue_key(a, "member", ttl_s=60); w.board.clock = w.board.db.clock = lambda: time.time() + w.off
    assert w.board.principal(k["key"]); w.off = 120; assert w.board.principal(k["key"]) is None
    w.off = 0; w.board.kill(w.platform, True)
    with pytest.raises(S.Unavailable): w.board.submit_job(a, "p1", "x", agent_id="ag")
    w.board.kill(w.platform, False)
