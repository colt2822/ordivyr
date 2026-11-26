"""Phase 3 reliability/data lifecycle: tracing across delegation, retention that never touches live work or financial records, tenant erasure, graceful degradation."""
import json, threading, time, urllib.request
import pytest
from ordivyr.board import api as API
from ordivyr.board.errors import Forbidden, Invalid, NotFound
from ordivyr.tests.board_support import World
from ordivyr.tests.test_board_accounts import human, PW


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi")]}, monkeypatch); yield x; x.close()


def finish(w, a, n=1, prefix="j"):
    w.platform_worker(); ids = []
    for i in range(n):
        j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag", idem_key=f"{prefix}{i}")["job_id"]; w.done(a, "p1", j); ids.append(j)
    for _ in range(60):
        w.board.reconcile()
        if all(w.board.db.c().execute("SELECT metered FROM jobs WHERE job_id=?", (j,)).fetchone()[0] for j in ids): break
        time.sleep(0.2)
    return ids


def test_trace_id_flows_from_request_to_job_children_and_is_tenant_scoped(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); b = w.org("other"); w.agent(b, "p1", "ag"); w.platform_worker()
    w.board.set_trace("tr-client-abc12345"); j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]; w.board.set_trace(None)
    v = w.board.job_view(w.board.db.c().execute("SELECT * FROM jobs WHERE job_id=?", (j,)).fetchone()); assert v["trace"] == "tr-client-abc12345"
    spec = json.loads(w.board.db.c().execute("SELECT spec FROM jobs WHERE job_id=?", (j,)).fetchone()[0]); assert spec["labels"]["trace_id"] == "tr-client-abc12345"
    w.done(a, "p1", j); t = w.board.trace_view(a, "tr-client-abc12345"); assert [x["job_id"] for x in t["jobs"]] == [j] and t["jobs"][0]["events"]
    with pytest.raises(NotFound): w.board.trace_view(b, "tr-client-abc12345")                                          # another tenant cannot read it, nor learn it exists
    for bad in ("x", "a" * 80, "tr bad id", "../etc/passwd", "tr-\r\nX: y"):
        with pytest.raises(NotFound): w.board.trace_view(a, bad)
    w.board.set_trace("not valid!!"); assert w.board.current_trace() is None                                           # malformed client ids are ignored, a fresh one is generated at submit


def test_http_layer_echoes_and_validates_trace_ids(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.platform_worker(); tok = w.board.issue_key(a, "admin")["key"]
    srv = API.serve(w.board, port=0); port = srv.server_address[1]; threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        def call(path, hdr=None, data=None):
            rq = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(data).encode() if data is not None else None, headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json", **(hdr or {})})
            with urllib.request.urlopen(rq, timeout=10) as r: return r.headers.get("X-Trace-Id"), json.loads(r.read())
        hid, body = call("/v1/projects/p1/jobs", {"X-Trace-Id": "tr-from-client-77"}, {"prompt": "[[hello]]", "agent_id": "ag"})
        assert hid == "tr-from-client-77" and body["trace"] == "tr-from-client-77"                                                    # well-formed client id is honoured end to end
        gid, body2 = call("/v1/traces/tr-from-client-77"); assert body2["jobs"][0]["job_id"] == body["job_id"] and gid                  # and the trace endpoint answers (with its own request id)
        hid2, body3 = call("/v1/projects/p1/jobs", {"X-Trace-Id": "bad id with spaces"}, {"prompt": "[[hello]]", "agent_id": "ag", "idem_key": "z"})
        assert hid2 != "bad id with spaces" and hid2.startswith("tr-") and body3["trace"] == hid2                                      # malformed -> replaced, never reflected
    finally: srv.shutdown(); srv.server_close()


def test_retention_deletes_only_old_finished_metered_jobs_and_keeps_money_and_audit(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); old = finish(w, a, 2, "old"); new = finish(w, a, 1, "new")
    long_ago = time.time() - 200 * 86400
    with w.board.db.tx() as c:
        for j in old: c.execute("UPDATE jobs SET created=? WHERE job_id=?", (long_ago, j))
    meter_before = w.board.db.c().execute("SELECT COUNT(*) FROM meter").fetchone()[0]; audit_before = w.board.db.c().execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    tids = [w.board.db.c().execute("SELECT tid FROM jobs WHERE job_id=?", (j,)).fetchone()[0] for j in old]
    r = w.board.retention_tick(); assert r["jobs"] == 2
    assert w.board.db.c().execute("SELECT COUNT(*) FROM jobs WHERE job_id IN (?,?)", tuple(old)).fetchone()[0] == 0 and all(w.board.store.get(t) is None for t in tids)
    assert w.board.db.c().execute("SELECT COUNT(*) FROM jobs WHERE job_id=?", (new[0],)).fetchone()[0] == 1                       # recent job kept
    assert w.board.db.c().execute("SELECT COUNT(*) FROM meter").fetchone()[0] == meter_before                                     # billing evidence is never retention-deleted
    assert w.board.db.c().execute("SELECT COUNT(*) FROM audit").fetchone()[0] >= audit_before and w.board.db.verify_audit()[0]            # the chain is intact after retention
    assert w.board.retention_tick()["jobs"] == 0                                                                                  # idempotent


def test_retention_never_touches_live_or_unmetered_work_and_policy_is_bounded(w):
    a = w.org("acme"); w.agent(a, "p1", "ag")
    from ordivyr.board import runtime_adapter as RA
    w.board.register_worker(a, "ordivyr", RA.capabilities(1, ("stub",))); j = w.board.submit_job(a, "p1", "queued forever", agent_id="ag")["job_id"]       # nobody runs it: stays queued
    with w.board.db.tx() as c: c.execute("UPDATE jobs SET created=? WHERE job_id=?", (time.time() - 900 * 86400, j))
    assert w.board.retention_tick()["jobs"] == 0 and w.board.db.c().execute("SELECT COUNT(*) FROM jobs WHERE job_id=?", (j,)).fetchone()[0] == 1
    assert w.board.set_retention(a, 7) == {"job_days": 7, "default": False} and w.board.set_retention(a, None)["default"]
    for bad in (0, -1, 5000, 1.5, "7", True):
        with pytest.raises(Invalid): w.board.set_retention(a, bad)
    viewer = w.board.issue_key(a, "viewer", "p1"); vp = w.board.principal(viewer["key"])
    with pytest.raises(Forbidden): w.board.set_retention(vp, 1)


def test_retention_prunes_dead_sessions_invites_mail_and_stale_throttle_rows(w):
    a = w.org("acme"); human(w, a, "u@corp.com"); now = time.time()
    s = w.board.login("u@corp.com", PW, ip="198.51.100.1"); w.board.logout(w.board.principal(s["session"]))
    with w.board.db.tx() as c:
        c.execute("UPDATE sessions SET revoked=?, expires=?", (now - 40 * 86400, now - 40 * 86400)); c.execute("UPDATE invites SET used=?, expires=?", (now - 40 * 86400, now - 40 * 86400))
        c.execute("INSERT INTO auth_throttle(user_id, ipk, failed, last_fail) VALUES('x','203.0.113.0/24',3,?)", (now - 5 * 86400,))
    r = w.board.retention_tick(now); assert r["sessions"] >= 1 and r["invites"] >= 1 and r["throttle"] >= 1


def test_erase_org_removes_content_and_access_keeps_the_financial_record(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); human(w, a, "only@corp.com"); other = w.org("keep"); human(w, other, "shared@corp.com")
    inv = w.board.invite_user(a, "shared@corp.com", "member"); w.board.accept_invite(inv["invite"], PW, "S")                                                        # also belongs to 'keep'
    ids = finish(w, a, 1); w.board.memory(a, "p1", "put", "project", "k", "secret customer data"); w.board.put_secret(a, "api", "supersecret")
    assert w.board.db.c().execute("SELECT COUNT(*) FROM memory WHERE org='acme'").fetchone()[0] == 1 and w.board.db.c().execute("SELECT COUNT(*) FROM secrets WHERE org='acme'").fetchone()[0] == 1
    k = w.board.issue_key(a, "admin")["key"]; assert w.board.principal(k) is not None
    with pytest.raises(Invalid): w.board.erase_org(w.platform, "acme", "wrong")
    with pytest.raises(Forbidden): w.board.erase_org(a, "acme", "acme")
    meter = w.board.db.c().execute("SELECT COUNT(*) FROM meter WHERE org='acme'").fetchone()[0]
    r = w.board.erase_org(w.platform, "acme", "acme"); assert r["erased"]["jobs"] == 1 and "meter" in r["kept"]
    c = w.board.db.c()
    for t in ("jobs", "agents", "memory", "secrets", "projects", "memberships", "invites"): assert c.execute(f"SELECT COUNT(*) FROM {t} WHERE org='acme'" if t != "memberships" else "SELECT COUNT(*) FROM memberships WHERE org='acme'").fetchone()[0] == 0, t
    assert c.execute("SELECT COUNT(*) FROM meter WHERE org='acme'").fetchone()[0] == meter                                       # money stays
    u = c.execute("SELECT * FROM users WHERE id=(SELECT id FROM users WHERE email LIKE ? LIMIT 1)", ("deleted-" + "%",)).fetchone(); assert u and u["pw_hash"] is None and u["status"] == "deleted"   # the sole-org user is anonymised
    assert c.execute("SELECT status FROM users WHERE email='shared@corp.com'").fetchone()[0] == "active" and w.board.login("shared@corp.com", PW, org="keep")["session"]   # a user who also belongs elsewhere keeps their account
    assert w.board.principal(k) is None                                                                                           # every key of the erased org is dead
    assert c.execute("SELECT COUNT(*) FROM audit WHERE action='org.erase'").fetchone()[0] == 1


def test_short_lived_request_threads_do_not_leak_database_connections(w):
    """Found by the real-PostgreSQL demo: every HTTP request thread opened a connection that was never closed ('too many clients' after ~100 requests)."""
    import gc
    def one(): w.board.db.c().execute("SELECT 1").fetchone(); w.board.store.get(1)
    for _ in range(250):
        t = threading.Thread(target=one); t.start(); t.join()
    gc.collect(); time.sleep(0.2); gc.collect()
    assert len(w.board.db._conns) < 25, len(w.board.db._conns)
    sc = getattr(w.board.store, "_conns", [])
    assert len(sc) < 25, len(sc)
    for pool in (getattr(w.board.db, "_pool", None), getattr(w.board.store, "_pool", None)):      # SQLite: connections are reused, not reopened
        if pool: assert len(pool.all) < 25, len(pool.all)


def test_connection_pool_reuses_rolls_back_and_drops_closed_connections(tmp_path):
    from ordivyr.durable import SqlitePool
    pool = SqlitePool(tmp_path / "p.db")
    c, lease = pool.lease(); c.execute("CREATE TABLE t(x)"); c.execute("BEGIN IMMEDIATE"); c.execute("INSERT INTO t VALUES(1)"); del lease      # the thread dies mid-transaction
    c2, lease2 = pool.lease(); assert c2 is c and not c2.in_transaction and c2.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0
    c2.close(); del lease2; c3, _lease3 = pool.lease(); assert c3 is not c and c3.execute("SELECT 1").fetchone()[0] == 1
    pool.close(); assert not pool.all


def test_upgrade_from_schema_v4_preserves_data_and_adds_every_later_table(tmp_path, monkeypatch):
    """A Board database created by an older release (schema v4) must upgrade in place: data intact, all later tables present, migrations recorded once."""
    from ordivyr.board import db as DBM
    full = list(DBM.MIGRATIONS); monkeypatch.setattr(DBM, "MIGRATIONS", [m for m in full if m[0] <= 4])
    d = DBM.DB(tmp_path / "board.db"); assert d.schema_version() == 4
    with d.tx() as c: c.execute("INSERT INTO orgs(id,name,plan,created) VALUES('legacy','Legacy Co','team',1.0)"); c.execute("INSERT INTO projects(org,id,budget_usd,created) VALUES('legacy','p1',5.0,1.0)")
    d.close(); monkeypatch.setattr(DBM, "MIGRATIONS", full)
    d = DBM.DB(tmp_path / "board.db"); assert d.schema_version() == full[-1][0]
    assert d.c().execute("SELECT plan FROM orgs WHERE id='legacy'").fetchone()[0] == "team" and d.c().execute("SELECT budget_usd FROM projects WHERE org='legacy'").fetchone()[0] == 5.0
    have = {r[0] for r in d.c().execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"auth_throttle", "reservations", "refunds", "outbox", "retention"} <= have
    assert d.c().execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == len(full); d.close()


def test_connection_holder_never_closes_a_connection_in_a_forked_child():
    """Regression (found by the PostgreSQL regression run): subprocess.Popen(preexec_fn=...) runs GC in the forked child; a finalizer that closed an inherited psycopg connection there sent
    Terminate down the socket the PARENT still used ('server closed the connection unexpectedly'). Release must only ever happen in the process that opened the connection."""
    import os, select
    from ordivyr.board.db import _ConnHolder
    r, w = os.pipe(); h = _ConnHolder("conn", lambda c: os.write(w, b"released")); pid = os.fork()
    if pid == 0:
        try: del h
        finally: os._exit(0)
    os.waitpid(pid, 0); assert not select.select([r], [], [], 0.2)[0], "the forked child released the parent's connection"
    del h; assert os.read(r, 20) == b"released"                                                  # the owning process still releases normally
    os.close(r); os.close(w)
