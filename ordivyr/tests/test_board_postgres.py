"""PostgreSQL-only evidence: provably the postgres backend, migrations, concurrent starts, cross-process races, kill -9 of a Board process AND a worker, and an immediate-shutdown crash drill.
Skipped unless BOARD_TEST_PG_DSN is set (see docs/board/OPERATIONS.md)."""
import json, os, signal, subprocess, sys, threading, time, shutil, pytest
from pathlib import Path
from ordivyr.tests.board_support import World, wait_for, ScriptedModel

DSN = os.environ.get("BOARD_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="BOARD_TEST_PG_DSN not set")


def newdb(name):
    import psycopg
    admin = DSN; c = psycopg.connect(admin, autocommit=True); c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'); c.execute(f'CREATE DATABASE "{name}"'); c.close()
    return admin.replace("/postgres?", f"/{name}?", 1)


def dropdb(name):
    import psycopg
    c = psycopg.connect(DSN, autocommit=True); c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'); c.close()


@pytest.fixture
def pgw(tmp_path, monkeypatch):
    w = World(tmp_path, {"nap": [("sleep", 2.5), ("say", "rested")], "hello": [("say", "hi")]}, monkeypatch)
    yield w; w.close()


def test_backend_is_really_postgres(pgw):
    assert pgw.board.db.backend == "postgres" and pgw.board.store.__class__.__name__ == "PgStore"
    assert "PostgreSQL" in pgw.board.db.c().execute("SELECT version()").fetchone()[0]


def test_migrations_versioned_tamper_downgrade_and_concurrent_start(tmp_path):
    from ordivyr.board.db import DB, MIGRATIONS
    import psycopg
    name = "bt_mig_" + os.urandom(3).hex(); dsn = newdb(name)
    try:
        dbs, errs = [], []
        def boot():
            try: dbs.append(DB(None, dsn=dsn))
            except Exception as e: errs.append(e)
        ts = [threading.Thread(target=boot) for _ in range(6)]; [t.start() for t in ts]; [t.join() for t in ts]
        assert not errs and all(d.schema_version() == MIGRATIONS[-1][0] for d in dbs)
        assert dbs[0].c().execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == len(MIGRATIONS)       # applied exactly once each, despite 6 racing starters
        for d in dbs: d.close()
        c = psycopg.connect(dsn, autocommit=True)
        c.execute("UPDATE schema_migrations SET checksum='deadbeef' WHERE version=1")
        with pytest.raises(RuntimeError, match="checksum mismatch"): DB(None, dsn=dsn)
        from hashlib import sha256
        c.execute("UPDATE schema_migrations SET checksum=%s WHERE version=1", (sha256(MIGRATIONS[0][2].encode()).hexdigest(),))
        c.execute("INSERT INTO schema_migrations(version,name,checksum,applied) VALUES(9999,'from-the-future','x',0)")
        with pytest.raises(RuntimeError, match="newer than this Board build"): DB(None, dsn=dsn)
        c.close()
    finally: dropdb(name)


def test_cross_process_quota_race_admits_exactly_the_limit(pgw, monkeypatch):
    """Two Board objects (own connections, as two processes would have) race past a monthly quota. READ COMMITTED alone would admit more than the limit."""
    from ordivyr.board import service as S
    monkeypatch.setitem(S.PLANS["team"], "monthly_jobs", 7)
    a = pgw.org("acme"); pgw.agent(a, "p1", "ag"); pgw.platform_worker(); other = pgw.reborn(); a2 = other.principal(pgw.board.issue_key(a, "admin")["key"])
    ok, denied, other_err = [], [], []
    def go(b, p, i):
        try: ok.append(b.submit_job(p, "p1", "[[hello]]", agent_id="ag", idem_key=f"k{i}")["job_id"])
        except S.QuotaError: denied.append(i)
        except Exception as e: other_err.append(repr(e))
    ts = [threading.Thread(target=go, args=(*((pgw.board, a) if i % 2 else (other, a2)), i)) for i in range(24)]; [t.start() for t in ts]; [t.join() for t in ts]
    assert not other_err and len(ok) == 7 and len(denied) == 17, (len(ok), len(denied), other_err)
    assert pgw.board.db.c().execute("SELECT COUNT(*) FROM jobs WHERE org='acme'").fetchone()[0] == 7


def test_two_board_processes_two_workers_kill_9_one_of_each(pgw, tmp_path):
    a = pgw.org("acme"); pgw.agent(a, "p1", "ag"); env = {**os.environ, "ORDIVYR_GATEWAY_HOME": str(pgw.gwhome), "PYTHONPATH": os.getcwd()}; procs = []
    def board_proc(n):
        p = subprocess.Popen([sys.executable, "-m", "ordivyr.tests._board_server_proc", str(tmp_path / f"b{n}"), pgw.dsn], env=env, cwd=os.getcwd(), stdout=subprocess.PIPE, text=True); procs.append(p); return p, json.loads(p.stdout.readline())
    def worker_proc(n, lease, tok):
        tf = tmp_path / f"tok{n}"; tf.write_text(tok)
        p = subprocess.Popen([sys.executable, "-m", "ordivyr.board.worker", "--url", f"http://127.0.0.1:{lease}", "--token-file", str(tf), "--name", f"w{n}", "--ws", str(tmp_path / f"ws{n}"), "--ttl", "2", "--slots", "2"], env=env, cwd=os.getcwd()); procs.append(p); return p
    try:
        b1, i1 = board_proc(1); b2, i2 = board_proc(2)
        t1 = pgw.board.register_worker(a, "ordivyr", __import__("ordivyr.board.runtime_adapter", fromlist=["x"]).capabilities(2, ("stub",)), node="n1")["token"]
        t2 = pgw.board.register_worker(a, "ordivyr", __import__("ordivyr.board.runtime_adapter", fromlist=["x"]).capabilities(2, ("stub",)), node="n2")["token"]
        w1 = worker_proc(1, i1["lease"], t1); w2 = worker_proc(2, i2["lease"], t2)
        jobs = [pgw.board.submit_job(a, "p1", "[[nap]]", agent_id="ag", idem_key=f"n{i}")["job_id"] for i in range(8)]
        wait_for(lambda: sum(pgw.board.get_job(a, "p1", j)["status"] == "running" for j in jobs) >= 3, 30, what="jobs running across both workers")
        os.kill(b1.pid, signal.SIGKILL); os.kill(w1.pid, signal.SIGKILL); b1.wait(5); w1.wait(5)            # kill -9 a Board process and a worker mid-job
        for j in jobs: v = pgw.done(a, "p1", j, 90); assert v["status"] == "completed" and v["result"]["text"] == "woke", v
        d = pgw.board.db.c(); wait_for(lambda: (pgw.board.reconcile(), d.execute("SELECT COUNT(DISTINCT job_id) FROM meter").fetchone()[0] == 8)[1], 30, what="metering by the two live loops + this third reconciler")
        assert d.execute("SELECT COUNT(*) FROM (SELECT job_id,kind FROM meter GROUP BY job_id,kind HAVING COUNT(*)>1) x").fetchone()[0] == 0          # exactly-once metering
        assert d.execute("SELECT COUNT(DISTINCT job_id) FROM meter").fetchone()[0] == 8
        for j in jobs: assert [e["kind"] for e in pgw.board.job_events(a, "p1", j)].count("commit") == 1
        assert pgw.board.db.verify_audit() == (True, None)
        assert any(pgw.board.get_job(a, "p1", j)["attempt"] >= 2 for j in jobs), "the kill should have forced at least one retry"
    finally:
        for p in procs:
            if p.poll() is None: p.kill()


def pgbin(n):
    d = os.environ.get("BOARD_TEST_PG_BIN"); return str(Path(d) / n) if d else shutil.which(n)


@pytest.mark.skipif(not (pgbin("initdb") and pgbin("pg_ctl")), reason="initdb/pg_ctl not available (set BOARD_TEST_PG_BIN)")
def test_crash_drill_immediate_shutdown_and_recovery(tmp_path, monkeypatch):
    """Own private cluster: SIGQUIT-style immediate stop mid-flight (no clean shutdown, no checkpoint). Committed data survives, Board reconnects, the audit chain verifies, nothing is replayed twice."""
    from ordivyr.board.service import Board
    d = tmp_path / "pg"; sock = tmp_path / "sock"; sock.mkdir()
    subprocess.run([pgbin("initdb"), "-D", str(d), "-U", "postgres", "-A", "trust", "-E", "UTF8"], check=True, capture_output=True)
    opts = f"-c listen_addresses='' -c unix_socket_directories='{sock}' -c fsync=on"
    def start(): subprocess.run([pgbin("pg_ctl"), "-D", str(d), "-o", opts, "-l", str(tmp_path / "pg.log"), "-w", "start"], check=True, capture_output=True)
    def stop(mode): subprocess.run([pgbin("pg_ctl"), "-D", str(d), "-m", mode, "-w", "stop"], check=True, capture_output=True)
    start()
    try:
        dsn = f"postgresql://postgres:@/postgres?host={sock}"; b = Board(tmp_path / "h", dsn=dsn); b.init_platform(); plat = b.principal((tmp_path / "h" / "platform.token").read_text())
        adm = b.principal(b.create_org(plat, "acme", "acme", "team")["admin_key"]); b.create_project(adm, "p1")
        before = b.db.c().execute("SELECT COUNT(*) FROM audit").fetchone()[0]; stop("immediate"); start(); time.sleep(1.0)
        assert b.db.c().execute("SELECT COUNT(*) FROM audit").fetchone()[0] == before            # standalone statement: reconnect-once, data intact
        assert b.projects(adm) and b.db.verify_audit() == (True, None)
        stop("immediate")                                                                          # server down: a WRITE must fail loudly, never silently drop or double-apply
        with pytest.raises(Exception): b.create_project(adm, "p2")
        start(); time.sleep(1.0); n = b.db.c().execute("SELECT COUNT(*) FROM projects WHERE org='acme'").fetchone()[0]; assert n == 1       # p2 was NOT half-created
        b.create_project(adm, "p2"); assert b.db.c().execute("SELECT COUNT(*) FROM projects WHERE org='acme'").fetchone()[0] == 2 and b.db.verify_audit() == (True, None)
    finally:
        subprocess.run([pgbin("pg_ctl"), "-D", str(d), "-m", "immediate", "stop"], capture_output=True)


def test_pg_upgrade_from_schema_v4_in_place(monkeypatch):
    from ordivyr.board import db as DBM
    full = list(DBM.MIGRATIONS); name = "bt_up_" + os.urandom(3).hex(); dsn = newdb(name)
    try:
        monkeypatch.setattr(DBM, "MIGRATIONS", [m for m in full if m[0] <= 4]); d = DBM.DB(None, dsn=dsn); assert d.schema_version() == 4
        with d.tx() as c: c.execute("INSERT INTO orgs(id,name,plan,created) VALUES('legacy','Legacy Co','team',1.0)"); c.execute("INSERT INTO projects(org,id,budget_usd,created) VALUES('legacy','p1',5.0,1.0)")
        d.close(); monkeypatch.setattr(DBM, "MIGRATIONS", full); d = DBM.DB(None, dsn=dsn); assert d.schema_version() == full[-1][0]
        assert d.c().execute("SELECT plan FROM orgs WHERE id='legacy'").fetchone()[0] == "team"
        have = {r[0] for r in d.c().execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")}
        assert {"auth_throttle", "reservations", "refunds", "outbox", "retention"} <= have; d.close()
    finally: dropdb(name)
