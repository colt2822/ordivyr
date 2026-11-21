"""PostgreSQL-only verification against a REAL server (skipped unless ORDIVYR_PG_DSN + psycopg). Beyond the shared conformance suite:
multi-connection / multi-process contention, exactly-once commits under races, lease expiry + fencing with a controllable clock, backend termination
(mid-transaction and between statements), idempotent submit races, tenant isolation across connections, and a SQLite-vs-PostgreSQL differential run.
Crash/restart (`pg_ctl -m immediate`) additionally needs ORDIVYR_PG_CTL (path to pg_ctl) + ORDIVYR_PG_DATA + ORDIVYR_PG_OPTS."""
import itertools, json, multiprocessing as mp, os, subprocess, threading, time
import pytest
from ordivyr import durable as D
try: from ordivyr.hosting import pgstore
except Exception: pgstore = None

DSN = os.environ.get("ORDIVYR_PG_DSN", ""); CTL = os.environ.get("ORDIVYR_PG_CTL", ""); DATA = os.environ.get("ORDIVYR_PG_DATA", ""); OPTS = os.environ.get("ORDIVYR_PG_OPTS", "")   # captured at import: conftest scrubs ORDIVYR_*
pytestmark = pytest.mark.skipif(not (DSN and pgstore is not None and pgstore.psycopg is not None), reason="needs ORDIVYR_PG_DSN + psycopg")
TRUNC = "TRUNCATE tasks, events, checkpoints, evidence, outputs, tenants, usage, nodes RESTART IDENTITY"

class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t

@pytest.fixture
def pg(request):
    clock = Clock(); s = pgstore.PgStore(DSN, clock=clock); s.clk = clock
    with s.tx() as c: c.execute(TRUNC)
    request.addfinalizer(s.close); return s

def another(pg): return pgstore.PgStore(DSN, clock=pg.clock)          # an independent connection pool = an independent coordinator

def kill_backends(except_pid=None):
    import psycopg
    with psycopg.connect(DSN, autocommit=True) as c:
        return c.execute("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()").fetchone()[0]

def test_many_coordinators_claim_concurrently_no_duplicates(pg):
    N = 600
    for i in range(N): pg.submit("k", {"i": i}, f"i{i}")
    stores = [another(pg) for _ in range(8)]; got = [[] for _ in stores]; errs = []
    def work(n):
        try:
            end = time.time() + 60
            while sum(len(g) for g in got) < N and time.time() < end:       # an empty batch under SKIP LOCKED means "contended", not "queue empty": poll again
                got[n] += stores[n].claim_many(f"w{n}", node=f"n{n}", limit=7)
        except Exception as e: errs.append(repr(e))
    ths = [threading.Thread(target=work, args=(n,)) for n in range(8)]; [t.start() for t in ths]; [t.join() for t in ths]
    for s in stores: s.close()
    assert not errs, errs
    ids = [t["id"] for g in got for t in g]; fences = [t["fence"] for g in got for t in g]
    assert len(ids) == N and len(set(ids)) == N, "a task was claimed twice or lost"
    assert len(set(fences)) == N, "fences must be unique across coordinators"
    assert sum(1 for g in got if g) >= 2, "work was not shared across coordinators"
    assert pg.counts() == {"claimed": N} and pg.audit() == []

def _proc_claim(args):
    dsn, n = args; s = pgstore.PgStore(dsn); out = []; end = time.time() + 60
    while time.time() < end:
        b = s.claim_many(f"p{n}", node=f"np{n}", limit=11); out += [(t["id"], t["fence"]) for t in b]
        if not b and s.counts().get("queued", 0) == 0: break
    s.close(); return out

def test_separate_processes_claim_without_overlap(pg):
    for i in range(400): pg.submit("k", {}, f"i{i}")
    with mp.get_context("spawn").Pool(4) as pool: res = pool.map(_proc_claim, [(DSN, n) for n in range(4)])
    ids = [i for r in res for i, _ in r]; assert len(ids) == 400 and len(set(ids)) == 400 and len({f for r in res for _, f in r}) == 400

def test_racing_completes_commit_exactly_once(pg):
    pg.submit("k", {}); t = pg.claim("w"); pg.begin(t["id"], t["fence"]); pg.add_evidence(t["id"], t["fence"], "ok", True)
    stores = [another(pg) for _ in range(8)]; res = []; bar = threading.Barrier(8)
    def go(s):
        bar.wait()
        try: s.complete(t["id"], t["fence"], {"r": 1}); res.append("ok")
        except D.StaleLease: res.append("stale")
        except Exception as e: res.append(type(e).__name__)
    ths = [threading.Thread(target=go, args=(s,)) for s in stores]; [x.start() for x in ths]; [x.join() for x in ths]
    for s in stores: s.close()
    assert res.count("ok") == 1 and res.count("stale") == 7, res
    assert pg.get(t["id"])["state"] == "completed" and pg.audit() == []
    with pg.tx() as c: assert c.execute("SELECT count(*) AS n FROM events WHERE task_id=%s AND kind='commit'", (t["id"],)).fetchone()["n"] == 1

def test_lease_expiry_reap_and_fencing_with_two_workers(pg):
    pg.submit("k", {}, max_attempts=3); t1 = pg.claim("a", ttl=5); pg.begin(t1["id"], t1["fence"])
    pg.clk.t += 6                                                   # a's lease lapses
    assert pg.reap() == [(t1["id"], "queued")]
    t2 = pg.claim("b", ttl=5); assert t2["fence"] > t1["fence"] and t2["attempt"] == 2
    with pytest.raises(D.StaleLease): pg.complete(t1["id"], t1["fence"], {"late": True})        # the zombie cannot commit
    with pytest.raises(D.StaleLease): pg.heartbeat(t1["id"], t1["fence"])
    pg.begin(t2["id"], t2["fence"]); pg.add_evidence(t2["id"], t2["fence"], "ok", True); pg.complete(t2["id"], t2["fence"], {"by": "b"})
    assert pg.get(t1["id"])["state"] == "completed" and pg.get(t1["id"])["result"]["by"] == "b" and pg.audit() == []
    pg.submit("k", {}, "x", max_attempts=1); t3 = pg.claim("a", ttl=1); pg.clk.t += 2
    assert pg.reap() == [(t3["id"], "failed")]                                                 # final attempt exhausted by lease expiry

def test_idempotent_submit_race_creates_one_task(pg):
    stores = [another(pg) for _ in range(16)]; ids = []; bar = threading.Barrier(16)
    def go(s): bar.wait(); ids.append(s.submit("k", {"x": 1}, "same-key"))
    ths = [threading.Thread(target=go, args=(s,)) for s in stores]; [x.start() for x in ths]; [x.join() for x in ths]
    for s in stores: s.close()
    assert len(set(ids)) == 1 and pg.counts() == {"queued": 1}

def test_backend_killed_between_statements_recovers_on_next_call(pg):
    pg.submit("k", {}, "a"); assert pg.claim("w") is not None
    assert kill_backends() >= 1
    with pytest.raises(Exception): pg.submit("k", {}, "b")             # the dead connection surfaces as an error, not as silent loss
    assert pg.submit("k", {}, "b") and pg.counts() == {"claimed": 1, "queued": 1}          # and the adapter reconnects by itself on the next call

def test_backend_killed_mid_transaction_leaves_no_partial_state(pg):
    pg.submit("k", {}, max_attempts=3); t = pg.claim("w"); pg.begin(t["id"], t["fence"])
    before = pg.get(t["id"]); c = pg._conn()
    c.execute("UPDATE tasks SET state='completed' WHERE id=%s", (t["id"],)); c.execute("INSERT INTO events(task_id,ts,kind) VALUES(%s,1,'commit')", (t["id"],))
    kill_backends()
    with pytest.raises(Exception): c.commit()
    try: c.rollback()
    except Exception: pass
    after = pg.get(t["id"]); assert after["state"] == before["state"] and pg.audit() == []          # the half-written commit never became visible
    pg.complete(t["id"], t["fence"], {"r": 1}); assert pg.get(t["id"])["state"] == "completed" and pg.audit() == []

def test_lock_contention_deadlock_free_under_mixed_load(pg):
    for i in range(200): pg.submit("k", {}, f"i{i}", max_attempts=2)
    stores = [another(pg) for _ in range(6)]; errs = []; done = []
    def work(n):
        s = stores[n]
        try:
            end = time.time() + 60
            while time.time() < end:
                b = s.claim_many(f"w{n}", node=f"n{n}", limit=5)
                if not b:
                    if s.counts().get("queued", 0) == 0: return
                    continue
                for t in b:
                    s.begin(t["id"], t["fence"])
                    if int(t["id"]) % 5 == 0 and t["attempt"] == 1: s.fail(t["id"], t["fence"], "boom", backoff=0)
                    else: s.add_evidence(t["id"], t["fence"], "ok", True); s.complete(t["id"], t["fence"], {"n": n}); done.append(t["id"])
        except Exception as e: errs.append(repr(e))
    ths = [threading.Thread(target=work, args=(n,)) for n in range(6)]; [x.start() for x in ths]; [x.join(60) for x in ths]
    assert not errs and not any(x.is_alive() for x in ths), errs
    while (b := pg.claim_many("sweep", limit=50)):        # retried tasks
        for t in b: pg.begin(t["id"], t["fence"]); pg.add_evidence(t["id"], t["fence"], "ok", True); pg.complete(t["id"], t["fence"], {}); done.append(t["id"])
    for s in stores: s.close()
    assert len(done) == len(set(done)) == 200 and pg.counts() == {"completed": 200} and pg.audit() == []

def test_tenant_isolation_across_connections(pg):
    a, b = another(pg), another(pg)
    pg.tenant_set("A", max_queued=3)
    ia = [a.submit("k", {}, f"a{i}", tenant="A") for i in range(3)]; ib = b.submit("k", {"secret": 1}, "b0", tenant="B")
    with pytest.raises(Exception, match="(?i)quota|queued"): a.submit("k", {}, "a-over", tenant="A")
    assert b.get_for("A", ib) is None and a.get_for("A", ib) is None and b.get_for("B", ib) is not None and a.get_for("A", ia[0]) is not None and b.get_for("B", ia[0]) is None
    assert pg.counts_for("A") == {"queued": 3} and pg.counts_for("B") == {"queued": 1}
    assert {t["tenant"] for t in b.claim_many("w", limit=10, tenants=["B"])} == {"B"} and pg.counts_for("A") == {"queued": 3}
    assert pg.usage_of("B")["claims"] == 1 and pg.usage_of("A")["claims"] == 0
    assert a.submit("k", {}, "a0", tenant="A") == ia[0] and a.submit("k", {}, "a0", tenant="B") != ia[0]          # idempotency keys are per tenant
    a.close(); b.close()

def _transcript(s, clk):
    """A scripted scenario whose observable results must be identical on SQLite and PostgreSQL."""
    out = []
    s.tenant_set("T1", weight=2.0, max_active=2); s.tenant_set("T2", weight=1.0)
    ids = {n: s.submit("k", {"n": n}, n, priority=p, tenant=t, max_attempts=2) for n, p, t in (("a", 0, "T1"), ("b", 5, "T1"), ("c", 0, "T1"), ("d", 0, "T2"), ("e", 1, "T2"))}
    out.append(("dup", s.submit("k", {}, "a", tenant="T1") == ids["a"]))
    got = s.claim_many("w", limit=10); out.append(("claim1", sorted((ids_r(ids, t["id"]), t["fence"] > 0, t["attempt"]) for t in got)))     # T1 limited to max_active=2
    t = got[0]; s.begin(t["id"], t["fence"]); out.append(("fail1", s.fail(t["id"], t["fence"], "x", backoff=0))); clk.t += 1
    t = next(x for x in got if x["id"] != got[0]["id"]); s.begin(t["id"], t["fence"]); s.add_evidence(t["id"], t["fence"], "ok", True); s.complete(t["id"], t["fence"], {"r": 1}); out.append(("complete", ids_r(ids, t["id"])))
    out.append(("cancel", s.cancel(ids["c"]))); out.append(("counts", dict(sorted(s.counts().items()))))
    clk.t += 100; out.append(("reap", sorted((ids_r(ids, i), st) for i, st in s.reap()))); out.append(("audit", s.audit()))
    out.append(("usage", {k: s.usage_of("T1")[k] for k in ("submitted", "claims", "completed", "failed")}))
    return out

def ids_r(ids, i): return next(n for n, v in ids.items() if v == i)

def test_differential_sqlite_vs_postgres_transcript(pg, tmp_path):
    ck = Clock(); lite = D.Store(tmp_path / "q.db", clock=ck); pg.clk.t = ck.t
    class Both:                                                   # drive PG's clock in lock-step
        pass
    pg_t = _transcript(pg, pg.clk)
    lite_t = _transcript(lite, ck)
    assert pg_t == lite_t, "\n".join(f"{a!r}\n  pg  ={b!r}\n  lite={c!r}" for (a, b), (_, c) in zip(pg_t, lite_t) if b != c)

@pytest.mark.skipif(not (CTL and DATA), reason="needs ORDIVYR_PG_CTL + ORDIVYR_PG_DATA (a disposable server this test may crash)")
def test_server_crash_immediate_restart_preserves_committed_work_and_recovers(pg):
    for i in range(60): pg.submit("k", {}, f"i{i}", max_attempts=3)
    first = pg.claim_many("w", limit=30); done = []
    for t in first[:20]: pg.begin(t["id"], t["fence"]); pg.add_evidence(t["id"], t["fence"], "ok", True); pg.complete(t["id"], t["fence"], {}); done.append(t["id"])
    held = [t for t in first[20:]]                                                        # leased but unfinished at the moment of the crash
    r = subprocess.run([CTL, "-D", DATA, "-m", "immediate", "-o", OPTS, "-w", "restart"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=120, start_new_session=True); assert r.returncode == 0, r.stderr      # (not capture_output: the restarted postmaster would inherit the pipe and hang us)
    s2 = pgstore.PgStore(DSN, clock=pg.clock)
    assert all(s2.get(i)["state"] == "completed" for i in done), "a committed task was lost by the crash"
    assert s2.counts().get("completed") == 20 and s2.audit() == []
    for t in held:                                                                         # their leases survive; the old workers can still finish with their fences ...
        s2.begin(t["id"], t["fence"]); s2.add_evidence(t["id"], t["fence"], "ok", True); s2.complete(t["id"], t["fence"], {})
    rest = []
    while (b := s2.claim_many("w2", limit=20)): rest += b
    for t in rest: s2.begin(t["id"], t["fence"]); s2.add_evidence(t["id"], t["fence"], "ok", True); s2.complete(t["id"], t["fence"], {})
    assert s2.counts() == {"completed": 60} and s2.audit() == [] and len({t["id"] for t in first} & {t["id"] for t in rest}) == 0
    s2.close()
