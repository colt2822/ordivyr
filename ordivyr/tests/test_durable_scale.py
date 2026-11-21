"""Coordinator fairness + concurrency ladder (deterministic synthetic workers, no model) and external-effect safety under races."""
import threading, time, pytest
from concurrent.futures import ThreadPoolExecutor
from ordivyr import durable as D
from ordivyr.durable_net import Coordinator, RemoteStore
from ordivyr.hosting import bench


def test_fair_lock_is_fifo_and_reentrant():
    g = D.FairRLock(); order = []; started = []
    g.__enter__()                                                  # main thread holds the gate
    def w(i):
        started.append(i)
        with g: order.append(i)
    ts = []
    for i in range(6):
        t = threading.Thread(target=w, args=(i,)); t.start(); ts.append(t)
        while len(started) <= i: time.sleep(0.001)
        time.sleep(0.02)                                          # ensure strict arrival order
    with g: pass                                                  # reentrant on the owner
    g.__exit__()
    for t in ts: t.join(5)
    assert order == list(range(6))


def test_nested_tx_does_not_deadlock(tmp_path):
    s = D.Store(tmp_path / "q.db")
    with s.tx() as c:
        c.execute("SELECT 1")
        with s._gate: pass


@pytest.mark.parametrize("agents,drivers", [(100, 16), (300, 64), (400, 128)])
def test_http_concurrency_ladder_exactly_once(agents, drivers):
    r = bench.level(agents, "http", drivers=drivers, hold=0.5, batch=1)
    assert r["passed"], r["errors"] or r["audit_violations"]
    assert r["completed"] == r["commit_events"] == r["unique_fences"] == agents


def test_racing_callers_run_external_effect_at_most_once_over_http(tmp_path):
    st = D.Store(tmp_path / "q.db"); co = Coordinator(st, "t").start(); rs = RemoteStore(f"http://127.0.0.1:{co.port}", "t", timeout=20)
    try:
        tid = rs.submit("x", {}); t = rs.claim("w", "main", 60.0); rs.begin(tid, t["fence"]); ran, outcomes = [], []
        def go(_):
            try: outcomes.append(("ok", rs.effect(tid, t["fence"], "charge-1", lambda k: (ran.append(k), time.sleep(0.05), {"n": 1})[2], lambda k: ("unknown", None))))
            except D.NeedsApproval: outcomes.append(("parked", None))
        with ThreadPoolExecutor(8) as ex: list(ex.map(go, range(8)))
        assert len(ran) == 1                                       # the external call happened once, no matter how many callers raced
        try: assert rs.effect(tid, t["fence"], "charge-1", lambda k: ran.append("DUP"), lambda k: ("unknown", None)) == {"n": 1}
        except D.NeedsApproval: pass                               # a losing racer may have parked the task for a human: safe (no second execution), just not silent
        assert len(ran) == 1 and "DUP" not in ran
    finally: co.stop()


def test_stale_fence_cannot_start_or_commit_an_effect(tmp_path):
    st = D.Store(tmp_path / "q.db", clock=lambda: time.time()); tid = st.submit("x", {}); t1 = st.claim("w1", "main", 0.05); st.begin(tid, t1["fence"]); time.sleep(0.1); st.reap()
    t2 = st.claim("w2", "main", 30.0); assert t2["fence"] > t1["fence"]; st.begin(tid, t2["fence"]); ran = []
    with pytest.raises(D.StaleLease): st.effect(tid, t1["fence"], "k", lambda k: ran.append(1))             # zombie worker is refused before any external call
    assert ran == []


def test_crash_between_effect_and_commit_is_not_silently_reexecuted(tmp_path):
    """Exactly-once DB commit != exactly-once external execution: if the process dies after do() but before op_commit, the next attempt must reconcile or park, never blindly redo."""
    st = D.Store(tmp_path / "q.db"); tid = st.submit("x", {}); t = st.claim("w", "main", 30.0); st.begin(tid, t["fence"]); ext = []
    def do(k): ext.append(k); raise SystemExit("crash after the external call landed")
    with pytest.raises(SystemExit): st.effect(tid, t["fence"], "pay", do)
    st.release(tid, t["fence"], "crash", delay=0)
    t = st.claim("w2", "main", 30.0); st.begin(tid, t["fence"])
    with pytest.raises(D.NeedsApproval): st.effect(tid, t["fence"], "pay", lambda k: ext.append("DUP"))      # no reconciler: parked for a human
    assert ext == ["pay"]
    st2 = D.Store(tmp_path / "q2.db"); t2id = st2.submit("x", {}); tt = st2.claim("w", "main", 30.0); st2.begin(t2id, tt["fence"])
    try: st2.effect(t2id, tt["fence"], "pay", do)
    except SystemExit: pass
    st2.release(t2id, tt["fence"], "crash", delay=0); tt = st2.claim("w2", "main", 30.0); st2.begin(t2id, tt["fence"]); n = len(ext)
    assert st2.effect(t2id, tt["fence"], "pay", lambda k: ext.append("DUP"), lambda k: ("committed", {"paid": True})) == {"paid": True} and len(ext) == n         # reconciler proves it landed
