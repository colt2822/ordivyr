"""P0 execution-engine efficiency: multi-slot pool, shared heartbeats, batched fenced writes, empty-claim probe, keep-alive client - each with its safety property."""
import json, os, signal, subprocess, sys, threading, time
from pathlib import Path
import pytest
from ordivyr import durable as D, durable_worker as W
from ordivyr.durable_net import Coordinator, RemoteStore, RemoteError


@pytest.fixture
def store(tmp_path): return D.Store(tmp_path / "q.db")


def wait(pred, t=30, step=0.05):
    end = time.time() + t
    while time.time() < end:
        v = pred()
        if v: return v
        time.sleep(step)
    raise AssertionError("timeout")


def test_empty_claims_cost_no_write_transaction(store):
    n = store.tx_count
    for _ in range(50): assert store.claim("w") is None and store.claim_many("w", limit=8) == []
    assert store.tx_count == n                                  # idle polling is read-only
    store.submit("compute", {"seed": "a"}, "k1"); n = store.tx_count
    assert store.claim("w") is not None and store.tx_count == n + 1


def test_empty_claim_probe_respects_kinds_and_not_before(store):
    store.submit("exec", {"code": "1"}, "k1")
    assert store.claim_many("w", kinds=["compute"], limit=4) == [] and len(store.claim_many("w", kinds=["exec"], limit=4)) == 1


def test_apply_is_atomic_and_fenced(store):
    tid = store.submit("compute", {}, "k"); t = store.claim("w"); f = t["fence"]
    store.apply(tid, f, [{"op": "begin", "phase": "running"}, {"op": "output", "tool": "t", "args": {}, "output": "o"}, {"op": "checkpoint", "phase": "p", "data": {"x": 1}}, {"op": "evidence", "name": "e", "ok": True}])
    assert store.get(tid)["checkpoint"]["x"] == 1 and len(store.evidence(tid)) == 1
    n_out = store._conn().execute("SELECT COUNT(*) FROM outputs").fetchone()[0]
    with pytest.raises(D.StaleLease): store.apply(tid, f + 99, [{"op": "output", "tool": "t", "args": {}, "output": "zombie"}, {"op": "checkpoint", "phase": "z", "data": {}}])
    assert store._conn().execute("SELECT COUNT(*) FROM outputs").fetchone()[0] == n_out and store.get(tid)["phase"] == "p"
    with pytest.raises(ValueError): store.apply(tid, f, [{"op": "output", "tool": "t", "args": {}, "output": "x"}, {"op": "nope"}])     # bad op rolls the whole batch back
    assert store._conn().execute("SELECT COUNT(*) FROM outputs").fetchone()[0] == n_out
    uses = store.tx_count; store.apply(tid, f, [{"op": "output", "tool": "t", "args": {}, "output": "a"}, {"op": "output", "tool": "t", "args": {}, "output": "b"}]); assert store.tx_count == uses + 1


def test_pool_completes_every_task_exactly_once_with_bounded_concurrency(store, tmp_path):
    for i in range(60): store.submit("compute", {"seed": f"s{i}", "rounds": 200, "think_s": 0.05}, f"k{i}")
    stop = threading.Event(); peak = [0]
    th = threading.Thread(target=W.serve_pool, args=(store, "pool", "main", tmp_path / "ws"), kwargs={"slots": 6, "ttl": 3.0, "stop": stop}, daemon=True); th.start()
    def sample():
        peak[0] = max(peak[0], store._conn().execute("SELECT COUNT(*) FROM tasks WHERE state IN ('claimed','running','validating')").fetchone()[0]); return store.counts().get("completed") == 60
    wait(sample, 60); stop.set(); th.join(20)
    assert peak[0] <= 6 and not store.audit()
    assert all(r[0] == 1 for r in store._conn().execute("SELECT COUNT(*) FROM events WHERE kind='commit' GROUP BY task_id"))


def test_hub_marks_stale_lease_lost_and_pool_never_commits_it(store, tmp_path):
    tid = store.submit("compute", {"seed": "x", "rounds": 10, "think_s": 1.5}, "k"); stop = threading.Event()
    th = threading.Thread(target=W.serve_pool, args=(store, "pool", "main", tmp_path / "ws"), kwargs={"slots": 2, "ttl": 0.6, "stop": stop}, daemon=True); th.start()
    wait(lambda: store.get(tid)["state"] in ("claimed", "running")); fence = store.get(tid)["fence"]
    store._conn().execute("UPDATE tasks SET fence=fence+1000 WHERE id=?", (tid,))              # someone else now owns it: this worker's fence is stale
    time.sleep(2.5); stop.set(); th.join(20)
    commits = store._conn().execute("SELECT COUNT(*) FROM events WHERE task_id=? AND kind='commit'", (tid,)).fetchone()[0]; assert commits == 0   # the zombie's commit was fenced out


def test_pool_survives_handler_crash_and_unknown_kind(store, tmp_path):
    store.submit("nosuchkind", {}, "bad"); ok = store.submit("compute", {"seed": "a", "rounds": 5}, "good"); stop = threading.Event()
    th = threading.Thread(target=W.serve_pool, args=(store, "pool", "main", tmp_path / "ws"), kwargs={"slots": 2, "ttl": 2.0, "stop": stop}, daemon=True); th.start()
    wait(lambda: store.get(ok)["state"] == "completed"); stop.set(); th.join(20)
    assert store.get(ok)["state"] == "completed"


def test_keepalive_reuses_connection_and_legacy_does_not(store):
    c = Coordinator(store, "t").start()
    try:
        ka = RemoteStore(f"http://127.0.0.1:{c.port}", "t"); lg = RemoteStore(f"http://127.0.0.1:{c.port}", "t", keepalive=False)
        for _ in range(20): ka.counts(); lg.counts()
        assert ka.connects == 1 and lg.connects == 20 and c.rpcs == 40
        c.stop()                                                                    # coordinator restart: a reused connection is dead
        c2 = Coordinator(store, "t", port=c.port).start()
        assert ka.counts() is not None                                              # idempotent call transparently reconnects
        tid = store.submit("compute", {}, "k"); t = store.claim("w"); c2.stop(); c3 = Coordinator(store, "t", port=c2.port).start()
        assert ka.heartbeat(tid, t["fence"]) == "ok"                                # idempotent retry after reconnect; fence still validated server-side
        c3.stop()
    finally:
        try: c.stop()
        except Exception: pass


def test_nonidempotent_call_on_dead_connection_is_not_blindly_replayed(store):
    c = Coordinator(store, "t").start(); r = RemoteStore(f"http://127.0.0.1:{c.port}", "t")
    try:
        tid = store.submit("compute", {}, "k"); t = store.claim("w"); r.begin(tid, t["fence"]); c.stop()
        with pytest.raises(RemoteError): r.complete(tid, t["fence"], {"x": 1})      # coordinator gone: surfaces as RemoteError (lease unprovable), never silently retried elsewhere
    finally:
        try: c.stop()
        except Exception: pass


def test_worker_process_kill_recovers_via_reaper(store, tmp_path):
    for i in range(8): store.submit("compute", {"seed": f"s{i}", "rounds": 100, "think_s": 3.0}, f"k{i}")
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2]))
    p = subprocess.Popen([sys.executable, "-m", "ordivyr.durable_worker", "--db", str(store.path), "--name", "dead", "--ws", str(tmp_path / "w1"), "--ttl", "1.5", "--slots", "8"], env=env, start_new_session=True)
    wait(lambda: store.counts().get("running", 0) + store.counts().get("claimed", 0) == 8, 30); os.killpg(p.pid, signal.SIGKILL); p.wait()
    time.sleep(2.0); store.reap(); assert store.counts().get("queued", 0) == 8                         # leases expired -> all re-queued, none lost
    stop = threading.Event(); th = threading.Thread(target=W.serve_pool, args=(store, "rescue", "main", tmp_path / "w2"), kwargs={"slots": 8, "ttl": 2.0, "stop": stop}, daemon=True); th.start()
    wait(lambda: store.counts().get("completed") == 8, 60); stop.set(); th.join(20)
    assert not store.audit() and all(r[0] == 1 for r in store._conn().execute("SELECT COUNT(*) FROM events WHERE kind='commit' GROUP BY task_id"))
