"""Durable execution: state machine, fencing, idempotent side effects, and real worker subprocesses killed with SIGKILL. No cloud, loopback only."""
import json, os, signal, socket, subprocess, sys, threading, time
from pathlib import Path
import pytest
from ordivyr import durable as D, durable_worker as W
from ordivyr.durable_net import Coordinator, RemoteStore, RemoteError

ROOT = str(Path(__file__).resolve().parents[2])
ENV = dict(os.environ, PYTHONPATH=ROOT)

def port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
def wait(pred, t=30, step=0.1):
    end = time.time() + t
    while time.time() < end:
        v = pred()
        if v: return v
        time.sleep(step)
    raise AssertionError("timeout")
def spawn(mod, *args):
    return subprocess.Popen([sys.executable, "-m", mod, *map(str, args)], env=ENV, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def kill(p):
    try: os.killpg(p.pid, 9)
    except OSError: pass
    p.wait()

@pytest.fixture
def store(tmp_path): return D.Store(tmp_path / "q.db")

def test_lifecycle_and_idempotent_submit(store):
    a = store.submit("exec", {"code": "print(1)"}, "k1"); assert store.submit("exec", {"code": "print(2)"}, "k1") == a
    t = store.claim("w", ttl=5); assert t["id"] == a and t["state"] == "claimed" and t["fence"] == 1 and t["attempt"] == 1
    store.begin(a, t["fence"]); store.begin(a, t["fence"], "validating"); store.complete(a, t["fence"], {"ok": 1})
    assert store.get(a)["state"] == "completed" and store.get(a)["result"] == {"ok": 1}; assert store.audit() == []
    assert [e["kind"] for e in store.history(a)] == ["submitted", "claimed", "state", "state", "commit"]

def test_expired_worker_cannot_commit_over_newer_result(store):
    clock = [1000.0]; store.clock = lambda: clock[0]; a = store.submit("exec", {}, "k"); old = store.claim("old", ttl=5); store.begin(a, old["fence"])
    clock[0] += 6; assert store.reap() == [(a, "queued")]
    new = store.claim("new", ttl=5); assert new["fence"] > old["fence"]; store.begin(a, new["fence"]); store.complete(a, new["fence"], {"by": "new"})
    for fn in (lambda: store.complete(a, old["fence"], {"by": "old"}), lambda: store.heartbeat(a, old["fence"]), lambda: store.checkpoint(a, old["fence"], "x", {}), lambda: store.add_evidence(a, old["fence"], "e", True)):
        with pytest.raises(D.StaleLease): fn()
    assert store.get(a)["result"] == {"by": "new"} and store.audit() == []

def test_stale_worker_rejected_even_before_reap_runs(store):
    a = store.submit("exec", {}); old = store.claim("old", ttl=5); store.begin(a, old["fence"])
    with store.tx() as c: c.execute("UPDATE tasks SET state='queued', lease_owner=NULL WHERE id=?", (a,))       # supervisor re-queued it
    new = store.claim("new"); assert new["fence"] == old["fence"] + 1
    with pytest.raises(D.StaleLease): store.complete(a, old["fence"], {"x": 1})

def test_retry_budget_and_failure_reason_kept(store):
    a = store.submit("exec", {}, max_attempts=2)
    t = store.claim("w"); store.begin(a, t["fence"]); assert store.fail(a, t["fence"], "boom 1", backoff=0) == "queued"
    t = store.claim("w"); assert t["attempt"] == 2; store.begin(a, t["fence"]); assert store.fail(a, t["fence"], "boom 2", backoff=0) == "failed"
    g = store.get(a); assert g["state"] == "failed" and "boom 2" in g["failure"]; assert [e["detail"] for e in store.history(a) if e["kind"] == "attempt_failed"].__len__() == 2; assert store.claim("w") is None

def test_infra_release_does_not_burn_attempts(store):
    a = store.submit("exec", {}, max_attempts=1)
    for _ in range(5):
        t = store.claim("w"); assert t["attempt"] == 1; store.begin(a, t["fence"]); store.release(a, t["fence"], "model down", delay=0)
    assert store.get(a)["state"] == "queued" and store.get(a)["infra"] == 5

def test_cancel_queued_and_running(store):
    q = store.submit("exec", {}); assert store.cancel(q) == "cancelled"; r = store.submit("exec", {}); t = store.claim("w"); store.begin(r, t["fence"])
    assert store.cancel(r) == "cancelling" and store.heartbeat(r, t["fence"]) == "cancel"; store.cancelled(r, t["fence"]); assert store.get(r)["state"] == "cancelled"; assert store.audit() == []

def test_single_commit_enforced_by_database(store):
    a = store.submit("exec", {}); t = store.claim("w"); store.begin(a, t["fence"]); store.complete(a, t["fence"], {})
    with pytest.raises(Exception), store.tx() as c: c.execute("INSERT INTO events(task_id,ts,kind) VALUES(?,?,'commit')", (a, 1.0))

def test_effect_exactly_once_with_reconcile(store):
    a = store.submit("exec", {}); sink = []; do = lambda k: (sink.append(k), {"n": len(sink)})[1]
    rec = lambda k: ("committed", {"n": 1}) if k in sink else ("absent", None)
    t = store.claim("w"); store.begin(a, t["fence"]); store.op_begin(a, t["fence"], "op")                       # crash right after the intent, effect NOT performed
    with store.tx() as c: c.execute("UPDATE tasks SET state='queued' WHERE id=?", (a,))
    t = store.claim("w2"); store.begin(a, t["fence"]); assert store.effect(a, t["fence"], "op", do, rec) == {"n": 1} and sink == ["op"]
    assert store.effect(a, t["fence"], "op", do, rec) == {"n": 1} and sink == ["op"]                         # replay: cached, not re-executed
    b = store.submit("exec", {}); t = store.claim("w"); store.begin(b, t["fence"]); sink2 = ["opb"]; store.op_begin(b, t["fence"], "opb")        # crash AFTER the effect landed
    with store.tx() as c: c.execute("UPDATE tasks SET state='queued' WHERE id=?", (b,))
    t = store.claim("w"); store.begin(b, t["fence"]); assert store.effect(b, t["fence"], "opb", lambda k: sink2.append("DUP"), lambda k: ("committed", {"n": 9})) == {"n": 9} and sink2 == ["opb"]

def test_unreconcilable_effect_needs_explicit_approval(store):
    a = store.submit("exec", {}); t = store.claim("w"); store.begin(a, t["fence"]); store.op_begin(a, t["fence"], "op")
    with store.tx() as c: c.execute("UPDATE tasks SET state='queued' WHERE id=?", (a,))
    t = store.claim("w"); store.begin(a, t["fence"]); ran = []
    with pytest.raises(D.NeedsApproval): store.effect(a, t["fence"], "op", lambda k: ran.append(1))
    store.hold(a, t["fence"], "unreconcilable"); assert store.get(a)["state"] == "needs_approval" and not ran and store.claim("w") is None
    assert store.approve(a, "retry"); t = store.claim("w"); store.begin(a, t["fence"]); store.effect(a, t["fence"], "op", lambda k: ran.append(1) or 1); assert ran == [1]

def test_concurrent_claim_never_double_assigns(store):
    ids = [store.submit("exec", {}) for _ in range(60)]; got = []; lock = threading.Lock()
    def w(n):
        while True:
            t = store.claim(f"t{n}", ttl=30)
            if not t: return
            store.begin(t["id"], t["fence"]); store.complete(t["id"], t["fence"], {"w": n})
            with lock: got.append(t["id"])
    th = [threading.Thread(target=w, args=(i,)) for i in range(8)]; [x.start() for x in th]; [x.join() for x in th]
    assert sorted(got) == ids and store.audit() == [] and store.counts() == {"completed": 60}

def test_concurrency_cap_and_governor(store):
    for _ in range(4): store.submit("exec", {})
    store.set_cap(2); assert store.claim("a") and store.claim("b") and store.claim("c") is None; store.set_cap(0); assert store.claim("d") is None
    from ordivyr.durable_sup import Governor
    g = Governor(); ok = {"mem_avail_mb": 20000, "swap_used_mb": 0, "psi_mem": 0}
    assert g.scale(ok) == 1.0 and g.scale({**ok, "mem_avail_mb": 2000}) == 0.5 and g.scale({**ok, "mem_avail_mb": 500}) == 0.0 and g.scale({**ok, "psi_mem": 50}) == 0.5

def test_remote_store_fencing_and_auth(store, tmp_path):
    co = Coordinator(store, "tok").start()
    try:
        rs = RemoteStore(f"http://127.0.0.1:{co.port}", "tok"); a = rs.submit("exec", {"code": "print(1)"}, "r"); t = rs.claim("rw", "n1", 5); assert t["fence"] == 1 and t["lease_node"] == "n1"
        with store.tx() as c: c.execute("UPDATE tasks SET lease_expires=0 WHERE id=?", (a,))
        store.reap(); t2 = rs.claim("rw2", "main", 5); rs.begin(a, t2["fence"])
        with pytest.raises(D.StaleLease): rs.complete(a, t["fence"], {"stale": 1})
        rs.complete(a, t2["fence"], {"ok": 1}); assert store.get(a)["result"] == {"ok": 1}
        with pytest.raises(RemoteError): RemoteStore(f"http://127.0.0.1:{co.port}", "bad").counts()
    finally: co.stop()
    with pytest.raises(RemoteError): RemoteStore(f"http://127.0.0.1:{co.port}", "tok", timeout=1).counts()

# ---------------------------------------------------------------- real worker processes
def test_real_worker_killed_mid_exec_is_recovered_by_another(tmp_path):
    db = tmp_path / "q.db"; s = D.Store(db); ws = tmp_path / "ws"; marker = tmp_path / "ran"
    code = f"import time,pathlib; open({str(marker)!r},'a').write('x'); time.sleep(3); print('done')"
    a = s.submit("exec", {"code": code}, "slow"); w1 = spawn("ordivyr.durable_worker", "--db", db, "--name", "w1", "--ws", ws, "--ttl", 2)
    try:
        wait(lambda: s.get(a)["state"] in ("running", "validating") and marker.exists()); kill(w1)                                 # SIGKILL mid-task
        time.sleep(2.5); assert [x for x in s.reap()] == [(a, "queued")]
        w2 = spawn("ordivyr.durable_worker", "--db", db, "--name", "w2", "--ws", ws, "--ttl", 2)
        try: wait(lambda: s.get(a)["state"] == "completed", 40)
        finally: kill(w2)
    finally: kill(w1)
    g = s.get(a); assert g["result"]["stdout"].strip() == "done" and g["attempt"] == 2 and s.audit() == []
    assert [e["kind"] for e in s.history(a)].count("lease_expired") == 1

def test_real_worker_retries_failing_exec_then_fails_with_reason(tmp_path):
    db = tmp_path / "q.db"; s = D.Store(db); a = s.submit("exec", {"code": "import sys; sys.exit(3)"}, max_attempts=2)
    w = spawn("ordivyr.durable_worker", "--db", db, "--name", "w", "--ws", tmp_path / "ws", "--ttl", 3)
    try: wait(lambda: s.get(a)["state"] == "failed", 40)
    finally: kill(w)
    assert "exit 3" in s.get(a)["failure"] and s.get(a)["attempt"] == 2 and s.audit() == []
