"""P3 NodeAgent: lease/claim/heartbeat aggregation, lease safety, worker-loss recovery, coordinator-outage behaviour."""
import threading, time
import pytest
from ordivyr import durable as D, durable_worker as W
from ordivyr.durable_net import Coordinator, RemoteStore
from ordivyr.hosting.nodeagent import NodeStore


def wait(pred, t=30, step=0.05):
    end = time.time() + t
    while time.time() < end:
        v = pred()
        if v: return v
        time.sleep(step)
    raise AssertionError("timeout")


@pytest.fixture
def st(tmp_path): return D.Store(tmp_path / "q.db")


def test_one_upstream_claim_feeds_many_workers_and_one_heartbeat_covers_all(st):
    for i in range(40): st.submit("k", {}, f"i{i}")
    n = NodeStore(st, "n1", sync=True, capacity=40, ttl=3.0)
    got = [n.claim("w%d" % i) for i in range(40)]; assert all(got) and n.stats["upstream_claims"] <= 41
    n2 = NodeStore(st, "n2", sync=True, capacity=40, ttl=3.0); [st.submit("k", {}, f"j{i}") for i in range(40)]
    batch = n2.claim_many("big", limit=40); assert len(batch) == 40 and n2.stats["upstream_claims"] == 1            # one coordinator call for 40 tasks
    before = st.tx_count
    for t in batch: assert n2.heartbeat(t["id"], t["fence"]) == "ok"                                              # 40 worker heartbeats ...
    assert st.tx_count == before                                                                                  # ... cost the coordinator nothing
    n2.beat(); assert st.tx_count == before + 1 and n2.stats["upstream_heartbeats"] == 1                          # ... one aggregated renewal


def test_commits_still_go_through_the_coordinator_fence_exactly_once(st):
    st.submit("k", {}, "a"); n = NodeStore(st, "n1", sync=True, ttl=3.0); t = n.claim("w"); n.begin(t["id"], t["fence"]); n.complete(t["id"], t["fence"], {"ok": 1})
    assert st.get(t["id"])["state"] == "completed"
    with pytest.raises(D.StaleLease): n.complete(t["id"], t["fence"], {"again": 1})                              # node no longer holds it
    with pytest.raises(D.StaleLease): st.complete(t["id"], t["fence"], {"again": 1})                              # and neither does the coordinator accept it


def test_lease_lost_upstream_is_seen_by_local_workers(st):
    st.submit("k", {}, "a"); n = NodeStore(st, "n1", sync=True, ttl=3.0); t = n.claim("w"); st._conn().execute("UPDATE tasks SET fence=fence+50 WHERE id=?", (t["id"],))        # coordinator re-leased it
    n.beat()
    with pytest.raises(D.StaleLease): n.heartbeat(t["id"], t["fence"])
    assert n.heartbeat_many([(t["id"], t["fence"])]) == {t["id"]: "stale"}
    with pytest.raises(D.StaleLease): n.complete(t["id"], t["fence"], {})
    assert st.get(t["id"])["state"] != "completed"


def test_cancel_request_reaches_the_worker(st):
    tid = st.submit("k", {}, "a"); n = NodeStore(st, "n1", sync=True, ttl=3.0); t = n.claim("w"); st.cancel(tid); n.beat(); assert n.heartbeat(tid, t["fence"]) == "cancel"


def test_silent_worker_leases_are_released_immediately_and_rerun_once(st):
    clk = [1000.0]; tid = st.submit("k", {}, "a"); n = NodeStore(st, "n1", sync=True, ttl=30.0, worker_timeout=5.0, clock=lambda: clk[0]); t = n.claim("ghost")
    clk[0] += 6.0; n.sweep()                                                                                       # ghost never heartbeated: released, not waiting 30 s for lease expiry
    assert st.get(tid)["state"] == "queued" and n.stats["released_for_dead_worker"] == 1 and n.events[0]["kind"] == "worker-lost"
    with pytest.raises(D.StaleLease): n.complete(t["id"], t["fence"], {"zombie": 1})
    t2 = st.claim("healthy"); st.begin(t2["id"], t2["fence"]); st.complete(t2["id"], t2["fence"], {"ok": 1})
    assert sum(1 for r in st._conn().execute("SELECT 1 FROM events WHERE kind='commit'")) == 1


def test_coordinator_outage_makes_node_abandon_leases_after_ttl(tmp_path):
    st = D.Store(tmp_path / "q.db"); c = Coordinator(st, "t").start(); up = RemoteStore(f"http://127.0.0.1:{c.port}", "t", timeout=1)
    st.submit("k", {}, "a"); clk = [1000.0]; n = NodeStore(up, "n1", sync=True, ttl=2.0, clock=lambda: clk[0]); t = n.claim("w"); assert t
    c.stop(); n.beat(); assert n.heartbeat(t["id"], t["fence"]) == "ok"                                            # outage shorter than ttl: still provable
    clk[0] += 2.5; n.beat()
    with pytest.raises(D.StaleLease): n.heartbeat(t["id"], t["fence"])                                             # > ttl without renewal: abandon (self-fencing)


def test_close_releases_prefetched_but_unhanded_tasks(st):
    for i in range(10): st.submit("k", {}, f"i{i}")
    n = NodeStore(st, "n1", sync=True, ttl=3.0); got = n.claim_many("w", limit=3); n._refill(10)                              # 3 handed out, rest sit in the buffer as real leases
    assert st.counts().get("claimed") == 10; n.close(); assert st.counts().get("queued") == 7 and st.counts().get("claimed") == 3


def test_capacity_is_respected_and_reported(st):
    for i in range(50): st.submit("k", {}, f"i{i}")
    n = NodeStore(st, "n1", sync=True, capacity=8, ttl=3.0); assert len(n.claim_many("w", limit=50)) == 8 and n.claim("w") is None
    n.up.node_report("n1", 8); assert {x["node"]: x["capacity"] for x in st.nodes()} == {"n1": 8}


def test_pool_workers_run_through_the_node_agent_and_cut_coordinator_rpcs(tmp_path):
    def run(via_node):
        st = D.Store(tmp_path / f"q{via_node}.db"); c = Coordinator(st, "t").start(); up = RemoteStore(f"http://127.0.0.1:{c.port}", "t", timeout=10)
        for i in range(80): st.submit("compute", {"seed": f"s{i}", "rounds": 20, "think_s": 0.2}, f"k{i}")
        stop = threading.Event(); node = NodeStore(up, "n1", capacity=40, ttl=3.0).start() if via_node else None; store = node or up
        ths = [threading.Thread(target=W.serve, args=(store, f"w{i}", "n1", tmp_path / f"ws{via_node}", 3.0, None, stop), kwargs={"poll": 0.05, "longpoll": 1.0}, daemon=True) for i in range(40)]
        r0 = c.rpcs; [t.start() for t in ths]
        wait(lambda: st.counts().get("completed") == 80, 90); rpcs = c.rpcs - r0; stop.set()
        if node: node.close()
        assert not st.audit() and all(v == 1 for v in [r[0] for r in st._conn().execute("SELECT COUNT(*) FROM events WHERE kind='commit' GROUP BY task_id")])
        c.stop(); return rpcs / 80
    direct, agg = run(False), run(True)
    assert agg < direct * 0.85, (direct, agg)
    print(f"coordinator RPCs per completed task: direct={direct:.2f} via NodeAgent={agg:.2f}")
