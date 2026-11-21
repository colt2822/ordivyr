"""P2 distributed execution: stable sharding, global ids/fencing, shard failure, tenant migration, long-poll dispatch, per-node capacity."""
import subprocess, sys, threading, time
from pathlib import Path
import pytest
from ordivyr import durable as D, durable_worker as W
from ordivyr.durable_net import Coordinator, RemoteStore
from ordivyr.hosting.shard import ShardMap, ShardedStore, stable_hash


def wait(pred, t=40, step=0.05):
    end = time.time() + t
    while time.time() < end:
        v = pred()
        if v: return v
        time.sleep(step)
    raise AssertionError("timeout")


def commits(store, tid=None):
    q = "SELECT task_id, COUNT(*) FROM events WHERE kind='commit' GROUP BY task_id"; return {r[0]: r[1] for r in store._conn().execute(q)}


@pytest.fixture
def cluster(tmp_path):
    stores = [D.Store(tmp_path / f"s{i}.db") for i in range(3)]; return stores, ShardMap(tmp_path / "map.json", 3), tmp_path


def test_hash_is_stable_across_processes_and_independent_of_hash_randomization():
    here = [stable_hash(f"tenant-{i}", 7) for i in range(20)]
    out = subprocess.run([sys.executable, "-c", "from ordivyr.hosting.shard import stable_hash; print([stable_hash(f'tenant-{i}', 7) for i in range(20)])"], capture_output=True, text=True, env={"PYTHONHASHSEED": "random", "PATH": "/usr/bin", "PYTHONPATH": str(Path(__file__).resolve().parents[2])}).stdout
    assert out.strip() == str(here) and len(set(here)) > 3


def test_assignment_is_persistent_and_growth_moves_nobody(tmp_path):
    m = ShardMap(tmp_path / "m.json", 3); before = {f"t{i}": m.shard_of(f"t{i}") for i in range(30)}
    m2 = ShardMap(tmp_path / "m.json"); assert {t: m2.shard_of(t) for t in before} == before                    # reload: same
    m3 = ShardMap(tmp_path / "m.json", 8); assert {t: m3.shard_of(t) for t in before} == before and m3.n == 8     # grow: existing tenants stay put
    with pytest.raises(ValueError): ShardMap(tmp_path / "m.json", 2)


def test_global_ids_route_every_fenced_call_to_the_issuing_shard(cluster):
    stores, smap, _ = cluster; ss = ShardedStore(stores, smap); g = {t: ss.submit("k", {"t": t}, f"i-{t}", tenant=t) for t in ("a", "b", "c", "d", "e", "f")}
    assert len(set(g.values())) == 6 and sum(s.counts().get("queued", 0) for s in stores) == 6
    ts = ss.claim_many("w", limit=10); assert len(ts) == 6 and {t["id"] for t in ts} == set(g.values())
    for t in ts: assert ss.heartbeat_many([(t["id"], t["fence"])])[t["id"]] == "ok"; ss.begin(t["id"], t["fence"]); ss.complete(t["id"], t["fence"], {"ok": 1})
    assert ss.counts() == {"completed": 6} and all(ss.get(i)["state"] == "completed" and ss.get(i)["id"] == i for i in g.values())
    assert ss.submit("k", {}, "i-a", tenant="a") == g["a"]                                                        # idempotent through the router
    with pytest.raises(D.StaleLease): ss.complete(ts[0]["id"], ts[0]["fence"], {"again": 1})                      # no duplicate completion


def test_tenant_isolation_across_shards_a_tenant_token_cannot_reach_other_shards(cluster):
    stores, smap, _ = cluster; ss = ShardedStore(stores, smap); a = ss.submit("k", {}, "x", tenant="alice"); b = ss.submit("k", {}, "x", tenant="bob")
    assert a != b and stores[smap.shard_of("alice")].get_for("alice", a // 1024)["tenant"] == "alice" and stores[smap.shard_of("alice")].get_for("bob", a // 1024) is None


def test_shard_failure_degrades_only_its_tenants_and_recovers_exactly_once(tmp_path):
    stores = [D.Store(tmp_path / f"s{i}.db") for i in range(2)]; coords = [Coordinator(s, "t", reap_every=0.5).start() for s in stores]; ports = [c.port for c in coords]
    smap = ShardMap(tmp_path / "m.json", 2); tenants = {}
    for i in range(200):
        t = f"t{i}"; tenants.setdefault(smap.shard_of(t), t)
        if len(tenants) == 2: break
    ss = ShardedStore([RemoteStore(f"http://127.0.0.1:{p}", "t", timeout=2) for p in ports], smap, cooldown=0.3)
    ids = {sh: [ss.submit("compute", {"seed": f"{sh}{k}", "rounds": 10, "think_s": 0.05}, f"{sh}-{k}", tenant=t) for k in range(10)] for sh, t in tenants.items()}
    stop = threading.Event(); th = threading.Thread(target=W.serve_pool, args=(ss, "pool", "n1", tmp_path / "ws"), kwargs={"slots": 4, "ttl": 1.5, "stop": stop, "longpoll": 0.3}, daemon=True); th.start()
    wait(lambda: stores[0].counts().get("completed", 0) + stores[1].counts().get("completed", 0) >= 4)
    coords[1].stop()                                                                                                   # shard 1's coordinator dies mid-run
    wait(lambda: stores[0].counts().get("completed") == 10)                                                            # shard 0's tenant is unaffected
    coords[1] = Coordinator(stores[1], "t", port=ports[1], reap_every=0.5).start()                                   # back up, same durable state
    wait(lambda: stores[1].counts().get("completed") == 10, 60); stop.set(); th.join(30)
    for s in stores: assert not s.audit() and all(v == 1 for v in commits(s).values())
    for c in coords: c.stop()


def test_tenant_migration_moves_queued_work_without_duplicate_execution(cluster):
    stores, smap, _ = cluster; ss = ShardedStore(stores, smap); t = "mover"; src = smap.shard_of(t); dst = (src + 1) % 3
    stores[src].tenant_set(t, weight=2.0, max_queued=100)
    ids = [ss.submit("k", {"i": i}, f"m{i}", tenant=t) for i in range(20)]
    running = ss.claim_many("w", limit=2, tenants=[t]); [ss.begin(r["id"], r["fence"]) for r in running]
    with pytest.raises(TimeoutError): ss.migrate_tenant(t, dst, drain_s=0.3)                                         # leases still live -> aborted, tenant unfrozen
    assert stores[src].claim_many("w2", limit=1, tenants=[t])                                                          # claims work again after the abort
    for r in running: ss.complete(r["id"], r["fence"], {"ok": 1})
    for r in stores[src].tasks(["claimed"]): stores[src].fail(r["id"], r["fence"], "give back", retry=True, backoff=0)
    res = ss.migrate_tenant(t, dst, drain_s=5.0); assert res["to"] == dst and smap.shard_of(t) == dst and res["moved"] >= 17
    assert stores[src].counts_for(t).get("queued", 0) == 0 and stores[dst].counts_for(t).get("queued") == res["moved"]
    assert ss.migrate_tenant(t, dst)["moved"] == 0                                                                    # idempotent
    new = ss.submit("k", {}, "after", tenant=t); assert new % 1024 == dst                                              # routed to the new shard
    assert stores[src].claim_many("w3", limit=50, tenants=[t]) == []                                                   # source can never run it again (frozen + retired)
    done = set()
    for x in ss.claim_many("w", limit=50, tenants=[t]): ss.begin(x["id"], x["fence"]); ss.complete(x["id"], x["fence"], {"ok": 1}); done.add(x["payload"].get("i"))
    assert all(v == 1 for s in stores for v in commits(s).values())


def test_migration_crash_between_copy_and_retire_does_not_duplicate(cluster):
    stores, smap, _ = cluster; ss = ShardedStore(stores, smap); t = "crashy"; src = smap.shard_of(t); dst = (src + 1) % 3
    [ss.submit("k", {"i": i}, f"c{i}", tenant=t) for i in range(5)]
    stores[src].freeze_tenant(t)
    for r in stores[src].export_queued(t): stores[dst].submit(r["kind"], r["payload"], idem_key=r["idem_key"] or f"mig:{src}:{r['id']}", tenant=t)     # steps 1-3 done, then "crash"
    res = ss.migrate_tenant(t, dst, drain_s=2.0)                                                                      # recovery: re-run
    assert stores[dst].counts_for(t) == {"queued": 5} and stores[src].counts_for(t).get("queued", 0) == 0 and smap.shard_of(t) == dst


# ---------------------------------------------------------------- event-driven dispatch & node capacity
def test_long_poll_wakes_on_submit_and_idles_without_writes(tmp_path):
    st = D.Store(tmp_path / "q.db"); n0 = st.tx_count; got = []
    th = threading.Thread(target=lambda: got.append((time.time(), st.claim_many_wait("w", wait_s=5.0)))); th.start(); time.sleep(0.5)
    assert st.tx_count == n0                                                                                           # waiting costs no write transactions
    t0 = time.time(); st.submit("k", {}, "a"); th.join(5); assert got and got[0][1] and got[0][0] - t0 < 0.3
    t = time.time(); assert st.claim_many_wait("w", wait_s=0.4) == [] and 0.35 < time.time() - t < 1.0


def test_one_submit_wakes_exactly_one_of_many_waiters(tmp_path):
    st = D.Store(tmp_path / "q.db"); res = []
    ths = [threading.Thread(target=lambda i=i: res.append(st.claim_many_wait(f"w{i}", wait_s=1.5, limit=1))) for i in range(6)]; [t.start() for t in ths]; time.sleep(0.3)
    st.submit("k", {}, "only"); [t.join(5) for t in ths]; assert sum(1 for r in res if r) == 1


def test_long_poll_over_http_and_coordinator_restart(tmp_path):
    st = D.Store(tmp_path / "q.db"); c = Coordinator(st, "t").start(); rs = RemoteStore(f"http://127.0.0.1:{c.port}", "t", timeout=2); got = []
    th = threading.Thread(target=lambda: got.append(rs.claim_many_wait("w", "n", 5.0, None, 4, None, 8.0))); th.start(); time.sleep(0.4); t0 = time.time(); st.submit("k", {}, "x"); th.join(10)
    assert got and len(got[0]) == 1 and time.time() - t0 < 0.5
    c.stop(); c2 = Coordinator(st, "t", port=c.port).start(); st.submit("k", {}, "y"); assert len(rs.claim_many_wait("w", "n", 5.0, None, 4, None, 3.0)) == 1; c2.stop()


def test_node_capacity_bounds_only_that_node(tmp_path):
    st = D.Store(tmp_path / "q.db"); [st.submit("k", {}, f"i{i}") for i in range(30)]
    st.node_report("small", capacity=3); st.node_report("big", capacity=20)
    a = st.claim_many("w", "small", limit=10); assert len(a) == 3 and st.claim_many("w", "small", limit=10) == []     # at capacity
    b = st.claim_many("w", "big", limit=10); assert len(b) == 10                                                      # unrelated node unaffected
    assert len(st.claim_many("w", "unreported", limit=5)) == 5                                                        # nodes that never reported are not throttled
    for t in a: st.begin(t["id"], t["fence"]); st.complete(t["id"], t["fence"], {})
    assert len(st.claim_many("w", "small", limit=10)) == 3                                                            # capacity frees as leases finish
    ns = {n["node"]: n for n in st.nodes()}; assert ns["small"]["capacity"] == 3 and ns["small"]["leases"] == 3


def test_stale_capacity_report_is_ignored(tmp_path):
    t = [1000.0]; st = D.Store(tmp_path / "q.db", clock=lambda: t[0]); [st.submit("k", {}, f"i{i}") for i in range(10)]
    st.node_report("n", capacity=1); assert len(st.claim_many("w", "n", limit=5)) == 1
    t[0] += st.NODE_FRESH_S + 1; assert len(st.claim_many("w", "n", limit=5)) == 5


def test_sharded_multi_node_pools_finish_tenants_with_correct_accounting(cluster):
    stores, smap, tmp = cluster; ss = ShardedStore(stores, smap); tenants = ["acme", "globex", "initech", "umbrella"]
    for t in tenants:
        for k in range(15): ss.submit("compute", {"seed": f"{t}{k}", "rounds": 50, "think_s": 0.02}, f"{t}-{k}", tenant=t)
    stop = threading.Event(); pools = [threading.Thread(target=W.serve_pool, args=(ss, f"p{i}", f"node{i}", tmp / f"ws{i}"), kwargs={"slots": 4, "ttl": 2.0, "stop": stop, "longpoll": 0.3}, daemon=True) for i in range(3)]
    [p.start() for p in pools]
    wait(lambda: ss.counts().get("completed") == 60, 60); stop.set(); [p.join(30) for p in pools]
    for t in tenants: u = stores[smap.shard_of(t)].usage_of(t); assert (u["submitted"], u["completed"], u["failed"]) == (15, 15, 0)
    for s in stores: assert not s.audit() and all(v == 1 for v in commits(s).values())
    nodes = {r["lease_node"] for s in stores for r in s._conn().execute("SELECT DISTINCT lease_node FROM tasks")}; assert len(nodes) >= 2          # work really spread over several nodes
