"""P1 tenancy: fair scheduling, quotas, metering, idempotency scoping, authenticated tenant/worker principals, cross-tenant access attempts."""
import sqlite3
import pytest
from ordivyr import durable as D
from ordivyr.durable_net import Coordinator, RemoteStore, RemoteError


@pytest.fixture
def store(tmp_path): return D.Store(tmp_path / "q.db")


def by_tenant(ts):
    out = {}
    for t in ts: out[t["tenant"]] = out.get(t["tenant"], 0) + 1
    return out


def test_noisy_neighbor_cannot_starve_small_tenant(store):
    for i in range(500): store.submit("k", {}, f"a{i}", tenant="noisy")
    for i in range(20): store.submit("k", {}, f"b{i}", tenant="small")
    got = by_tenant(store.claim_many("w", limit=40))
    assert got == {"noisy": 20, "small": 20}                       # equal share although noisy queued 25x more and was first in line
    assert by_tenant(store.claim_many("w", limit=10)) == {"noisy": 10}   # small is drained; noisy continues


def test_weighted_fairness(store):
    store.tenant_set("big", weight=3); store.tenant_set("small", weight=1)
    for i in range(100): store.submit("k", {}, f"a{i}", tenant="big"); store.submit("k", {}, f"b{i}", tenant="small")
    got = by_tenant(store.claim_many("w", limit=40)); assert 28 <= got["big"] <= 32 and 8 <= got["small"] <= 12


def test_fairness_counts_leases_already_held(store):
    for i in range(30): store.submit("k", {}, f"a{i}", tenant="a")
    first = store.claim_many("w", limit=10)                         # a holds 10 leases
    for i in range(30): store.submit("k", {}, f"b{i}", tenant="b")
    assert by_tenant(store.claim_many("w2", limit=10)) == {"b": 10}   # newcomer catches up before a gets more


def test_max_active_quota(store):
    store.tenant_set("cap", max_active=3)
    for i in range(10): store.submit("k", {}, f"c{i}", tenant="cap"); store.submit("k", {}, f"o{i}", tenant="other")
    got = by_tenant(store.claim_many("w", limit=20)); assert got["cap"] == 3 and got["other"] == 10
    assert store.claim_many("w", limit=5, tenants=["cap"]) == []   # still at its ceiling


def test_max_queued_quota_rejects_and_is_metered(store):
    store.tenant_set("q", max_queued=2); store.submit("k", {}, "1", tenant="q"); store.submit("k", {}, "2", tenant="q")
    with pytest.raises(D.QuotaExceeded): store.submit("k", {}, "3", tenant="q")
    assert store.counts_for("q") == {"queued": 2} and store.usage_of("q")["quota_rejections"] == 1
    store.submit("k", {}, "x", tenant="free")                         # other tenants unaffected


def test_idempotency_keys_are_tenant_scoped(store):
    a = store.submit("k", {"who": "a"}, "same", tenant="a"); b = store.submit("k", {"who": "b"}, "same", tenant="b")
    assert a != b and store.submit("k", {}, "same", tenant="a") == a and store.get(b)["payload"] == {"who": "b"}


def test_usage_metering(store):
    tid = store.submit("k", {}, "m", tenant="t"); t = store.claim("w"); store.begin(tid, t["fence"]); store.complete(tid, t["fence"], {"ok": 1})
    u = store.usage_of("t"); assert (u["submitted"], u["claims"], u["completed"]) == (1, 1, 1) and u["lease_seconds"] >= 0
    t2 = store.submit("k", {}, "f", tenant="t", max_attempts=1); c = store.claim("w"); store.fail(t2, c["fence"], "boom", retry=False); assert store.usage_of("t")["failed"] == 1


def test_old_database_without_tenant_column_migrates(tmp_path):
    p = tmp_path / "old.db"; c = sqlite3.connect(p)
    c.executescript("CREATE TABLE tasks(id INTEGER PRIMARY KEY AUTOINCREMENT, idem_key TEXT UNIQUE, kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued', priority INTEGER NOT NULL DEFAULT 0, attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3, infra INTEGER NOT NULL DEFAULT 0, fence INTEGER NOT NULL DEFAULT 0, lease_owner TEXT, lease_node TEXT, lease_expires REAL, not_before REAL NOT NULL DEFAULT 0, cancel_requested INTEGER NOT NULL DEFAULT 0, phase TEXT, checkpoint TEXT, result TEXT, failure TEXT, created REAL NOT NULL, updated REAL NOT NULL); INSERT INTO tasks(kind,payload,created,updated) VALUES('k','{}',1,1);")
    c.commit(); c.close(); s = D.Store(p)
    assert s.get(1)["tenant"] == "default" and s.claim("w")["id"] == 1


def test_tenant_events_and_get_are_scoped(store):
    a = store.submit("k", {}, "a", tenant="a"); b = store.submit("k", {}, "b", tenant="b")
    assert store.get_for("a", a) and store.get_for("a", b) is None and store.cancel_for("a", b) is None and store.get(b)["state"] == "queued"
    assert {e["task_id"] for e in store.events_for("a")} == {a} and store.counts_for("a") == {"queued": 1}


@pytest.fixture
def hosted(store):
    pr = {"tok-a": {"role": "tenant", "tenant": "a"}, "tok-b": {"role": "tenant", "tenant": "b"}, "tok-w": {"role": "worker"}, "tok-wa": {"role": "worker", "tenants": ["a"]}}
    c = Coordinator(store, "admin", principals=pr).start(); mk = lambda t: RemoteStore(f"http://127.0.0.1:{c.port}", t)
    yield store, mk; c.stop()


def test_authenticated_principals_and_cross_tenant_attacks(hosted):
    store, mk = hosted; A, B, W, WA = mk("tok-a"), mk("tok-b"), mk("tok-w"), mk("tok-wa")
    ta = A.submit("k", {"x": 1}, "i1", tenant="b")                          # tries to submit AS tenant b: the token wins
    tb = B.submit("k", {"y": 2}, "i2")
    assert store.get(ta)["tenant"] == "a" and store.get(tb)["tenant"] == "b"
    assert A.get(ta)["id"] == ta and A.get(tb) is None                      # cannot read b's task
    assert A.cancel(tb) is None and store.get(tb)["state"] == "queued"      # cannot cancel it
    assert {e["task_id"] for e in A.events()} == {ta} and A.counts() == {"queued": 1} and A.usage()["submitted"] == 1
    for bad in ("claim", "claim_many", "complete", "tenant_set", "heartbeat", "reap"):
        with pytest.raises(PermissionError): getattr(A, bad)() if bad in ("claim", "reap") else getattr(A, bad)(1, 1) if bad != "tenant_set" else A.tenant_set("a", 100)
    with pytest.raises(PermissionError): W.submit("k", {}, "w")             # workers cannot submit or administer
    with pytest.raises(RemoteError): mk("nope").counts()                    # unauthenticated -> 401
    t = WA.claim("wa");  assert t["id"] == ta                               # tenant-restricted worker only ever sees a's work
    assert WA.claim("wa") is None                                           # b's queued task is invisible to it
    t2 = W.claim("w"); assert t2["id"] == tb                                # unrestricted worker serves b
    with pytest.raises(PermissionError): WA.heartbeat(tb, t2["fence"], 10)  # restricted worker cannot touch b's lease even with the right fence
    with pytest.raises(PermissionError): WA.complete(tb, t2["fence"], {})
    assert W.heartbeat(tb, t2["fence"], 10) == "ok"
