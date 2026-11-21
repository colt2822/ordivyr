"""TaskStore conformance: the SAME behavioural contract run against SQLite (always) and PostgreSQL (only when ORDIVYR_PG_DSN is set and psycopg is importable).
The PG leg is SKIPPED - not passed - on machines without a server. Last run against a real PostgreSQL 16.15: 12/12 PG pass (see pgstore.py header)."""
import os, itertools
import pytest
from ordivyr import durable as D

try: from ordivyr.hosting import pgstore
except Exception: pgstore = None
PG_DSN = os.environ.get("ORDIVYR_PG_DSN", "")        # captured at import: conftest scrubs ORDIVYR_* from the environment for every test
PG = bool(PG_DSN) and pgstore is not None and pgstore.psycopg is not None
_n = itertools.count()


@pytest.fixture(params=["sqlite", pytest.param("pg", marks=pytest.mark.skipif(not PG, reason="needs ORDIVYR_PG_DSN + psycopg (SKIPPED here, not passed)"))])
def store(request, tmp_path):
    if request.param == "sqlite": return D.Store(tmp_path / "q.db")
    s = pgstore.PgStore(PG_DSN)
    with s.tx() as c: c.execute("TRUNCATE tasks, events, checkpoints, evidence, outputs, tenants, usage, nodes RESTART IDENTITY")
    request.addfinalizer(s.close); return s


def run_one(s, w="w"):
    t = s.claim(w); s.begin(t["id"], t["fence"]); s.add_evidence(t["id"], t["fence"], "ok", True); s.complete(t["id"], t["fence"], {"r": 1}); return t


def test_idempotent_submit(store):
    a = store.submit("k", {"x": 1}, "same"); assert store.submit("k", {"x": 2}, "same") == a


def test_claim_complete_and_audit(store):
    store.submit("k", {}); t = run_one(store); assert store.get(t["id"])["state"] == "completed" and store.audit() == []


def test_fences_monotonic_and_stale_writer_rejected(store):
    store.submit("k", {}, max_attempts=3); t1 = store.claim("a", ttl=-1); store.reap(); t2 = store.claim("b")
    assert t2["fence"] > t1["fence"]
    with pytest.raises(D.StaleLease): store.complete(t1["id"], t1["fence"], {})
    with pytest.raises(D.StaleLease): store.heartbeat(t1["id"], t1["fence"])


def test_claim_many_never_duplicates(store):
    for i in range(20): store.submit("k", {}, f"i{i}")
    got = store.claim_many("a", limit=8) + store.claim_many("b", limit=8) + store.claim_many("c", limit=8)
    ids = [t["id"] for t in got]; assert len(ids) == 20 and len(set(ids)) == 20


def test_single_commit(store):
    store.submit("k", {}); t = run_one(store)
    with pytest.raises(D.StaleLease): store.complete(t["id"], t["fence"], {})
    assert store.audit() == []


def test_retry_then_fail(store):
    store.submit("k", {}, max_attempts=2)
    t = store.claim("w"); assert store.fail(t["id"], t["fence"], "x", backoff=0) == "queued"
    t = store.claim("w"); assert store.fail(t["id"], t["fence"], "x", backoff=0) == "failed"


def test_cancel_queued_and_running(store):
    a = store.submit("k", {}, "a"); assert store.cancel(a) == "cancelled"
    store.submit("k", {}, "b"); t = store.claim("w"); assert store.cancel(t["id"]) == "cancelling" and store.heartbeat(t["id"], t["fence"]) == "cancel"


def test_heartbeat_many_verdicts(store):
    store.submit("k", {}, "a"); store.submit("k", {}, "b"); a, b = store.claim_many("w", limit=2)
    r = store.heartbeat_many([(a["id"], a["fence"]), (b["id"], b["fence"] + 999)]); assert r[a["id"]] == "ok" and r[b["id"]] == "stale"


def test_tenant_quota_and_isolation(store):
    store.tenant_set("t", max_queued=2); store.submit("k", {}, "1", tenant="t"); store.submit("k", {}, "2", tenant="t")
    with pytest.raises(D.QuotaExceeded): store.submit("k", {}, "3", tenant="t")
    assert store.usage_of("t")["quota_rejections"] == 1


def test_fair_claim_across_tenants(store):
    for i in range(50): store.submit("k", {}, f"n{i}", tenant="noisy")
    for i in range(5): store.submit("k", {}, f"s{i}", tenant="small")
    got = store.claim_many("w", limit=10); assert sum(1 for t in got if t["tenant"] == "small") >= 4


def test_max_active_enforced(store):
    store.tenant_set("t", max_active=2)
    for i in range(6): store.submit("k", {}, f"i{i}", tenant="t")
    assert len(store.claim_many("w", limit=6)) == 2


def test_reap_requeues_and_exhausts(store):
    store.submit("k", {}, max_attempts=1); store.claim("w", ttl=-1); assert store.reap()[0][1] == "failed"
