"""Executable contracts for the hosting layer. Any adapter (embedded or future) must pass these. No mocks of infrastructure: real SQLite, real HTTP lease API, real subprocesses."""
import json, os, signal, subprocess, sys, tempfile, time
from pathlib import Path
import pytest
from ordivyr import durable as D
from ordivyr.durable_net import Coordinator, RemoteStore
from ordivyr.hosting import local, modes, registry
from ordivyr.hosting.contracts import ExecSpec, QuotaExceeded, TaskStore, Executor, ArtifactStorage, Authenticator, Meter

ROOT = str(Path(__file__).resolve().parents[2])

@pytest.fixture(params=["embedded", "remote"])
def store(request, tmp_path):
    st = D.Store(tmp_path / "q.db")
    if request.param == "embedded": yield st; return
    c = Coordinator(st, "tok").start(); yield RemoteStore(f"http://127.0.0.1:{c.port}", "tok"); c.stop()

# ---------------------------------------------------------------- TaskStore contract (embedded AND over HTTP)
def test_store_contract_surface(store):
    names = [n for n in vars(TaskStore) if not n.startswith('_') and callable(getattr(TaskStore, n))]
    assert names and all(callable(getattr(store, n)) for n in names)

def test_idempotent_submit_claim_complete(store):
    a = store.submit("k", {"x": 1}, "idem"); assert store.submit("k", {"x": 2}, "idem") == a
    t = store.claim("w", ttl=5); assert t["id"] == a and t["fence"] >= 1 and store.claim("w2", ttl=5) is None
    store.begin(a, t["fence"]); store.checkpoint(a, t["fence"], "p", {"n": 1}); store.complete(a, t["fence"], {"ok": True})
    assert store.get(a)["state"] == "completed" and store.get(a)["result"] == {"ok": True}

def test_stale_fence_rejected_after_reclaim(store):
    a = store.submit("k", {}); t = store.claim("w", ttl=5); store.begin(a, t["fence"])
    assert store.fail(a, t["fence"], "boom", backoff=0) == "queued"; t2 = store.claim("w2", ttl=5); assert t2["fence"] > t["fence"]
    with pytest.raises(D.StaleLease): store.complete(a, t["fence"], {"late": 1})
    store.begin(a, t2["fence"]); store.complete(a, t2["fence"], {"ok": 1}); assert store.get(a)["result"] == {"ok": 1}

# ---------------------------------------------------------------- deployment modes
def test_self_hosted_needs_nothing_external(tmp_path):
    s = modes.build(home=tmp_path); assert s.mode == "self_hosted" and isinstance(s.store, D.Store) and isinstance(s.auth, local.LocalAuth)
    assert isinstance(s.storage, ArtifactStorage) and isinstance(s.executor, Executor) and isinstance(s.meter, Meter) and isinstance(s.auth, Authenticator)
    assert (tmp_path / "admin.token").stat().st_mode & 0o077 == 0

def test_managed_requires_multitenant_auth(tmp_path):
    s = modes.build({"mode": "managed"}, tmp_path); assert isinstance(s.auth, local.TokenAuth) and isinstance(s.meter, local.SqliteMeter)
    registry.register("auth", "single", lambda spec: local.LocalAuth(tmp_path / "t"))
    with pytest.raises(modes.ConfigError, match="multi-tenant"): modes.build({"mode": "managed", "auth": {"adapter": "single"}}, tmp_path)

def test_hosted_refuses_process_isolation(tmp_path):
    with pytest.raises(modes.ConfigError, match="process-level"): modes.build({"mode": "hosted"}, tmp_path)

def test_hosted_accepts_a_real_isolating_executor_when_registered(tmp_path):
    class Boxed(local.LocalProcessExecutor): isolation = "container"
    registry.register("executor", "boxed", lambda spec: Boxed())
    assert modes.build({"mode": "hosted", "executor": {"adapter": "boxed"}}, tmp_path).executor.isolation == "container"

def test_unregistered_adapter_fails_loudly(tmp_path):
    with pytest.raises(KeyError, match="no store adapter"): modes.build({"store": {"adapter": "postgres"}}, tmp_path)

# ---------------------------------------------------------------- tenants: storage, auth, quotas, metering
def test_storage_tenant_boundary_and_traversal(tmp_path):
    st = local.FsStorage(tmp_path); st.put("a", "x/y.txt", b"1"); st.put("b", "x/y.txt", b"2")
    assert st.get("a", "x/y.txt") == b"1" and st.list("b") == ["x/y.txt"]
    for bad in ("../b/x/y.txt", "/etc/passwd", "x/../../b/x/y.txt"):
        with pytest.raises(ValueError): st.get("a", bad)
    with pytest.raises(ValueError): st.get("../b", "x/y.txt")
    os.symlink(str(tmp_path / "b"), str(tmp_path / "a" / "link"))
    with pytest.raises(ValueError): st.get("a", "link/x/y.txt")

def test_storage_lifecycle_expiry(tmp_path):
    st = local.FsStorage(tmp_path); st.put("t", "old", b"x"); os.utime(tmp_path / "t" / "old", (1, 1)); st.put("t", "new", b"y")
    assert st.expire("t", 3600) == 1 and st.list("t") == ["new"]

def test_token_auth_hashes_revokes_audits(tmp_path):
    a = local.TokenAuth(tmp_path / "a.db"); tok = a.issue("u1", "acme", "user", actor="root"); assert a.authenticate(tok).tenant == "acme" and a.authenticate("nope") is None
    assert tok not in Path(tmp_path / "a.db").read_bytes().decode("latin1")                 # plaintext token is never stored
    assert a.revoke("u1", actor="root") == 1 and a.authenticate(tok) is None
    assert [r[2] for r in a.audit()] == ["issue", "revoke"]

def test_principal_least_privilege():
    from ordivyr.hosting.contracts import Principal
    assert Principal("w", "t", "worker").can("claim") and not Principal("w", "t", "worker").can("submit") and not Principal("u", "t", "user").can("claim")

def test_quota_and_metering(tmp_path):
    q = local.StaticQuota({"acme": {"concurrent_tasks": 2}, "*": {"concurrent_tasks": 5}}); q.check("acme", "concurrent_tasks", 1)
    with pytest.raises(QuotaExceeded): q.check("acme", "concurrent_tasks", 2)
    q.check("other", "concurrent_tasks", 4)
    m = local.SqliteMeter(tmp_path / "u.db"); m.record("acme", "task_seconds", 3.5); m.record("acme", "task_seconds", 1.5); m.record("other", "task_seconds", 9)
    assert m.usage("acme") == {"task_seconds": 5.0} and m.usage("nobody") == {}

def test_byok_models_per_tenant(tmp_path, monkeypatch):
    kf = tmp_path / "k"; kf.write_text("sk-customer\n"); monkeypatch.setenv("X_KEY", "env-key")
    m = local.ConfigModels({"acme": {"gpt": {"base": "https://api.example/v1", "key_file": str(kf)}}, "*": {"local": {"base": "http://127.0.0.1:8080/v1", "key_env": "X_KEY"}}})
    assert m.resolve("acme", "gpt").key == "sk-customer" and m.resolve("zed", "local").key == "env-key"
    with pytest.raises(KeyError): m.resolve("zed", "gpt")

# ---------------------------------------------------------------- executor: limits + runaway protection + no orphans
def test_executor_kills_runaway_and_enforces_memory(tmp_path):
    ex = local.LocalProcessExecutor(); h = ex.start(ExecSpec([sys.executable, "-c", "import time; time.sleep(60)"], str(tmp_path), timeout_s=1)); t = time.time(); h.wait(10); assert time.time() - t < 8 and h.rc != 0
    h = ex.start(ExecSpec([sys.executable, "-c", "x = bytearray(900*1024*1024)"], str(tmp_path), max_memory_mb=200)); assert h.wait(20) != 0

# ---------------------------------------------------------------- one-command self-hosted start, real processes, graceful stop, durable restart
def test_ordivyr_up_runs_a_task_and_survives_restart(tmp_path):
    env = dict(os.environ, PYTHONPATH=ROOT, ORDIVYR_HOME=str(tmp_path))
    def up(): return subprocess.Popen([sys.executable, "-m", "ordivyr", "up", "--workers", "1"], env=env, stdout=subprocess.PIPE, text=True, start_new_session=True)
    p = up(); json.loads(p.stdout.readline()); st = D.Store(tmp_path / "queue.db"); tid = st.submit("exec", {"code": "print(42)"}, "t1")
    end = time.time() + 40
    while time.time() < end and st.get(tid)["state"] != "completed": time.sleep(0.2)
    assert st.get(tid)["state"] == "completed" and "42" in st.get(tid)["result"]["stdout"]
    t2 = st.submit("exec", {"code": "import time; time.sleep(30)"}, "t2"); time.sleep(2); os.killpg(p.pid, signal.SIGKILL); p.wait()          # hard crash mid-task
    p = up(); json.loads(p.stdout.readline()); t3 = st.submit("exec", {"code": "print(7)"}, "t3"); end = time.time() + 60
    while time.time() < end and st.get(t3)["state"] != "completed": time.sleep(0.2)
    assert st.get(t3)["state"] == "completed" and st.audit() == []
    os.killpg(p.pid, signal.SIGTERM); p.wait(30)
    left = subprocess.run(["pgrep", "-f", f"ordivyr.durable_worker.*{tmp_path}"], capture_output=True, text=True).stdout.split(); assert left == []

# ---------------------------------------------------------------- batch operations keep per-task fencing (embedded AND over HTTP)
def test_claim_many_distinct_fences_and_cap(store):
    ids = [store.submit("k", {"i": i}, f"b{i}") for i in range(6)]
    ts = store.claim_many("w", ttl=5, limit=4); assert len(ts) == 4 and len({t["fence"] for t in ts}) == 4 and [t["id"] for t in ts] == ids[:4]
    rest = store.claim_many("w2", ttl=5, limit=10); assert [t["id"] for t in rest] == ids[4:] and store.claim_many("w3", ttl=5) == []
    for t in ts + rest: store.begin(t["id"], t["fence"]); store.complete(t["id"], t["fence"], {"ok": 1})
    assert store.counts() == {"completed": 6}

def test_heartbeat_many_reports_stale_without_extending(store):
    a, b = store.submit("k", {}), store.submit("k", {}); ta, tb = store.claim_many("w", ttl=5, limit=2)
    store.begin(ta["id"], ta["fence"]); assert store.fail(ta["id"], ta["fence"], "x", backoff=0) == "queued"; new = store.claim("w2", ttl=5)
    r = store.heartbeat_many([(ta["id"], ta["fence"]), (tb["id"], tb["fence"])], ttl=5)
    assert r == {ta["id"]: "stale", tb["id"]: "ok"}
    with pytest.raises(D.StaleLease): store.complete(ta["id"], ta["fence"], {"late": 1})
    store.begin(new["id"], new["fence"]); store.complete(new["id"], new["fence"], {"ok": 1})
