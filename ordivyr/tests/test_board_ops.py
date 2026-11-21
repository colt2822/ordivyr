import json, os, signal, subprocess, sys, threading, time, pytest
from pathlib import Path
from ordivyr.board import vault as V
from ordivyr.board.errors import Conflict, Forbidden, Invalid, NotFound, QuotaError, Unavailable
from ordivyr.tests.board_support import World, wait_for
from ordivyr import durable as D
from ordivyr.board import sandbox as SB

needs_sbx = pytest.mark.skipif(not SB.available(), reason="bwrap not available")


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi")], "slow": [("sleep", 1.5), ("say", "slept")]}, monkeypatch); x.off = 0.0; x.board.allow_local_endpoints = True; x.board.lease_url = x.url; yield x
    x.board.fleet_shutdown(); x.close()


def leased(w, a, prompt="[[hello]]", agent="ag", org="acme"):
    """Submit a job and take its lease directly through the queue, as a worker would. -> (tid, fence, job_id)"""
    jid = w.board.submit_job(a, "p1", prompt, agent_id=agent, idem_key=os.urandom(4).hex())["job_id"]
    tid = w.board.db.c().execute("SELECT tid FROM jobs WHERE job_id=?", (jid,)).fetchone()[0]
    t = w.board.store.claim("probe", "n", 60, ["board.ordivyr"], [f"{org}:p1"]); assert t and t["id"] == tid; return tid, t["fence"], jid


# ------------------------------------------------------------------ secrets
def test_secrets_sealed_listed_without_values_and_audited_without_values(w):
    a = w.org("acme"); w.board.put_secret(a, "provider_key", "sk-very-secret-value-123")
    row = w.board.db.c().execute("SELECT blob FROM secrets").fetchone()[0]; assert row.startswith("v1.") and "sk-very-secret" not in row
    assert w.board.secrets_list(a) == [{"name": "provider_key", "project": None, "version": 1, "updated": w.board.secrets_list(a)[0]["updated"], "by": a.actor}]
    assert w.board.put_secret(a, "provider_key", "v2")["version"] == 2
    dump = json.dumps(w.board.db.audit_rows(org="acme")) + json.dumps(w.board.secrets_list(a)); assert "sk-very-secret" not in dump and "v2" not in json.loads(json.dumps(w.board.secrets_list(a)))[0].values()
    for bad in ("", "x" * 9000, None, 5): 
        with pytest.raises(Invalid): w.board.put_secret(a, "n", bad)
    with pytest.raises(Invalid): w.board.put_secret(a, "bad name!", "v")
    member = w.board.principal(w.board.issue_key(a, "member")["key"])
    for f in (lambda: w.board.put_secret(member, "n", "v"), lambda: w.board.secrets_list(member), lambda: w.board.delete_secret(member, "provider_key")):
        with pytest.raises(Forbidden): f()
    w.board.delete_secret(a, "provider_key"); assert w.board.secrets_list(a) == []


def test_ciphertext_copied_between_tenants_does_not_decrypt(w):
    a = w.org("acme"); b = w.org("beta"); w.board.put_secret(a, "k", "A-SECRET"); w.board.put_secret(b, "k", "B-SECRET")
    blob_a = w.board.db.c().execute("SELECT blob FROM secrets WHERE org='acme'").fetchone()[0]
    with w.board.db.tx() as c: c.execute("UPDATE secrets SET blob=? WHERE org='beta'", (blob_a,))                    # an attacker with database write access swaps ciphertexts
    with pytest.raises(Unavailable): w.board._secret_value("beta", None, "k")
    with w.board.db.tx() as c: c.execute("UPDATE secrets SET name='other' WHERE org='acme'")                         # ...or renames a row
    with pytest.raises(Unavailable): w.board._secret_value("acme", None, "other")
    with pytest.raises(V.VaultError): w.board.vault.open(blob_a[:-4] + "AAAA", "secret|acme||k")                      # tampering is detected too


def test_fenced_secret_access_is_allowlisted_scoped_and_audited(w):
    a = w.org("acme"); b = w.org("beta"); w.board.put_secret(a, "k1", "ORG-LEVEL"); w.board.put_secret(a, "k2", "NOT-LISTED"); w.board.put_secret(b, "k1", "BETA-VALUE"); w.board.put_secret(a, "k1", "PROJECT-LEVEL", project="p1")
    w.agent(a, "p1", "ag", permissions={"secrets": ["k1"]}); w.agent(a, "p1", "plain"); w.agent(b, "p1", "bag", permissions={"secrets": ["k1", "only_acme"]})
    from ordivyr.board import runtime_adapter as RA
    w.board.register_worker(a, "ordivyr", RA.capabilities(2, ("stub",))); w.board.register_worker(b, "ordivyr", RA.capabilities(2, ("stub",)))
    tid, fence, jid = leased(w, a); assert w.board.w_secret(tid, fence, "k1") == {"value": "PROJECT-LEVEL"}                  # project-level wins over org-level
    for name in ("k2", "nope", "../x"):
        with pytest.raises(PermissionError): w.board.w_secret(tid, fence, name)                                         # not in permissions.secrets
    with pytest.raises(D.StaleLease): w.board.w_secret(tid, fence + 1, "k1")
    assert "secret.read" in [r["action"] for r in w.board.db.audit_rows(org="acme")] and "PROJECT-LEVEL" not in json.dumps(w.board.db.audit_rows(org="acme"))
    btid, bfence, _ = leased(w, b, agent="bag", org="beta"); assert w.board.w_secret(btid, bfence, "k1") == {"value": "BETA-VALUE"}          # beta gets BETA's, never acme's
    with pytest.raises(NotFound): w.board.w_secret(btid, bfence, "only_acme")                                            # allow-listed but absent in beta: acme's secret of any name is unreachable
    p2, f2, _ = leased(w, a, agent="plain")
    with pytest.raises(PermissionError): w.board.w_secret(p2, f2, "k1")                                                  # agent without the permission


def test_secret_lease_call_over_the_wire_cannot_cross_tenants(w):
    from ordivyr.board.coordinator import BoardRemote
    from ordivyr.board import runtime_adapter as RA
    a = w.org("acme"); b = w.org("beta"); w.board.put_secret(a, "k1", "ACME-ONLY"); w.agent(a, "p1", "ag", permissions={"secrets": ["k1"]})
    ta = w.board.register_worker(a, "ordivyr", RA.capabilities(2, ("stub",)))["token"]; tb = w.board.register_worker(b, "ordivyr", RA.capabilities(2, ("stub",)))["token"]
    tid, fence, _ = leased(w, a)
    assert BoardRemote(w.url, ta).board_secret(tid, fence, "k1") == {"value": "ACME-ONLY"}
    with pytest.raises(Exception) as e: BoardRemote(w.url, tb).board_secret(tid, fence, "k1")                           # beta's worker token + acme's tid
    assert "ACME-ONLY" not in str(e.value)


def test_master_key_rotation_rewraps_everything_and_vault_file_is_guarded(w, tmp_path):
    a = w.org("acme"); w.board.put_secret(a, "k", "VALUE"); old = w.board.db.c().execute("SELECT blob FROM secrets").fetchone()[0]
    r = w.board.rotate_master_key(w.platform); new = w.board.db.c().execute("SELECT blob FROM secrets").fetchone()[0]
    assert r["rewrapped"] >= 1 and old.split(".")[1] == "k1" and new.split(".")[1] == "k2" and w.board._secret_value("acme", None, "k") == "VALUE"
    with pytest.raises(Forbidden): w.board.rotate_master_key(a)
    kf = w.board.home / "master.key"; assert oct(kf.stat().st_mode & 0o777) == "0o600"
    os.chmod(kf, 0o640)
    with pytest.raises(V.VaultError, match="chmod 600"): V.Vault(kf)
    os.chmod(kf, 0o600); lone = V.Vault(tmp_path / "other.key"); assert lone.open(lone.seal("x", "a"), "a") == b"x"
    with pytest.raises(V.VaultError): V.Vault(kf).open(lone.seal("x", "a"), "a")                                         # a different master key cannot open it


def test_vault_from_env_for_container_secrets(monkeypatch, tmp_path):
    import base64
    monkeypatch.setenv("ORDIVYR_BOARD_MASTER_KEY", base64.b64encode(os.urandom(32)).decode()); v = V.Vault(None); assert v.open(v.seal("z", "ctx"), "ctx") == b"z"
    monkeypatch.setenv("ORDIVYR_BOARD_MASTER_KEY", base64.b64encode(b"short").decode())
    with pytest.raises(V.VaultError): V.Vault(None)


# ------------------------------------------------------------------ endpoint SSRF guard
def test_customer_model_endpoints_cannot_point_at_internal_addresses(w, monkeypatch):
    w.board.allow_local_endpoints = False; a = w.org("acme")
    for base in ("https://169.254.169.254/latest", "https://127.0.0.1:8080", "https://10.0.0.5", "https://[::1]/", "https://192.168.1.1", "http://api.example.com", "https://u:p@api.example.com", "ftp://x", "https://0.0.0.0"):
        w.board.put_secret(a, "endpoint:e1", json.dumps({"base": base, "key": "k"}))
        with pytest.raises(Invalid): w.board.provision_worker(a, "x", endpoints=["e1"])
    monkeypatch.setattr("socket.getaddrinfo", lambda h, *x, **k: [(2, 1, 6, "", ("93.184.216.34", 0))]); w.board.put_secret(a, "endpoint:e1", json.dumps({"base": "https://api.example.com", "key": "k"}))
    assert w.board.provision_worker(a, "ok", endpoints=["e1"])["state"] == "pending"
    monkeypatch.setattr("socket.getaddrinfo", lambda h, *x, **k: [(2, 1, 6, "", ("10.1.2.3", 0))])                       # DNS rebinding style: a public-looking name that resolves privately
    w.board.put_secret(a, "endpoint:e2", json.dumps({"base": "https://sneaky.example.com", "key": "k"}))
    with pytest.raises(Invalid): w.board.provision_worker(a, "y", endpoints=["e2"])
    with pytest.raises(Invalid): w.board.provision_worker(a, "z", endpoints=["missing"])


# ------------------------------------------------------------------ hosted worker lifecycle (real processes, real sandbox)
def hosted(w, a, slots=1):
    w.board.put_secret(a, "endpoint:stub", json.dumps({"base": w.model.url, "local": True, "models": ["m"]})); w.agent(a, "p1", "ag")
    return w.board.provision_worker(a, "main", slots=slots, endpoints=["stub"])


def converge(w, until, timeout=40, step=0.3, what="state"):
    end = time.time() + timeout
    while time.time() < end:
        w.board.fleet_tick(); v = until()
        if v: return v
        time.sleep(step)
    raise AssertionError("timed out waiting for " + what)


def state(w, a, hid): return next(h for h in w.board.hosted_list(a) if h["id"] == hid)


@needs_sbx
def test_hosted_worker_provision_run_crash_recover_hang_detect_stop_start_deprovision(w):
    a = w.org("acme"); h = hosted(w, a); hid = h["id"]; w.board.online_s = 4.0; w.board.startup_grace_s = 1.0
    converge(w, lambda: state(w, a, hid)["state"] == "running" and state(w, a, hid)["online"], what="hosted worker running")
    j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]; v = w.done(a, "p1", j, 30); assert v["status"] == "completed" and v["result"]["text"] == "hi"      # a real sandboxed run on the hosted worker
    pid = state(w, a, hid)["restarts"], w.board.db.c().execute("SELECT pid FROM hosted WHERE id=?", (hid,)).fetchone()[0]; os.kill(pid[1], signal.SIGKILL)               # crash
    converge(w, lambda: state(w, a, hid)["restarts"] == 1 and state(w, a, hid)["state"] in ("starting", "running") and w.board.db.c().execute("SELECT pid FROM hosted WHERE id=?", (hid,)).fetchone()[0] != pid[1], what="restart after kill -9")
    j2 = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag", idem_key="after-crash")["job_id"]; assert w.done(a, "p1", j2, 40)["status"] == "completed"
    converge(w, lambda: state(w, a, hid)["state"] == "running", what="running again")
    pid2 = w.board.db.c().execute("SELECT pid FROM hosted WHERE id=?", (hid,)).fetchone()[0]; os.kill(pid2, signal.SIGSTOP)                                                 # hang: alive but unresponsive
    converge(w, lambda: state(w, a, hid)["restarts"] >= 1 and w.board.db.c().execute("SELECT pid FROM hosted WHERE id=?", (hid,)).fetchone()[0] != pid2 and state(w, a, hid)["state"] in ("starting", "running"), timeout=60, what="unresponsive worker killed and replaced")
    with pytest.raises(ProcessLookupError): os.kill(pid2, 0)
    assert "hosted_unhealthy" in [x["kind"] for x in w.board.alerts_of(a)]
    w.board.stop_hosted(a, hid); converge(w, lambda: state(w, a, hid)["state"] == "stopped", what="stopped")
    live = w.board.db.c().execute("SELECT pid FROM hosted WHERE id=?", (hid,)).fetchone()[0]; assert live is None
    w.board.start_hosted(a, hid); converge(w, lambda: state(w, a, hid)["state"] == "running", what="restarted by start")
    wid = h["worker"]; tok = w.board.vault.open(w.board.db.c().execute("SELECT token_blob FROM hosted WHERE id=?", (hid,)).fetchone()[0], f"hosted|{hid}").decode()
    w.board.deprovision_hosted(a, hid); assert w.board.worker_principal(tok) is None                                                                                         # token dead immediately
    converge(w, lambda: not (w.board.home / "fleet" / hid).exists(), what="workspace purged"); assert w.board.hosted_list(a) == []
    audit = [r["action"] for r in w.board.db.audit_rows(org="acme")]; assert {"hosted.provision", "hosted.stop", "hosted.start", "hosted.deprovision", "hosted.purged"} <= set(audit) and w.board.db.verify_audit()[0]


@needs_sbx
def test_hosted_worker_environment_is_scrubbed_and_other_orgs_cannot_see_or_control_it(w):
    a = w.org("acme"); b = w.org("beta"); h = hosted(w, a); hid = h["id"]; os.environ["BOARD_PG_DSN_PROBE"] = "must-not-leak"; os.environ["ORDIVYR_BOARD_MASTER_KEY"] = "x"
    try: converge(w, lambda: state(w, a, hid)["state"] in ("starting", "running"), what="spawned")
    finally: os.environ.pop("ORDIVYR_BOARD_MASTER_KEY"); os.environ.pop("BOARD_PG_DSN_PROBE")
    pid = w.board.db.c().execute("SELECT pid FROM hosted WHERE id=?", (hid,)).fetchone()[0]; env = Path(f"/proc/{pid}/environ").read_bytes().decode().split("\0")
    assert not any("MASTER_KEY" in e or "BOARD_PG" in e or "DSN" in e for e in env) and any(e.startswith("ORDIVYR_GATEWAY_HOME=") for e in env)
    for f in (lambda: w.board.stop_hosted(b, hid), lambda: w.board.scale_hosted(b, hid, 4), lambda: w.board.deprovision_hosted(b, hid), lambda: w.board.start_hosted(b, hid)):
        with pytest.raises(NotFound): f()
    assert w.board.hosted_list(b) == [] and (w.board.home / "fleet" / hid / "token").stat().st_mode & 0o777 == 0o600
    viewer = w.board.principal(w.board.issue_key(a, "viewer")["key"])
    with pytest.raises(Forbidden): w.board.stop_hosted(viewer, hid)
    assert w.board.hosted_list(viewer)[0]["id"] == hid and "token" not in json.dumps(w.board.hosted_list(viewer))
    w.board.scale_hosted(a, hid, 3); converge(w, lambda: state(w, a, hid)["slots"] == 3 and state(w, a, hid)["state"] in ("starting", "running"), what="rescaled")


def test_crash_loop_is_contained_alerted_and_resettable(w):
    a = w.org("acme"); h = hosted(w, a); hid = h["id"]; w.board.clock = w.board.db.clock = lambda: time.time() + w.off
    with w.board.db.tx() as c: c.execute("DELETE FROM secrets WHERE name='endpoint:stub'")                           # every spawn now fails: a stand-in for a worker that cannot start
    for _ in range(12): w.board.fleet_tick(); w.off += 90
    s = state(w, a, hid); assert s["state"] == "failed" and "restart limit" in s["last_error"] and "hosted_failed" in [x["kind"] for x in w.board.alerts_of(a)]
    n = w.board.db.c().execute("SELECT window_restarts FROM hosted WHERE id=?", (hid,)).fetchone()[0]; w.board.fleet_tick(); w.off += 90; w.board.fleet_tick()
    assert w.board.db.c().execute("SELECT window_restarts FROM hosted WHERE id=?", (hid,)).fetchone()[0] == n                # failed means STOP retrying, not retry forever
    w.board.put_secret(a, "endpoint:stub", json.dumps({"base": w.model.url, "local": True})); w.board.start_hosted(a, hid); assert state(w, a, hid)["state"] == "pending"


@needs_sbx
def test_supervisor_failover_after_kill_9_of_the_supervising_board_process(w, tmp_path):
    from ordivyr.tests.test_board_postgres import DSN
    a = w.org("acme"); hosted(w, a); hid = w.board.hosted_list(a)[0]["id"]; w.board.lease_url = None                       # this process does not supervise
    env = {**os.environ, "ORDIVYR_GATEWAY_HOME": str(w.gwhome), "PYTHONPATH": os.getcwd()}; procs = []
    def boot(n):
        args = [sys.executable, "-m", "ordivyr.tests._board_server_proc", str(w.tmp / "board"), w.dsn or ""]
        p = subprocess.Popen(args, env=env, cwd=os.getcwd(), stdout=subprocess.PIPE, text=True); procs.append(p); return p, json.loads(p.stdout.readline())
    try:
        if not w.dsn: pytest.skip("failover needs a shared database (PostgreSQL): two SQLite-home processes would share files, covered by the kill -9 PG test")
        p1, _ = boot(1); converge_db = lambda: next(h for h in w.board.hosted_list(a) if h["id"] == hid)
        wait_for(lambda: converge_db()["state"] == "running" and converge_db()["online"], 60, what="supervisor 1 runs the hosted worker")
        wpid = w.board.db.c().execute("SELECT pid FROM hosted WHERE id=?", (hid,)).fetchone()[0]; os.kill(p1.pid, signal.SIGKILL); p1.wait(5)
        wait_for(lambda: not Path(f"/proc/{wpid}").exists() or Path(f"/proc/{wpid}/stat").read_text().split()[2] == "Z", 10, what="worker dies with its supervisor (PDEATHSIG)")
        p2, _ = boot(2); wait_for(lambda: converge_db()["state"] == "running" and w.board.db.c().execute("SELECT pid FROM hosted WHERE id=?", (hid,)).fetchone()[0] != wpid, 60, what="supervisor 2 takes the lease and respawns")
        j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]; assert w.done(a, "p1", j, 60)["status"] == "completed"
    finally:
        for p in procs:
            if p.poll() is None: p.kill()


# ------------------------------------------------------------------ health, retry, metrics
def test_health_report_flags_backlog_without_workers_and_metrics_hold_no_tenant_data(w):
    from ordivyr.board import runtime_adapter as RA
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.board.register_worker(a, "ordivyr", RA.capabilities(2, ("stub",))); w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")
    h = w.board.health_of(a); assert h["status"].startswith("degraded") and h["queue"]["p1"]["queued"] == 1 and h["workers"][0]["online"] is False
    m = w.board.metrics_text(); assert 'board_queue_tasks{state="queued"} 1' in m and "board_up 1" in m and "acme" not in m and 'board_db_backend{backend="' in m
    b = w.org("beta"); assert w.board.health_of(b)["queue"]["p1"]["queued"] == 0 and w.board.health_of(b)["workers"] == []


def test_retry_failed_or_cancelled_job_creates_a_new_linked_job(w):
    from ordivyr.board import runtime_adapter as RA
    a = w.org("acme"); w.agent(a, "p1", "ag"); r = w.board.register_worker(a, "ordivyr", RA.capabilities(2, ("stub",))); j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]
    with pytest.raises(Conflict): w.board.retry_job(a, "p1", j)                                                          # not terminal yet
    w.board.cancel_job(a, "p1", j); assert w.board.get_job(a, "p1", j)["status"] == "cancelled"
    w.worker(r["token"], "own", slots=1); nj = w.board.retry_job(a, "p1", j); assert nj["job_id"] != j and w.done(a, "p1", nj["job_id"], 30)["result"]["text"] == "hi"
    b = w.org("beta")
    with pytest.raises(NotFound): w.board.retry_job(b, "p1", j)


def test_busy_worker_is_not_reported_unresponsive(w):
    """Regression (found by the real-model run): a hosted worker whose slots were all busy never claimed, so last_seen went stale and the supervisor killed it mid-job every ~55 s.
    Any authorised lease call (heartbeat) must now keep the worker visibly alive."""
    from ordivyr.board.coordinator import BoardRemote
    from ordivyr.board import runtime_adapter as RA
    a = w.org("acme"); w.agent(a, "p1", "ag", permissions={"secrets": []})
    r = w.board.register_worker(a, "ordivyr", RA.capabilities(2, ("stub",)))
    tid, fence, _ = leased(w, a)
    with w.board.db.tx() as c: c.execute("UPDATE workers SET last_seen=1.0 WHERE id=?", (r["worker"],))
    w.board._alive_at = {}
    BoardRemote(w.url, r["token"]).heartbeat(tid, fence, 6.0)
    seen = w.board.db.c().execute("SELECT last_seen FROM workers WHERE id=?", (r["worker"],)).fetchone()[0]
    assert seen > 1000, "a heartbeat from a busy worker must refresh last_seen"
