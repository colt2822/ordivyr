import os, signal, subprocess, sys, time, pytest
from ordivyr.tests.board_support import World, wait_for
from ordivyr.board import contract as C, runtime_adapter as RA
from ordivyr.board.coordinator import BoardRemote
from ordivyr.board.service import Unavailable
from ordivyr.durable import StaleLease
from ordivyr.durable_net import RemoteError


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi")], "slow": [("sleep_once", 20)], "long": [("tool_after", 1.2, "list_files", {})] * 8}, monkeypatch); yield x; x.close()


def own_worker(w, admin, name="ow", engine="ordivyr", project=None, run=True):
    r = w.board.register_worker(admin, engine, RA.capabilities(2, ("stub",)), project=project, node=name)
    if run: w.worker(r["token"], name, engine)
    return r


def remote(w, token): return BoardRemote(w.url, token, timeout=5)


def test_wrong_foreign_and_api_tokens_are_refused_by_the_lease_api(w):
    a = w.org("acme"); r = own_worker(w, a, run=False); mk = w.board.issue_key(a, "admin")["key"]
    for tok in ("nope", "", mk, (w.tmp / "board" / "platform.token").read_text()):      # junk, empty, an org API key, the platform operator token
        with pytest.raises(RemoteError): remote(w, tok).claim("x")
    assert remote(w, r["token"]).claim("ow") is None                                    # the real worker token is fine (queue empty)


def test_org_worker_serves_only_its_own_org_and_cannot_touch_others(w):
    a = w.org("acme"); b = w.org("beta"); w.agent(a, "p1", "ag"); w.agent(b, "p1", "ag")
    w.board.set_spend_limit(a, gateway_budget_usd=0.5); w.board.set_spend_limit(b, gateway_budget_usd=0.5)
    ra = own_worker(w, a, "wa", run=False)
    with pytest.raises(Unavailable): w.board.submit_job(b, "p1", "x", agent_id="ag")      # beta has no runtime: acme's worker is not eligible for it
    rb = own_worker(w, b, "wb", run=False)
    jb = w.board.submit_job(b, "p1", "[[hello]]", agent_id="ag")["job_id"]; ja = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]
    tid_b = w.board.db.c().execute("SELECT tid FROM jobs WHERE job_id=?", (jb,)).fetchone()[0]; tid_a = w.board.db.c().execute("SELECT tid FROM jobs WHERE job_id=?", (ja,)).fetchone()[0]
    WA = remote(w, ra["token"]); got = WA.claim_many_wait("wa", "wa", 5, ["board.ordivyr", "board.lite", None][:2], 10, wait_s=0)      # asks for more kinds / no tenant filter: ignored
    assert [t["id"] for t in got] == [tid_a]                                              # only acme's task, never beta's
    WB = remote(w, rb["token"]); held_b = WB.claim_many_wait("wb", "wb", 5, None, 1, wait_s=0)[0]
    assert WA.board_gateway_spend(tid_a, got[0]["fence"], "reserve", "call-a", 0.2)["status"] == "reserved"
    with pytest.raises(PermissionError): WA.board_gateway_spend(tid_b, held_b["fence"], "reserve", "call-b", 0.2)
    for bad in (lambda: WA.heartbeat(tid_b, 1, 5), lambda: WA.complete(tid_b, 1, {}), lambda: WA.fail(tid_b, 1, "x"), lambda: WA.board_delegate(tid_b, 1, {"agent": "ag", "prompt": "x"}),
                lambda: WA.board_memory(tid_b, 1, "get", "project", "k"), lambda: WA.board_gateway_spend(tid_b, 1, "reserve", "bad", 0.1), lambda: WA.heartbeat_many([[tid_b, 1]], 5), lambda: WA.cancelled(tid_b, 1)):
        with pytest.raises(PermissionError): bad()
    for m in ("get", "evidence", "node_report", "cap", "reap", "submit", "tenant_set", "cancel"):
        with pytest.raises((PermissionError, AttributeError)): getattr(WA, m)(tid_b) if m != "submit" else WA.submit("k", {})
    assert w.board.get_job(b, "p1", jb)["status"] == "running"                 # only beta's own worker claimed it; acme's cross-tenant calls changed nothing


def test_org_without_projects_gets_no_work_even_though_empty_filter_means_all_in_the_queue(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.platform_worker(); empty = w.org("zed", projects=())
    r = own_worker(w, empty, "zw", run=False)
    w.stops[-1].set(); time.sleep(1.0)                                                    # stop the platform worker so the next task stays queued for the probe
    w.board.submit_job(a, "p1", "[[hello]] again", agent_id="ag")
    assert w.board.store.counts().get("queued") == 1
    assert remote(w, r["token"]).claim_many_wait("zw", "zw", 5, None, 10, wait_s=0) == []


def test_engine_kinds_are_forced_a_lite_worker_cannot_claim_ordivyr_jobs(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); lite = w.board.register_worker(w.platform, "lite", C.capabilities("lite", ["read_file"], 2, ["cancel"], isolation="namespace"), platform=True)
    own = own_worker(w, a, "ow", run=False); j = w.board.submit_job(a, "p1", "x", agent_id="ag")["job_id"]
    assert remote(w, lite["token"]).claim_many_wait("l", "l", 5, ["board.ordivyr"], 5, wait_s=0) == []          # asked for ordivyr kinds; the server forces board.lite
    assert len(remote(w, own["token"]).claim_many_wait("o", "o", 5, None, 5, wait_s=0)) == 1


def test_drain_revoke_and_kill_switch(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); r = own_worker(w, a, "ow", run=False); wid = r["worker"]; R = remote(w, r["token"])
    w.board.submit_job(a, "p1", "x", agent_id="ag"); w.board.drain_worker(a, wid); assert R.claim("ow") is None
    with pytest.raises(Unavailable): w.board.submit_job(a, "p1", "y", agent_id="ag")      # nothing eligible while the only worker is drained
    w.board.drain_worker(a, wid, False); t = R.claim("ow", "ow", 5); assert t is not None
    w.board.kill(w.platform); assert R.claim("ow") is None and R.heartbeat(t["id"], t["fence"], 5) == "cancel"      # kill: no new work, running work told to stop
    with pytest.raises(Unavailable): w.board.submit_job(a, "p1", "z", agent_id="ag")
    w.board.kill(w.platform, False); w.board.revoke_worker(a, wid)
    with pytest.raises(RemoteError): R.claim("ow")                                        # revocation is immediate
    assert w.board.workers(a)[0]["revoked"] is True


def test_rogue_worker_cannot_store_a_nonconforming_result_as_success(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); r = own_worker(w, a, "rogue", run=False); R = remote(w, r["token"])
    j = w.board.submit_job(a, "p1", "x", agent_id="ag")["job_id"]; t = R.claim("rogue", "rogue", 5); R.begin(t["id"], t["fence"])
    with pytest.raises(StaleLease): R.complete(t["id"], t["fence"], {"status": "completed", "text": "trust me"})
    v = w.board.get_job(a, "p1", j); assert v["status"] == "failed" and "invalid_result" in v["error"] and "result" not in v
    j2 = w.board.submit_job(a, "p1", "x2", agent_id="ag")["job_id"]; t2 = R.claim("rogue", "rogue", 5); R.begin(t2["id"], t2["fence"])
    with pytest.raises(StaleLease): R.complete(t2["id"], t2["fence"], C.make_result("some-other-job", "completed", "done"))      # right shape, wrong job
    assert w.board.get_job(a, "p1", j2)["status"] == "failed"


def test_cancellation_reaches_a_running_job(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.platform_worker()
    j = w.board.submit_job(a, "p1", "[[long]]", agent_id="ag")["job_id"]
    wait_for(lambda: w.board.get_job(a, "p1", j)["status"] == "running", 10, what="running")
    n0 = len(w.model.seen); w.board.cancel_job(a, "p1", j)
    v = wait_for(lambda: (lambda x: x if x["status"] == "cancelled" else None)(w.board.get_job(a, "p1", j)), 15, what="cancelled")
    time.sleep(2.5); assert len(w.model.seen) <= n0 + 3, "the model kept being called long after cancel"          # stopped within ~a heartbeat, not after 8 turns
    assert [e["kind"] for e in w.board.job_events(a, "p1", j)][-1] == "cancelled"


def test_kill_dash_9_mid_job_reap_retry_and_stale_fence_rejected(w, tmp_path):
    a = w.org("acme"); w.agent(a, "p1", "ag"); r = own_worker(w, a, "victim", run=False)
    tf = tmp_path / "tok"; tf.write_text(r["token"]); env = {**os.environ, "ORDIVYR_GATEWAY_HOME": str(w.gwhome), "PYTHONPATH": os.getcwd()}
    victim = subprocess.Popen([sys.executable, "-m", "ordivyr.board.worker", "--url", w.url, "--token-file", str(tf), "--name", "victim", "--ws", str(tmp_path / "vws"), "--ttl", "2", "--slots", "1"], env=env, cwd=os.getcwd())
    try:
        j = w.board.submit_job(a, "p1", "[[slow]]", agent_id="ag")["job_id"]
        wait_for(lambda: w.board.get_job(a, "p1", j)["status"] == "running", 20, what="running in the victim process")
        tid = w.board.db.c().execute("SELECT tid FROM jobs WHERE job_id=?", (j,)).fetchone()[0]; dead_fence = w.board.store.get(tid)["fence"]
        os.kill(victim.pid, signal.SIGKILL); victim.wait(5)
        wait_for(lambda: w.board.get_job(a, "p1", j)["status"] == "queued", 20, what="lease expiry -> reaped back to queued")
        w.worker(r["token"], "survivor", slots=1, ttl=3.0)
        v = w.done(a, "p1", j, 30); assert v["status"] == "completed" and v["result"]["text"] == "recovered" and v["attempt"] == 2, v
        evs = [e["kind"] for e in w.board.job_events(a, "p1", j)]; assert "lease_expired" in evs and evs.count("commit") == 1
        with pytest.raises(StaleLease): remote(w, r["token"]).complete(tid, dead_fence, C.make_result(j, "completed", "done", "zombie write"))      # the dead worker's late commit
        assert w.board.get_job(a, "p1", j)["result"]["text"] == "recovered"
    finally:
        if victim.poll() is None: victim.kill()


# ----------------------------------------------------------------------------- raw wire attacks: keyword-only calls must not slip past the tenant check
def raw(url, token, m, a=(), k=None):
    import json, urllib.request, urllib.error
    req = urllib.request.Request(url, json.dumps({"m": m, "a": list(a), "k": k or {}}).encode(), {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read())


def test_keyword_only_wire_calls_cannot_reach_another_orgs_task(w):
    a = w.org("acme"); b = w.org("beta"); w.agent(a, "p1", "ag"); w.agent(b, "p1", "ag", permissions={"memory": "write", "delegate": ["ag"]})
    ra = own_worker(w, a, "wa", run=False); rb = own_worker(w, b, "wb", run=False)
    jb = w.board.submit_job(b, "p1", "victim", agent_id="ag")["job_id"]; w.board.memory(b, "p1", "put", "project", "secret", {"v": 1})
    tb = remote(w, rb["token"]).claim_many_wait("wb", "wb", 30, None, 1, wait_s=0)[0]; tid, fence = tb["id"], tb["fence"]; remote(w, rb["token"]).begin(tid, fence)
    before = (w.board.get_job(b, "p1", jb)["status"], len(w.board.list_jobs(b, "p1")), w.board.memory(b, "p1", "get", "project", "secret"))
    good = C.make_result(jb, "completed", "done", "x"); TK = ra["token"]
    attacks = [("heartbeat", {"tid": tid, "fence": fence, "ttl": 999}), ("heartbeat_many", {"leases": [[tid, fence]], "ttl": 999}), ("fail", {"tid": tid, "fence": fence, "reason": "x", "retry": False}),
               ("complete", {"tid": tid, "fence": fence, "result": good}), ("cancelled", {"tid": tid, "fence": fence}), ("hold", {"tid": tid, "fence": fence, "reason": "x"}), ("release", {"tid": tid, "fence": fence, "reason": "x"}),
               ("checkpoint", {"tid": tid, "fence": fence, "phase": "p", "data": {}}), ("board_memory", {"tid": tid, "fence": fence, "op": "get", "ns": "project", "key": "secret"}),
               ("board_memory", {"tid": tid, "fence": fence, "op": "put", "ns": "project", "key": "secret", "value": "pwn"}), ("board_delegate", {"tid": tid, "fence": fence, "req": {"agent": "ag", "prompt": "x"}}),
               ("board_children", {"tid": tid, "fence": fence}), ("heartbeat", {"fence": fence}), ("complete", {"result": good})]       # last two: no task named at all
    for m, k in attacks:
        s, body = raw(w.url, TK, m, k=k); assert s == 403, (m, s, body)
    for m, a in (("heartbeat", [tid, fence, 999]), ("fail", [tid, fence, "x", False]), ("board_memory", [tid, fence, "get", "project", "secret"])):      # positional spelling is refused too
        assert raw(w.url, TK, m, a=a)[0] == 403, m
    after = (w.board.get_job(b, "p1", jb)["status"], len(w.board.list_jobs(b, "p1")), w.board.memory(b, "p1", "get", "project", "secret"))
    assert after == before and after[0] == "running", (before, after)                                   # nothing about org beta's job, jobs or memory changed
    assert raw(w.url, rb["token"], "heartbeat", k={"tid": tid, "fence": fence, "ttl": 30})[1] == {"ok": "ok"}      # the legitimate owner's keyword call still works
    s, mem = raw(w.url, rb["token"], "board_memory", k={"tid": tid, "fence": fence, "op": "get", "ns": "project", "key": "secret"}); assert s == 200 and mem["ok"]["value"] == {"v": 1}      # ...and so does its own memory read


def test_base_coordinator_keyword_only_calls_and_empty_tenant_list(tmp_path):
    from ordivyr import durable as D
    from ordivyr.durable_net import Coordinator
    st = D.Store(tmp_path / "q.db"); ta = st.submit("k", {"x": 1}, tenant="a"); tb = st.submit("k", {"x": 2}, tenant="b")
    c = Coordinator(st, "admin-tok", principals={"wa": {"role": "worker", "tenants": ["a"]}, "wnone": {"role": "worker", "tenants": []}, "wany": {"role": "worker"}}).start()
    try:
        url = f"http://127.0.0.1:{c.port}"
        t = raw(url, "wany", "claim_many", a=["w"], k={"limit": 2})[1]["ok"]; assert len(t) == 2; fb = next(x["fence"] for x in t if x["id"] == tb)
        for m, k in (("heartbeat", {"tid": tb, "fence": fb, "ttl": 99}), ("fail", {"tid": tb, "fence": fb, "reason": "x", "retry": False}), ("heartbeat_many", {"leases": [[tb, fb]], "ttl": 99}), ("heartbeat", {"fence": fb})):
            assert raw(url, "wa", m, k=k)[0] == 403, m
        assert raw(url, "wa", "heartbeat", a=[tb, fb, 99])[0] == 403 and raw(url, "wa", "heartbeat_many", a=[[[tb, fb]], 99])[0] == 403
        assert st.get(tb)["state"] in ("claimed", "running") and st.get(tb)["failure"] is None
        st.submit("k", {"x": 3}, tenant="c")
        assert raw(url, "wnone", "claim", a=["w"])[1]["ok"] is None and raw(url, "wnone", "claim_many", a=["w"], k={"limit": 5})[1]["ok"] == []      # [] = serves nobody (previously: everybody)
    finally: c.stop()
