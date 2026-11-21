import json, time, pytest
from ordivyr.tests.board_support import World, wait_for
from ordivyr.board import contract as C, runtime_adapter as RA, service as S
from ordivyr.board.coordinator import BoardRemote
from ordivyr.board.service import Board, NotFound, Forbidden, Invalid, QuotaError, Conflict, Unavailable
from ordivyr.durable import StaleLease


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi")]}, monkeypatch); yield x; x.close()


def lease(w, admin, jid, name="probe"):
    """Claim a job by hand as a (non-executing) worker so server-side rules can be probed deterministically. Returns (remote, tid, fence)."""
    if not hasattr(w, "_probe"):
        r = w.board.register_worker(admin, "ordivyr", RA.capabilities(1, ("stub",)), node=name); w._probe = BoardRemote(w.url, r["token"], timeout=5)
    R = w._probe; held = w.__dict__.setdefault("_held", {})                       # job_id -> (tid, fence) for every lease the probe took (a claim may return other queued jobs first)
    for t in R.claim_many_wait(name, name, 60, None, 50, wait_s=0): held[w.board.db.c().execute("SELECT job_id FROM jobs WHERE tid=?", (t["id"],)).fetchone()[0]] = (t["id"], t["fence"])
    tid, fence = held[jid]; R.begin(tid, fence); return R, tid, fence


# ----------------------------------------------------------------------------- delegation
def test_team_delegation_two_children_aggregated_end_to_end(w):
    w.model.scripts["lead"] = [("tool", "delegate", {"agent": "ana", "prompt": "[[hello]] part A"}), ("tool", "delegate", {"agent": "bob", "prompt": "[[hello]] part B"}),
                               ("tool", "child_results", {"wait_s": 30}), ("say", "aggregated")]
    a = w.org("acme"); w.agent(a, "p1", "ana"); w.agent(a, "p1", "bob"); w.agent(a, "p1", "lead", tools=["delegate", "child_results"]); w.board.define_team(a, "p1", "t", "lead", ["ana", "bob"]); w.platform_worker()
    jid = w.board.submit_job(a, "p1", "coordinate [[lead]]", agent_id="lead")["job_id"]; v = w.done(a, "p1", jid, 60)
    assert v["status"] == "completed" and v["ok"] and v["result"]["text"] == "aggregated", v
    kids = [w.board.get_job(a, "p1", k) for k in w.board.get_job(a, "p1", jid)["children"]]
    assert len(kids) == 2 and {k["agent"] for k in kids} == {"ana", "bob"} and all(k["status"] == "completed" and k["parent"] == jid and k["depth"] == 1 and k["root"] == jid for k in kids)
    tool_msgs = [m for m in w.model.seen[-1]["messages"] if m["role"] == "tool"]; cr = json.loads(tool_msgs[-1]["content"])       # what the lead's last model turn saw from child_results
    assert cr["all_done"] is True and sorted(c["text"] for c in cr["children"]) == ["hi", "hi"] and {c["status"] for c in cr["children"]} == {"completed"}
    w.board.reconcile(); u = w.board.usage(a)["total"]; assert u["jobs_completed"] == 3 and u["turns"] == 1 + 1 + 4         # lead made 4 model turns, each child 1


def test_delegation_server_side_rules(w, monkeypatch):
    monkeypatch.setitem(S.PLANS['free'], 'max_active', 50)      # the probe holds several leases at once; this test is about delegation rules, not the concurrency cap
    a = w.org("acme", plan="free", projects=("p1", "p2")); w.agent(a, "p2", "foreign"); w.agent(a, "p1", "kid"); w.agent(a, "p1", "kid_w", permissions={"write": True})
    w.agent(a, "p1", "any", permissions={"delegate": True}); w.agent(a, "p1", "lead", permissions={"delegate": ["kid"]}); w.agent(a, "p1", "nodel")
    w.platform_worker(slots=1); w.stops[-1].set(); time.sleep(0.8)                                      # keep the platform worker idle: we drive leases by hand
    j = w.board.submit_job(a, "p1", "x", agent_id="lead", limits={"budget_usd": 0.10})["job_id"]; R, tid, fence = lease(w, a, j)
    with pytest.raises(PermissionError, match="permission_denied"): R.board_delegate(tid, fence, {"agent": "kid_w", "prompt": "x"})        # not on the explicit list
    with pytest.raises(PermissionError, match="permission_denied"): R.board_delegate(tid, fence, {"agent": "foreign", "prompt": "x"})   # other project's agent is not on the list either
    c1 = R.board_delegate(tid, fence, {"agent": "kid", "prompt": "one", "limits": {"budget_usd": 0.10}}); assert R.board_delegate(tid, fence, {"agent": "kid", "prompt": "one", "limits": {"budget_usd": 0.10}})["job_id"] == c1["job_id"]   # re-delegation after a crash dedups
    ch = w.board.get_job(a, "p1", c1["job_id"]); assert ch["spec"]["org"] == "acme" and ch["spec"]["project"] == "p1" and ch["spec"]["parent"] == {"job_id": j, "depth": 1} and ch["spec"]["limits"]["budget_usd"] == pytest.approx(0.10)
    with pytest.raises(PermissionError, match="budget"): R.board_delegate(tid, fence, {"agent": "kid", "prompt": "two"})                  # the first child reserved the whole remaining budget
    with pytest.raises(StaleLease): R.board_delegate(tid, fence + 1, {"agent": "kid", "prompt": "x"})                                       # stale/forged fence cannot spawn work
    j2 = w.board.submit_job(a, "p1", "x", agent_id="nodel")["job_id"]; _, t2, f2 = lease(w, a, j2)
    with pytest.raises(PermissionError, match="tool_not_granted"): R.board_delegate(t2, f2, {"agent": "kid", "prompt": "x"})                 # agent without the delegate permission
    j3 = w.board.submit_job(a, "p1", "x", agent_id="any")["job_id"]; _, t3, f3 = lease(w, a, j3)
    with pytest.raises(PermissionError, match="not_found"): R.board_delegate(t3, f3, {"agent": "foreign", "prompt": "x"})                  # delegate=True still cannot reach an agent of another project


def test_fanout_depth_descendant_and_escalation_limits(w, monkeypatch):
    monkeypatch.setitem(S.PLANS['free'], 'max_active', 50)
    a = w.org("acme", plan="free"); w.agent(a, "p1", "d", permissions={"delegate": True}); w.agent(a, "p1", "leaf"); w.agent(a, "p1", "writer", permissions={"write": True})
    w.platform_worker(slots=1); w.stops[-1].set(); time.sleep(0.8)
    j = w.board.submit_job(a, "p1", "x", agent_id="d")["job_id"]; R, tid, fence = lease(w, a, j)
    with pytest.raises(PermissionError, match="escalate"): R.board_delegate(tid, fence, {"agent": "writer", "prompt": "w"})                 # delegate=True may not mint a stronger agent
    kids = [R.board_delegate(tid, fence, {"agent": "d" if i == 0 else "leaf", "prompt": f"k{i}"})["job_id"] for i in range(3)]               # free plan fan-out = 3
    with pytest.raises(PermissionError, match="quota_exceeded"): R.board_delegate(tid, fence, {"agent": "leaf", "prompt": "k4"})
    assert len(w.board.get_job(a, "p1", j)["children"]) == 3
    _, t1, f1 = lease(w, a, kids[0]); c2 = R.board_delegate(t1, f1, {"agent": "d", "prompt": "deeper"})["job_id"]                              # depth 2 = free-plan maximum
    assert w.board.get_job(a, "p1", c2)["depth"] == 2
    _, t2, f2 = lease(w, a, kids[1]); _, t3, f3 = lease(w, a, kids[2]); _, t4, f4 = lease(w, a, c2)
    with pytest.raises(PermissionError, match="depth"): R.board_delegate(t4, f4, {"agent": "leaf", "prompt": "too deep"})                  # depth 3 > plan limit 2


def test_unspecified_child_budget_is_an_equal_share_not_everything(w, monkeypatch):
    monkeypatch.setitem(S.PLANS['free'], 'max_active', 50)
    a = w.org("acme", plan="free"); w.agent(a, "p1", "lead", permissions={"delegate": True}); w.agent(a, "p1", "kid"); w.platform_worker(slots=1); w.stops[-1].set(); time.sleep(0.8)
    j = w.board.submit_job(a, "p1", "x", agent_id="lead", limits={"budget_usd": 0.90})["job_id"]; R, tid, fence = lease(w, a, j)
    got = [w.board.get_job(a, "p1", R.board_delegate(tid, fence, {"agent": "kid", "prompt": f"k{i}"})["job_id"])["spec"]["limits"]["budget_usd"] for i in range(3)]
    assert got == pytest.approx([0.30, 0.30, 0.30])                                                       # free plan fan-out 3: all three siblings fit
    with pytest.raises(PermissionError, match="fan-out"): R.board_delegate(tid, fence, {"agent": "kid", "prompt": "k3"})


def test_cancelling_a_parent_cancels_its_descendants(w):
    a = w.org("acme"); w.agent(a, "p1", "lead", permissions={"delegate": ["kid"]}); w.agent(a, "p1", "kid"); w.platform_worker(slots=1); w.stops[-1].set(); time.sleep(0.8)
    j = w.board.submit_job(a, "p1", "x", agent_id="lead")["job_id"]; R, tid, fence = lease(w, a, j); kid = R.board_delegate(tid, fence, {"agent": "kid", "prompt": "k"})["job_id"]
    assert w.board.cancel_job(a, "p1", j)["cancelled"] == 2
    assert w.board.get_job(a, "p1", kid)["status"] == "cancelled"
    w.board.reconcile(); assert w.board.get_job(a, "p1", kid)["status"] == "cancelled"


# ----------------------------------------------------------------------------- scheduler
def mk_sched(w, a, every="every 30 minutes"):
    w.agent(a, "p1", "ag"); w.platform_worker(); w.board.create_schedule(a, "p1", "nightly", "[[hello]]", "ag", every=every); return w.board.schedules(a, "p1")[0]


def test_timer_fires_once_per_window_and_catches_up_with_one_run(w):
    a = w.org("acme"); s = mk_sched(w, a); t0 = time.time()
    assert w.board.tick(t0 + 29 * 60) == [] and w.board.tick(t0 + 31 * 60) == [s["id"]] and w.board.tick(t0 + 31 * 60) == []
    assert len(w.board.list_jobs(a, "p1")) == 1
    assert w.board.tick(t0 + 31 * 60 + 5 * 3600) == [s["id"]] and len(w.board.list_jobs(a, "p1")) == 2          # machine was "off" for 5 h: ONE catch-up run, not ten
    assert w.board.tick(t0 + 31 * 60 + 5 * 3600 + 60) == []
    w.board.set_schedule(a, "p1", s["id"], False); assert w.board.tick(t0 + 99999) == []
    w.board.set_schedule(a, "p1", s["id"], True); w.board.pause_project(a, "p1"); assert w.board.tick(t0 + 99999) == []
    w.board.pause_project(a, "p1", False); w.board.kill(w.platform); assert w.board.tick(t0 + 99999) == []


def test_scheduler_restart_between_submit_and_bookkeeping_does_not_double_fire(w):
    a = w.org("acme"); s = mk_sched(w, a); t0 = time.time() + 31 * 60
    row = w.board.db.c().execute("SELECT * FROM schedules WHERE id=?", (s["id"],)).fetchone()
    w.board._fire(row, row["runs"] + 1, "crashed-scheduler", t0)                    # the process dies right here: task submitted, schedule row NOT advanced
    assert len(w.board.list_jobs(a, "p1")) == 1
    reborn = w.reborn()                           # a fresh Board process over the same files
    assert reborn.tick(t0) == [s["id"]]                                            # it still sees the window as owed...
    assert len(w.board.list_jobs(a, "p1")) == 1                                    # ...but the idempotency key makes the re-submit a no-op
    assert reborn.tick(t0) == [] and len(w.board.list_jobs(a, "p1")) == 1


def test_refused_fire_does_not_hot_loop_and_is_audited(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); r = w.board.register_worker(w.platform, "ordivyr", RA.capabilities(1, ("stub",), isolation="namespace"), platform=True)
    w.board.create_schedule(a, "p1", "n", "x", "ag", every="every 30 minutes"); w.board.drain_worker(w.platform, r["worker"]); t0 = time.time() + 31 * 60
    assert w.board.tick(t0) == [] and w.board.tick(t0 + 1) == []                   # no runtime -> refused, slot consumed
    assert any(x["action"] == "schedule.refused" for x in w.board.audit_export(a)["rows"])


def test_webhook_trigger(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.platform_worker(); h = w.board.create_schedule(a, "p1", "hook", "[[hello]]", "ag", webhook=True); _, sid, tok = h["hook_path"].rsplit("/", 2)
    for bad in (("nope", tok), (sid, "wrong")):
        with pytest.raises(NotFound): w.board.fire_hook(*bad)
    r = w.board.fire_hook(sid, tok); assert w.done(a, "p1", r["job_id"])["status"] == "completed"
    with pytest.raises(QuotaError): w.board.fire_hook(sid, tok)                                                  # cooldown
    assert w.board.fire_hook(sid, tok, idem="evt-1")["job_id"] == w.board.fire_hook(sid, tok, idem="evt-1")["job_id"]      # sender retry with the same event id = same job
    assert tok not in json.dumps(w.board.schedules(a, "p1")) and w.board.db.c().execute("SELECT hook_hash FROM schedules").fetchone()[0] != tok


# ----------------------------------------------------------------------------- metering, plans, quotas
def test_metering_is_exactly_once_even_with_concurrent_reconcilers(w):
    import threading
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.platform_worker(); ids = [w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"] for _ in range(3)]
    for i in ids: w.done(a, "p1", i)
    other = w.reborn(); ts = [threading.Thread(target=b.reconcile) for b in (w.board, other, w.board, other)]; [t.start() for t in ts]; [t.join() for t in ts]
    u = w.board.usage(a)["total"]; assert u["jobs_completed"] == 3 and u["prompt_tokens"] == 33 and u["completion_tokens"] == 21 and u["turns"] == 3
    w.board.reconcile(); assert w.board.usage(a)["total"] == u and w.board.db.c().execute("SELECT COUNT(*) FROM meter WHERE kind='jobs_completed'").fetchone()[0] == 3


def test_held_failed_and_cancelled_jobs(w):
    a = w.org("acme"); w.agent(a, "p1", "ghost", model_ref={"endpoint": "ghost", "model": "m"}); w.agent(a, "p1", "ag")
    w.board.register_worker(w.platform, "ordivyr", RA.capabilities(2, (), validators=False, isolation="namespace"), platform=True)                  # no endpoint restriction advertised
    r = w.board.register_worker(w.platform, "ordivyr", RA.capabilities(2, (), isolation="namespace"), platform=True); w.worker(r["token"], "open")
    h = w.done(a, "p1", w.board.submit_job(a, "p1", "x", agent_id="ghost")["job_id"]); assert h["status"] == "held" and "needs_owner" in h["error"]      # unknown endpoint on that node -> a human must act
    with pytest.raises(Forbidden): w.board.approve_job(w.board.principal(w.board.issue_key(a, "member", "p1")["key"]), "p1", h["job_id"])
    assert w.board.cancel_job(a, "p1", h["job_id"])["cancelled"] == 1 and w.board.get_job(a, "p1", h["job_id"])["status"] == "cancelled"
    h2 = w.done(a, "p1", w.board.submit_job(a, "p1", "again", agent_id="ghost")["job_id"]); assert h2["status"] == "held"
    w.stops[-1].set(); time.sleep(1.0)                                                                                           # worker stopped: an approved job stays queued where we can see it
    assert w.board.approve_job(a, "p1", h2["job_id"])["approved"] and w.board.get_job(a, "p1", h2["job_id"])["status"] == "queued"
    with pytest.raises(Conflict): w.board.approve_job(a, "p1", h2["job_id"])                                                      # no longer held
    w.board.reconcile(); u = w.board.usage(a)["total"]; assert u.get("jobs_cancelled") == 1 and "jobs_completed" not in u
    with pytest.raises(Forbidden): w.board.submit_job(w.board.principal(w.board.issue_key(a, "member", "p1")["key"]), "p1", "x", agent={"permissions": {"write": True}})      # members cannot smuggle capability in inline
    with pytest.raises(Forbidden): w.board.submit_job(w.board.principal(w.board.issue_key(a, "member", "p1")["key"]), "p1", "x", agent_id="ag", validators=[{"name": "t", "cmd": "true"}])
    w.board.revoke_worker(w.platform, r["worker"]); w.board.revoke_worker(w.platform, w.board.db.c().execute("SELECT id FROM workers WHERE revoked IS NULL").fetchone()[0])
    w.board.register_worker(w.platform, "ordivyr", RA.capabilities(2, (), validators=False, isolation="namespace"), platform=True)
    with pytest.raises(Unavailable): w.board.submit_job(a, "p1", "x", agent_id="ag", validators=[{"name": "t", "cmd": "true"}])          # the only runtime does not advertise validators: refused up front


def test_plan_quotas_and_idempotent_submit(w, monkeypatch):
    monkeypatch.setitem(S.PLANS["free"], "monthly_jobs", 2); monkeypatch.setitem(S.PLANS["free"], "max_projects", 2); monkeypatch.setitem(S.PLANS["free"], "max_queued", 2)
    a = w.org("acme", plan="free", projects=("p1",)); w.agent(a, "p1", "ag"); w.board.create_project(a, "p2")
    with pytest.raises(QuotaError): w.board.create_project(a, "p3")
    r = w.board.register_worker(w.platform, "ordivyr", RA.capabilities(1, ("stub",), isolation="namespace"), platform=True)                       # registered, never started: jobs stay queued
    j1 = w.board.submit_job(a, "p1", "x", agent_id="ag", idem_key="same")["job_id"]; assert w.board.submit_job(a, "p1", "x", agent_id="ag", idem_key="same")["job_id"] == j1
    w.board.submit_job(a, "p1", "y", agent_id="ag")
    with pytest.raises(QuotaError): w.board.submit_job(a, "p1", "z", agent_id="ag")                                         # monthly limit (2) or queue limit (2): refused, nothing orphaned
    assert len(w.board.list_jobs(a, "p1")) == 2 and w.board.db.c().execute("SELECT COUNT(*) FROM jobs WHERE tid IS NULL").fetchone()[0] == 0
    w.board.set_plan(w.platform, "acme", "team"); assert w.board.usage(a)["plan"] == "team" and w.board.usage(a)["limits"]["monthly_jobs"] == 20000


def test_project_budget_blocks_new_jobs(w):
    a = w.org("acme", projects=()); w.board.create_project(a, "p1", budget_usd=1.0); w.agent(a, "p1", "ag"); w.platform_worker(); w.stops[-1].set()
    j = w.board.submit_job(a, "p1", "x", agent_id="ag")["job_id"]
    with w.board.db.tx() as c: c.execute("INSERT INTO meter(ts,org,project,job_id,kind,qty) VALUES(?,?,?,?,?,?)", (time.time(), "acme", "p1", "j-old", "cost_usd", 1.5))
    with pytest.raises(QuotaError, match="budget"): w.board.submit_job(a, "p1", "y", agent_id="ag")
    assert w.board.usage(a)["total"]["cost_usd"] == 1.5


# ----------------------------------------------------------------------------- memory
def test_memory_scoping_private_per_agent_shared_per_project(w):
    w.model.scripts["m1"] = [("tool", "memory_put", {"ns": "agent", "key": "note", "value": "mine"}), ("tool", "memory_put", {"ns": "project", "key": "shared", "value": "for all"}), ("say", "ok")]
    w.model.scripts["m2"] = [("tool", "memory_get", {"ns": "agent", "key": "note"}), ("tool", "memory_get", {"ns": "project", "key": "shared"}), ("tool", "memory_put", {"ns": "project", "key": "x", "value": 1}), ("say", "ok")]
    a = w.org("acme", projects=("p1", "p2")); w.agent(a, "p1", "w1", permissions={"memory": "write"}); w.agent(a, "p1", "r2", permissions={"memory": "read"}); w.platform_worker()
    w.done(a, "p1", w.board.submit_job(a, "p1", "[[m1]]", agent_id="w1")["job_id"]); w.done(a, "p1", w.board.submit_job(a, "p1", "[[m2]]", agent_id="r2")["job_id"])
    assert w.board.memory(a, "p1", "get", "agent:w1", "note")["value"] == "mine" and w.board.memory(a, "p1", "get", "project", "shared")["value"] == "for all"
    log = json.dumps(w.model.seen[-1]["messages"]); assert '\\"found\\": false' in log or '"found": false' in log                      # r2 reading ITS private namespace sees nothing of w1's
    assert w.board.memory(a, "p1", "get", "project", "x")["found"] is False                                                           # read-only agent's write was refused
    assert w.board.memory(a, "p2", "get", "project", "shared")["found"] is False                                                      # other project: separate


def test_memory_limits_and_namespace_forgery(w):
    a = w.org("acme"); w.agent(a, "p1", "w1", permissions={"memory": "write"}); w.platform_worker(slots=1); w.stops[-1].set(); time.sleep(0.8)
    j = w.board.submit_job(a, "p1", "x", agent_id="w1")["job_id"]; R, tid, fence = lease(w, a, j)
    with pytest.raises(PermissionError): R.board_memory(tid, fence, "get", "agent:someone-else", "note")                               # a runtime cannot name another agent's namespace
    with pytest.raises(PermissionError, match="invalid"): R.board_memory(tid, fence, "put", "project", "k", "x" * (S.MEM_MAX_VALUE + 1))
    with pytest.raises(PermissionError, match="invalid"): R.board_memory(tid, fence, "put", "project", "../etc", "x")
    assert R.board_memory(tid, fence, "put", "agent", "k", {"a": [1, 2]}) == {"ok": True} and R.board_memory(tid, fence, "list", "agent")["keys"] == ["k"]


# ----------------------------------------------------------------------------- audit and controls
def test_audit_chain_detects_tampering_and_is_org_scoped(w):
    a = w.org("acme"); b = w.org("beta"); w.agent(a, "p1", "ag"); w.platform_worker(); w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag"); w.board.pause_project(a, "p1")
    ex = w.board.audit_export(a); assert ex["chain_ok"] and {"project.create", "agent.define", "job.submit", "project.pause", "key.issue"} <= {r["action"] for r in ex["rows"]}
    assert all(r["org"] == "acme" for r in ex["rows"]) and all(r["org"] == "beta" for r in w.board.audit_export(b)["rows"])
    assert any(r["action"] == "org.create" for r in w.board.audit_export(w.platform)["rows"])
    with pytest.raises(Forbidden): w.board.audit_export(w.board.principal(w.board.issue_key(a, "viewer")["key"]))
    mid = ex["rows"][2]["id"]
    with w.board.db.tx() as c: c.execute("UPDATE audit SET action='nothing.to.see' WHERE id=?", (mid,))
    ok, bad = w.board.db.verify_audit(); assert not ok and bad == mid
    with w.board.db.tx() as c: c.execute("UPDATE audit SET action='x' WHERE id=?", (mid,))


def test_paused_project_and_suspended_org(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.platform_worker(); key = w.board.issue_key(a, "member", "p1")["key"]; w.board.pause_project(a, "p1")
    with pytest.raises(Conflict): w.board.submit_job(a, "p1", "x", agent_id="ag")
    w.board.pause_project(a, "p1", False); j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]; w.done(a, "p1", j)
    assert w.board.principal(key) is not None
    w.board.set_org_status(w.platform, "acme", "suspended")
    assert w.board.principal(key) is None and w.board.principal(w.board.db.c().execute("SELECT 1").fetchone() and "ordb_x") is None          # every key of a suspended org stops working
    w.board.set_org_status(w.platform, "acme", "active"); assert w.board.principal(key) is not None
