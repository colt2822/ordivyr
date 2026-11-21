import pytest
from ordivyr.tests.board_support import World, wait_for
from ordivyr.board import contract as C
from ordivyr.board.service import NotFound, Forbidden, Invalid, QuotaError, Conflict, Unavailable


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi there")]}, monkeypatch); yield x; x.close()


def test_job_runs_end_to_end_through_contract(w):
    a = w.org("acme"); w.agent(a, "p1", "greeter"); w.platform_worker()
    j = w.board.submit_job(a, "p1", "say hello [[hello]]", agent_id="greeter"); r = w.done(a, "p1", j["job_id"])
    assert r["status"] == "completed", r
    res = r["result"]; assert C.validate_result(res) == [] and res["text"] == "hi there" and res["stop"] == "done"
    assert res["usage"]["prompt_tokens"] == 11 and res["usage"]["completion_tokens"] == 7 and res["usage"]["turns"] == 1
    assert res["completion"]["model_said_done"] is True and res["completion"]["tests_passed"] is None
    assert r["spec"]["org"] == "acme" and r["spec"]["project"] == "p1" and "key" not in str(r["spec"]).lower().replace("keys", "")


# ----------------------------------------------------------------------------- tenant isolation
def two_orgs(w):
    a = w.org("acme", projects=("p1", "p2")); b = w.org("beta", projects=("p1",))
    for adm, proj in ((a, "p1"), (a, "p2"), (b, "p1")): w.agent(adm, proj, "ag", permissions={"memory": "write"})
    return a, b


def test_cross_org_and_cross_project_isolation_on_every_surface(w):
    a, b = two_orgs(w); w.platform_worker()
    ja = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]; w.done(a, "p1", ja)
    w.board.memory(a, "p1", "put", "project", "secret", {"v": 1}); w.board.create_schedule(a, "p1", "s", "[[hello]]", "ag", every="every 30 minutes")
    sid = w.board.schedules(a, "p1")[0]["id"]
    member_p2 = w.board.principal(w.board.issue_key(a, "member", project="p2", label="p2 only")["key"])
    for who, proj, why in ((b, "p1", "other org, same project name"), (member_p2, "p1", "same org, sibling project")):
        for call in (lambda: w.board.get_job(who, proj, ja), lambda: w.board.cancel_job(who, proj, ja), lambda: w.board.job_events(who, proj, ja),
                     lambda: w.board.memory(who, proj, "get", "project", "secret") if who is member_p2 else (_ for _ in ()).throw(NotFound()),
                     lambda: w.board.set_schedule(who, proj, sid, False)):
            with pytest.raises((NotFound, Forbidden)): call()
    assert w.board.list_jobs(b, "p1") == [] and w.board.get_job(a, "p1", ja)["status"] == "completed"
    assert w.board.memory(b, "p1", "get", "project", "secret")["found"] is False            # same names, different org: its own empty namespace
    with pytest.raises(NotFound): w.board.submit_job(b, "p2", "x", agent_id="ag")           # project p2 does not exist in org beta
    with pytest.raises(NotFound): w.board.submit_job(member_p2, "p1", "x", agent_id="ag")
    assert [j["project"] for j in w.board.list_jobs(a, "p1")] == ["p1"]
    # a job id from org A used inside org B's own project is simply unknown
    with pytest.raises(NotFound): w.board.get_job(b, "p1", ja)
    w.board.reconcile()
    assert w.board.usage(b)["total"] == {} and w.board.usage(a)["total"].get("jobs_completed") == 1


def test_roles_viewer_member_admin_platform(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.platform_worker()
    viewer = w.board.principal(w.board.issue_key(a, "viewer", "p1")["key"]); member = w.board.principal(w.board.issue_key(a, "member", "p1")["key"])
    with pytest.raises(Forbidden): w.board.submit_job(viewer, "p1", "x", agent_id="ag")
    with pytest.raises(Forbidden): w.board.define_agent(member, "p1", "evil", {"permissions": {"write": True}})      # members cannot mint capability
    with pytest.raises(Forbidden): w.board.issue_key(member, "admin")
    with pytest.raises(Forbidden): w.board.create_project(member, "p9")
    with pytest.raises(Forbidden): w.board.register_worker(member, "ordivyr", {"contract_version": "1.1", "engine": "ordivyr", "tools": [], "max_concurrency": 1})
    j = w.board.submit_job(member, "p1", "[[hello]]", agent_id="ag")["job_id"]; w.done(member, "p1", j); assert w.board.get_job(viewer, "p1", j)["status"] == "completed"
    with pytest.raises(Forbidden): w.board.cancel_job(viewer, "p1", j)
    with pytest.raises(Forbidden): w.board.get_job(w.platform, "p1", j)                      # the operator administers, it does not read customer data
    with pytest.raises(Forbidden): w.board.list_jobs(w.platform, "p1")
    with pytest.raises(Forbidden): w.board.create_org(a, "evil")
    assert w.board.principal("ordb_garbage") is None and w.board.principal("") is None
    assert w.board.get_job(a, 'p1', j)['status'] == 'completed'


def test_revoked_and_expired_keys_stop_working_immediately(w):
    a = w.org("acme"); k = w.board.issue_key(a, "member", "p1"); m = w.board.principal(k["key"]); assert m
    w.board.revoke_key(a, k["kid"]); assert w.board.principal(k["key"]) is None
    k2 = w.board.issue_key(a, "viewer", "p1", ttl_s=1); assert w.board.principal(k2["key"]); w.board.db.clock = lambda: __import__("time").time() + 5; assert w.board.principal(k2["key"]) is None
    other = w.org("beta")
    with pytest.raises(NotFound): w.board.revoke_key(other, k2["kid"])               # another org's admin cannot revoke it


# ----------------------------------------------------------------------------- runtime permission enforcement
def test_ungranted_tool_is_refused_at_runtime_not_just_in_the_prompt(w):
    w.model.scripts["sneaky"] = [("tool", "write_file", {"path": "pwned.txt", "content": "x"}), ("tool", "delegate", {"agent": "ag", "prompt": "x"}), ("tool", "memory_put", {"key": "k", "value": "v"}), ("say", "finished")]
    a = w.org("acme"); w.agent(a, "p1", "ag", tools=["read_file", "write_file"], permissions={"write": False}, system="You MAY write files and delegate."); w.platform_worker()
    r = w.done(a, "p1", w.board.submit_job(a, "p1", "go [[sneaky]]", agent_id="ag", workspace="shared")["job_id"])
    assert r["status"] == "completed" and r["result"]["text"] == "finished"
    root = w.tmp / "ws-plat" / "board" / "acme" / "p1" / "shared"; assert not (root / "pwned.txt").exists()          # capability gate beat the (permissive) prompt
    assert w.board.memory(a, "p1", "get", "project", "k")["found"] is False
    offered = {n for names in w.model.offered() for n in names}; assert "write_file" not in offered and "delegate" not in offered and "memory_put" not in offered
    assert r["result"]["completion"]["code_written"] is None
    assert w.board.list_jobs(a, "p1")[0]["status"] == "completed" and len(w.board.list_jobs(a, "p1")) == 1        # no hidden child job appeared


def test_granted_tools_work_and_workspace_stays_in_its_project(w):
    w.model.scripts["writer"] = [("tool", "write_file", {"path": "out.txt", "content": "hello"}), ("say", "wrote it")]
    a = w.org("acme", projects=("p1", "p2")); w.agent(a, "p1", "wr", permissions={"write": True}); w.agent(a, "p2", "wr", permissions={"write": True}); w.platform_worker()
    r1 = w.done(a, "p1", w.board.submit_job(a, "p1", "[[writer]]", agent_id="wr", workspace="shared")["job_id"]); r2 = w.done(a, "p2", w.board.submit_job(a, "p2", "[[writer]]", agent_id="wr", workspace="shared")["job_id"])
    assert r1["result"]["completion"]["code_written"] is True
    base = w.tmp / "ws-plat" / "board"; assert (base / "acme/p1/shared/out.txt").read_text() == "hello" and (base / "acme/p2/shared/out.txt").exists()      # same workspace NAME, separate directories
    with pytest.raises(Invalid): w.board.submit_job(a, "p1", "x", agent_id="wr", workspace="../p2/shared")
