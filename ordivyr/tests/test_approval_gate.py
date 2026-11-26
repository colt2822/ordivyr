"""permissions.approve: the Board parks a job before a chosen tool call until an org admin decides. Real Board, coordinator and workers (in-process AND sandboxed); the model is scripted."""
import pytest
from ordivyr.tests.board_support import World, wait_for
from ordivyr.board import runtime_adapter as RA, sandbox as SB, gate as G
from ordivyr.board.errors import Invalid, Unavailable

A = ("tool", "write_file", {"path": "a.txt", "content": "A"})
B = ("tool", "write_file", {"path": "b.txt", "content": "B"})
C = ("tool", "write_file", {"path": "c.txt", "content": "C"})


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"one": [A, ("say", "end")], "two": [A, B, ("say", "end")], "three": [A, B, C, ("say", "end")]}, monkeypatch); yield x; x.close()


@pytest.fixture(params=["inprocess", "sandbox"])
def ready(request, w):
    adm = w.org("acme")
    w.agent(adm, "p1", "ag", permissions={"write": True, "approve": ["write_file"]})
    if request.param == "sandbox":
        if not SB.available(): pytest.skip("bwrap unavailable")
        w.platform_worker()
    else:
        r = w.board.register_worker(adm, "ordivyr", RA.capabilities(2, ("stub",))); w.worker(r["token"], "cust")
    return w, adm


def start(w, adm, script):
    return w.board.submit_job(adm, "p1", f"go [[{script}]]", agent_id="ag", workspace="ws1")["job_id"]


def files(w): return sorted(p.name for p in w.tmp.glob("ws-*/**/*.txt"))


def tool_results(w): return [m["content"] for m in w.model.seen[-1]["messages"] if m["role"] == "tool"]


def test_held_before_the_call_then_retry_runs_it(ready):
    w, adm = ready; j = start(w, adm, "one"); v = w.done(adm, "p1", j)
    assert v["status"] == "held" and "approval required for write_file" in v["error"] and "a.txt" in v["error"] and files(w) == []
    w.board.approve_job(adm, "p1", j, "retry"); v = w.done(adm, "p1", j)
    assert v["status"] == "completed", v
    assert files(w) == ["a.txt"] and tool_results(w) == ["wrote 1 characters to a.txt"]


def test_skip_refuses_the_call_and_the_job_finishes(ready):
    w, adm = ready; j = start(w, adm, "one"); assert w.done(adm, "p1", j)["status"] == "held"
    w.board.approve_job(adm, "p1", j, "skip"); v = w.done(adm, "p1", j)
    assert v["status"] == "completed", v
    assert files(w) == [] and "declined" in tool_results(w)[0]


def test_two_distinct_calls_need_exactly_two_approvals(ready):
    w, adm = ready; j = start(w, adm, "two"); assert "a.txt" in w.done(adm, "p1", j)["error"]
    w.board.approve_job(adm, "p1", j, "retry")
    v = wait_for(lambda: (lambda v: v if v["status"] == "completed" or (v["status"] == "held" and "b.txt" in v.get("error", "")) else None)(w.board.get_job(adm, "p1", j)), 30)
    assert v["status"] == "held" and files(w) == ["a.txt"]
    w.board.approve_job(adm, "p1", j, "retry"); v = w.done(adm, "p1", j)
    assert v["status"] == "completed", v
    assert files(w) == ["a.txt", "b.txt"]


def test_three_gated_calls_finish_even_past_the_attempt_budget(ready):
    w, adm = ready; j = start(w, adm, "three")
    for name in ("a.txt", "b.txt", "c.txt"):
        wait_for(lambda: (lambda v: v["status"] == "held" and name in v.get("error", ""))(w.board.get_job(adm, "p1", j)), 30, what=name); w.board.approve_job(adm, "p1", j, "retry")
    v = w.done(adm, "p1", j)
    assert v["status"] == "completed" and v["attempt"] == 4 and files(w) == ["a.txt", "b.txt", "c.txt"], v


def test_approval_survives_a_validation_retry(w):
    adm = w.org("acme"); w.agent(adm, "p1", "ag", permissions={"write": True, "approve": ["write_file"]})
    r = w.board.register_worker(adm, "ordivyr", RA.capabilities(2, ("stub",))); w.worker(r["token"], "cust")
    j = w.board.submit_job(adm, "p1", "go [[one]]", agent_id="ag", workspace="ws1", validators=[{"name": "no", "cmd": ["false"]}])["job_id"]
    assert w.done(adm, "p1", j)["status"] == "held"; w.board.approve_job(adm, "p1", j, "retry")
    v = wait_for(lambda: (lambda v: v if v["status"] == "failed" or (v["status"] == "held" and v["attempt"] > 1) else None)(w.board.get_job(adm, "p1", j)), 30)
    assert v["status"] == "failed" and "validation" in v["error"] and v["attempt"] == 3, v


def test_workers_without_the_gate_can_neither_admit_nor_claim_gated_jobs(w):
    adm = w.org("acme"); w.agent(adm, "p1", "ag", permissions={"write": True, "approve": ["write_file"]})
    old = RA.capabilities(2, ("stub",)); old["features"] = [f for f in old["features"] if f != G.FEATURE]
    o = w.board.register_worker(adm, "ordivyr", old)
    with pytest.raises(Unavailable): w.board.submit_job(adm, "p1", "x", agent_id="ag")
    n = w.board.register_worker(adm, "ordivyr", RA.capabilities(2, ("stub",)))
    j = w.board.submit_job(adm, "p1", "x", agent_id="ag")["job_id"]
    claim = lambda r: w.coord.scope(w.board.worker_principal(r["token"]), "claim", ["x"], {"kinds": ["board.ordivyr.gated"]})[2]["kinds"]
    assert claim(o) == ["board.ordivyr"] and claim(n) == ["board.ordivyr", "board.ordivyr.gated"]                   # what the worker asks for is ignored
    assert w.board.store.claim("old", kinds=claim(o)) is None and w.board.store.claim("new", kinds=claim(n))["payload"]["job_id"] == j


def test_gate_definition_rules(w):
    adm = w.org("acme")
    for perms, eng in (({"approve": ["read_file"]}, "ordivyr"), ({"approve": "write_file"}, "ordivyr"), ({"approve": ["write_file"]}, "lite")):
        with pytest.raises(Invalid): w.board.define_agent(adm, "p1", "bad", {"permissions": perms, "engine": eng})
    gated = {"agent": {"permissions": {"approve": ["edit_file"]}}}
    assert G.gated(gated) == {"edit_file", "write_file"}
    assert w.board._escalates({"write": True, "delegate": True, "approve": ["write_file"]}, {"write": True})
    assert not w.board._escalates({"write": True, "approve": ["write_file"]}, {"write": True, "approve": ["write_file"]})
    assert "approval_gate" not in RA.capabilities(1, engine="lite")["features"]


def test_an_approval_only_answers_the_call_that_was_pending():
    job = {"agent": {"permissions": {"write": True, "approve": ["write_file"]}}}; saved = []
    stale = {"pending": {"digest": "d", "attempt": 2}, "owner_approval": {"attempt": 1, "resolution": "retry"}}
    assert G.Gate(job, stale, 3, saved.append).decided == {} and saved == []
    with pytest.raises(Exception, match="approval required"): G.Gate(job, None, 1, saved.append).check("write_file", {"path": "a"})
    assert G.Gate(job, None, 1, saved.append).check("read_file", {}) is None
