"""job_timings over a real delegation tree: the real Board + durable store, with the test acting as the worker (claim/delegate/transition calls are the production ones)."""
import pytest
from ordivyr.tests.board_support import World


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {}, monkeypatch); yield x; x.close()


def test_delegation_tree_with_validating_held_and_ticks(w):
    from ordivyr.board import runtime_adapter as RA
    b = w.board; adm = w.org("acme")
    b.register_worker(w.platform, "ordivyr", RA.capabilities(4, ("stub",), isolation="namespace"), platform=True)      # registered so jobs are admissible; no worker loop runs
    w.agent(adm, "p1", "lead", permissions={"delegate": ["kid"]}); w.agent(adm, "p1", "kid")
    root = b.submit_job(adm, "p1", "plan", agent_id="lead")["job_id"]
    t = b.store.claim("test", ttl=60); b.store.begin(t["id"], t["fence"])
    kids = [b.w_delegate(t["id"], t["fence"], {"agent": "kid", "prompt": f"part {i}"})["job_id"] for i in (1, 2)]
    b.store.record_output(t["id"], t["fence"], "delegate", {"agent": "kid"}, "ok")
    k1 = b.store.claim("test", ttl=60); b.store.begin(k1["id"], k1["fence"]); b.store.begin(k1["id"], k1["fence"], "validating"); b.store.complete(k1["id"], k1["fence"], {"text": "done"})
    k2 = b.store.claim("test", ttl=60); b.store.begin(k2["id"], k2["fence"]); b.store.hold(k2["id"], k2["fence"], "needs owner")
    tree = b.job_timings(adm, "p1", root); rows = {j["job_id"]: j for j in tree["jobs"]}
    assert tree["root"] == root and set(rows) == {root, *kids} and not tree["truncated"]
    assert tree["jobs"][0]["job_id"] == root and rows[root]["depth"] == 0 and rows[root]["parent"] is None
    assert all(rows[k]["depth"] == 1 and rows[k]["parent"] == root for k in kids)
    assert len(rows[root]["ticks"]) == 1 and rows[root]["segments"][-1]["open"]
    phases = {j: [s["phase"] for s in r["segments"]] for j, r in rows.items()}
    done = b.get_job(adm, "p1", kids[0])["status"], b.get_job(adm, "p1", kids[1])["status"]
    assert sorted(done) == ["completed", "held"]
    byst = {rows[k]["status"]: phases[k] for k in kids}
    assert byst["completed"] == ["queued", "running", "validating"] and byst["held"] == ["queued", "running", "held"]
    assert b.job_timings(adm, "p1", kids[1])["root"] == root and len(b.job_timings(adm, "p1", kids[1])["jobs"]) == 3          # asking from a child shows the same tree
    assert b.job_timings(adm, "p1", root, cap=2)["truncated"]
    assert b.store.approve(k2["id"], "retry"); k2 = b.store.claim("test", ttl=60); b.store.begin(k2["id"], k2["fence"]); b.store.complete(k2["id"], k2["fence"], {"text": "ok"})
    after = {j["job_id"]: [s["phase"] for s in j["segments"]] for j in b.job_timings(adm, "p1", root)["jobs"]}
    assert ["queued", "running", "held", "queued", "running"] in after.values()
