"""The live job stream must follow a job that has no queue task yet when the stream opens (it used to keep the row it read first, and emitted no events or steps)."""
import pytest
from ordivyr.tests.board_support import World


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi")]}, monkeypatch); yield x; x.close()


def test_stream_picks_up_a_task_dispatched_after_it_opened(w):
    a = w.org("acme"); w.agent(a, "p1", "ag")
    from ordivyr.board import runtime_adapter as RA
    reg = w.board.register_worker(w.platform, "ordivyr", RA.capabilities(4, ("stub",), isolation="namespace"), platform=True)      # registered, not started yet
    j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]
    tid = w.board.db.c().execute("SELECT tid FROM jobs WHERE job_id=?", (j,)).fetchone()[0]
    with w.board.db.tx() as c: c.execute("UPDATE jobs SET tid=NULL WHERE job_id=?", (j,))      # as if the queue had not accepted it yet
    seen = []

    def emit(kind, data):
        seen.append(kind)
        if seen == ["status"]:                                                                  # stream is open: now dispatch and run it
            with w.board.db.tx() as c: c.execute("UPDATE jobs SET tid=? WHERE job_id=?", (tid, j))
            w.worker(reg["token"], "plat", "ordivyr", 4, sandbox=True)

    end = w.board.job_stream(a, "p1", j, emit, poll=0.1, max_s=30)
    assert end and end["status"] == "completed" and "event" in seen and seen[-1] == "end", seen
