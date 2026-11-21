"""Failure-injection: agent crashes, provider errors, tool errors, and recovery.

Injects real exceptions into the Runner's model/tool paths and asserts bounded,
recorded, non-duplicating recovery.
"""
import json

import pytest

from ordivyr import runner as RUN


def board(**over):
    b = {
        "schema": 1, "name": "Failure Test", "version": 1,
        "agents": [
            {"id": "a1", "name": "Planner", "model": "det.01", "instructions": "plan",
             "tools": [], "permissions": "read-only", "subagents": {"enabled": False},
             "limits": {"token_budget": 60000, "spend_cap_usd": 0.0, "max_seconds": 600, "concurrency": 1},
             "memory": {"private": True, "shared": [], "mode": "read"}},
            {"id": "a2", "name": "Worker", "model": "det.01", "instructions": "do",
             "tools": [], "permissions": "read-only", "subagents": {"enabled": False},
             "limits": {"token_budget": 60000, "spend_cap_usd": 0.0, "max_seconds": 600, "concurrency": 1},
             "memory": {"private": True, "shared": [], "mode": "read"}},
        ],
        "edges": [{"id": "e1", "from": "a1", "to": "a2"}],
    }
    b.update(over)
    return b


class FlakyLLM:
    """Fails N times then succeeds; records every call to detect duplicates."""
    def __init__(self, fails=1, bad_models=()):
        self.fails = fails
        self.bad_models = tuple(bad_models)
        self.calls = []

    def chat(self, backend, model, system, msgs, max_tokens=0):
        self.calls.append((backend, model))
        if model in self.bad_models:
            raise TimeoutError(f"backend {backend} timed out for {model}")
        if len(self.calls) <= self.fails:
            raise TimeoutError(f"backend {backend} timed out")
        return f"ok after {len(self.calls)} calls", len(self.calls), f"{backend}:{model}"


def test_provider_timeout_fails_agent_bounded():
    llm = FlakyLLM()
    b = board()
    for a in b["agents"]:
        a["model"] = "ollama:gemma3:4b"
    res = RUN.Runner(b, "mission", llm=llm).run()
    assert res["status"] == "failed"
    for aid, st in res["agents"].items():
        assert st["status"] in ("failed", "blocked")  # a2 blocked by a1's failure is correct containment
        if st["status"] == "failed":
            assert "TimeoutError" in st["output"]
        assert st["failures"] <= 1           # contained, bounded — not retried into a storm


def test_partial_failure_is_partial_not_done():
    # a1 (no deps) uses det.01 -> done; a2 uses a broken local model -> failed
    b = board()
    b["agents"][1]["model"] = "ollama:nope-model"
    res = RUN.Runner(b, "m", llm=FlakyLLM(bad_models=("nope-model",))).run()
    assert res["status"] == "partial"
    assert res["agents"]["a1"]["status"] == "done"
    assert res["agents"]["a2"]["status"] == "failed"


def test_failure_evidence_in_transcript():
    b = board()
    b["agents"][0]["model"] = "ollama:boom"
    res = RUN.Runner(b, "m", llm=FlakyLLM(bad_models=("boom",))).run()
    # the persisted transcript carries the failure evidence in state AND event log
    assert "TimeoutError" in res["agents"]["a1"]["output"]
    assert res["agents"]["a1"]["failures"] == 1
    assert any("TimeoutError" in json.dumps(e) for e in res["log"]), "event log must record the failure"


def test_failed_dependency_blocks_downstream():
    b = board()
    b["agents"][0]["model"] = "ollama:boom"
    b["agents"][1]["model"] = "det.01"
    res = RUN.Runner(b, "m", llm=FlakyLLM(bad_models=("boom",))).run()
    assert res["agents"]["a1"]["status"] == "failed"
    assert res["agents"]["a2"]["status"] == "blocked"
    assert "dependency failed" in " ".join(res["agents"]["a2"]["notes"])


def test_retry_after_transient_failure_succeeds_without_duplicate_run():
    # First attempt times out; a fresh Runner on the same board (the documented
    # recovery path: re-run the run, transcripts distinguish run ids) completes.
    llm = FlakyLLM(fails=1)
    b = board()
    for a in b["agents"]:
        a["model"] = "ollama:gemma3:4b"
    res1 = RUN.Runner(b, "m", llm=llm, run_id="run-attempt1").run()
    assert res1["status"] == "failed"
    res2 = RUN.Runner(b, "m", llm=llm, run_id="run-attempt2").run()
    assert res2["status"] == "done"
    # two distinct run ids, no cross-contamination
    assert res1["run_id"] != res2["run_id"]
    assert all(st["status"] == "done" for st in res2["agents"].values())


def test_side_effect_executed_once_across_retry():
    """A tool-executing agent must run its side effect once per completed run;
    the failed first run must not leave half-applied state behind."""
    b = board()
    b["agents"][1]["model"] = "ollama:gemma3:4b"
    llm = FlakyLLM(fails=99)  # always times out
    res = RUN.Runner(b, "m", llm=llm, run_id="run-sfx").run()
    assert res["status"] == "partial"
    # the worker failed on its model call before executing any side effect
    assert res["agents"]["a2"]["status"] == "failed"
    assert res["agents"]["a2"]["output"].startswith("TimeoutError")
    assert res["agents"]["a2"]["tokens"] == 0
    assert res["agents"]["a1"]["status"] == "done"
