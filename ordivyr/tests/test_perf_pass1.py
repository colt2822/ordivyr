"""Performance Pass 1 regressions: turn vs tool-call accounting, malformed/truncated tool calls never run, output limits, fresh-vs-cached budget, read-only stays read-only."""
import json, os, tempfile, unittest
from pathlib import Path
from ordivyr import agentloop as AL
from ordivyr.selfhost import agents as AG
from ordivyr.selfhost.gateway import Reply
from ordivyr.tests.test_agentloop import seq_http, oa_text


def call(name, args, cid):
    return {"id": cid, "name": name, "arguments": args if isinstance(args, str) else json.dumps(args)}


class FakeGW:
    """Scripted Gateway.chat: each item is (text, [calls], finish)."""
    def __init__(self, script): self.script = list(script); self.seen = []
    def chat(self, aid, ep, md, msgs, tools=None, max_tokens=None, timeout=0):
        self.seen.append({"max_tokens": max_tokens, "tools": [t["function"]["name"] if "function" in t else t.get("name") for t in (tools or [])]})
        text, calls, finish = self.script.pop(0) if self.script else ("done", [], "stop")
        return Reply(text, calls, {"prompt_tokens": 100, "completion_tokens": 10}, 0.0, md, ep, 0.0, finish)


def agent(**kw):
    a = {"id": "a1", "endpoint": "ep", "model": "m", "system": "s", "permissions": {"write": True, "web": False, "terminal": "none"}, "tools": None}; a.update(kw); return a


class Turns(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp()); (self.d / "a.txt").write_text("hi")

    def test_multi_tool_turn_is_one_turn(self):
        gw = FakeGW([("", [call("read_file", {"path": "a.txt"}, f"c{i}") for i in range(5)], "tool_calls"), ("finished", [], "stop")])
        r = AG.run_agent(agent(max_steps=2), "go", self.d, gw)
        self.assertEqual((r["steps"], r["tool_calls"], r["stop"], r["text"]), (2, 5, "done", "finished"))

    def test_long_session_is_not_cut_at_old_ceiling(self):
        gw = FakeGW([("", [call("read_file", {"path": "a.txt"}, f"c{i}")], "tool_calls") for i in range(30)] + [("ok", [], "stop")])
        r = AG.run_agent(agent(), "go", self.d, gw)                       # no max_steps in config -> AL.MAX_STEPS (64), was 8
        self.assertEqual((r["stop"], r["steps"], r["tool_calls"]), ("done", 31, 30))

    def test_explicit_turn_limit_still_enforced(self):
        gw = FakeGW([("", [call("read_file", {"path": "a.txt"}, f"c{i}")], "tool_calls") for i in range(10)])
        r = AG.run_agent(agent(max_steps=3), "go", self.d, gw); self.assertEqual((r["stop"], r["steps"]), ("steps", 3))

    def test_tool_call_limit(self):
        gw = FakeGW([("", [call("read_file", {"path": "a.txt"}, f"c{i}") for i in range(4)], "tool_calls") for _ in range(5)])
        r = AG.run_agent(agent(max_tool_calls=6), "go", self.d, gw); self.assertEqual(r["stop"], "tool_calls"); self.assertEqual(r["tool_calls"], 6)

    def test_wall_clock_limit(self):
        t = [0.0]
        def clock(): t[0] += 100; return t[0]
        gw = FakeGW([("", [call("read_file", {"path": "a.txt"}, f"c{i}")], "tool_calls") for i in range(10)])
        r = AG.run_agent(agent(max_seconds=250), "go", self.d, gw, clock=clock); self.assertEqual(r["stop"], "time"); self.assertLess(r["steps"], 10)

    def test_spend_limit(self):
        class Paid(FakeGW):
            def chat(s, *a, **k): r = FakeGW.chat(s, *a, **k); r.cost_usd = 0.4; return r
        gw = Paid([("", [call("read_file", {"path": "a.txt"}, f"c{i}")], "tool_calls") for i in range(10)])
        r = AG.run_agent(agent(budget_usd=1.0), "go", self.d, gw); self.assertEqual((r["stop"], r["steps"]), ("budget", 3))


class Malformed(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp())

    def run_one(self, calls, finish="tool_calls", extra=None, **kw):
        gw = FakeGW([("", calls, finish)] + (extra or [("recovered", [], "stop")])); return AG.run_agent(agent(**kw), "go", self.d, gw), gw

    def test_invalid_json_never_executes(self):
        r, _ = self.run_one([call("write_file", '{"path": "x.txt", "content": "par', "c1")])
        self.assertFalse((self.d / "x.txt").exists()); self.assertEqual((r["tool_calls"], r["malformed_calls"], r["stop"]), (0, 1, "done"))

    def test_missing_required_param_never_executes(self):
        r, _ = self.run_one([call("write_file", {"path": "x.txt"}, "c1")]); self.assertFalse((self.d / "x.txt").exists()); self.assertEqual(r["malformed_calls"], 1)

    def test_non_object_arguments_never_execute(self):
        r, _ = self.run_one([call("write_file", "[1,2]", "c1")]); self.assertEqual((r["tool_calls"], r["malformed_calls"]), (0, 1))

    def test_length_truncated_complete_looking_call_never_executes(self):
        r, _ = self.run_one([call("write_file", {"path": "x.txt", "content": "whole"}, "c1")], finish="length")
        self.assertFalse((self.d / "x.txt").exists()); self.assertEqual((r["tool_calls"], r["truncated_turns"]), (0, 1))

    def test_valid_call_next_turn_runs_after_correction(self):
        r, _ = self.run_one([call("write_file", '{"path": "x', "c1")], extra=[("", [call("write_file", {"path": "x.txt", "content": "ok"}, "c2")], "tool_calls"), ("fin", [], "stop")])
        self.assertEqual((self.d / "x.txt").read_text(), "ok"); self.assertEqual((r["tool_calls"], r["malformed_calls"], r["stop"]), (1, 1, "done"))

    def test_identical_malformed_call_repeated_trips_breaker(self):
        bad = ("", [call("write_file", '{"path": "x', "c")], "tool_calls"); gw = FakeGW([bad] * 20)
        r = AG.run_agent(agent(), "go", self.d, gw); self.assertEqual(r["stop"], "malformed"); self.assertLessEqual(r["steps"], AL.MAX_SAME_BAD + 1)

    def test_varying_malformed_calls_trip_breaker_in_bounded_turns(self):
        gw = FakeGW([("", [call("write_file", '{"path": "x%d' % i, "c")], "tool_calls") for i in range(20)])
        r = AG.run_agent(agent(), "go", self.d, gw); self.assertEqual(r["stop"], "malformed"); self.assertLessEqual(r["steps"], AL.MAX_BAD_TURNS)

    def test_history_replay_contains_only_valid_json(self):
        gw = FakeGW([("", [call("write_file", '{"path": "x', "c1")], "tool_calls"), ("end", [], "stop")])
        seen = []
        orig = gw.chat
        def spy(aid, ep, md, msgs, **k): seen.append(json.loads(json.dumps(msgs))); return orig(aid, ep, md, msgs, **k)
        gw.chat = spy; AG.run_agent(agent(), "go", self.d, gw)
        for m in seen[-1]:
            for tc in m.get("tool_calls") or []: json.loads(tc["function"]["arguments"])


class Limits(unittest.TestCase):
    def test_output_limit_defaults_and_overrides(self):
        os.environ.pop("ORDIVYR_MAX_OUTPUT_TOKENS", None)
        self.assertEqual(AL.output_limit("some-model"), AL.DEFAULT_OUTPUT_TOKENS); self.assertEqual(AL.output_limit("some-model", 40000), 40000); self.assertEqual(AL.output_limit("m", 10), AL.MIN_OUTPUT_TOKENS)
        os.environ["ORDIVYR_MAX_OUTPUT_TOKENS"] = "32768"
        try: self.assertEqual(AL.output_limit("some-model"), 32768)
        finally: os.environ.pop("ORDIVYR_MAX_OUTPUT_TOKENS")

    def test_run_agent_requests_the_resolved_limit(self):
        d = Path(tempfile.mkdtemp()); gw = FakeGW([("hi", [], "stop")]); AG.run_agent(agent(max_output_tokens=20000), "go", d, gw); self.assertEqual(gw.seen[0]["max_tokens"], 20000)
        gw = FakeGW([("hi", [], "stop")]); AG.run_agent(agent(), "go", d, gw); self.assertEqual(gw.seen[0]["max_tokens"], AL.output_limit("m"))

    def test_new_agents_default_to_the_new_turn_ceiling(self):
        import inspect; self.assertEqual(inspect.signature(AG.AgentStore.create).parameters["max_steps"].default, AL.MAX_STEPS)


class ReadOnly(unittest.TestCase):
    def test_read_only_agent_has_no_write_tool_and_cannot_write(self):
        d = Path(tempfile.mkdtemp()); (d / "a.txt").write_text("hi")
        gw = FakeGW([("", [call("read_file", {"path": "a.txt"}, "c1"), call("write_file", {"path": "w.txt", "content": "x"}, "c2")], "tool_calls"), ("end", [], "stop")])
        r = AG.run_agent(agent(permissions={"write": False, "web": False, "terminal": "none"}), "go", d, gw)
        self.assertFalse((d / "w.txt").exists()); self.assertNotIn("write_file", gw.seen[0]["tools"]); self.assertIn("read_file", gw.seen[0]["tools"])


class Budget(unittest.TestCase):
    def box(self): return AL.ToolBox(Path(tempfile.mkdtemp()))

    def _replies(self, usage, n):
        out = []
        for i in range(n):
            out.append({"choices": [{"message": {"role": "assistant", "content": "", "tool_calls": [{"id": f"c{i}", "type": "function", "function": {"name": "list_files", "arguments": "{}"}}]}}], "usage": usage})
        return out + [oa_text("end")]

    def test_cached_input_is_not_charged_against_the_fresh_budget(self):
        u = {"prompt_tokens": 1000, "completion_tokens": 10, "prompt_tokens_details": {"cached_tokens": 900}}          # 110 fresh/turn
        text, tokens, _, steps, stop = AL.run("openai", "https://api.openai.com/v1", "k", "m", "s", "p", self.box(), http=seq_http(self._replies(u, 8)), token_budget=300)
        self.assertEqual(stop, "budget"); self.assertGreaterEqual(steps, 3)                                                  # uncached accounting would have stopped at turn 1
        u2 = {"prompt_tokens": 1000, "completion_tokens": 10}
        *_, steps2, stop2 = AL.run("openai", "https://api.openai.com/v1", "k", "m", "s", "p", self.box(), http=seq_http(self._replies(u2, 8)), token_budget=300)
        self.assertEqual(stop2, "budget"); self.assertLess(steps2, steps)                                                    # no cache telemetry -> full input is billable: stops sooner

    def test_budget_still_caps_without_cache(self):
        u = {"prompt_tokens": 500, "completion_tokens": 100}
        *_, steps, stop = AL.run("openai", "https://api.openai.com/v1", "k", "m", "s", "p", self.box(), http=seq_http(self._replies(u, 8)), token_budget=1000); self.assertEqual(stop, "budget"); self.assertLessEqual(steps, 3)


if __name__ == "__main__": unittest.main()
