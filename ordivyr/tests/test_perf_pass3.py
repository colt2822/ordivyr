"""Performance Pass 3: validator feedback into bounded recovery, repeated-failure circuit breaker, completion levels."""
import json, tempfile, unittest
from pathlib import Path
from ordivyr import agentloop as AL
from ordivyr.tests.test_agentloop import seq_http, oa_call, oa_text

URL = "https://x.test/v1"


def run(d, replies, seen=None, **kw):
    st = {}; r = AL.run("openai", URL, "k", "m", "s", "p", AL.ToolBox(d, write=True), seq_http(replies, seen), stats=st, **kw); return r, st


def write(path, content, cid="w"): return oa_call("write_file", {"path": path, "content": content}, cid)


def pytest_like(d):
    """A real validator: the file must define answer() == 42; the report is the exact failure text."""
    def v(box):
        try: ns = {}; exec(compile((d / "m.py").read_text(), "m.py", "exec"), ns); assert ns["answer"]() == 42, f"AssertionError: answer() returned {ns['answer']()} expected 42"; return True, ""
        except BaseException as e: return False, f"FAILED m.py::test_answer\n{type(e).__name__}: {e}"
    return v


class Recovery(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp())

    def test_exact_failure_reaches_the_model_and_repair_succeeds(self):
        seen = []; rep = [write("m.py", "def answer(): return 41\n"), oa_text("done"), write("m.py", "def answer(): return 42\n", "w2"), oa_text("fixed")]
        (text, _, _, steps, stop), st = run(self.d, rep, seen, validator=pytest_like(self.d))
        self.assertEqual((stop, text, st["repairs"]), ("done", "fixed", 1)); self.assertTrue(st["completion"]["tests_passed"] and st["completion"]["code_written"] and st["completion"]["syntax_ok"])
        fb = [m for m in seen[2]["messages"] if m["role"] == "user"][-1]["content"]; self.assertIn("answer() returned 41 expected 42", fb); self.assertIn("FAILED m.py::test_answer", fb)

    def test_same_failure_twice_trips_repeat_failure_not_a_loop(self):
        rep = [write("m.py", "def answer(): return 41\n"), oa_text("done"), oa_text("done again")] + [oa_text("x")] * 10
        (_, _, _, steps, stop), st = run(self.d, rep, validator=pytest_like(self.d), max_repairs=5); self.assertEqual(stop, "repeat_failure"); self.assertEqual(steps, 3)

    def test_repairs_are_bounded_and_end_unverified(self):
        rep = [write("m.py", "def answer(): return 1\n"), oa_text("a"), write("m.py", "def answer(): return 2\n", "w2"), oa_text("b"), write("m.py", "def answer(): return 3\n", "w3"), oa_text("c"), oa_text("d")]
        (_, _, _, steps, stop), st = run(self.d, rep, validator=pytest_like(self.d), max_repairs=2); self.assertEqual((stop, st["repairs"]), ("unverified", 2)); self.assertFalse(st["completion"]["tests_passed"])

    def test_no_validator_means_tests_unknown_not_passed(self):
        (_, _, _, _, stop), st = run(self.d, [write("m.py", "def answer(): return 1\n"), oa_text("done")]); c = st["completion"]
        self.assertEqual(stop, "done"); self.assertIsNone(c["tests_passed"]); self.assertIsNone(c["independent_review"]); self.assertTrue(c["model_said_done"] and c["code_written"])

    def test_syntax_level_is_distinct_from_tests(self):
        (_, _, _, _, stop), st = run(self.d, [write("m.py", "def answer(:\n"), oa_text("done")]); self.assertIs(st["completion"]["syntax_ok"], False)
        (_, _, _, _, _), st2 = run(Path(tempfile.mkdtemp()), [oa_text("just words")]); self.assertFalse(st2["completion"]["code_written"]); self.assertIsNone(st2["completion"]["syntax_ok"])

    def test_model_claiming_done_without_writing_is_visible(self):
        (_, _, _, _, stop), st = run(self.d, [oa_text("All done!")], validator=pytest_like(self.d), max_repairs=0); self.assertEqual(stop, "unverified"); self.assertFalse(st["completion"]["code_written"])

    def test_turn_limit_still_wins_over_repairs(self):
        rep = [oa_text("a"), oa_text("b"), oa_text("c")]; (_, _, _, steps, stop), st = run(self.d, rep, validator=lambda b: (False, "boom %d" % len(rep)), max_steps=1, max_repairs=5); self.assertEqual((stop, steps), ("steps", 1))


class Breaker(unittest.TestCase):
    def test_identical_failing_call_nudges_then_stops(self):
        d = Path(tempfile.mkdtemp()); seen = []; rep = [oa_call("edit_file", {"path": "nope.py", "old_string": "a", "new_string": "b"}, f"c{i}") for i in range(10)]
        (text, _, _, steps, stop), st = run(d, rep, seen); self.assertEqual(stop, "repeat_failure"); self.assertEqual(steps, AL.FAIL_STOP)
        third = json.dumps(seen[AL.FAIL_NUDGE]["messages"][-1]); self.assertIn("change your approach", third); self.assertNotIn("change your approach", json.dumps(seen[1]["messages"][-1]))

    def test_changing_the_call_resets_nothing_but_does_not_trip(self):
        d = Path(tempfile.mkdtemp()); rep = [oa_call("read_file", {"path": f"n{i}.txt"}, f"c{i}") for i in range(8)] + [oa_text("ok")]
        (_, _, _, steps, stop), st = run(d, rep); self.assertEqual(stop, "done")          # 8 different failing calls: each is new, not a loop

    def test_success_between_failures_is_not_counted_as_a_loop(self):
        d = Path(tempfile.mkdtemp()); (d / "a.txt").write_text("x"); rep = []
        for i in range(AL.FAIL_STOP): rep += [oa_call("read_file", {"path": "gone.txt"}, f"f{i}"), oa_call("read_file", {"path": "a.txt"}, f"s{i}")]
        (_, _, _, _, stop), _ = run(d, rep + [oa_text("ok")]); self.assertEqual(stop, "repeat_failure")          # counted per identical call across the run, not per consecutive run


class Signature(unittest.TestCase):
    def test_noise_is_normalised_but_movement_is_not(self):
        a = AL._failure_sig("FAILED t.py 0.12s at 0x7f12ab /tmp/pytest-1/x/ AssertionError: got 1"); b = AL._failure_sig("FAILED t.py 0.98s at 0x55aa00 /tmp/pytest-9/y/ AssertionError: got 1")
        self.assertEqual(a, b); self.assertNotEqual(a, AL._failure_sig("FAILED t.py 0.12s at 0x7f12ab /tmp/pytest-1/x/ AssertionError: got 2"))
