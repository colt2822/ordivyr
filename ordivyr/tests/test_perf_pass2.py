"""Performance Pass 2: prefix-stable history, Anthropic history cache breakpoints, surgical edit_file, paginated read_file, bounded search, head+tail retention with spill."""
import copy, json, os, tempfile, unittest
from pathlib import Path
from ordivyr import agentloop as AL, filetools as FT
from ordivyr.tests.test_agentloop import seq_http, oa_call, oa_text


def mk(files=None, write=True):
    d = Path(tempfile.mkdtemp())
    for k, v in (files or {}).items():
        p = d / k; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(v if isinstance(v, bytes) else v.encode())
    return d, AL.ToolBox(d, write=write)


class Read(unittest.TestCase):
    def test_numbered_and_paginated_with_notice(self):
        d, b = mk({"f.txt": "\n".join(f"line{i}" for i in range(1, 1001))})
        r = b.call("read_file", {"path": "f.txt"}); self.assertIn("     1\tline1", r); self.assertIn("   400\tline400", r); self.assertNotIn("line401", r)
        self.assertIn("showing lines 1-400 of 1000", r); self.assertIn("offset=401", r)
        r2 = b.call("read_file", {"path": "f.txt", "offset": 401, "limit": 10}); self.assertIn("   401\tline401", r2); self.assertIn("   410\tline410", r2); self.assertIn("offset=411", r2)
        r3 = b.call("read_file", {"path": "f.txt", "offset": 995}); self.assertIn("end of file", r3); self.assertIn("  1000\tline1000", r3)

    def test_errors_are_clear(self):
        d, b = mk({"f.txt": "a\nb", "bin.dat": b"\0\1\2"})
        self.assertIn("past the end", b.call("read_file", {"path": "f.txt", "offset": 9})); self.assertIn("binary", b.call("read_file", {"path": "bin.dat"}))
        self.assertTrue(b.call("read_file", {"path": "../x"}).startswith("ERROR")); self.assertIn("(empty file)", mk({"e": ""})[1].call("read_file", {"path": "e"}))

    def test_char_cap_cuts_at_a_line_boundary_and_says_where_to_continue(self):
        d, b = mk({"w.txt": "\n".join("x" * 1900 for _ in range(100))})
        r = b.call("read_file", {"path": "w.txt", "limit": 100}); self.assertLess(len(r), FT.READ_MAX_CHARS + 500); self.assertRegex(r, r"offset=\d+ to continue")

    def test_long_line_is_flagged(self):
        d, b = mk({"m.js": "y" * 5000}); self.assertIn("line cut at", b.call("read_file", {"path": "m.js"}))

    def test_symlink_not_followed(self):
        d, b = mk({"a": "1"}); out = Path(tempfile.mkdtemp()); (out / "s").write_text("SECRET"); os.symlink(out, d / "lnk")
        self.assertTrue(b.call("read_file", {"path": "lnk/s"}).startswith("ERROR")); self.assertTrue(b.call("grep", {"pattern": "SECRET"}).startswith("no matches"))


class Edit(unittest.TestCase):
    def e(self, b, **a): return b.call("edit_file", a)

    def test_unique_exact_replace_is_surgical(self):
        d, b = mk({"a.py": "def f():\n    return 1\n\ndef g():\n    return 2\n"}); r = self.e(b, path="a.py", old_string="    return 1\n", new_string="    return 11\n")
        self.assertTrue(r.startswith("edited a.py at line 2")); self.assertEqual((d / "a.py").read_text(), "def f():\n    return 11\n\ndef g():\n    return 2\n")

    def test_ambiguous_is_refused_with_line_numbers_and_file_untouched(self):
        d, b = mk({"a.py": "x = 1\ny = 1\nz = 1\n"}); before = (d / "a.py").read_bytes(); r = self.e(b, path="a.py", old_string="= 1", new_string="= 2")
        self.assertTrue(r.startswith("ERROR")); self.assertIn("matches 3 places", r); self.assertIn("1, 2, 3", r); self.assertEqual((d / "a.py").read_bytes(), before)
        self.assertIn("3 exact", self.e(b, path="a.py", old_string="= 1", new_string="= 2", replace_all=True)); self.assertEqual((d / "a.py").read_text(), "x = 2\ny = 2\nz = 2\n")

    def test_not_found_gives_hint_and_never_writes(self):
        d, b = mk({"a.py": "alpha = compute(1, 2)\n"}); r = self.e(b, path="a.py", old_string="alpha = compute(1, 3)", new_string="q")
        self.assertIn("not found", r); self.assertIn("Closest line is 1", r); self.assertEqual((d / "a.py").read_text(), "alpha = compute(1, 2)\n")

    def test_crlf_is_preserved(self):
        d, b = mk({"w.txt": b"one\r\ntwo\r\nthree\r\n"}); self.e(b, path="w.txt", old_string="two\nthree", new_string="2\n3\n4")
        self.assertEqual((d / "w.txt").read_bytes(), b"one\r\n2\r\n3\r\n4\r\n")

    def test_whitespace_tolerant_only_when_unique_and_reindents(self):
        d, b = mk({"a.py": "class A:\n    def f(self):\n        return 1\n"})
        r = self.e(b, path="a.py", old_string="def f(self):\n    return 1", new_string="def f(self):\n    return 2"); self.assertIn("whitespace-tolerant", r)
        self.assertEqual((d / "a.py").read_text(), "class A:\n    def f(self):\n        return 2\n")
        d2, b2 = mk({"a.py": "  v = 1\n    v = 1\n"}); r = self.e(b2, path="a.py", old_string="v   =  1", new_string="v = 2")           # two tolerant hits: ambiguous -> refuse
        self.assertTrue(r.startswith("ERROR")); self.assertEqual((d2 / "a.py").read_text(), "  v = 1\n    v = 1\n")

    def test_guards(self):
        d, b = mk({"a.txt": "x", ".git/config": "c"}); out = Path(tempfile.mkdtemp()); (out / "t").write_text("orig"); os.symlink(out, d / "lnk")
        for kw in (dict(path=".git/config", old_string="c", new_string="d"), dict(path="lnk/t", old_string="orig", new_string="pwn"), dict(path="../a", old_string="x", new_string="y"),
                   dict(path="a.txt", old_string="", new_string="y"), dict(path="a.txt", old_string="x", new_string="x"), dict(path="nope.txt", old_string="x", new_string="y")):
            self.assertTrue(self.e(b, **kw).startswith("ERROR"), kw)
        self.assertEqual((out / "t").read_text(), "orig"); self.assertEqual((d / ".git/config").read_text(), "c")

    def test_needs_write_grant_and_tool_is_not_even_offered_read_only(self):
        d, b = mk({"a.txt": "x"}, write=False); self.assertNotIn("edit_file", [x["name"] for x in b.defs]); self.assertTrue(self.e(b, path="a.txt", old_string="x", new_string="y").startswith("ERROR: not allowed"))
        self.assertEqual((d / "a.txt").read_text(), "x")

    def test_atomic_keeps_mode_and_leaves_no_temp(self):
        d, b = mk({"run.sh": "echo a\n"}); os.chmod(d / "run.sh", 0o755); self.e(b, path="run.sh", old_string="a", new_string="b")
        self.assertEqual(os.stat(d / "run.sh").st_mode & 0o777, 0o755); self.assertEqual([p.name for p in d.iterdir()], ["run.sh"])

    def test_write_failure_midway_keeps_original(self):
        d, b = mk({"a.txt": "keep"}); real = os.replace
        def boom(*a, **k): raise OSError("disk")
        os.replace = boom
        try: r = self.e(b, path="a.txt", old_string="keep", new_string="lost")
        finally: os.replace = real
        self.assertTrue(r.startswith("ERROR")); self.assertEqual((d / "a.txt").read_text(), "keep"); self.assertEqual([p.name for p in d.iterdir()], ["a.txt"])


class Search(unittest.TestCase):
    def test_grep_skips_noise_and_reports_location(self):
        d, b = mk({"src/a.py": "needle here\nother", "node_modules/x.js": "needle", ".git/c": "needle", "src/b.bin": b"needle\0", "src/c.py": "none"})
        r = b.call("grep", {"pattern": "needle"}); self.assertEqual(r, "src/a.py:1: needle here")
        self.assertIn("src/a.py:1", b.call("grep", {"pattern": "NEEDLE", "ignore_case": True, "glob": "*.py"})); self.assertTrue(b.call("grep", {"pattern": "needle", "glob": "*.js"}).startswith("no matches"))
        self.assertTrue(b.call("grep", {"pattern": "("}).startswith("no matches")); self.assertIn("bad regex", b.call("grep", {"pattern": "(", "regex": True}))          # literal by default

    def test_grep_is_bounded(self):
        d, b = mk({"big.txt": "hit\n" * 500}); r = b.call("grep", {"pattern": "hit"}); self.assertEqual(r.count("big.txt:"), FT.GREP_MAX_MATCHES); self.assertIn("stopped at", r)

    def test_find_files(self):
        d, b = mk({"a/x.py": "", "a/y.txt": "", "node_modules/z.py": "", "b.py": ""}); r = b.call("find_files", {"glob": "*.py"}).split("\n"); self.assertEqual(sorted(r), ["a/x.py", "b.py"])

    def test_read_only_and_parallel_safe(self):
        self.assertTrue({"grep", "find_files", "read_file"} <= AL.READ_ONLY)


class Retain(unittest.TestCase):
    def test_head_and_tail_kept_and_full_output_pageable(self):
        d, b = mk({"a": "x"}); big = "HEAD\n" + "\n".join(f"row{i}" for i in range(5000)) + "\nTAIL-ERROR: boom"
        out = FT.retain(b, big, AL.MAX_RESULT)
        self.assertLessEqual(len(out), AL.MAX_RESULT + 400); self.assertTrue(out.startswith("HEAD")); self.assertTrue(out.endswith("TAIL-ERROR: boom")); self.assertIn("spill:1", out)
        r = b.call("read_file", {"path": "spill:1", "offset": 3000, "limit": 3}); self.assertIn("row2998", r)
        self.assertTrue(b.call("read_file", {"path": "spill:9"}).startswith("ERROR")); self.assertTrue(b.call("read_file", {"path": "spill:../../etc/passwd"}).startswith("ERROR"))

    def test_spill_is_task_local_and_cleaned_up(self):
        d, b = mk({"a": "x"}); b.spill("data"); sd = b.spill_dir(); self.assertTrue(sd.exists()); self.assertEqual(oct(os.stat(sd).st_mode & 0o777), "0o700")
        d2, b2 = mk({"a": "x"}); self.assertTrue(b2.call("read_file", {"path": "spill:1"}).startswith("ERROR"))          # another box cannot see it
        import gc; del b; gc.collect(); self.assertFalse(sd.exists())

    def test_short_results_untouched(self):
        d, b = mk({"a": "x"}); self.assertEqual(FT.retain(b, "short", 100), "short"); self.assertIsNone(b._spill)


class History(unittest.TestCase):
    """The stored history is append-only below the compaction threshold: the bytes sent for turn N are a prefix of the bytes sent for turn N+1."""
    def script(self, n, size=900):
        d = Path(tempfile.mkdtemp())
        for i in range(n): (d / f"f{i}.txt").write_text(("line %d " % i) * size)
        return d, [oa_call("read_file", {"path": f"f{i}.txt"}, f"c{i}", tokens=10) for i in range(n)] + [oa_text("done")]

    def test_prefix_stable_below_threshold(self):
        d, replies = self.script(8); seen = []
        AL.run("openai", "https://x.test/v1", "k", "m", "s", "p", AL.ToolBox(d), seq_http(replies, seen))
        for a, b in zip(seen, seen[1:]):
            self.assertEqual(json.dumps(b["messages"][:len(a["messages"])], sort_keys=True), json.dumps(a["messages"], sort_keys=True))

    def test_compaction_only_under_pressure_once_and_with_checkpoint(self):
        d, replies = self.script(10)
        for r in replies[:-1]: r["usage"] = {"prompt_tokens": 60_000, "completion_tokens": 10}          # occupancy above the threshold from turn 1
        seen = []; st = {}
        AL.run("openai", "https://x.test/v1", "k", "m", "s", "p", AL.ToolBox(d), seq_http(replies, seen), stats=st)
        self.assertGreaterEqual(st["compactions"], 1); first_user = seen[-1]["messages"][1]["content"]; self.assertIn(AL.CKPT, first_user); self.assertIn("f0.txt", first_user); self.assertEqual(first_user.count(AL.CKPT), 1)
        self.assertIn("elided", json.dumps(seen[-1]["messages"][3]))
        d2, r2 = self.script(10); seen2 = []; st2 = {}
        AL.run("openai", "https://x.test/v1", "k", "m", "s", "p", AL.ToolBox(d2), seq_http(r2, seen2), stats=st2); self.assertEqual(st2["compactions"], 0)

    def test_prune_false_never_compacts(self):
        d, replies = self.script(6)
        for r in replies[:-1]: r["usage"] = {"prompt_tokens": 90_000, "completion_tokens": 1}
        st = {}; AL.run("openai", "https://x.test/v1", "k", "m", "s", "p", AL.ToolBox(d), seq_http(replies), prune=False, stats=st); self.assertEqual(st["compactions"], 0)

    def test_duplicate_result_pointer_after_compaction_gives_full_text_again(self):
        d = Path(tempfile.mkdtemp()); (d / "f.txt").write_text("z" * 3000); seen = []
        rep = [oa_call("read_file", {"path": "f.txt"}, f"c{i}") for i in range(7)] + [oa_text("ok")]
        for r in rep[:-1]: r["usage"] = {"prompt_tokens": 60_000, "completion_tokens": 1}
        AL.run("openai", "https://x.test/v1", "k", "m", "s", "p", AL.ToolBox(d), seq_http(rep, seen))
        self.assertIn(AL.DUP_STUB, json.dumps(seen[2]["messages"][-1]))          # first repeat: pointer, no compaction yet


class Breakpoints(unittest.TestCase):
    def test_anthropic_request_marks_history_but_stored_history_is_clean(self):
        msgs = [{"role": "user", "content": "go"}, {"role": "assistant", "content": [{"type": "tool_use", "id": "1", "name": "x", "input": {}}]}, {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "1", "content": "r"}]}]
        orig = copy.deepcopy(msgs); v = AL._with_breakpoints(msgs)
        self.assertEqual(msgs, orig); self.assertEqual(v[-1]["content"][-1]["cache_control"], {"type": "ephemeral"}); self.assertEqual(v[0]["content"][-1]["cache_control"], {"type": "ephemeral"}); self.assertNotIn("cache_control", json.dumps(v[1]))

    def test_marker_budget_never_exceeds_four_with_tools_and_system(self):
        seen = []; d = Path(tempfile.mkdtemp()); (d / "a").write_text("x")
        tu = lambda i: {"content": [{"type": "tool_use", "id": f"t{i}", "name": "read_file", "input": {"path": "a"}}], "usage": {"input_tokens": 4, "output_tokens": 2}}
        AL.run("anthropic", "https://api.anthropic.com", "k", "m", "sys", "go", AL.ToolBox(d), seq_http([tu(1), tu(2), tu(3), {"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 1, "output_tokens": 1}}], seen))
        for req in seen: self.assertLessEqual(json.dumps(req).count("cache_control"), 4)

    def test_non_anthropic_hosts_get_no_cache_control(self):
        seen = []; d = Path(tempfile.mkdtemp())
        AL.run("anthropic", "https://proxy.example.com", "k", "m", "sys", "go", AL.ToolBox(d), seq_http([{"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 1, "output_tokens": 1}}], seen)); self.assertNotIn("cache_control", json.dumps(seen[0]))

    def test_cache_accounting_split(self):
        seen = []; d = Path(tempfile.mkdtemp()); st = {}
        rep = [{"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 10, "cache_read_input_tokens": 900, "cache_creation_input_tokens": 50, "output_tokens": 5}}]
        AL.run("anthropic", "https://api.anthropic.com", "k", "m", "sys", "go", AL.ToolBox(d), seq_http(rep, seen), stats=st)
        self.assertEqual((st["input_tokens"], st["cached_input_tokens"], st["cache_write_tokens"], st["output_tokens"], st["context_tokens"]), (10, 900, 50, 5, 960)); self.assertEqual(st["billable_tokens"], 65)


class SavedAgents(unittest.TestCase):
    def test_allowlist_gains_refinements_only_of_tools_it_already_had(self):
        from ordivyr.selfhost import agents as AG
        from ordivyr.tests.test_perf_pass1 import FakeGW, agent
        d = Path(tempfile.mkdtemp())
        gw = FakeGW([("hi", [], "stop")]); AG.run_agent(agent(tools=["read_file", "write_file"]), "go", d, gw); self.assertEqual(set(gw.seen[0]["tools"]), {"read_file", "write_file", "edit_file", "grep", "find_files"})
        gw = FakeGW([("hi", [], "stop")]); AG.run_agent(agent(tools=["read_file"]), "go", d, gw); self.assertEqual(set(gw.seen[0]["tools"]), {"read_file", "grep", "find_files"})
        gw = FakeGW([("hi", [], "stop")]); AG.run_agent(agent(tools=["list_files"]), "go", d, gw); self.assertEqual(set(gw.seen[0]["tools"]), {"list_files"})


if __name__ == "__main__": unittest.main()
