import json, threading, time, urllib.request
from ordivyr import agentloop as AL, replay as RP, runner as RUN, durable_worker as DW


def test_spin_cycle_detects_alternation_not_progress():
    a, b = ("read", "x", 1), ("edit", "y", 2)
    assert AL._spin_cycle([a, b] * 3) and not AL._spin_cycle([a, b] * 2)
    assert not AL._spin_cycle([a, b, a, b, a, ("edit", "y", 3)])
    assert AL._spin_cycle([a, b, ("t", "z", 9)] * 3)


def test_manifest_hashes_everything_but_vcs_metadata(tmp_path):
    (tmp_path / "a.py").write_text("1"); (tmp_path / "node_modules").mkdir(); (tmp_path / "node_modules" / "x.js").write_text("2"); (tmp_path / ".git").mkdir(); (tmp_path / ".git" / "h").write_text("3"); (tmp_path / "pkg").mkdir(); (tmp_path / "pkg" / "b.py").write_text("4")
    assert sorted(DW.manifest(tmp_path)) == ["a.py", "node_modules/x.js", "pkg/b.py"]


def _board():
    from ordivyr import core
    b = core.new_board("T")
    for n in ("A", "B"): b["agents"].append(core.new_agent(0, 0, n, id=n.lower()))
    b["edges"].append({"id": "a-b", "from": "a", "to": "b", "kind": "delegate"}); return b


def test_replay_matches_recording_and_flags_changes(tmp_path):
    board = _board(); first = RUN.Runner(board, "m").run()
    res, diff = RP.replay(board, first); assert res["status"] == first["status"] and diff == []
    tampered = json.loads(json.dumps(first)); tampered["agents"]["a"]["status"] = "failed"; tampered["agents"]["a"]["output"] = "boom"
    res, diff = RP.replay(board, tampered); assert res["agents"]["a"]["status"] == "failed" and res["agents"]["b"]["status"] == "blocked"


def test_handoff_block_and_derived_and_caps():
    from ordivyr import handoff as HO
    h = HO.extract('done\n```handoff\n{"summary":"S","changed_files":["a.py"],"junk":1,"open_risks":"x"}\n```')
    assert h == {"summary": "S", "changed_files": ["a.py"], "artifacts": [], "open_risks": []}
    d = HO.extract("Edited src/app/main.py\nRisk: flaky net\n" + "x" * 5000)
    assert d["changed_files"] == ["src/app/main.py"] and d["open_risks"] == ["flaky net"] and len(d["summary"]) <= 2500


def test_provider_retries_transient_then_succeeds_and_fallback(monkeypatch):
    from ordivyr import providers as PV
    monkeypatch.setattr(PV, "_sleep", lambda s: None); calls = []
    def http(m, u, h, b, t): calls.append(u); return (529, b"{}") if len(calls) < 3 else (200, b'{"ok":1}')
    assert PV._call(http, "POST", "http://x/v1", {}, {}, 5) == {"ok": 1} and len(calls) == 3
    always = lambda m, u, h, b, t: (503, b"{}")
    try: PV._call(always, "POST", "http://x/v1", {}, {}, 5); assert False
    except PV.ProviderError: pass
    assert 0 <= PV.backoff_delay(3, rnd=lambda: 1.0) <= PV.BACKOFF_CAP and PV.backoff_delay(0, retry_after=2) == 2


def test_signed_webhooks_roundtrip_and_runner_emits():
    from ordivyr import webhooks_out as WO
    got = []; em = WO.Emitter("https://example.test/h", "s3cret", post=lambda u, b, h, t: (got.append((b, h)), 200)[1], background=False)
    r = RUN.Runner(_board(), "m", on_event=em).run(); assert r["status"] == "done" and len(got) == 2
    body, hd = got[0]; assert WO.verify("s3cret", body, hd) and not WO.verify("wrong", body, hd) and not WO.verify("s3cret", body + b"x", hd) and not WO.verify("s3cret", body, hd, now=0)
    for bad in (("http://evil.test/h", "k"), ("ftp://x/h", "k"), ("https://x/h", "")):
        try: WO.Emitter(*bad); assert False
        except ValueError: pass


def test_workspace_isolation_conflict_and_promotion(tmp_path):
    from ordivyr import workspace as W
    src = tmp_path / "src"; src.mkdir(); (src / "a.txt").write_text("a"); (src / "b.txt").write_text("b")
    w1, w2 = W.open_workspace(src, "n1", tmp_path), W.open_workspace(src, "n2", tmp_path)
    (w1.dir / "a.txt").write_text("a1"); (w1.dir / "new.txt").write_text("n"); (w2.dir / "a.txt").write_text("a2"); (w2.dir / "b.txt").write_text("b2")
    assert w1.promote() == {"added": ["new.txt"], "modified": ["a.txt"], "deleted": []} and (src / "a.txt").read_text() == "a1"
    try: w2.promote(); assert False
    except W.Conflict as c: assert c.files == ["a.txt"]
    assert (src / "b.txt").read_text() == "b"                       # refused as a whole: nothing from w2 landed
    w1.close(); w2.close()


def test_scopes_enforced_fail_closed():
    from ordivyr import scopes as S
    assert S.allowed("coder", "write_file") and not S.allowed("reviewer", "write_file") and not S.allowed("researcher", "run_command") and not S.allowed("mystery", "edit_file")
    call = S.guard("reviewer", lambda n, a: "ran"); assert call("read_file", {}) == "ran" and call("edit_file", {}).startswith("ERROR")


def test_toolbox_scope_blocks_write_even_when_write_enabled(tmp_path):
    box = AL.ToolBox(tmp_path, write=True, web=False, ask=False); box.scope = "reviewer"
    assert box.call("write_file", {"path": "x.txt", "content": "hi"}).startswith("ERROR") and not (tmp_path / "x.txt").exists()
    box.scope = "coder"; box.call("write_file", {"path": "x.txt", "content": "hi"}); assert (tmp_path / "x.txt").read_text() == "hi"


def test_scorecard_aggregates(tmp_path):
    from ordivyr import scorecard as SC
    r1 = RUN.Runner(_board(), "m").run(); r1["board_id"] = "bx"; r2 = json.loads(json.dumps(r1)); r2["status"] = "failed"; r2["agents"]["a"]["status"] = "failed"
    (tmp_path / "1.json").write_text(json.dumps(r1)); (tmp_path / "2.json").write_text(json.dumps(r2)); (tmp_path / "junk.json").write_text("{")
    c = SC.scorecard(SC.collect(tmp_path))["bx"]; assert c["runs"] == 2 and c["completion_rate"] == 0.5 and c["agent_failure_rate"] == 0.25


def test_workspace_git_worktree_mode_never_promotes_dot_git(tmp_path):
    import subprocess
    from ordivyr import workspace as W
    src = tmp_path / "repo"; src.mkdir(); (src / "a.txt").write_text("a")
    for c in (["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "i"]): subprocess.run(["git", "-C", str(src)] + c, check=True, capture_output=True)
    w = W.open_workspace(src, "n", tmp_path); assert w.mode == "worktree"; (w.dir / "b.txt").write_text("b")
    assert w.promote() == {"added": ["b.txt"], "modified": [], "deleted": []} and (src / "b.txt").exists() and (src / ".git").is_dir(); w.close()


def test_handoff_requested_only_from_agents_with_dependents():
    r = RUN.Runner(_board(), "m"); assert r._has_dependents("a") and not r._has_dependents("b")


def test_runner_passes_agent_scope_to_toolbox(tmp_path, monkeypatch):
    from ordivyr import core
    seen = []
    def fake_run(proto, base, key, model, system, prompt, box, **kw): seen.append(box.scope); return "ok", 1, "m", 1, "done"
    monkeypatch.setattr(AL, "run", fake_run)
    b = core.new_board("T"); ag = core.new_agent(0, 0, "R", id="r", model="acct.acct"); ag["scope"] = "reviewer"; b["agents"].append(ag)
    r = RUN.Runner(b, "m", accounts={"acct": {"protocol": "openai", "base": "http://127.0.0.1:1/v1", "key": "", "model": "m"}}, workdir=str(tmp_path))
    r._execute("r"); assert seen == ["reviewer"]


def test_replay_never_touches_real_memory():
    assert type(RP.ReplayRunner(_board(), "m", {"agents": {}}).mem).__name__ == "NullMemory"


def test_webhook_flush_and_slow_endpoint_does_not_block():
    from ordivyr import webhooks_out as WO
    gate = threading.Event(); em = WO.Emitter("https://example.test/h", "k", post=lambda u, b, h, t: (gate.wait(5), 200)[1])
    t0 = time.time(); em("completed", {}); assert time.time() - t0 < 0.5 and not em.flush(0.05); gate.set(); assert em.flush(5) and em.delivered == 1


def test_workspace_promote_never_deletes_gitignored_files(tmp_path):
    import subprocess
    from ordivyr import workspace as W
    src = tmp_path / "repo"; src.mkdir(); (src / "a.txt").write_text("a"); (src / ".gitignore").write_text("secret.env\n")
    for c in (["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "i"]): subprocess.run(["git", "-C", str(src)] + c, check=True, capture_output=True)
    (src / "secret.env").write_text("KEY=1"); w = W.open_workspace(src, "n", tmp_path); assert w.mode == "worktree"
    (w.dir / "b.txt").write_text("b"); w.promote(); assert (src / "secret.env").read_text() == "KEY=1" and (src / "b.txt").exists(); w.close()


def test_scope_field_passes_board_validation():
    from ordivyr import core
    b = _board(); b["agents"][0]["scope"] = "reviewer"; assert core.validate(b)["errors"] == []


def _scripted(calls):
    from ordivyr.tests.test_agentloop import seq_http, oa_call
    return seq_http([oa_call(n, a, cid=f"c{i}") for i, (n, a) in enumerate(calls)])


def test_loop_stops_on_alternating_calls(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    calls = [("read_file", {"path": "a.txt"}), ("list_files", {})] * 6
    box = AL.ToolBox(tmp_path, write=False, web=False, ask=False)
    text, tk, used, steps, stop = AL.run("openai", "http://127.0.0.1:1", "", "m", "s", "p", box, http=_scripted(calls), max_steps=20)
    assert stop == "repeat_failure" and "alternated" in text


def test_loop_stops_on_repeated_failures_to_one_path(tmp_path):
    calls = [("edit_file", {"path": "nope.txt", "old_string": f"o{i}", "new_string": "n"}) for i in range(10)]
    box = AL.ToolBox(tmp_path, write=True, web=False, ask=False)
    text, tk, used, steps, stop = AL.run("openai", "http://127.0.0.1:1", "", "m", "s", "p", box, http=_scripted(calls), max_steps=20)
    assert stop == "repeat_failure" and "nope.txt" in text and "varying arguments" in text


def test_server_retry_after_header_reaches_the_backoff_and_is_capped(monkeypatch):
    import json, threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from ordivyr import providers as PV
    plan = [(503, "3"), (529, "900"), (200, None)]
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            st, ra = plan.pop(0); out = json.dumps({"data": [{"id": "m"}]}).encode(); self.send_response(st)
            if ra: self.send_header("Retry-After", ra)
            self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    slept = []; monkeypatch.setattr(PV, "_sleep", slept.append)
    try: assert PV.list_models("openai", f"http://127.0.0.1:{srv.server_address[1]}/v1", "") == ["m"]
    finally: srv.shutdown(); srv.server_close()
    assert slept == [3.0, PV.BACKOFF_CAP]
    assert not hasattr(PV._with_retry_after(b"x", "Wed, 21 Oct 2026 07:28:00 GMT"), "retry_after") and not hasattr(PV._with_retry_after(b"x", "nan"), "retry_after")
