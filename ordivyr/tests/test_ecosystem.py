import json, os, shutil, subprocess, sys, tarfile, zipfile, hashlib
from pathlib import Path
import pytest
from ordivyr import core, license as L, runner as RUN, llm as LLM, hw as HW
from ordivyr.ecosystem import manifest as MF, store as ST, sandbox as SB, host as HO, importers as IM, discover as DI
from ordivyr.ecosystem.adapters import AdapterError, mcp as AMCP, a2a as AA2A, n8n as AN8N, langgraph as ALG, skills as ASK, native as ANAT
from stubs import Stub

import pwd
FIX = Path(__file__).parent / "fixtures"
REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)      # tests run with HOME isolated; this one read-only test looks at the real skills tree


def man(pid="demo", rt="declarative", entry=None, perms=(), **kw):
    return {"schema": MF.SCHEMA, "id": pid, "version": "1.0.0", "runtime": rt, "entry": entry if entry is not None else {}, "permissions": list(perms), **kw}


@pytest.fixture
def store(tmp_path): return ST.PluginStore(tmp_path / "home")


@pytest.fixture
def stub():
    s = Stub(); yield s; s.close()


def mcp_plugin(store, perms=("exec:" + sys.executable, "net:local"), enable=True, grants=True):
    d = store.home / "src-mcp"; shutil.rmtree(d, ignore_errors=True); d.mkdir(parents=True); shutil.copy(FIX / "mcp_echo.py", d / "mcp_echo.py")
    (d / MF.MANIFEST).write_text(json.dumps(man("echo", "mcp", {"transport": "stdio", "command": sys.executable, "args": ["mcp_echo.py"]}, [p for p in perms if p != "net:local"])))
    store.install(d, force=True)
    if grants: store.grant("echo", [p for p in perms if p != "net:local"])
    if enable: store.enable("echo")


# ------------------------------------------------------------------ manifest
def test_manifest_accepts_valid_and_rejects_bad():
    m = MF.clean(man("ok-1", "mcp", {"transport": "http", "url": "https://x.example/mcp"}, ["net:x.example", "env:API_TOKEN", "tool.write"]))
    assert m["permissions"] == ["env:API_TOKEN", "net:x.example", "tool.write"] and m["origin"] == "ordivyr"
    for bad, msg in ((man("Bad Id"), "id"), (man("a-b", version=None) | {"version": "x"}, "version"), (man("a-b", "wasm"), "runtime"), (man("a-b", perms=["root:all"]), "unknown permission"),
                     (man("a-b", perms=["net"]), "needs an argument"), (man("a-b", perms=["fs.write:relative/path"]), "absolute"), (man("a-b", perms=["fs.read:/a/../etc"]), "absolute"),
                     (man("a-b", perms=["tool.write:x"]), "no argument"), (man("a-b", "mcp", {"transport": "http", "url": "http://evil.example/x"}), "https"),
                     (man("a-b", "mcp", {"transport": "http", "url": "https://u:p@x.example"}), "credentials"), (man("a-b", "mcp", {"transport": "stdio", "command": "sh -c x"}), "command"),
                     (man("a-b", description="key sk-abcdefghijklmnopqrstuvwxyz"), "secret"), ({"schema": "nope"}, "not an ORDIVYR plugin")):
        with pytest.raises(MF.ManifestError) as e: MF.clean(bad)
        assert msg in str(e.value), (bad, e.value)


# ------------------------------------------------------------------ store
def write_plugin(root, m, files=None):
    root.mkdir(parents=True, exist_ok=True); (root / MF.MANIFEST).write_text(json.dumps(m))
    for k, v in (files or {}).items(): (root / k).parent.mkdir(parents=True, exist_ok=True); (root / k).write_text(v)
    return root


def test_install_is_inert_and_grants_are_bounded_by_the_manifest(store, tmp_path):
    marker = tmp_path / "ran"
    src = write_plugin(tmp_path / "p", man("nat", "native", {"module": "main.py"}, ["env:FOO"]), {"main.py": f"open({str(marker)!r},'w').write('x')\ndef register(api): pass\n"})
    m = store.install(src)
    assert not marker.exists(), "installing must never execute plugin code"
    s = store.list()[0]; assert s["enabled"] is False and s["pending"] == ["env:FOO"] and s["verified"]
    with pytest.raises(ST.StoreError): store.grant("nat", ["net:evil.example"])        # not requested
    store.grant("nat", ["env:FOO"]); assert store.state("nat")["grants"] == ["env:FOO"]
    assert oct((store.dir / "nat" / "main.py").stat().st_mode & 0o777) == "0o644"
    with pytest.raises(ST.StoreError): store.install(src)                               # already installed
    store.install(src, force=True); assert store.state("nat")["grants"] == ["env:FOO"]   # same permissions -> grants kept
    write_plugin(src, man("nat", "native", {"module": "main.py"}, ["env:FOO", "net:x.example"]), {"main.py": "def register(api): pass\n"})
    store.install(src, force=True); assert store.state("nat")["grants"] == [] and not store.state("nat")["enabled"]    # widened -> re-consent


def test_tamper_detection_blocks_enable_and_calls(store, tmp_path):
    store.install(write_plugin(tmp_path / "p", man("t1"), {"skills/a/SKILL.md": "---\nname: a\ndescription: d\n---\nbody"}))
    store.enable("t1"); assert store.verify("t1")
    (store.dir / "t1" / "skills/a/SKILL.md").write_text("---\nname: a\ndescription: d\n---\nPWNED")
    assert not store.verify("t1")
    h = HO.Host(store); assert h.call("t1", "use_skill", {"name": "a"}).startswith("ERROR: plugin content changed")
    store.disable("t1")
    with pytest.raises(ST.StoreError): store.enable("t1")


def test_archive_install_zip_tar_pin_and_hostile_archives(store, tmp_path):
    src = write_plugin(tmp_path / "p", man("arc"))
    z = tmp_path / "p.zip"
    with zipfile.ZipFile(z, "w") as f: f.write(src / MF.MANIFEST, "wrapper/" + MF.MANIFEST)
    t = tmp_path / "p.tgz"
    with tarfile.open(t, "w:gz") as f: f.add(src / MF.MANIFEST, MF.MANIFEST)
    assert store.install(z)["id"] == "arc"; store.uninstall("arc")
    assert store.install(t, sha256=hashlib.sha256(t.read_bytes()).hexdigest())["id"] == "arc"; store.uninstall("arc")
    with pytest.raises(ST.StoreError, match="sha256"): store.install(t, sha256="0" * 64)
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as f: f.writestr("../../escape.txt", "x"); f.writestr(MF.MANIFEST, json.dumps(man("evil")))
    with pytest.raises(ST.StoreError, match="unsafe path"): store.install(evil)
    assert not (tmp_path / "escape.txt").exists()
    tl = tmp_path / "link.tar"
    with tarfile.open(tl, "w") as f:
        info = tarfile.TarInfo("l"); info.type = tarfile.SYMTYPE; info.linkname = "/etc/passwd"; f.addfile(info)
    with pytest.raises(ST.StoreError, match="regular files"): store.install(tl)
    d = write_plugin(tmp_path / "q", man("sym")); os.symlink("/etc/passwd", d / "link")
    with pytest.raises(ST.StoreError, match="symlink"): store.install(d)


def test_native_trust_is_pinned_to_exact_content(store, tmp_path):
    code = "def register(api):\n    api.add_tool('shout', {'description': 'upper', 'fn': lambda a: a.get('t', '').upper(), 'readOnly': True})\n"
    store.install(write_plugin(tmp_path / "n", man("nat2", "native", {"module": "main.py"}), {"main.py": code})); store.enable("nat2")
    h = HO.Host(store)
    assert "not trusted" in h.call("nat2", "shout", {"t": "hi"})
    store.trust_native("nat2", MF.tree_hash(store.path("nat2")))
    h2 = HO.Host(store); assert h2.call("nat2", "shout", {"t": "hi"}) == "HI"
    with pytest.raises(ST.StoreError): store.trust_native("nat2", "0" * 64)
    (store.dir / "nat2" / "main.py").write_text(code + "# changed\n")
    assert "changed after install" in HO.Host(store).call("nat2", "shout", {"t": "x"})


# ------------------------------------------------------------------ sandbox
def test_policy_network_env_exec(monkeypatch):
    p = SB.Policy(["net:api.example.com", "env:KEEP", "exec:node"])
    assert p.check_url("https://api.example.com/x")
    for u in ("https://other.example.com/", "http://127.0.0.1:9/x", "https://api.example.com.evil.com/"):
        with pytest.raises(SB.Denied): p.check_url(u)
    assert SB.Policy(["net:local"]).check_url("http://127.0.0.1:9/x") and SB.Policy(["net:127.0.0.1:9"]).check_url("http://127.0.0.1:9/x")
    monkeypatch.setenv("KEEP", "1"); monkeypatch.setenv("LEAK", "2"); e = p.env(); assert e.get("KEEP") == "1" and "LEAK" not in e
    p.check_exec("node"); p.check_exec("/usr/bin/node")
    with pytest.raises(SB.Denied): p.check_exec("bash")


def _bwrap_works():
    if not shutil.which("bwrap"): return False
    return subprocess.run(["bwrap", "--ro-bind", "/", "/", "true"], capture_output=True).returncode == 0


needs_bwrap = pytest.mark.skipif(not _bwrap_works(), reason="bubblewrap unavailable here")


@needs_bwrap
def test_bubblewrap_hides_home_and_blocks_network_unless_granted(tmp_path, isolated_home):
    secret = isolated_home / "secret.txt"; secret.write_text("TOPSECRET")
    pd = tmp_path / "plug"; pd.mkdir()
    def run(perms, code):
        argv, mode = SB.wrap_command(SB.Policy(perms), sys.executable, ["-c", code], pd); assert mode == "bubblewrap"
        return subprocess.run(argv, capture_output=True, text=True, timeout=20)
    r = run([], f"print(open({str(secret)!r}).read())"); assert "TOPSECRET" not in r.stdout and r.returncode != 0
    r = run([f"fs.read:{isolated_home}"], f"print(open({str(secret)!r}).read())"); assert "TOPSECRET" in r.stdout
    r = run([], f"open({str(isolated_home / 'w.txt')!r},'w').write('x')"); assert not (isolated_home / "w.txt").exists()
    r = run([f"fs.write:{isolated_home}"], f"open({str(isolated_home / 'w.txt')!r},'w').write('x')"); assert (isolated_home / "w.txt").exists()
    import socket, threading
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]
    conn = f"import socket; s=socket.create_connection(('127.0.0.1',{port}),timeout=3); print('CONNECTED')"
    assert "CONNECTED" not in run([], conn).stdout
    assert "CONNECTED" in run(["net:local"], conn).stdout
    srv.close()


# ------------------------------------------------------------------ adapters: MCP
def test_mcp_stdio_real_process_env_scrub_and_write_gate(store, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "hunter2"); monkeypatch.setenv("OK_VAR", "visible")
    mcp_plugin(store, ("exec:" + sys.executable, "env:OK_VAR"))
    h = HO.Host(store)
    assert {t for t in h.toolmap(["echo"])} == {"echo__echo", "echo__mutate", "echo__getenv", "echo__readfile"}
    assert h.call("echo", "echo", {"text": "hi"}) == "echo:hi"
    assert h.call("echo", "getenv", {"name": "OK_VAR"}) == "visible"                      # granted
    assert h.call("echo", "getenv", {"name": "SECRET_TOKEN"}) == "<unset>"               # never passed
    assert "tool.write permission is not granted" in h.call("echo", "mutate", {})
    h.close()


def test_mcp_stdio_write_tool_after_grant_and_exec_denied_without_grant(store):
    mcp_plugin(store, ("exec:" + sys.executable, "tool.write")); h = HO.Host(store)
    assert h.call("echo", "mutate", {}) == "mutated"; h.close()
    store.revoke("echo", ["exec:" + sys.executable]); h2 = HO.Host(store)
    assert h2.toolmap(["echo"]) == {}                                   # refused to start: exec grant revoked
    assert "echo" in h2.errors and "exec permission" in h2.errors["echo"]


@needs_bwrap
def test_mcp_stdio_cannot_read_home_unless_granted(store, isolated_home):
    (isolated_home / "token.txt").write_text("PRIVATE")
    mcp_plugin(store, ("exec:" + sys.executable,)); h = HO.Host(store); h.adapter("echo")
    assert h.adapter("echo").mode == "bubblewrap"
    assert "PRIVATE" not in h.call("echo", "readfile", {"path": str(isolated_home / "token.txt")}); h.close()


def test_mcp_http_json_and_sse(store, stub):
    def rpc(body, hd):
        m = body.get("method")
        if m == "initialize": return 200, {"Mcp-Session-Id": "S1"}, {"jsonrpc": "2.0", "id": body["id"], "result": {}}
        if "id" not in body: return 202, {}, {}
        if m == "tools/list": return 200, {}, {"jsonrpc": "2.0", "id": body["id"], "result": {"tools": [{"name": "ping", "description": "p", "annotations": {"readOnlyHint": True}}]}}
        sse = ("event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": "pong:" + hd.get("Mcp-Session-Id", "")}]}}) + "\n\n").encode()
        return 200, {"Content-Type": "text/event-stream"}, sse
    stub.route("POST", "/mcp", rpc)
    a = AMCP.McpHttp({"transport": "http", "url": stub.url + "/mcp"}, SB.Policy(["net:local"]))
    assert [t["name"] for t in a.tools()] == ["ping"] and a.tools()[0]["readOnly"]
    assert a.call("ping", {}) == "pong:S1"
    with pytest.raises(SB.Denied): AMCP.McpHttp({"transport": "http", "url": stub.url + "/mcp"}, SB.Policy([]))


# ------------------------------------------------------------------ adapters: A2A / n8n / LangGraph
def test_a2a_client_card_fallback_reply_and_task_polling(stub):
    stub.route("GET", "/.well-known/agent.json", lambda b, h: (200, {}, {"name": "Remote", "description": "does things", "skills": [{"name": "summarise"}]}))
    state = {"n": 0}
    def rpc(body, hd):
        if body["method"] == "message/send": return 200, {}, {"jsonrpc": "2.0", "id": body["id"], "result": {"kind": "task", "id": "T1", "status": {"state": "working"}}}
        state["n"] += 1
        res = {"kind": "task", "id": "T1", "status": {"state": "completed"}, "artifacts": [{"parts": [{"kind": "text", "text": "ANSWER"}]}]} if state["n"] >= 2 else {"id": "T1", "status": {"state": "working"}}
        return 200, {}, {"jsonrpc": "2.0", "id": body["id"], "result": res}
    stub.route("POST", "/", rpc)
    c = AA2A.A2AClient({"url": stub.url}, SB.Policy(["net:local"]), poll=(0, 5), sleep=lambda s: None)
    assert "summarise" in c.tools()[0]["description"]
    assert c.call("ask", {"message": "hello"}) == "ANSWER"
    sent = [b for m, p, b, h in stub.seen if b and b.get("method") == "message/send"][0]
    assert sent["params"]["message"]["parts"][0]["text"] == "hello"


def test_a2a_server_side_card_and_handler():
    b = core.new_board("Team"); b["agents"].append(core.new_agent(0, 0, "Dev", id="a1", instructions="writes code"))
    card = AA2A.card_for_board(b, "http://x/a2a"); assert card["skills"][0]["name"] == "Dev" and card["name"] == "Team"
    ok = AA2A.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {"parts": [{"kind": "text", "text": "do it"}]}}}, lambda t: "done:" + t)
    assert ok["result"]["parts"][0]["text"] == "done:do it"
    assert AA2A.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tasks/cancel"}, str)["error"]["code"] == -32601
    assert AA2A.handle_rpc({"jsonrpc": "2.0", "id": 3, "method": "message/send", "params": {"message": {"parts": []}}}, str)["error"]["code"] == -32602
    assert AA2A.handle_rpc({"jsonrpc": "2.0", "id": 4, "method": "message/send", "params": {"message": {"parts": [{"text": "x"}]}}}, lambda t: 1 / 0)["error"]["code"] == -32000


def test_n8n_webhook_tool_and_workflow_import(stub, tmp_path):
    stub.route("POST", "/webhook/lead", lambda b, h: (200, {}, {"received": b}))
    wf = {"name": "Lead intake", "nodes": [{"type": "n8n-nodes-base.webhook", "name": "Hook", "parameters": {"path": "lead"}}, {"type": "n8n-nodes-base.set", "name": "x", "parameters": {}}]}
    f = tmp_path / "wf.json"; f.write_text(json.dumps(wf))
    doc, _, _ = IM.n8n_workflow(f, stub.url); assert doc["permissions"] == ["net:local"]
    m = MF.clean(doc); a = AN8N.N8n(m["entry"], SB.Policy(m["permissions"]))
    assert json.loads(a.call("hook", {"payload": {"email": "a@b.co"}}))["received"] == {"email": "a@b.co"}
    with pytest.raises(SB.Denied): AN8N.N8n(m["entry"], SB.Policy([])).call("hook", {})
    f.write_text(json.dumps({"name": "x", "nodes": [{"type": "n8n-nodes-base.cron"}]}))
    with pytest.raises(MF.ManifestError): IM.n8n_workflow(f, stub.url)


def test_langgraph_run_discover_and_key_only_when_env_granted(stub, monkeypatch):
    monkeypatch.setenv("LG_KEY", "k-123")
    stub.route("POST", "/runs/wait", lambda b, h: (200, {}, {"messages": [{"role": "user", "content": "q"}, {"role": "ai", "content": [{"type": "text", "text": "final answer"}]}]}))
    stub.route("POST", "/assistants/search", lambda b, h: (200, {}, [{"assistant_id": "agent", "name": "Agent", "graph_id": "g"}]))
    e = {"url": stub.url, "assistant_id": "agent", "api_key_env": "LG_KEY"}
    a = ALG.LangGraph(e, SB.Policy(["net:local", "env:LG_KEY"])); assert a.call("run", {"input": "hi"}) == "final answer"
    run = [x for x in stub.seen if x[1] == "/runs/wait"][0]; assert run[2] == {"assistant_id": "agent", "input": {"messages": [{"role": "user", "content": "hi"}]}} and run[3].get("x-api-key") == "k-123"
    assert a.discover()[0]["assistant_id"] == "agent"
    b = ALG.LangGraph(e, SB.Policy(["net:local"])); b.call("run", {"input": "hi"}); assert "x-api-key" not in [x for x in stub.seen if x[1] == "/runs/wait"][-1][3]


# ------------------------------------------------------------------ importers
SKILL = "---\nname: pdf-tools\ndescription: \"Work with PDFs\"\nmetadata: {\"openclaw\": {\"requires\": {\"bins\": [\"pdftotext\"], \"env\": [\"PDF_KEY\"]}}}\nprerequisites:\n  commands: [qpdf]\n---\n# PDF\nUse pdftotext.\n"


def test_import_skills_copies_only_skill_md_and_reports_advisory(tmp_path, store):
    root = tmp_path / "skills" / "docs" / "pdf-tools"; root.mkdir(parents=True); (root / "SKILL.md").write_text(SKILL); (root / "run.sh").write_text("rm -rf /"); (root / "scripts").mkdir()
    doc, files, notes = IM.skills_dir(tmp_path / "skills", "openclaw")
    assert list(files) == ["skills/pdf-tools/SKILL.md"] and any("run.sh" in n for n in notes) and doc["permissions"] == []
    assert set(doc["advisory_permissions"]) == {"exec:pdftotext", "exec:qpdf", "env:PDF_KEY"}
    m = store.install_manifest(doc, files); assert not (store.dir / m["id"] / "run.sh").exists()
    store.enable(m["id"]); h = HO.Host(store)
    out = h.call(m["id"], "use_skill", {"name": "pdf-tools"}); assert 'trust="untrusted-reference"' in out and "Use pdftotext" in out
    assert "pdf-tools: Work with PDFs" in h.skills_prompt([m["id"]])


def test_import_opencode_jsonc_and_mcp_json_never_imports_secret_values(tmp_path, store):
    cfg = tmp_path / "opencode.jsonc"
    cfg.write_text('''// comment\n{"mcp": {"local-tool": {"type": "local", "command": ["npx", "-y", "server-x"], "environment": {"API_KEY": "sk-abcdefghijklmnopqrstuvwxyz", "MODE": "x"}},
      "remote-one": {"type": "remote", "url": "https://mcp.example.com/sse"}, /* trailing */ },}''')
    res = IM.opencode_config(cfg); docs = {d["id"]: d for d, _, _ in res if d}
    assert docs["mcp-local-tool"]["entry"] == {"transport": "stdio", "command": "npx", "args": ["-y", "server-x"]}
    assert "env:API_KEY" in docs["mcp-local-tool"]["permissions"] and "exec:npx" in docs["mcp-local-tool"]["permissions"]
    assert any("secret" in n for n in res[0][2]) and "sk-abcdefghijklmnopqrstuvwxyz" not in json.dumps(docs)
    assert docs["mcp-remote-one"]["permissions"] == ["net:mcp.example.com"]
    for d in docs.values(): store.install_manifest(d)
    j = tmp_path / ".mcp.json"; j.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["x"]}, "bad": {}}}))
    out = IM.mcp_servers(j); assert out[0][0]["id"] == "mcp-fs" and out[1][0] is None


def test_import_agents_markdown_maps_tools_and_leaves_model_on_default(tmp_path, store):
    d = tmp_path / ".opencode" / "agent"; d.mkdir(parents=True)
    (d / "reviewer.md").write_text("---\ndescription: Reviews code\nmodel: anthropic/claude-x\ntools:\n  bash: true\n  write: false\n  webfetch: true\n---\nYou review pull requests carefully.\n")
    doc, files, _ = IM.agents_dir(d); m = store.install_manifest(doc, files); store.enable(m["id"])
    a = HO.Host(store).agents(m["id"])[0]; assert a["tools"] == ["http_api", "shell"] and a["permissions"] == "read-only" and a["source_model"] == "anthropic/claude-x"
    ag = IM.agent_to_board_agent(core, a); assert ag["model"] == "det.01" and ag["instructions"].startswith("You review")


@pytest.mark.skipif(not (REAL_HOME / ".hermes" / "skills").is_dir(), reason="no Hermes skills on this machine")
def test_real_hermes_skills_import(store):
    real = REAL_HOME / ".hermes" / "skills"; cat = next(p for p in sorted(real.iterdir()) if p.is_dir() and list(p.glob("**/SKILL.md")))
    doc, files, notes = IM.skills_dir(cat, "hermes"); m = store.install_manifest(doc, files); assert m["runtime"] == "declarative" and files


# ------------------------------------------------------------------ discovery + catalog
def test_scan_local_lists_without_importing(tmp_path):
    home = tmp_path / "h"; (home / ".hermes/skills/cat/s1").mkdir(parents=True); (home / ".hermes/skills/cat/s1/SKILL.md").write_text(SKILL)
    (home / ".hermes/plugins/hp").mkdir(parents=True); (home / ".config/opencode").mkdir(parents=True); (home / ".config/opencode/opencode.json").write_text('{"mcp": {"a": {"type": "remote", "url": "https://x.example/m"}}}')
    cwd = tmp_path / "w"; (cwd / ".opencode/agent").mkdir(parents=True); (cwd / ".opencode/agent/a.md").write_text("---\ndescription: d\n---\nb"); (cwd / ".mcp.json").write_text('{"mcpServers": {"s": {"command": "x"}}}')
    wf = tmp_path / "wfs"; wf.mkdir(); (wf / "w.json").write_text(json.dumps({"name": "n", "nodes": [{"type": "n8n-nodes-base.webhook"}]}))
    hits = DI.scan_local(home, cwd, [wf]); by = {(h["origin"], h["kind"]): h for h in hits}
    assert by[("hermes", "skills")]["items"] == 1 and by[("hermes", "plugin")]["importable"] is False and by[("opencode", "mcp-config")]["items"] == 1
    assert by[("opencode", "agents")]["items"] == 1 and by[("mcp", "mcp-config")]["importable"] and by[("n8n", "workflow")]["importable"]
    assert not (tmp_path / "state").exists()


def test_catalog_requires_pin_and_verifies_hash(store, stub, tmp_path):
    src = write_plugin(tmp_path / "cp", man("fromcat")); z = tmp_path / "cp.zip"
    with zipfile.ZipFile(z, "w") as f: f.write(src / MF.MANIFEST, MF.MANIFEST)
    data = z.read_bytes(); stub.route("GET", "/pkg.zip", lambda b, h: (200, {"Content-Type": "application/zip"}, data))
    good = hashlib.sha256(data).hexdigest()
    cat = DI.Catalog({"plugins": [{"id": "fromcat", "description": "x", "origin": "ordivyr", "source": {"url": stub.url + "/pkg.zip", "sha256": good}},
                                  {"id": "badpin", "source": {"url": stub.url + "/pkg.zip", "sha256": "0" * 64}}, {"id": "nopin", "source": {"url": stub.url + "/pkg.zip"}}]})
    assert [p["id"] for p in cat.search("fromcat")] == ["fromcat"]
    with pytest.raises(ST.StoreError, match="does not match"): cat.install(store, "badpin")
    with pytest.raises(ST.StoreError, match="no sha256"): cat.install(store, "nopin")
    assert cat.install(store, "fromcat")["id"] == "fromcat" and store.list()[0]["enabled"] is False


# ------------------------------------------------------------------ host + runner integration
def test_host_license_gating_cap_and_audit_redaction(store, stub):
    stub.route("POST", "/webhook/h", lambda b, h: (200, {}, {"ok": 1}))
    store.install_manifest(man("hook", "n8n", {"webhooks": [{"name": "h", "url": stub.url + "/webhook/h"}]}, ["net:local", "tool.write"])); store.grant("hook", ["net:local", "tool.write"]); store.enable("hook")
    h = HO.Host(store, max_calls=2)
    assert h.licensed({"mcp": ["hook", "ghost"]}) == ["hook"] and h.licensed({"mcp": []}) == []
    for _ in range(2): assert json.loads(h.call("hook", "h", {"api_key": "sk-abcdefghijklmnop1234", "x": 1})) == {"ok": 1}
    assert "call cap" in h.call("hook", "h", {})
    log = json.dumps(store.read_audit()); assert "sk-abcdefghijklmnop1234" not in log and "call" in log
    h.reset_run(); store.disable("hook"); assert "disabled" in h.call("hook", "h", {})
    L.EXTRA_MCP[:] = []; store.enable("hook"); h.sync_license(L); assert L.EXTRA_MCP == ["hook"]; L.EXTRA_MCP[:] = []


def test_runner_gives_an_agent_only_licensed_plugin_tools_end_to_end(store, stub):
    """Real HTTP: an OpenAI-compatible stub model asks for a plugin tool; the runner executes it through the guarded host and returns the final answer."""
    mcp_plugin(store, ("exec:" + sys.executable,))
    turn = {"n": 0}
    def chat(body, hd):
        turn["n"] += 1; names = [t["function"]["name"] for t in body.get("tools", [])]
        chat.last_tools = names
        if turn["n"] == 1:
            return 200, {}, {"model": "stub", "usage": {"total_tokens": 10}, "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "echo__echo", "arguments": json.dumps({"text": "from-model"})}}]}}]}
        tool_msg = [m for m in body["messages"] if m.get("role") == "tool"][-1]["content"]
        return 200, {}, {"model": "stub", "usage": {"total_tokens": 5}, "choices": [{"message": {"role": "assistant", "content": "FINAL(" + tool_msg + ")"}}]}
    stub.route("POST", "/v1/chat/completions", chat)
    b = core.new_board("T"); a = core.new_agent(0, 0, "Worker", id="w1", model="openai:stub-model", mcp=["echo"]); b["agents"].append(a)
    mgr = LLM.Manager([LLM.OpenAIBackend(stub.url + "/v1")], HW.Hardware())
    host = HO.Host(store)
    r = RUN.Runner(b, "use the tool", llm=mgr, plugins=host).run()
    assert r["status"] == "done", r["agents"]
    assert r["agents"]["w1"]["output"] == "FINAL(echo:from-model)" and "echo__echo" in chat.last_tools
    assert any(e["event"] == "call" and e["plugin"] == "echo" for e in store.read_audit())
    # an agent whose License does not list the plugin sees no plugin tools and cannot call it
    turn["n"] = 1; a["mcp"] = []; b["agents"][0] = a
    def plain(body, hd): chat.last_tools = [t["function"]["name"] for t in body.get("tools", [])]; return 200, {}, {"model": "stub", "choices": [{"message": {"content": "plain"}}]}
    stub.route("POST", "/v1/chat/completions", plain)
    r2 = RUN.Runner(b, "x", llm=mgr, plugins=host).run(); assert r2["agents"]["w1"]["output"] == "plain" and chat.last_tools == []
    host.close()


# ------------------------------------------------------------------ CLI
def test_cli_plugin_lifecycle(tmp_path, capsys):
    from ordivyr import cli
    home = str(tmp_path / "h"); src = write_plugin(tmp_path / "c", man("clip", "declarative", {"skills": ["s"]}, []), {"skills/s/SKILL.md": "---\nname: s\ndescription: d\n---\nB"})
    run = lambda *a: cli.main(["plugin", "--home", home, *a])
    assert run("install", str(src)) == 0 and run("enable", "clip") == 0
    capsys.readouterr(); assert run("call", "clip", "use_skill", '{"name": "s"}') == 0 and "B" in capsys.readouterr().out
    assert run("verify", "clip") == 0
    (Path(home) / "plugins/clip/skills/s/SKILL.md").write_text("tampered"); assert run("verify", "clip") == 1
    assert run("grant", "clip", "net:evil.example") == 1                     # not requested -> refused
    assert run("uninstall", "clip") == 0 and run("list") == 0


def test_shipped_example_native_plugin_works(store):
    ex = Path(__file__).resolve().parents[1] / "examples" / "plugins" / "shout-native"
    store.install(ex); store.enable("shout"); store.trust_native("shout", MF.tree_hash(store.path("shout")))
    assert HO.Host(store).call("shout", "shout", {"text": "ok"}) == "OK"


@needs_bwrap
def test_bubblewrap_command_living_in_a_hidden_tree_still_runs(tmp_path):
    """Regression (found by the clean-room release check): /tmp and $HOME are blanked inside the sandbox; a command that lives there (a venv python) must be re-bound."""
    b = tmp_path / "venv" / "bin"; b.mkdir(parents=True); os.symlink(os.path.realpath(sys.executable), b / "python"); (tmp_path / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    argv, mode = SB.wrap_command(SB.Policy([]), str(b / "python"), ["-c", "print('ran')"], tmp_path / "plug"); (tmp_path / "plug").mkdir()
    r = subprocess.run(argv, capture_output=True, text=True, timeout=20); assert mode == "bubblewrap" and r.stdout.strip() == "ran", r.stderr


def test_loading_a_native_plugin_does_not_change_its_hash(store):
    """Regression (found by the installed-package smoke test): importing main.py must not write __pycache__ into the pinned folder or invalidate verification."""
    ex = Path(__file__).resolve().parents[1] / "examples" / "plugins" / "shout-native"
    store.install(ex); store.enable("shout"); store.trust_native("shout", MF.tree_hash(store.path("shout")))
    h = HO.Host(store); h.adapter("shout"); (store.dir / "shout" / "__pycache__").mkdir(exist_ok=True); (store.dir / "shout" / "__pycache__" / "x.pyc").write_bytes(b"x")
    assert store.verify("shout") and h.call("shout", "shout", {"text": "a"}) == "A"


def test_stdio_plugins_fail_closed_without_working_bwrap(monkeypatch, tmp_path):
    monkeypatch.setattr(SB.shutil, "which", lambda c: None if c == "bwrap" else "/bin/true")
    monkeypatch.delenv("ORDIVYR_ALLOW_UNCONFINED", raising=False)
    with pytest.raises(SB.Denied):
        SB.wrap_command(SB.Policy([]), "true", [], tmp_path)
    monkeypatch.setenv("ORDIVYR_ALLOW_UNCONFINED", "1")
    argv, mode = SB.wrap_command(SB.Policy([]), "true", [], tmp_path)
    assert mode == "env-only" and "WITHOUT" in SB.confinement()
