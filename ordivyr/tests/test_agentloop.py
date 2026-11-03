import json, os, sys, tempfile, unittest
from pathlib import Path
from ordivyr import agentloop as AL, providers as PV


def seq_http(replies, seen=None):
    it = iter(replies)
    def http(method, url, headers, data, timeout):
        if seen is not None: seen.append(json.loads(data))
        return 200, json.dumps(next(it)).encode()
    return http


def oa_call(name, args, cid="c1", tokens=10): return {"choices": [{"message": {"role": "assistant", "content": "", "tool_calls": [{"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}}], "usage": {"total_tokens": tokens}}
def oa_text(t, tokens=5): return {"choices": [{"message": {"role": "assistant", "content": t}}], "usage": {"total_tokens": tokens}}


class Box(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); (self.d / "a.txt").write_text("hello"); self.out = Path(tempfile.mkdtemp()); (self.out / "secret").write_text("S")
        self.b = AL.ToolBox(self.d, write=True, web=True)

    def test_files_confined_to_working_folder(self):
        self.assertEqual(self.b.call("read_file", {"path": "a.txt"}), "hello"); self.assertIn("a.txt", self.b.call("list_files", {}))
        for bad in ("../x", "/etc/passwd", "sub/../../x"): self.assertTrue(self.b.call("read_file", {"path": bad}).startswith("ERROR"), bad)
        os.symlink(self.out, self.d / "lnk")
        self.assertTrue(self.b.call("read_file", {"path": "lnk/secret"}).startswith("ERROR")); self.assertTrue(self.b.call("write_file", {"path": "lnk/pwn", "content": "x"}).startswith("ERROR"))
        self.assertFalse((self.out / "pwn").exists())

    def test_write_needs_grant_and_never_touches_git(self):
        ro = AL.ToolBox(self.d); self.assertNotIn("write_file", [d["name"] for d in ro.defs]); self.assertTrue(ro.call("write_file", {"path": "x", "content": "y"}).startswith("ERROR: not allowed"))
        self.assertTrue(self.b.call("write_file", {"path": ".git/config", "content": "x"}).startswith("ERROR")); self.assertIn("wrote", self.b.call("write_file", {"path": "n/new.txt", "content": "hi"})); self.assertEqual((self.d / "n/new.txt").read_text(), "hi")

    def test_no_shell_tool_exists(self):
        self.assertFalse([d for d in self.b.defs if "shell" in d["name"] or "exec" in d["name"] or "bash" in d["name"]])

    def test_fetch_refuses_private_and_local(self):
        for u in ("http://127.0.0.1/", "http://localhost:8840/api", "http://169.254.169.254/latest/meta-data", "http://10.0.0.5/", "http://[::1]/", "file:///etc/passwd", "ftp://x", "http://u:p@example.com/"):
            self.assertTrue(self.b.call("fetch_url", {"url": u}).startswith("ERROR"), u)
        noweb = AL.ToolBox(self.d); self.assertTrue(noweb.call("fetch_url", {"url": "http://example.com"}).startswith("ERROR: not allowed"))

    def test_fetch_pins_resolved_ip(self):
        import threading, http.server
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(s): b = b"<html><script>x</script><p>public page</p></html>"; s.send_response(200); s.send_header("Content-Type", "text/html"); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
            def log_message(s, *a): pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
        try: out = AL.fetch_url(f"http://pub.example:{srv.server_port}/", _resolve=lambda h: "127.0.0.1")        # pretend DNS said so; connection goes to the vetted IP
        finally: srv.shutdown()
        self.assertIn("public page", out); self.assertNotIn("script", out)


class Loop(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp()); (self.d / "a.txt").write_text("hello world")

    def test_openai_tool_calls_roundtrip(self):
        seen = []; box = AL.ToolBox(self.d, write=True)
        h = seq_http([oa_call("read_file", {"path": "a.txt"}), oa_call("write_file", {"path": "out.txt", "content": "done"}, "c2"), oa_text("all done")], seen)
        text, tok, model, steps, why = AL.run("openai", "https://x.test/v1", "k", "m", "sys", "go", box, h)
        self.assertEqual((text, tok, steps, why), ("all done", 25, 3, "done")); self.assertEqual((self.d / "out.txt").read_text(), "done")
        self.assertEqual(seen[1]["messages"][-1], {"role": "tool", "tool_call_id": "c1", "content": "hello world"}); self.assertIn("tools", seen[0])

    def test_anthropic_tool_use_roundtrip(self):
        seen = []; box = AL.ToolBox(self.d)
        tu = {"content": [{"type": "tool_use", "id": "tu1", "name": "read_file", "input": {"path": "a.txt"}}], "usage": {"input_tokens": 4, "output_tokens": 2}}
        fin = {"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 6, "output_tokens": 1}}
        text, tok, _, steps, why = AL.run("anthropic", "https://api.anthropic.com", "k", "m", "sys", "go", box, seq_http([tu, fin], seen))
        self.assertEqual((text, tok, steps, why), ("ok", 13, 2, "done")); self.assertEqual(seen[1]["messages"][-1]["content"][0], {"type": "tool_result", "tool_use_id": "tu1", "content": "hello world"})

    def test_step_cap_and_token_budget(self):
        forever = [oa_call("list_files", {}, f"c{i}") for i in range(50)]
        _, _, _, steps, why = AL.run("openai", "https://x.test/v1", "k", "m", "s", "go", AL.ToolBox(self.d), seq_http(forever), max_steps=3); self.assertEqual((steps, why), (3, "steps"))
        _, tok, _, steps, why = AL.run("openai", "https://x.test/v1", "k", "m", "s", "go", AL.ToolBox(self.d), seq_http([oa_call("list_files", {}, "a", 500), oa_text("x")]), token_budget=400); self.assertEqual(why, "budget")

    def test_ask_user_ends_the_turn_with_a_question(self):
        text, _, _, steps, why = AL.run("openai", "https://x.test/v1", "k", "m", "s", "go", AL.ToolBox(self.d), seq_http([oa_call("ask_user", {"question": "which file?"})]))
        self.assertEqual((text, why, steps), ("QUESTION: which file?", "question", 1))

    def test_bad_tool_call_is_reported_to_the_model_not_crashed(self):
        h = seq_http([oa_call("rm_rf", {}), oa_text("fine")]); text, *_ = AL.run("openai", "https://x.test/v1", "k", "m", "s", "go", AL.ToolBox(self.d), h); self.assertEqual(text, "fine")

    def test_gemini_is_text_only(self):
        with self.assertRaises(PV.ProviderError): AL.run("gemini", "https://g.test/v1beta", "k", "m", "s", "go", AL.ToolBox(self.d), seq_http([]))


STUB = '''import sys, json
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m: continue
    r = {"jsonrpc": "2.0", "id": m["id"]}
    if m["method"] == "initialize": r["result"] = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "stub", "version": "1"}}
    elif m["method"] == "tools/list": r["result"] = {"tools": [{"name": "echo", "description": "echo text", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
    elif m["method"] == "tools/call": r["result"] = {"content": [{"type": "text", "text": "echo:" + json.dumps(m["params"]["arguments"])}], "isError": False}
    else: r["error"] = {"code": -32601, "message": "nope"}
    print(json.dumps(r), flush=True)
'''


class Mcp(unittest.TestCase):
    def test_stdio_client_and_loop(self):
        d = Path(tempfile.mkdtemp()); (d / "srv.py").write_text(STUB)
        c = AL.McpClient({"command": sys.executable, "args": [str(d / "srv.py")]}, {}, d)
        try:
            tools = c.tools(); self.assertEqual(tools[0]["name"], "echo")
            box = AL.ToolBox(d, mcp={"mcp__stub__echo": (c, tools[0])}); self.assertIn("mcp__stub__echo", [x["name"] for x in box.defs])
            h = seq_http([oa_call("mcp__stub__echo", {"text": "hi"}), oa_text("got it")])
            text, *_ = AL.run("openai", "https://x.test/v1", "k", "m", "s", "go", box, h); self.assertEqual(text, "got it")
            self.assertEqual(box.call("mcp__stub__echo", {"text": "x"}), 'echo:{"text": "x"}')
        finally: c.close()
        self.assertTrue(c.p.wait(5) is not None)                                                              # process group is reaped


if __name__ == "__main__": unittest.main()
