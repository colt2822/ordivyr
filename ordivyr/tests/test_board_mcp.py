"""Board MCP server driven by ORDIVYR's own stdio MCP client, against a real Board HTTP API and worker (scripted model)."""
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import pytest
from ordivyr.agentloop import McpClient
from ordivyr.board import api as A, mcp_server as MS
from ordivyr.tests.board_support import wait_for
from ordivyr.tests.test_board_api import w, call, setup          # noqa: F401  (w is the fixture)

ROOT = Path(__file__).resolve().parents[2]


def client(w, key, project="p1"):
    return McpClient({"command": sys.executable, "args": ["-m", "ordivyr.board.mcp_server"]}, {"BOARD_URL": w.api, "BOARD_API_KEY": key, "BOARD_PROJECT": project}, ROOT)


def test_submit_follow_and_isolation_over_mcp(w):
    pt, ka, kb = setup(w); member = call(w, "POST", "/v1/keys", ka, {"role": "member", "project": "p1"})[1]["key"]; a = client(w, member); b = client(w, kb); seen = []
    def go(c, name, **args): out = c.call(name, args); seen.append(out); return out
    try:
        names = {t["name"] for t in a.tools()}
        assert names == set(MS.TOOLS) and not any(x in n for n in names for x in ("approve", "refuse", "define", "key", "secret"))
        assert json.loads(go(a, "list_agents"))["agents"][0]["id"] == "ag"
        j = json.loads(go(a, "submit_job", agent_id="ag", prompt="go [[hello]]", idem_key="one"))["job_id"]
        assert json.loads(go(a, "submit_job", agent_id="ag", prompt="go [[hello]]", idem_key="one"))["job_id"] == j
        wait_for(lambda: json.loads(go(a, "get_job", job_id=j))["status"] == "completed", 20)
        assert json.loads(go(a, "get_job", job_id=j))["result"]["text"] == "hi"
        for t in ("job_events", "job_timings", "job_outputs"): assert not go(a, t, job_id=j).startswith("ERROR")
        assert j in go(a, "list_jobs", status="completed")
        for t in ("get_job", "job_outputs", "cancel_job"): assert go(b, t, job_id=j).startswith("ERROR: HTTP 404")          # other org, same project name
        for bad in (f"{j}/approve", f"{j}?x=1", "..", f"{j}#"): assert "invalid job_id" in go(a, "cancel_job", job_id=bad)
        assert "invalid project" in go(a, "list_jobs", project="p1/jobs/x")
        assert go(a, "submit_job", agent_id="ag", prompt="x", validators="rm").startswith("ERROR")
        assert go(a, "approve_job", job_id=j) == "ERROR: unknown tool"
        go(a, "get_job", job_id=member.replace("/", ""))                      # even a key echoed back by a caller's own argument must not come out
        assert all(member not in s and kb not in s for s in seen)
    finally: a.close(); b.close()


def test_refuses_to_send_the_key_over_remote_http_or_through_a_redirect():
    with pytest.raises(SystemExit): MS.BoardApi("http://board.example.com", "k")
    with pytest.raises(SystemExit): MS.BoardApi("http://127.0.0.1:1", None)
    hits = []
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            hits.append(self.path); self.send_response(302); self.send_header("Location", "/stolen"); self.send_header("Content-Length", "0"); self.end_headers()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = MS.handle(MS.BoardApi(f"http://127.0.0.1:{srv.server_address[1]}", "sekret", "p1"), {"id": 1, "method": "tools/call", "params": {"name": "list_agents"}})
    finally: srv.shutdown(); srv.server_close()
    assert r["result"]["isError"] and "302" in r["result"]["content"][0]["text"] and hits == ["/v1/projects/p1/agents"]
    assert MS.handle(None, {"method": "notifications/initialized"}) is None and MS.handle(None, {"id": 2, "method": "nope"})["error"]["code"] == -32601
