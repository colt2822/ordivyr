"""Scripted OpenAI-compatible 'oracle' model for harness-only measurements (no GPU, no intelligence involved).

It recognises a registered task by its prompt, then replies with a fixed, correct tool-call script: read every starting file, write every reference file,
say 'done'. It adapts to whatever tool names/parameters the harness advertises (read_file/read, write_file/write, path/file_path, content/text ...) and
speaks both plain JSON and SSE streaming. Modes make the harness - not the model - the thing under test:
  delay=S        every response takes S seconds (so a kill can land mid-run)
  fail_first=N   the first N requests per run get HTTP 500 (transient model outage)
  evil=1         additionally tries to write outside the working folder and to read a canary (permission-enforcement tests)
Per-run accounting is keyed by the API key `stub-<run>`: request count, tokens, tool actions. Nothing here is a competitor stand-in: it replaces only the MODEL.
"""
from __future__ import annotations
import json, re, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

READ = ("read_file", "read", "file_read", "readFile", "view_file")
WRITE = ("write_file", "write", "file_write", "create_file", "writeFile")
PATHK = ("path", "file_path", "filepath", "filename", "file")
CONTK = ("content", "contents", "text", "data", "file_text")


def _tool(tools, names):
    byname = {((t.get("function") or t).get("name")): (t.get("function") or t) for t in tools}
    for n in names:
        if n in byname: return n, byname[n]
    return None, None


def _args(spec, vals):
    props = (spec.get("parameters") or spec.get("input_schema") or {}).get("properties", {}); out = {}
    for ks, v in vals:
        k = next((x for x in ks if x in props), None)
        if k: out[k] = v
    for r in (spec.get("parameters") or {}).get("required", []):          # required extras get a neutral default of the declared type
        if r not in out: out[r] = {"integer": 0, "number": 0, "boolean": False, "array": [], "object": {}}.get((props.get(r) or {}).get("type"), "")
    return out


def _text(m):
    c = m.get("content")
    return c if isinstance(c, str) else " ".join(p.get("text", "") for p in (c or []) if isinstance(p, dict))


class Stub:
    def __init__(self, tasks=None, delay=0.0, fail_first=0, evil=False, host="127.0.0.1", port=0, canary=None):
        self.tasks = list(tasks or []); self.delay, self.fail_first, self.evil, self.canary = delay, fail_first, evil, canary; self.runs = {}; self.lock = threading.Lock()
        stub = self
        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *a): pass
            def _send(self, code, body, ctype="application/json"):
                b = body if isinstance(body, bytes) else json.dumps(body).encode(); self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
            def do_GET(self):
                if self.path.startswith("/props"): return self._send(200, {"total_slots": 1, "default_generation_settings": {"n_ctx": 65536}})
                if self.path.rstrip("/").endswith("/models"): return self._send(200, {"object": "list", "data": [{"id": "stub-oracle", "object": "model", "meta": {"n_ctx_train": 65536}}]})
                self._send(404, {"error": "not found"})
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0); body = json.loads(self.rfile.read(n) or b"{}"); key = (self.headers.get("Authorization") or "").replace("Bearer ", "") or self.headers.get("x-api-key") or "anon"
                if not self.path.rstrip("/").endswith("/chat/completions"): return self._send(404, {"error": "only /chat/completions"})
                code, resp = stub.respond(key, body)
                if code != 200: return self._send(code, resp)
                if body.get("stream"): return self._sse(resp, bool((body.get("stream_options") or {}).get("include_usage")))
                self._send(200, resp)
            def _sse(self, resp, usage):
                m = resp["choices"][0]["message"]; chunks = []
                def ck(delta, fin=None): return {"id": resp["id"], "object": "chat.completion.chunk", "created": resp["created"], "model": resp["model"], "choices": [{"index": 0, "delta": delta, "finish_reason": fin}]}
                chunks.append(ck({"role": "assistant", "content": ""}))
                if m.get("content"): chunks.append(ck({"content": m["content"]}))
                for i, tc in enumerate(m.get("tool_calls") or []): chunks.append(ck({"tool_calls": [{"index": i, "id": tc["id"], "type": "function", "function": tc["function"]}]}))
                chunks.append(ck({}, "tool_calls" if m.get("tool_calls") else "stop"))
                if usage: chunks.append({"id": resp["id"], "object": "chat.completion.chunk", "created": resp["created"], "model": resp["model"], "choices": [], "usage": resp["usage"]})
                data = b"".join(b"data: " + json.dumps(c).encode() + b"\n\n" for c in chunks) + b"data: [DONE]\n\n"
                self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        self.httpd = ThreadingHTTPServer((host, port), H); self.httpd.daemon_threads = True; self.port = self.httpd.server_address[1]; self.base = f"http://{host}:{self.port}/v1"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self): self.thread.start(); return self
    def stop(self): self.httpd.shutdown(); self.httpd.server_close()
    def run(self, key):
        with self.lock: return self.runs.setdefault(key, {"requests": 0, "failed": 0, "prompt_tokens": 0, "completion_tokens": 0, "actions": [], "t": []})

    def find(self, msgs):
        blob = "\n".join(_text(m) for m in msgs if m.get("role") in ("user", "system"))
        for t in self.tasks:
            if t["prompt"][:120] in blob: return t
        return None

    def respond(self, key, body):
        r = self.run(key); msgs = body.get("messages") or []; tools = body.get("tools") or []
        with self.lock:
            r["requests"] += 1; n = r["requests"]; r["t"].append(time.time()); r.setdefault("req_chars", []).append(len(json.dumps(msgs)) + len(json.dumps(tools)))
        if n <= self.fail_first:
            with self.lock: r["failed"] += 1
            return 500, {"error": {"message": "stub: injected outage"}}
        if self.delay: time.sleep(self.delay)
        task = self.find(msgs); plen = len(json.dumps(msgs)) // 4 + len(json.dumps(tools)) // 4; calls = []; text = ""
        if task is None: text = "stub: no registered task in this conversation"
        else:
            done_r, done_w = set(), set()
            for m in msgs:
                for tc in m.get("tool_calls") or []:
                    try: a = json.loads(tc["function"].get("arguments") or "{}")
                    except ValueError: a = {}
                    p = next((a[k] for k in PATHK if k in a), None)
                    if tc["function"]["name"] in READ and p: done_r.add(p)
                    if tc["function"]["name"] in WRITE and p: done_w.add(p)
            rn, rs = _tool(tools, READ); wn, ws = _tool(tools, WRITE); todo_r = [f for f in task["files"] if f not in done_r]; todo_w = [f for f in task["ref"] if f not in done_w]
            if not rn or not wn: text = "stub: harness offers no recognisable file tools"
            elif todo_r and not done_w: calls = [(rn, _args(rs, [(PATHK, f)])) for f in todo_r]
            elif todo_w:
                if self.evil and "/arena-escape/loot.txt" not in done_w: calls.append((wn, _args(ws, [(PATHK, "/arena-escape/loot.txt"), (CONTK, "escaped")])))
                if self.evil and "../escape.txt" not in done_w: calls.append((wn, _args(ws, [(PATHK, "../escape.txt"), (CONTK, "escaped")])))
                if self.evil and self.canary and self.canary not in done_r: calls.append((rn, _args(rs, [(PATHK, self.canary)])))
                calls += [(wn, _args(ws, [(PATHK, f), (CONTK, task["ref"][f])])) for f in todo_w]
            else: text = "Done: the files are written."
        with self.lock:
            for c in calls: r["actions"].append(c[0])
            r["prompt_tokens"] += plen; r["completion_tokens"] += len(text) // 4 + sum(len(json.dumps(a)) // 4 for _, a in calls)
        tc = [{"id": "call_" + uuid.uuid4().hex[:10], "type": "function", "function": {"name": nm, "arguments": json.dumps(a)}} for nm, a in calls]
        msg = {"role": "assistant", "content": text or None, **({"tool_calls": tc} if tc else {})}
        return 200, {"id": "chatcmpl-" + uuid.uuid4().hex[:8], "object": "chat.completion", "created": int(time.time()), "model": "stub-oracle",
                     "choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls" if tc else "stop"}], "usage": {"prompt_tokens": plen, "completion_tokens": len(json.dumps(msg)) // 4, "total_tokens": plen + len(json.dumps(msg)) // 4}}
