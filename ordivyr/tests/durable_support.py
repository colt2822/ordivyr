"""Real local processes used by the durable-execution tests: an OpenAI-compatible tool-calling model server and an idempotent side-effect sink.
The model server is a deterministic scripted policy (not an LLM): it makes the real agent loop issue real write_file tool calls over real HTTP, so
kill/restart behaviour of the server, the loop and the workers is genuine. The sink records every POST in an fsynced ledger keyed by Idempotency-Key.

  python -m ordivyr.tests.durable_support model PORT      |      python -m ordivyr.tests.durable_support sink PORT LEDGER
"""
import json, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def _serve(port, handler):
    s = ThreadingHTTPServer(("127.0.0.1", port), handler); s.daemon_threads = True; s.serve_forever()

class Model(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self._send(200, {"status": "ok"}) if self.path.startswith("/health") else self._send(404, {})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0))); msgs = body["messages"]
        spec = json.loads(next(m["content"] for m in msgs if m["role"] == "user")); k = sum(1 for m in msgs if m["role"] == "tool")
        time.sleep(spec.get("delay", 0))
        files = list(spec["files"].items())
        if k < len(files):
            name, content = files[k]
            msg = {"role": "assistant", "content": "", "tool_calls": [{"id": f"c{k}", "type": "function", "function": {"name": "write_file", "arguments": json.dumps({"path": name, "content": content})}}]}
        else: msg = {"role": "assistant", "content": "all files written"}
        self._send(200, {"model": "scripted-1", "choices": [{"message": msg}], "usage": {"total_tokens": 7}})

class Sink(BaseHTTPRequestHandler):
    ledger = None; lock = threading.Lock()
    def log_message(self, *a): pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def _rows(self):
        try: return [json.loads(l) for l in open(self.ledger) if l.strip()]
        except FileNotFoundError: return []
    def do_GET(self):
        if self.path.startswith("/lookup"):
            key = self.path.split("key=", 1)[1]; hit = [r for r in self._rows() if r["key"] == key]
            return self._send(200, {"found": bool(hit), "result": {"seq": hit[0]["seq"]} if hit else None})
        self._send(200, {"status": "ok"})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0))); key = self.headers["Idempotency-Key"]
        with self.lock:
            rows = self._rows(); hit = [r for r in rows if r["key"] == key]
            if not hit:
                row = {"seq": len(rows) + 1, "key": key, "ts": time.time(), "body": body}
                with open(self.ledger, "a") as f: f.write(json.dumps(row) + "\n"); f.flush(); os.fsync(f.fileno())
                hit = [row]
        time.sleep(float(self.headers.get("X-Delay-After", 0)))           # lets a test kill the caller after the effect landed but before it was acknowledged
        self._send(200, {"seq": hit[0]["seq"]})

if __name__ == "__main__":
    if sys.argv[1] == "model": _serve(int(sys.argv[2]), Model)
    else: Sink.ledger = sys.argv[3]; _serve(int(sys.argv[2]), Sink)
