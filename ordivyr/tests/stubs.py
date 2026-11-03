"""Real loopback HTTP stub server for adapter tests: routes[(METHOD, path)] = fn(req_json, headers) -> (status, headers, bytes|dict)."""
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Stub:
    def __init__(self):
        self.routes, self.seen = {}, []
        outer = self
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _do(self, method):
                n = int(self.headers.get("Content-Length") or 0); raw = self.rfile.read(n) if n else b""
                try: body = json.loads(raw) if raw else None
                except ValueError: body = None
                outer.seen.append((method, self.path, body, {k.lower(): v for k, v in self.headers.items()}))
                fn = outer.routes.get((method, self.path))
                if not fn: self.send_response(404); self.end_headers(); return
                st, hd, out = fn(body, self.headers)
                data = out if isinstance(out, bytes) else json.dumps(out).encode()
                self.send_response(st)
                for k, v in {"Content-Type": "application/json", **hd}.items(): self.send_header(k, v)
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
            def do_GET(self): self._do("GET")
            def do_POST(self): self._do("POST")
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H); self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
    def route(self, method, path, fn): self.routes[(method, path)] = fn
    def close(self): self.srv.shutdown(); self.srv.server_close()
