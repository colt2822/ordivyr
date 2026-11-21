"""Test/demo support for Board. STUB: the model is a scripted loopback OpenAI-compatible server (no network, no spend); everything else (queue, leases, coordinator HTTP, workers) is real."""
import json, os, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class ScriptedModel:
    """scripts: {name: [step,...]} with step = ("tool", name, args) | ("say", text) | ("sleep", seconds). The script for a request is chosen by a `[[name]]` marker in the user prompt;
    the step index = how many assistant messages the conversation already has. Records every request in .seen."""
    def __init__(self, scripts=None, usage=(11, 7)):
        self.scripts = dict(scripts or {}); self.seen = []; self.once = set(); self.usage = usage; outer = self
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}"); outer.seen.append(body)
                msgs = body.get("messages") or []; user = next((m["content"] for m in msgs if m["role"] == "user"), "")
                mk = re.search(r"\[\[([\w.-]+)\]\]", str(user)); script = outer.scripts.get(mk.group(1) if mk else "", [("say", "ok")])
                i = sum(1 for m in msgs if m["role"] == "assistant"); step = script[i] if i < len(script) else ("say", "done")
                if step[0] == "sleep": time.sleep(step[1]); step = ("say", "woke")
                if step[0] == "sleep_once":                      # only the FIRST request for this script sleeps (a re-run after a crash answers immediately)
                    first = (mk.group(1) if mk else "") not in outer.once; outer.once.add(mk.group(1) if mk else "")
                    if first: time.sleep(step[1])
                    step = ("say", "recovered")
                if step[0] == "tool_after": time.sleep(step[1]); step = ("tool", step[2], step[3])
                if step[0] == "tool":
                    msg = {"role": "assistant", "content": None, "tool_calls": [{"id": f"c{i}", "type": "function", "function": {"name": step[1], "arguments": step[2] if isinstance(step[2], str) else json.dumps(step[2])}}]}; fin = "tool_calls"
                else: msg = {"role": "assistant", "content": step[1]}; fin = "stop"
                out = json.dumps({"model": body.get("model"), "choices": [{"message": msg, "finish_reason": fin}], "usage": {"prompt_tokens": outer.usage[0], "completion_tokens": outer.usage[1]}}).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H); self.srv.daemon_threads = True; self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/v1"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
    def close(self): self.srv.shutdown(); self.srv.server_close()
    def offered(self): return [sorted(t["function"]["name"] for t in (b.get("tools") or [])) for b in self.seen]


def wait_for(fn, timeout=20.0, step=0.1, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v: return v
        time.sleep(step)
    raise AssertionError(f"timed out waiting for {what}")


class World:
    """A real Board + lease-API coordinator + (optional) workers on loopback."""
    def __init__(self, tmp, scripts=None, monkeypatch=None):
        from ordivyr.board.service import Board, P
        from ordivyr.board.coordinator import BoardCoordinator
        from ordivyr.selfhost.gateway import Gateway
        self.tmp = Path(tmp); self.pg = None; dsn = None
        admin = os.environ.get("BOARD_TEST_PG_DSN")
        if admin:                                                    # run the same suite against a REAL PostgreSQL: one fresh database per World
            import psycopg, secrets as _s
            self.pg = (admin, "bt_" + _s.token_hex(5)); c = psycopg.connect(admin, autocommit=True); c.execute(f'CREATE DATABASE "{self.pg[1]}"'); c.close(); dsn = admin.replace("/postgres?", f"/{self.pg[1]}?", 1)
        self.dsn = dsn; self.board = Board(self.tmp / "board", dsn=dsn); self.P = P
        self.model = ScriptedModel(scripts); self.gwhome = self.tmp / "gw"; self.gwhome.mkdir(); Gateway(self.gwhome).add_local("stub", self.model.url)
        if monkeypatch: monkeypatch.setenv("ORDIVYR_GATEWAY_HOME", str(self.gwhome))
        else: os.environ["ORDIVYR_GATEWAY_HOME"] = str(self.gwhome)
        self.board.init_platform(); self.platform = self.board.principal((self.tmp / "board" / "platform.token").read_text())
        self.coord = BoardCoordinator(self.board, reap_every=0.5).start(); self.url = f"http://127.0.0.1:{self.coord.port}"
        self.stops = []; self.threads = []

    def reborn(self):
        """A second Board process over the same persistent state (works on both backends)."""
        from ordivyr.board.service import Board
        return Board(self.tmp / "board", store=self.board.store, dsn=self.dsn)

    def org(self, org, plan="team", projects=("p1",)):
        r = self.board.create_org(self.platform, org, org, plan); admin = self.board.principal(r["admin_key"])
        for p in projects: self.board.create_project(admin, p)
        return admin

    def agent(self, admin, project, aid, **spec):
        spec.setdefault("model_ref", {"endpoint": "stub", "model": "m"}); spec.setdefault("system", "be brief"); spec.setdefault("permissions", {}); return self.board.define_agent(admin, project, aid, spec)

    def worker(self, token, name, engine="ordivyr", slots=2, ttl=4.0, sandbox=False):
        from ordivyr.board import worker as BW
        stop = threading.Event(); ws = self.tmp / f"ws-{name}"; ws.mkdir(exist_ok=True)
        t = threading.Thread(target=BW.run, args=(self.url, token, name, str(ws), engine, slots, ttl, stop, 0.5), kwargs={"sandbox": sandbox}, daemon=True); t.start(); self.stops.append(stop); self.threads.append(t); return stop

    def platform_worker(self, name="plat", engine="ordivyr", slots=4, endpoints=("stub",), sandbox=True):
        """A SHARED pool worker. Sandboxed (bwrap namespace) by default, exactly as production requires."""
        from ordivyr.board import runtime_adapter as RA
        r = self.board.register_worker(self.platform, engine, RA.capabilities(slots, endpoints, isolation="namespace" if sandbox else "process"), platform=True); self.worker(r["token"], name, engine, slots, sandbox=sandbox); return r

    def done(self, admin, project, jid, timeout=30):
        return wait_for(lambda: (lambda v: v if v["status"] in ("completed", "failed", "cancelled", "held") else None)(self.board.get_job(admin, project, jid)), timeout, what=f"job {jid}")

    def close(self):
        for s in self.stops: s.set()
        for t in self.threads: t.join(5)
        self.coord.stop(); self.model.close()
        if self.pg:
            import psycopg
            for o in (self.board.store, self.board.db):
                try: o.close()
                except Exception: pass
            c = psycopg.connect(self.pg[0], autocommit=True); c.execute(f'DROP DATABASE IF EXISTS "{self.pg[1]}" WITH (FORCE)'); c.close()
