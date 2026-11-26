"""Board HTTP API (JSON, bearer tokens only: no cookies, so no CSRF surface; no CORS). Binds loopback unless --allow-public-bind; put TLS in front for anything else.
The lease API for workers is a separate listener (coordinator.py)."""
from __future__ import annotations
import json, re, threading, time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from .service import Board, BoardError, Invalid, NotFound, QuotaError
from .reliability import TRACE_RX

STATIC = Path(__file__).parent / "static"
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


class Limiter:
    def __init__(self): self.h = defaultdict(deque); self.l = threading.Lock()
    def allow(self, key, limit, window):
        now = time.monotonic()
        with self.l:
            q = self.h[key]
            while q and q[0] <= now - window: q.popleft()
            if len(q) >= limit: return False
            q.append(now); return True


def _n(conv, x, default):
    """Numeric body field: a list/object/huge value is the caller's mistake (422), never a server error."""
    try: return conv(x or default)
    except (TypeError, ValueError, OverflowError): raise Invalid("expected a number")


def make_handler(board: Board, limits=None, tls=False, access_log=None):
    streams = {}; streams_lock = threading.Lock(); MAX_STREAMS = 4
    lim = Limiter(); L = {"login": (20, 60), "auth_fail": (30, 60), "hook": (120, 60), "api": (600, 60), **(limits or {})}
    R = []
    def route(method, pattern):
        rx = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")
        def deco(fn): R.append((method, rx, fn)); return fn
        return deco
    b = board; b.http_counts = getattr(b, "http_counts", {})

    U = {}                                                                         # unauthenticated routes (credentials are in the body): per-IP limited, uniform errors
    def unauth(path):
        def deco(fn): U[path] = fn; return fn
        return deco
    @unauth("/v1/auth/login")
    def _login(ip, body): return b.login(body.get("email"), body.get("password"), body.get("org"), body.get("code"), ip)
    @unauth("/v1/auth/login/mfa")
    def _login_mfa(ip, body): return b.login_mfa(body.get("mfa_token"), body.get("code"), ip)
    @unauth("/v1/auth/forgot")
    def _forgot(ip, body): return b.request_password_reset(body.get("email"), ip)
    @unauth("/v1/auth/unlock")
    def _unlock(ip, body): return b.unlock_account(body.get("email"), body.get("code"), ip)
    @unauth("/v1/auth/accept-invite")
    def _acc(ip, body): return b.accept_invite(body.get("invite"), body.get("password"), body.get("name", ""), ip)
    @unauth("/v1/auth/reset")
    def _rst(ip, body): return b.reset_password(body.get("token"), body.get("password"), ip)
    @unauth("/v1/auth/sso/begin")
    def _sb(ip, body): return b.sso_begin(body.get("org"))
    @unauth("/v1/auth/sso/login")
    def _sl(ip, body): return b.sso_login(body.get("org"), body.get("id_token"), body.get("nonce"), ip)

    @route("GET", "/v1/me")
    def _me(p, m, body, q):
        out = {"role": p.role, "org": p.org, "project": p.project, "user": p.user}
        if p.user:
            u = b.db.c().execute("SELECT email,name,mfa_enabled FROM users WHERE id=?", (p.user,)).fetchone(); out.update(email=u["email"], name=u["name"], mfa=bool(u["mfa_enabled"]))
            out["require_mfa"] = bool(b.db.c().execute("SELECT require_mfa FROM orgs WHERE id=?", (p.org,)).fetchone()[0])
        return out
    @route("POST", "/v1/auth/logout")
    def _lo(p, m, body, q): return b.logout(p)
    @route("GET", "/v1/auth/sessions")
    def _ses(p, m, body, q): return {"sessions": b.sessions(p)}
    @route("DELETE", "/v1/auth/sessions/{sid}")
    def _rses(p, m, body, q): return b.revoke_session(p, m["sid"])
    @route("POST", "/v1/auth/password")
    def _pw(p, m, body, q): return b.change_password(p, body.get("old"), body.get("new"))
    @route("POST", "/v1/auth/mfa/begin")
    def _mb(p, m, body, q): return b.mfa_begin(p)
    @route("POST", "/v1/auth/mfa/confirm")
    def _mc(p, m, body, q): return b.mfa_confirm(p, body.get("code"))
    @route("POST", "/v1/auth/mfa/disable")
    def _md(p, m, body, q): return b.mfa_disable(p, body.get("password"), body.get("code"))
    @route("POST", "/v1/org/require-mfa")
    def _rm(p, m, body, q): return b.set_require_mfa(p, bool(body.get("on", True)))
    @route("GET", "/v1/members")
    def _mem(p, m, body, q): return {"members": b.members(p)}
    @route("PUT", "/v1/members/{uid}")
    def _smem(p, m, body, q): return b.set_member(p, m["uid"], body.get("role"), body.get("project"))
    @route("DELETE", "/v1/members/{uid}")
    def _rmem(p, m, body, q): return b.remove_member(p, m["uid"])
    @route("POST", "/v1/members/{uid}/reset-password")
    def _ipr(p, m, body, q): return b.issue_password_reset(p, m["uid"], _n(int, body.get("ttl_s"), 3600))
    @route("GET", "/v1/invites")
    def _inv(p, m, body, q): return {"invites": b.invites(p)}
    @route("POST", "/v1/invites")
    def _cinv(p, m, body, q): return b.invite_user(p, body.get("email"), body.get("role"), body.get("project"), _n(int, body.get("ttl_s"), 7 * 86400))
    @route("DELETE", "/v1/invites/{iid}")
    def _rinv(p, m, body, q): return b.revoke_invite(p, m["iid"])
    @route("GET", "/v1/sso")
    def _gsso(p, m, body, q): return {"sso": b.sso_config(p)}
    @route("PUT", "/v1/sso")
    def _psso(p, m, body, q): return b.set_sso(p, body.get("issuer"), body.get("client_id"), body.get("alg"), body.get("jwks"), body.get("domains"), body.get("default_role", "member"), bool(body.get("enforce")))
    @route("GET", "/v1/keys")
    def _lk(p, m, body, q): return {"keys": b.keys(p)}
    @route("POST", "/v1/keys/{kid}/rotate")
    def _rotk(p, m, body, q): return b.rotate_key(p, m["kid"], _n(int, body.get("grace_s") if body.get("grace_s") is not None else 3600, 3600))
    @route("POST", "/v1/admin/orgs")
    def _co(p, m, body, q): return b.create_org(p, body.get("id"), body.get("name", ""), body.get("plan", "free"))
    @route("POST", "/v1/admin/orgs/{org}/plan")
    def _plan(p, m, body, q): return b.set_plan(p, m["org"], body.get("plan"))
    @route("POST", "/v1/admin/orgs/{org}/status")
    def _st(p, m, body, q): return b.set_org_status(p, m["org"], body.get("status"))
    @route("POST", "/v1/admin/kill")
    def _kill(p, m, body, q): return b.kill(p, bool(body.get("on", True)))
    @route("POST", "/v1/admin/workers")
    def _pw(p, m, body, q): return b.register_worker(p, body.get("engine"), body.get("capabilities"), node=body.get("node"), platform=True)
    @route("GET", "/v1/admin/health")
    def _h(p, m, body, q): b._need(p, "platform"); return b.health()
    @route("GET", "/v1/projects")
    def _lp(p, m, body, q): return {"projects": b.projects(p)}
    @route("POST", "/v1/projects")
    def _cp(p, m, body, q): return b.create_project(p, body.get("id"), body.get("budget_usd"))
    @route("POST", "/v1/projects/{project}/pause")
    def _pa(p, m, body, q): return b.pause_project(p, m["project"], True)
    @route("POST", "/v1/projects/{project}/resume")
    def _re(p, m, body, q): return b.pause_project(p, m["project"], False)
    @route("POST", "/v1/keys")
    def _ik(p, m, body, q): return b.issue_key(p, body.get("role"), body.get("project"), body.get("label", ""), body.get("ttl_s"))
    @route("DELETE", "/v1/keys/{kid}")
    def _rk(p, m, body, q): return b.revoke_key(p, m["kid"])
    @route("GET", "/v1/projects/{project}/agents")
    def _la(p, m, body, q): return {"agents": b.agents(p, m["project"])}
    @route("PUT", "/v1/projects/{project}/agents/{aid}")
    def _da(p, m, body, q): return b.define_agent(p, m["project"], m["aid"], body)
    @route("GET", "/v1/projects/{project}/teams")
    def _lt(p, m, body, q): return {"teams": b.teams(p, m["project"])}
    @route("PUT", "/v1/projects/{project}/teams/{tid}")
    def _dt(p, m, body, q): return b.define_team(p, m["project"], m["tid"], body.get("lead"), body.get("members"))
    @route("POST", "/v1/projects/{project}/jobs")
    def _sj(p, m, body, q):
        bad = set(body) - {"prompt", "agent_id", "agent", "engine", "limits", "model_ref", "idem_key", "workspace", "validators", "priority"}
        if bad: raise Invalid(f"unknown fields {sorted(bad)}")      # org/project/spec fields can never be supplied by a caller
        return b.submit_job(p, m["project"], body.get("prompt"), body.get("agent_id"), body.get("agent"), body.get("engine"), body.get("limits"), body.get("model_ref"), body.get("idem_key"), body.get("workspace"), body.get("validators"), _n(int, body.get("priority"), 0))
    @route("GET", "/v1/projects/{project}/jobs")
    def _lj(p, m, body, q): return {"jobs": b.list_jobs(p, m["project"], (q.get("status") or [None])[0], _n(int, (q.get("limit") or [100])[0], 100))}
    @route("GET", "/v1/projects/{project}/jobs/{jid}")
    def _gj(p, m, body, q): return b.get_job(p, m["project"], m["jid"])
    @route("POST", "/v1/projects/{project}/jobs/{jid}/cancel")
    def _cj(p, m, body, q): return b.cancel_job(p, m["project"], m["jid"])
    @route("POST", "/v1/projects/{project}/jobs/{jid}/approve")
    def _aj(p, m, body, q): return b.approve_job(p, m["project"], m["jid"], body.get("resolution", "retry"))
    @route("GET", "/v1/projects/{project}/jobs/{jid}/events")
    def _ej(p, m, body, q): return {"events": b.job_events(p, m["project"], m["jid"])}
    @route("GET", "/v1/projects/{project}/jobs/{jid}/timings")
    def _tj(p, m, body, q): return b.job_timings(p, m["project"], m["jid"])
    @route("GET", "/v1/projects/{project}/jobs/{jid}/outputs")
    def _oj(p, m, body, q):
        rows = b.job_outputs(p, m["project"], m["jid"], _n(int, q.get("after", [0])[0], 0),
                             _n(int, q.get("limit", [100])[0], 100))
        return {"outputs": rows, "next_after": rows[-1]["id"] if rows else None}
    @route("GET", "/v1/projects/{project}/memory/{ns}")
    def _ml(p, m, body, q): return b.memory(p, m["project"], "list", m["ns"])
    @route("GET", "/v1/projects/{project}/memory/{ns}/{key}")
    def _mg(p, m, body, q): return b.memory(p, m["project"], "get", m["ns"], m["key"])
    @route("PUT", "/v1/projects/{project}/memory/{ns}/{key}")
    def _mp(p, m, body, q): return b.memory(p, m["project"], "put", m["ns"], m["key"], body.get("value"))
    @route("GET", "/v1/projects/{project}/schedules")
    def _ls(p, m, body, q): return {"schedules": b.schedules(p, m["project"])}
    @route("POST", "/v1/projects/{project}/schedules")
    def _cs(p, m, body, q): return b.create_schedule(p, m["project"], body.get("name", ""), body.get("prompt"), body.get("agent_id"), body.get("every"), _n(int, body.get("max_per_day"), 6), bool(body.get("webhook")), body.get("engine"), body.get("limits"))
    @route("POST", "/v1/projects/{project}/schedules/{sid}/{act}")
    def _ss(p, m, body, q):
        if m["act"] not in ("enable", "disable"): raise NotFound("route")
        return b.set_schedule(p, m["project"], m["sid"], m["act"] == "enable")
    @route("GET", "/v1/workers")
    def _lw(p, m, body, q): return {"workers": b.workers(p)}
    @route("POST", "/v1/workers")
    def _rw(p, m, body, q): return b.register_worker(p, body.get("engine"), body.get("capabilities"), body.get("project"), body.get("node"))
    @route("POST", "/v1/workers/{wid}/{act}")
    def _wa(p, m, body, q):
        if m["act"] in ("drain", "undrain"): return b.drain_worker(p, m["wid"], m["act"] == "drain")
        if m["act"] == "revoke": return b.revoke_worker(p, m["wid"])
        raise NotFound("route")
    @route("GET", "/v1/spending")
    def _bs(p, m, body, q): return b.spending_state(p)
    @route("PUT", "/v1/spending/limits")
    def _bl(p, m, body, q): return b.set_spend_limit(p, body.get("gateway_budget_usd"))
    @route("GET", "/v1/alerts")
    def _al(p, m, body, q): return {"alerts": b.alerts_of(p)}
    @route("GET", "/v1/secrets")
    def _sl(p, m, body, q): return {"secrets": b.secrets_list(p)}
    @route("PUT", "/v1/secrets/{name}")
    def _sp(p, m, body, q): return b.put_secret(p, m["name"], body.get("value"), body.get("project"))
    @route("DELETE", "/v1/secrets/{name}")
    def _sd(p, m, body, q): return b.delete_secret(p, m["name"], (q.get("project") or [None])[0])
    @route("GET", "/v1/hosted")
    def _hl(p, m, body, q): return {"hosted": b.hosted_list(p)}
    @route("POST", "/v1/hosted")
    def _hp(p, m, body, q): return b.provision_worker(p, body.get("name", ""), body.get("slots", 2), body.get("project"), body.get("endpoints") or [])
    @route("POST", "/v1/hosted/{hid}/{act}")
    def _ha(p, m, body, q):
        a = m["act"]
        if a == "stop": return b.stop_hosted(p, m["hid"])
        if a == "start": return b.start_hosted(p, m["hid"])
        if a == "scale": return b.scale_hosted(p, m["hid"], body.get("slots"))
        if a == "deprovision": return b.deprovision_hosted(p, m["hid"])
        raise NotFound("route")
    @route("GET", "/v1/health")
    def _ho(p, m, body, q): return b.health_of(p)
    @route("POST", "/v1/projects/{project}/jobs/{jid}/retry")
    def _rj(p, m, body, q): return b.retry_job(p, m["project"], m["jid"])
    @route("POST", "/v1/admin/vault/rotate")
    def _vr(p, m, body, q): return b.rotate_master_key(p)
    @route("GET", "/v1/traces/{tid}")
    def _tr(p, m, body, q): return b.trace_view(p, m["tid"])
    @route("PUT", "/v1/retention")
    def _rt(p, m, body, q): return b.set_retention(p, body.get("job_days"))
    @route("POST", "/v1/admin/orgs/erase")
    def _er(p, m, body, q): return b.erase_org(p, body.get("org"), body.get("confirm"))
    @route("GET", "/v1/outbox")
    def _ob(p, m, body, q): return b.outbox_of(p)
    @route("GET", "/v1/usage")
    def _us(p, m, body, q): return b.usage(p, (q.get("project") or [None])[0], float((q.get("since") or [0])[0]))
    @route("GET", "/v1/audit")
    def _au(p, m, body, q): return b.audit_export(p, _n(int, (q.get("after") or [0])[0], 0), _n(int, (q.get("limit") or [1000])[0], 1000))

    class H(BaseHTTPRequestHandler):
        server_version = "ORDIVYR-Board"; sys_version = ""; protocol_version = "HTTP/1.1"; timeout = 60          # a stalled client cannot pin a thread forever
        def log_message(self, *a): pass
        def _send(self, code, obj, ctype="application/json", extra=None):
            raw = obj if isinstance(obj, bytes) else json.dumps(obj, default=str).encode()
            self._code = code; b.http_counts[f"{code // 100}xx"] = b.http_counts.get(f"{code // 100}xx", 0) + 1
            self.send_response(code); self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            if tls: self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            self.send_header("X-Trace-Id", getattr(self, "_trace", "-"))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Content-Security-Policy", CSP); self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items(): self.send_header(k, v)
            self.end_headers(); self.wfile.write(raw)
        def _sse(self, p, project, jid, q):
            """text/event-stream of one job's lifecycle, steps and spend-relevant status. Headers go out only after the job is authorised (so 403/404 stay JSON)."""
            b._scope(p, project, "read"); b._row(p.org, project, jid)
            with streams_lock:
                over = streams.get(p.kid, 0) >= MAX_STREAMS
                if not over: streams[p.kid] = streams.get(p.kid, 0) + 1
            if over: return self._send(429, {"error": {"code": "rate_limited", "message": f"at most {MAX_STREAMS} live streams per key"}})
            try:
                self._code = 200; self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Cache-Control", "no-store"); self.send_header("X-Accel-Buffering", "no")
                self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("X-Trace-Id", getattr(self, "_trace", "-")); self.send_header("Connection", "close"); self.end_headers(); self.close_connection = True
                dead = []
                def emit(event, data):
                    try: self.wfile.write(f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n".encode()); self.wfile.flush()
                    except OSError: dead.append(1)
                try: b.job_stream(p, project, jid, emit, alive=lambda: not dead, after=int((q.get("after") or ["0"])[0]) if (q.get("after") or ["0"])[0].isdigit() else 0)
                except BoardError as e: emit("error", {"code": e.code, "message": str(e)})
            finally:
                with streams_lock: streams[p.kid] = max(0, streams.get(p.kid, 1) - 1)
        def _body(self):
            cl = (self.headers.get("Content-Length") or "0").strip()
            if not cl.isdigit(): self.close_connection = True; raise Invalid("bad Content-Length")           # int() on junk was a 500; a negative length read until EOF
            n = int(cl)
            if n > 262_144: self.close_connection = True; raise Invalid("body too large")
            raw = self.rfile.read(n) if n else b""
            if not raw: return {}
            try: j = json.loads(raw)
            except (ValueError, RecursionError): raise Invalid("body is not JSON (or is nested too deeply)")
            if not isinstance(j, dict): raise Invalid("body must be a JSON object")
            def nul(x): return "\x00" in x if isinstance(x, str) else any(nul(k) or nul(v) for k, v in x.items()) if isinstance(x, dict) else any(nul(v) for v in x) if isinstance(x, list) else False
            try:
                if nul(j): raise Invalid("NUL bytes are not allowed")
            except RecursionError: raise Invalid("body is nested too deeply")
            return j
        def _run(self, method):
            t0 = time.monotonic(); self._code = 0; self._who = None
            tr = self.headers.get("X-Trace-Id") or ""; self._trace = tr if TRACE_RX.fullmatch(tr) else b.new_trace(); b.set_trace(self._trace)
            try: self._run2(method)
            finally:
                b.set_trace(None)
                if access_log: access_log({"trace": self._trace, "ts": round(time.time(), 3), "method": method, "path": urlparse(self.path).path[:120] if not re.search(r"/(hooks|auth)/", self.path) else "/" + self.path.split("/")[1] + "/…", "status": self._code, "ms": round((time.monotonic() - t0) * 1000, 1), "who": self._who})
        def _run2(self, method):
            try:
                u = urlparse(self.path); path = u.path.rstrip("/") or "/"; ip = self.client_address[0]
                if method == "GET" and path in ("/", "/dashboard.js", "/dashboard.css", "/mark.svg", "/brand.png"):
                    f = {"/": ("index.html", "text/html; charset=utf-8"), "/dashboard.js": ("dashboard.js", "application/javascript"), "/dashboard.css": ("dashboard.css", "text/css"), "/mark.svg": ("mark.svg", "image/svg+xml"), "/brand.png": ("brand.png", "image/png")}[path]
                    return self._send(200, (STATIC / f[0]).read_bytes(), f[1])
                if path == "/healthz": return self._send(200, {"ok": True})
                if method == "GET" and path == "/metrics":
                    pp = b.principal(self.headers.get("Authorization", "")[7:]); 
                    if pp is None or pp.role != "platform": return self._send(401, {"error": {"code": "unauthorized", "message": "metrics need the platform key"}})
                    return self._send(200, b.metrics_text().encode(), "text/plain; version=0.0.4")
                if path == "/readyz": return self._send(200, {"ok": True, "killed": b.killed})
                body = self._body() if method in ("POST", "PUT", "DELETE") else {}
                m = re.fullmatch(r"/v1/hooks/([^/]+)/([^/]+)", path)
                if m and method == "POST":
                    if not lim.allow(("hook", ip), *L["hook"]): return self._send(429, {"error": {"code": "rate_limited", "message": "slow down"}})
                    return self._send(202, b.fire_hook(m.group(1), m.group(2), self.headers.get("Idempotency-Key")))
                if method == "POST" and path in U:
                    if not lim.allow(("login", ip), *L["login"]): return self._send(429, {"error": {"code": "rate_limited", "message": "too many attempts"}})
                    return self._send(200, U[path](ip, body))
                tok = self.headers.get("Authorization", "")[7:] if self.headers.get("Authorization", "").startswith("Bearer ") else ""
                p = b.principal(tok)
                if p is None:
                    if not lim.allow(("auth", ip), *L["auth_fail"]): return self._send(429, {"error": {"code": "rate_limited", "message": "too many failed attempts"}})
                    return self._send(401, {"error": {"code": "unauthorized", "message": "missing, invalid, expired or revoked key"}})
                self._who = f"{p.role}:{p.org}:{p.kid}"
                if not lim.allow(("api", p.kid), *L["api"]): return self._send(429, {"error": {"code": "rate_limited", "message": "slow down"}})
                ms = re.fullmatch(r"/v1/projects/([^/]+)/jobs/([^/]+)/stream", path)
                if ms and method == "GET": return self._sse(p, ms.group(1), ms.group(2), parse_qs(u.query))
                for meth, rx, fn in R:
                    mm = rx.fullmatch(path)
                    if mm and meth == method: return self._send(200, fn(p, mm.groupdict(), body, parse_qs(u.query)))
                self._send(404, {"error": {"code": "not_found", "message": "no such route"}})
            except BoardError as e: self._send(e.status, {"error": {"code": e.code, "message": str(e), **e.ctx}})
            except Exception as e:
                b.db.meta("last_api_error", f"{type(e).__name__}: {e}"[:300]); self._send(500, {"error": {"code": "internal", "message": "internal error"}})      # details stay in the operator log, never in the response
        def do_GET(self): self._run("GET")
        def do_POST(self): self._run("POST")
        def do_PUT(self): self._run("PUT")
        def do_DELETE(self): self._run("DELETE")
    return H


def serve(board, host="127.0.0.1", port=0, allow_public_bind=False, limits=None, tls=None, access_log=None):
    if host not in ("127.0.0.1", "::1", "localhost") and not allow_public_bind: raise SystemExit("refusing to bind a non-loopback address without --allow-public-bind (and TLS in front)")
    class Srv(ThreadingHTTPServer):
        daemon_threads = True; request_queue_size = 256
    srv = Srv((host, port), make_handler(board, limits, bool(tls), access_log))
    if tls:
        import ssl; ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2; ctx.load_cert_chain(*tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    srv.tls = bool(tls); threading.Thread(target=srv.serve_forever, daemon=True, name="board-api").start(); return srv
