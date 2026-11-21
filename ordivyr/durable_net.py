"""Loopback lease API so workers on other machines (reached through `ssh -R`) use the same durable store without sharing the SQLite file.

Coordinator = a tiny threaded HTTP server wrapping a Store (bearer-token auth, whitelisted methods, JSON in/out). RemoteStore = the same method surface over
HTTP. Every StaleLease/NeedsApproval raised by the Store crosses the wire as a typed error, so fencing is enforced server-side regardless of what the
remote worker believes about its own lease.
"""
from __future__ import annotations
import hashlib, hmac, http.client, json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
MAX_RPC_BODY = 16 * 1024 * 1024
from . import durable as D

METHODS = ("submit", "claim", "claim_many", "heartbeat", "heartbeat_many", "begin", "checkpoint", "apply", "record_output", "add_evidence", "evidence", "complete", "fail", "release", "hold", "cancelled",
           "op_begin", "op_resolve", "op_commit", "get", "cancel", "counts", "cap", "tenant_set", "usage_of", "get_for", "cancel_for", "counts_for", "events_for", "reap", "claim_many_wait", "node_report", "nodes", "freeze_tenant", "active_of", "export_queued", "retire")
WORKER_METHODS = frozenset({"claim", "claim_many", "heartbeat", "heartbeat_many", "begin", "checkpoint", "apply", "record_output", "add_evidence", "evidence", "complete", "fail", "release", "hold", "cancelled", "op_begin", "op_resolve", "op_commit", "get", "cap", "claim_many_wait", "node_report"})
TENANT_METHODS = {"submit": "submit", "get": "get_for", "cancel": "cancel_for", "counts": "counts_for", "events": "events_for", "usage": "usage_of"}   # a tenant token reaches ONLY these, always bound to its own tenant
FENCED = frozenset({"heartbeat", "begin", "checkpoint", "apply", "record_output", "add_evidence", "complete", "fail", "release", "hold", "cancelled", "op_begin", "op_resolve", "op_commit", "get", "evidence"})
ERRORS = {"StaleLease": D.StaleLease, "NeedsApproval": D.NeedsApproval, "Cancelled": D.Cancelled, "QuotaExceeded": D.QuotaExceeded, "Forbidden": PermissionError}

class Coordinator:
    def __init__(self, store, token, host="127.0.0.1", port=0, principals=None, reap_every=None, tls=None):
        """`token` = the original single admin bearer token. `principals` = {token: {"role": "admin"|"worker"|"tenant", "tenant": name, "tenants": [names]}} for multi-tenant hosting."""
        self.store, self.token = store, token; self.reap_every = reap_every; self._stop = threading.Event(); self.rpcs = 0; self.conns = set(); self.principals = {hashlib.sha256(k.encode()).hexdigest(): v for k, v in (principals or {}).items()}
        outer = self
        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"          # keep-alive: one TCP connection serves many RPCs (a fresh connection per call was a measurable share of coordinator CPU)
            timeout = 120                          # idle keep-alive connections are reaped so threads are not pinned forever
            def log_message(self, *a): pass
            def setup(self): super().setup(); outer.conns.add(self.connection)
            def finish(self):
                try: super().finish()
                finally: outer.conns.discard(self.connection)
            def do_POST(self):
                try:
                    cl = (self.headers.get("Content-Length") or "0").strip()
                    if not cl.isdigit() or int(cl) > MAX_RPC_BODY:                    # unauthenticated callers must not make us buffer an attacker-chosen amount (or read a negative length: until EOF)
                        self.close_connection = True; return self._send(413 if cl.isdigit() else 400, {"error": "body", "msg": "bad or oversized Content-Length"})
                    pr = outer.auth(self.headers.get("Authorization", ""))
                    raw = self.rfile.read(int(cl)) or b"{}"                            # always drain the body: an unread body corrupts a keep-alive connection
                    if pr is None: return self._send(401, {"error": "auth", "msg": "bad token"})
                    outer.rpcs += 1
                    body = json.loads(raw); m = body.get("m"); a = list(body.get("a", [])); k = dict(body.get("k", {}))
                    m, a, k = outer.scope(pr, m, a, k)
                    r = getattr(outer.store, m)(*a, **k)
                    self._send(200, {"ok": r})
                except PermissionError as e: self._send(403, {"error": "Forbidden", "msg": str(e)})
                except (D.StaleLease, D.NeedsApproval, D.Cancelled, D.QuotaExceeded) as e: self._send(409, {"error": type(e).__name__, "msg": str(e)})
                except Exception as e: self._send(500, {"error": "server", "msg": f"{type(e).__name__}: {e}"})
            def _send(self, code, obj):
                b = json.dumps(obj, default=str).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        ThreadingHTTPServer.request_queue_size = 1024          # default backlog (5) resets connections under burst; found by the 100/1000-agent HTTP benchmark
        class Srv(ThreadingHTTPServer):
            def handle_error(self, request, client_address):          # a peer that vanished mid-reply (killed worker, partition) is routine, not a traceback
                import sys
                if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, TimeoutError)): super().handle_error(request, client_address)
        Srv.request_queue_size = 1024
        self.httpd = Srv((host, port), H); self.httpd.daemon_threads = True; self.tls = bool(tls)
        if tls:                                                    # (cert, key): TLS >= 1.2; the handshake happens lazily in each handler thread so a slow client cannot stall accept()
            import ssl; ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2; ctx.load_cert_chain(*tls)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True, do_handshake_on_connect=False)
        self.port = self.httpd.server_address[1]; self.thread = None
    def auth(self, header):
        if hmac.compare_digest(header, "Bearer " + self.token): return {"role": "admin"}
        return self.principals.get(hashlib.sha256(header[7:].encode()).hexdigest()) if header.startswith("Bearer ") else None
    def scope(self, pr, m, a, k):
        """Role gate + tenant binding. Raises PermissionError (-> 403) for anything the principal may not do; the tenant name is taken from the TOKEN, never from the request."""
        role = pr.get("role")
        if role == "admin":
            if m not in METHODS: raise PermissionError(f"unknown method {m!r}")
            return m, a, k
        if role == "tenant":
            if m not in TENANT_METHODS: raise PermissionError(f"tenant principals cannot call {m!r}")
            t = pr["tenant"]; m2 = TENANT_METHODS[m]
            if m == "submit": k.pop("tenant", None); k["tenant"] = t; return m2, a, k
            if m == "usage": return m2, [t], {}
            return m2, [t, *a], k
        if role == "worker":
            if m not in WORKER_METHODS: raise PermissionError(f"workers cannot call {m!r}")
            ts = pr.get("tenants")
            if ts is not None:                                    # a restricted worker; [] means "serves nobody" (the queue treats an empty filter as ALL, so it is replaced by an impossible tenant)
                ts = list(ts) or ["~no-such-tenant~"]
                if m in ("claim", "claim_many", "claim_many_wait"): k["tenants"] = ts
                elif m in FENCED or m == "heartbeat_many":
                    import inspect
                    try: args = dict(inspect.signature(getattr(self.store, m)).bind(*a, **k).arguments)      # positional or keyword: the check cannot be skipped by call spelling
                    except TypeError as e: raise PermissionError(f"malformed call to {m!r}: {e}")
                    tids = [x[0] for x in args["leases"]] if "leases" in args else [args["tid"]] if "tid" in args else None
                    if tids is None: raise PermissionError(f"{m!r} names no task: refused")
                    for tid in tids:
                        tn = self.store.tenant_of(tid) if hasattr(self.store, "tenant_of") else (self.store._conn().execute("SELECT tenant FROM tasks WHERE id=?", (tid,)).fetchone() or [None])[0]
                        if tn is None or tn not in ts: raise PermissionError("task belongs to a tenant this worker does not serve")
            return m, a, k
        raise PermissionError("no role")
    def _reaper(self):
        while not self._stop.wait(self.reap_every):
            try: self.store.reap()                                    # expired leases go back to the queue even if no supervisor process is running
            except Exception: pass
    def start(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="ordivyr-coordinator"); self.thread.start()
        if self.reap_every: threading.Thread(target=self._reaper, daemon=True, name="ordivyr-reaper").start()
        return self
    def stop(self):
        self._stop.set(); self.httpd.shutdown(); self.httpd.server_close()
        for c in list(self.conns):                      # a stopped coordinator must also drop its keep-alive connections (as a real process exit would)
            try: c.shutdown(2)
            except OSError: pass

class RemoteError(Exception):
    """The coordinator could not be reached (partition, tunnel down) - the caller must treat its lease as unprovable."""

IDEMPOTENT = frozenset({"heartbeat", "heartbeat_many", "get", "counts", "cap", "evidence"})   # safe to repeat if a reply was lost on a reused connection

class RemoteStore:
    """Method-for-method proxy for Store over HTTP. keepalive=True (default) keeps a SMALL POOL of persistent connections (`pool` max, shared by all threads of this client):
    500 worker threads share ~8 sockets instead of opening 500, which is what keeps the coordinator's thread count and accept queue bounded at thousands of agents.
    keepalive=False is the original connect-per-call behaviour, kept so benchmarks can A/B it. Retry policy on a reused connection: a failure while SENDING is retried once for any
    method (a half-sent request is never executed); a failure while waiting for the reply is retried only for IDEMPOTENT methods - otherwise it surfaces as RemoteError exactly as
    before (lease unprovable)."""
    def __init__(self, url, token, timeout=5.0, keepalive=True, pool=8):
        from urllib.parse import urlparse
        u = urlparse(url); self.host, self.port, self.token, self.timeout, self.keepalive = u.hostname, u.port, token, timeout, keepalive; self.tls_ctx = None
        if u.scheme == "https":
            import ssl, os; self.tls_ctx = ssl.create_default_context(cafile=os.environ.get("ORDIVYR_LEASE_CA") or None)       # verifies the server; a private CA goes in ORDIVYR_LEASE_CA
        self._idle = []; self._plock = threading.Lock(); self._slots = threading.BoundedSemaphore(max(1, pool)); self.rpcs = 0; self.connects = 0
    def _acquire(self):
        self._slots.acquire()
        with self._plock:
            if self._idle: return self._idle.pop(), True
        self.connects += 1; return (http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.tls_ctx) if self.tls_ctx else http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)), False
    def _release(self, c, keep):
        if keep and self.keepalive:
            with self._plock: self._idle.append(c)
        else:
            try: c.close()
            except Exception: pass
        self._slots.release()
    def _rpc(self, m, a, k):
        payload = json.dumps({"m": m, "a": a, "k": k}); hdr = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        if not self.keepalive: hdr["Connection"] = "close"
        self.rpcs += 1; tmo = self.timeout + (float(k.get("wait_s") or 0) if m == "claim_many_wait" else 0.0)
        for attempt in (0, 1):
            c, reused = self._acquire(); sent = False; keep = False
            try:
                c.timeout = tmo
                if c.sock is not None: c.sock.settimeout(tmo)
                c.request("POST", "/", payload, hdr); sent = True; r = c.getresponse(); raw = r.read(); j = json.loads(raw or b"{}"); keep = not r.will_close
                self._release(c, keep); break
            except (OSError, http.client.HTTPException, ValueError) as e:
                self._release(c, False)
                if attempt == 0 and reused and (not sent or m in IDEMPOTENT): continue
                raise RemoteError(f"{type(e).__name__}: {e}") from e
        if r.status == 200: return j["ok"]
        if j.get("error") in ERRORS: raise ERRORS[j["error"]](j.get("msg"))
        if r.status == 403: raise PermissionError(j.get("msg"))
        raise RemoteError(f"coordinator {r.status}: {j}")
    def __getattr__(self, name):
        if name == "heartbeat_many": raise AttributeError(name)
        if name not in METHODS and name not in TENANT_METHODS: raise AttributeError(name)
        return lambda *a, **k: self._rpc(name, list(a), k)
    def heartbeat_many(self, leases, ttl=15.0): return {int(k): v for k, v in self._rpc("heartbeat_many", [[list(x) for x in leases]], {"ttl": ttl}).items()}
    def effect(self, tid, fence, op_key, do, reconcile=None): return D.run_effect(self, tid, fence, op_key, do, reconcile)
