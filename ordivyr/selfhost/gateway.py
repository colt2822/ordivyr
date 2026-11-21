"""Unified Provider Gateway: ONE request shape for local engines and cloud providers, with cost control that fails closed.

Request: gateway.chat(agent, endpoint, model, messages, tools=, response_format=, max_tokens=, allow_paid_fallback=) -> Reply(text, tool_calls, usage, cost_usd, model, endpoint, latency_s)
Errors are normalised to GatewayError(code, message, endpoint, retryable): auth | rate_limit | quota | bad_request | unsupported | server | network | timeout |
  paid_not_authorized | cap_exceeded | unpriced_model | capability_unsupported | unknown_endpoint.

Rules (all enforced in code, all tested):
  * Local = loopback base URL = free. Anything else is PAID and requires `authorize(endpoint, caps=...)` first; unauthorised paid calls are refused before any network I/O.
  * Spend caps (per request / per day / total, USD) are checked BEFORE the call against ledger + in-flight reservations (worst case = prompt estimate + max_tokens at the output price) and the real cost is recorded after.
    A paid model with no known price is refused (fail closed) - you cannot cap what you cannot price.
  * No automatic fallback: `fallback=[...]` is tried in order only on retryable failures, and a paid endpoint after a free/local one needs `allow_paid_fallback=True` on that call.
  * API keys live in a 0600 file read inside this process only; they never appear in an Agent's environment, argv, prompt or any return value (replies carry no headers).
  * Capabilities (tools / vision / json) are declared per endpoint+model and probed for local llama.cpp (/props); a request needing one that is not available is refused, not silently degraded.
Wire protocols: OpenAI-compatible (OpenAI, OpenRouter, DeepSeek, Google's OpenAI-compatible endpoint, Ollama, llama.cpp, vLLM, any custom) with tools/vision/json; Anthropic Messages (text, tools, images).
"""
from __future__ import annotations
import http.client, ipaddress, json, math, os, socket, sqlite3, ssl, threading, time, urllib.error, urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
from .. import providers as PV

GOOGLE_OPENAI = "https://generativelanguage.googleapis.com/v1beta/openai"
PRESETS = {"claude-cli": ("cli", "cli://claude"), "openai": ("openai", "https://api.openai.com/v1"), "openrouter": ("openai", "https://openrouter.ai/api/v1"), "deepseek": ("openai", "https://api.deepseek.com/v1"),
           "google": ("openai", GOOGLE_OPENAI), "anthropic": ("anthropic", "https://api.anthropic.com"), "custom": ("openai", "")}
LOOPBACK = {"127.0.0.1", "localhost", "::1"}

class GatewayError(RuntimeError):
    def __init__(self, code, msg, endpoint=None, retryable=False): super().__init__(msg); self.code, self.endpoint, self.retryable = code, endpoint, retryable
    def to_dict(self): return {"error": {"code": self.code, "message": str(self), "endpoint": self.endpoint, "retryable": self.retryable}}

@dataclass
class Reply:
    text: str; tool_calls: list; usage: dict; cost_usd: float; model: str; endpoint: str; latency_s: float; finish: str = ""

def _loop(base): return (urlparse(base).hostname or "") in LOOPBACK

class Gateway:
    def __init__(self, home, http=None, prices=None, clock=time.time):
        self.home = Path(home); self.home.mkdir(parents=True, exist_ok=True); os.chmod(self.home, 0o700); self.http = http; self.clock = clock; self._lock = threading.Lock()
        self.cfg_path = self.home / "gateway.json"; self.sec_path = self.home / "gateway-secrets.json"; self._tl = threading.local(); self._dbpath = str(self.home / "spend.db"); self.db.execute("CREATE TABLE IF NOT EXISTS spend(id INTEGER PRIMARY KEY, ts REAL, agent TEXT, endpoint TEXT, model TEXT, tin INT, tout INT, usd REAL, status TEXT)"); self.db.execute("CREATE TABLE IF NOT EXISTS scoped_spend(id INTEGER PRIMARY KEY, scope TEXT NOT NULL, ts REAL NOT NULL, usd REAL NOT NULL, status TEXT NOT NULL)"); self.db.execute("CREATE INDEX IF NOT EXISTS scoped_spend_scope ON scoped_spend(scope,status)")
        self.prices = dict(prices or {})                         # {"model": (usd_per_mtok_in, usd_per_mtok_out)}
        self.cfg = json.loads(self.cfg_path.read_text()) if self.cfg_path.exists() else {"endpoints": {}, "prices": {}}; self.prices.update({k: tuple(v) for k, v in self.cfg.get("prices", {}).items()})

    @property
    def db(self):
        """One SQLite connection PER THREAD: transactions are per connection, so reservations made by concurrent threads (and, via the file lock, by other worker processes) serialise correctly."""
        c = getattr(self._tl, "db", None)
        if c is None: c = self._tl.db = sqlite3.connect(self._dbpath, isolation_level=None, timeout=30)
        return c

    # ---------------------------------------------------------------- configuration
    def _save(self): t = self.cfg_path.with_suffix(".tmp"); t.write_text(json.dumps(self.cfg, indent=1)); os.replace(t, self.cfg_path)
    def add_endpoint(self, eid, provider=None, base=None, protocol=None, key=None, models=None, caps=None, local=False):
        pr, pb = PRESETS.get(provider or "custom", ("openai", "")); base = (base or pb).rstrip("/"); protocol = protocol or pr
        if not base: raise GatewayError("bad_request", "endpoint needs a base URL", eid)
        if protocol != "cli" and not _loop(base) and urlparse(base).scheme != "https": raise GatewayError("bad_request", "non-loopback endpoints must use https", eid)
        e = {"id": eid, "provider": provider or "custom", "base": base, "protocol": protocol, "paid": protocol == "cli" or not _loop(base), "authorized": False, "caps": {"daily_usd": 0.0, "total_usd": 0.0, "per_request_usd": 0.0},
             "capabilities": caps or ({"tools": False, "vision": False, "json": False} if protocol == "cli" else {"tools": True, "vision": False, "json": True}), "models": models or []}
        self.cfg["endpoints"][eid] = e; self._save()
        if key:
            s = json.loads(self.sec_path.read_text()) if self.sec_path.exists() else {}; s[eid] = key
            fd = os.open(self.sec_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, json.dumps(s).encode()); os.close(fd)
        return self.describe(eid)
    def add_local(self, eid, base_url, key=None, vision=False, tools=True):
        return self.add_endpoint(eid, "custom", base_url, "openai", key, caps={"tools": tools, "vision": vision, "json": True}, local=True)
    def authorize(self, eid, daily_usd, total_usd, per_request_usd=None):
        """Explicit owner action. All three caps must be positive: there is no 'unlimited'."""
        e = self._ep(eid)
        if not e["paid"]: return self.describe(eid)
        values = [float(daily_usd), float(total_usd), float(daily_usd if per_request_usd is None else per_request_usd)]
        if not all(math.isfinite(x) and x > 0 for x in values): raise GatewayError("bad_request", "paid authorisation requires finite positive daily, total and request caps (USD)", eid)
        e["authorized"] = True; e["caps"] = dict(zip(('daily_usd', 'total_usd', 'per_request_usd'), values)); self._save(); return self.describe(eid)
    def revoke(self, eid): e = self._ep(eid); e["authorized"] = False; self._save(); return self.describe(eid)
    def set_price(self, model, usd_in_per_mtok, usd_out_per_mtok, cache_read_per_mtok=None, cache_write_per_mtok=None):
        """Prices are operator-supplied, never built in. Cache rates are optional: unset, cached/cache-write tokens are charged at the input price (no discount is assumed)."""
        t = (usd_in_per_mtok, usd_out_per_mtok) + (() if cache_read_per_mtok is None and cache_write_per_mtok is None else (usd_in_per_mtok if cache_read_per_mtok is None else cache_read_per_mtok, usd_in_per_mtok if cache_write_per_mtok is None else cache_write_per_mtok))
        t = tuple(float(x) for x in t)
        if not all(math.isfinite(x) and x >= 0 for x in t): raise GatewayError('bad_request', 'model rates must be finite and nonnegative', '')
        self.prices[model] = t; self.cfg.setdefault("prices", {})[model] = list(t); self._save()

    @staticmethod
    def _cost(pr, tin, tout, cache):
        """USD for one call. `tin` is the provider's reported prompt count; OpenAI-style counts include cached tokens (`incl`), Anthropic-style counts exclude cache reads/writes."""
        cr = cache.get("read", 0); cw = cache.get("write", 0); r_in, r_out = pr[0], pr[1]; r_cr = pr[2] if len(pr) > 2 else r_in; r_cw = pr[3] if len(pr) > 3 else r_in
        fresh = max(0, tin - cr) if cache.get("incl") else tin
        return (fresh * r_in + cr * r_cr + cw * r_cw + tout * r_out) / 1e6
    def _ep(self, eid):
        if eid not in self.cfg["endpoints"]: raise GatewayError("unknown_endpoint", f"no endpoint {eid!r}", eid)
        return self.cfg["endpoints"][eid]
    def _key(self, eid):
        try: return json.loads(self.sec_path.read_text()).get(eid, "")
        except (OSError, ValueError): return ""
    def describe(self, eid):
        e = dict(self._ep(eid)); e["has_key"] = bool(self._key(eid)); e["spent_today_usd"] = round(self.spent(eid, 86400), 6); e["spent_total_usd"] = round(self.spent(eid), 6); return e        # never includes the key
    def endpoints(self): return [self.describe(k) for k in self.cfg["endpoints"]]

    # ---------------------------------------------------------------- discovery
    def models(self, eid, http=None):
        e = self._ep(eid)
        if e["paid"] and not e["authorized"]: raise GatewayError("paid_not_authorized", f"{eid} is a paid provider and is not authorised", eid)
        try: names = PV.list_models(e["protocol"], e["base"], self._key(eid), http or self.http)
        except PV.ProviderError as ex: raise self._norm(ex, eid)
        return [{"id": n, "capabilities": e["capabilities"], "priced": n in self.prices or not e["paid"]} for n in names]

    # ---------------------------------------------------------------- spend
    RESERVE_TTL = 600.0            # a reservation whose worker died stops counting after this long (crash safety); live calls always finish sooner (timeout-bounded)
    def spent(self, eid=None, window_s=None):
        """Settled spend + ACTIVE reservations (durable rows, visible to every Gateway instance / worker process on this home)."""
        now = self.clock(); q = "SELECT COALESCE(SUM(usd),0) FROM spend WHERE (status IN ('ok','uncertain') OR (status='reserved' AND ts>?))"; a = [now - self.RESERVE_TTL]
        if eid: q += " AND endpoint=?"; a.append(eid)
        if window_s: q += " AND ts>?"; a.append(now - window_s)
        return self.db.execute(q, a).fetchone()[0]
    def usage(self, since_s=None, by="endpoint"):
        col = {"endpoint": "endpoint", "agent": "agent", "model": "model"}[by]; q = f"SELECT {col}, COUNT(*), SUM(tin), SUM(tout), SUM(usd) FROM spend WHERE status='ok'" + (" AND ts>?" if since_s else "") + f" GROUP BY {col}"
        return [{by: r[0], "calls": r[1], "tokens_in": r[2], "tokens_out": r[3], "usd": round(r[4] or 0, 6)} for r in self.db.execute(q, [self.clock() - since_s] if since_s else [])]
    def _price(self, model): return self.prices.get(model)
    def scope_usage(self, scope):
        rows = self.db.execute('SELECT status,COUNT(*),COALESCE(SUM(usd),0) FROM scoped_spend WHERE scope=? GROUP BY status', (str(scope),)).fetchall()
        return {'recorded_usd': round(sum(usd for status, count, usd in rows if status == 'ok'), 6),
                'reserved_or_uncertain_usd': round(sum(usd for status, count, usd in rows if status in ('reserved', 'uncertain')), 6),
                'unsettled_requests': sum(count for status, count, usd in rows if status in ('reserved', 'uncertain'))}
    def _estimate(self, e, model, messages, max_tokens, tools=None, response_format=None):
        if not e["paid"]: return 0.0
        pr = self._price(model)
        if pr is None and e["protocol"] == "cli": return 0.01          # CLI cost is only known after the call; a flat worst-case reservation keeps caps meaningful
        if pr is None: raise GatewayError("unpriced_model", f"{model!r} has no known price; set_price() first (spend cannot be capped without it)", e["id"])
        if len(pr) < 2 or not all(isinstance(x, (int, float)) and math.isfinite(x) and x >= 0 for x in pr):
            raise GatewayError('unpriced_model', 'model rates are invalid; configure finite nonnegative rates', e['id'])
        prompt_bytes = sum(len(json.dumps(m, ensure_ascii=True).encode("utf-8")) + 16 for m in messages) + 256
        for extra in (tools, response_format):
            if extra: prompt_bytes += len(json.dumps(extra, ensure_ascii=True).encode('utf-8'))
        input_rate = max([pr[0], *pr[2:]])
        return (prompt_bytes * input_rate + max_tokens * pr[1]) / 1e6     # include a higher configured cache write/read rate in the reservation

    # ---------------------------------------------------------------- the one call
    def chat(self, agent, endpoint, model, messages, tools=None, response_format=None, max_tokens=512, temperature=0.0, fallback=(), allow_paid_fallback=False, timeout=120, spend_scope=None, spend_limit_usd=None):
        chain = [endpoint] + list(fallback); last = None; free_seen = False
        for n, eid in enumerate(chain):
            e = self._ep(eid)
            if n and e["paid"] and (free_seen or not self._ep(chain[0])["paid"]) and not allow_paid_fallback:
                raise GatewayError("paid_not_authorized", f"fallback to paid endpoint {eid!r} needs allow_paid_fallback=True on this call (no automatic paid fallback)", eid)
            free_seen = free_seen or not e["paid"]
            try: return self._one(agent, e, model, messages, tools, response_format, max_tokens, temperature, timeout, spend_scope, spend_limit_usd)
            except GatewayError as g:
                last = g
                if not g.retryable: raise
        raise last

    def _one(self, agent, e, model, messages, tools, response_format, max_tokens, temperature, timeout, spend_scope=None, spend_limit_usd=None):
        eid = e["id"]; cap = e["capabilities"]
        if tools and not cap.get("tools"): raise GatewayError("capability_unsupported", f"{eid} does not support tool calls", eid)
        if response_format and not cap.get("json"): raise GatewayError("capability_unsupported", f"{eid} does not support structured output", eid)
        if _has_image(messages) and not cap.get("vision"): raise GatewayError("capability_unsupported", f"{eid}/{model} does not accept images", eid)
        if e["paid"] and not e["authorized"]: raise GatewayError("paid_not_authorized", f"{eid} is a paid provider; authorise it with spending caps first", eid)
        est = self._estimate(e, model, messages, max_tokens, tools, response_format); rid = sid = None
        if e["paid"] or spend_scope is not None:
            self.db.execute("BEGIN IMMEDIATE")                                  # check + reserve in ONE write transaction: concurrent workers/processes serialise here
            try:
                c = e["caps"]
                if e["paid"]:
                    if est > c["per_request_usd"]: raise GatewayError("cap_exceeded", f"worst-case cost ${est:.4f} exceeds per-request cap ${c['per_request_usd']}", eid)
                    if self.spent(eid, 86400) + est > c["daily_usd"]: raise GatewayError("cap_exceeded", f"daily cap ${c['daily_usd']} would be exceeded", eid)
                    if self.spent(eid) + est > c["total_usd"]: raise GatewayError("cap_exceeded", f"total cap ${c['total_usd']} would be exceeded", eid)
                    rid = self.db.execute("INSERT INTO spend(ts,agent,endpoint,model,tin,tout,usd,status) VALUES(?,?,?,?,0,0,?,'reserved')", (self.clock(), agent, eid, model, est)).lastrowid
                if spend_scope is not None:
                    current = self.db.execute("SELECT COALESCE(SUM(usd),0) FROM scoped_spend WHERE scope=? AND status IN ('reserved','ok','uncertain')", (str(spend_scope),)).fetchone()[0]
                    if spend_limit_usd is not None and current + est > float(spend_limit_usd) + 1e-12: raise GatewayError("cap_exceeded", "job spending budget would be exceeded", eid)
                    sid = self.db.execute("INSERT INTO scoped_spend(scope,ts,usd,status) VALUES(?,?,?,'reserved')", (str(spend_scope), self.clock(), est)).lastrowid
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK"); raise
        t0 = time.time(); self._tl.cache = {"read": 0, "write": 0, "incl": True}
        try:
            text, calls, tin, tout, finish, rmodel = {"anthropic": self._anthropic, "cli": self._cli}.get(e["protocol"], self._openai)(e, model, messages, tools, response_format, max_tokens, temperature, timeout)
        except BaseException as g:
            code = g.code if isinstance(g, GatewayError) else "internal"
            if sid and code in ("network", "timeout", "server"): self.db.execute("UPDATE scoped_spend SET status='uncertain' WHERE id=?", (sid,))
            elif sid: self.db.execute("UPDATE scoped_spend SET usd=0, status=? WHERE id=?", ("err:" + code, sid))
            if rid and code in ("network", "timeout", "server"): self.db.execute("UPDATE spend SET status='uncertain' WHERE id=?", (rid,))
            elif rid: self.db.execute("UPDATE spend SET usd=0, status=? WHERE id=?", ("err:" + code, rid))
            else: self.db.execute("INSERT INTO spend(ts,agent,endpoint,model,tin,tout,usd,status) VALUES(?,?,?,?,0,0,0,?)", (self.clock(), agent, eid, model, "err:" + code))
            raise
        pr = self._price(model); cache = dict(getattr(self._tl, "cache", None) or {}); usd = 0.0 if not e["paid"] else (self._cost(pr, tin, tout, cache) if pr else 0.0)
        if not cache.get("incl", True): tin += cache.get("read", 0) + cache.get("write", 0)          # report the whole prompt the model saw (Anthropic counts cache tokens separately)
        if e["protocol"] == "cli": usd = getattr(self._tl, "cli_cost", 0.0)
        if sid: self.db.execute("UPDATE scoped_spend SET ts=?, usd=?, status='ok' WHERE id=?", (self.clock(), usd, sid))
        if rid: self.db.execute("UPDATE spend SET ts=?, tin=?, tout=?, usd=?, status='ok' WHERE id=?", (self.clock(), tin, tout, usd, rid))
        else: self.db.execute("INSERT INTO spend(ts,agent,endpoint,model,tin,tout,usd,status) VALUES(?,?,?,?,?,?,?,'ok')", (self.clock(), agent, eid, model, tin, tout, usd))
        return Reply(text, calls, {"prompt_tokens": tin, "completion_tokens": tout, "cache_read_tokens": cache.get("read", 0), "cache_write_tokens": cache.get("write", 0),
                                   "uncached_input_tokens": max(0, tin - cache.get("read", 0) - cache.get("write", 0))}, usd, rmodel or model, eid, round(time.time() - t0, 3), finish)

    # ---------------------------------------------------------------- wire protocols
    def _post(self, e, path, payload, headers, timeout):
        url = e["base"] + path
        try:
            if self.http:                                                                  # deterministic test transport; production always uses the pinned transport below
                st, raw = self.http("POST", url, {"Content-Type": "application/json", **headers}, json.dumps(payload).encode(), timeout)
                if st >= 400: raise self._http_error(st, (raw or b"").decode(errors="ignore")[:300], e["id"])
                return json.loads(raw or b"{}")
            u = urlparse(url)
            if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password: raise GatewayError("bad_request", "endpoint URL is invalid", e["id"])
            port = u.port or (443 if u.scheme == "https" else 80)
            addresses = {x[4][0] for x in socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)}
            ips = [ipaddress.ip_address(a) for a in addresses]
            if not ips or any((not ip.is_loopback if u.scheme == "http" else not ip.is_global) for ip in ips):
                raise GatewayError("bad_request", "endpoint resolves to a non-permitted address", e["id"])
            target_ip = str(sorted(ips, key=lambda x: (x.version, int(x)))[0])
            class Pinned(http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection):
                def connect(self):
                    sock = socket.create_connection((target_ip, port), self.timeout)
                    if u.scheme == "https": sock = self._context.wrap_socket(sock, server_hostname=u.hostname)
                    self.sock = sock
            conn = Pinned(u.hostname, port, timeout=timeout, **({"context": ssl.create_default_context()} if u.scheme == "https" else {}))
            try:
                conn.request("POST", (u.path or "/") + (("?" + u.query) if u.query else ""), json.dumps(payload).encode(), {"Content-Type": "application/json", "User-Agent": "ordivyr-gateway", **headers})
                r = conn.getresponse(); raw = r.read(8_000_001)
                if len(raw) > 8_000_000: raise GatewayError("bad_request", "provider response exceeded limit", e["id"])
                if r.status >= 300: raise self._http_error(r.status, raw.decode(errors="ignore")[:300], e["id"])
                return json.loads(raw or b"{}")
            finally: conn.close()
        except GatewayError: raise
        except urllib.error.HTTPError as ex:
            body = ""
            try: body = ex.read().decode(errors="ignore")[:300]
            except Exception: pass
            raise self._http_error(ex.code, body, e["id"])
        except TimeoutError: raise GatewayError("timeout", "request timed out", e["id"], True)
        except (urllib.error.URLError, OSError) as ex: raise GatewayError("network", f"cannot reach endpoint: {getattr(ex, 'reason', ex)}", e["id"], True)
    @staticmethod
    def _http_error(code, body, eid):
        low = body.lower()
        if code in (401, 403): return GatewayError("auth", "credentials rejected by the provider", eid)
        if code == 429: return GatewayError("quota" if "quota" in low or "billing" in low or "credit" in low else "rate_limit", "provider rate/quota limit", eid, retryable=True)
        if code in (400, 404, 413, 422): return GatewayError("bad_request", f"provider rejected the request (HTTP {code})", eid)
        return GatewayError("server", f"provider error (HTTP {code})", eid, retryable=code >= 500)
    def _norm(self, ex, eid): return GatewayError("rate_limit" if isinstance(ex, PV.LimitError) else "bad_request", str(ex)[:200], eid, isinstance(ex, PV.LimitError))

    def _openai(self, e, model, messages, tools, rf, max_tokens, temperature, timeout):
        key = self._key(e["id"]); p = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
        if tools: p["tools"] = tools
        if rf: p["response_format"] = rf
        j = self._post(e, "/chat/completions", p, {"Authorization": "Bearer " + key} if key else {}, timeout)
        ch = (j.get("choices") or [{}])[0]; m = ch.get("message") or {}; u = j.get("usage") or {}
        self._tl.cache = {"read": int((u.get("prompt_tokens_details") or {}).get("cached_tokens") or u.get("prompt_cache_hit_tokens") or 0), "write": 0, "incl": True}
        return (m.get("content") or ""), [{"id": c.get("id"), "name": c["function"]["name"], "arguments": c["function"].get("arguments", "{}")} for c in (m.get("tool_calls") or [])], \
            int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0), ch.get("finish_reason") or "", j.get("model")
    def _cli(self, e, model, messages, tools, rf, max_tokens, temperature, timeout):
        """A logged-in Claude Code CLI as a provider (text only; subscription auth stays inside the CLI, ORDIVYR never sees it). Cost = what the CLI reports; bounded by timeout and the gateway caps."""
        import subprocess, shutil
        exe = shutil.which("claude")
        if not exe: raise GatewayError("unsupported", "claude CLI not installed", e["id"])
        system = "\n".join(m["content"] for m in messages if m["role"] == "system"); user = "\n\n".join(str(m["content"]) for m in messages if m["role"] == "user")
        argv = [exe, "-p", user, "--output-format", "json", "--no-session-persistence", "--permission-mode", "dontAsk", "--tools", "", "--max-turns", "1", "--model", model] + (["--append-system-prompt", system] if system else [])
        try: r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/")})
        except subprocess.TimeoutExpired: raise GatewayError("timeout", "claude CLI timed out", e["id"], True)
        try: j = json.loads(r.stdout)
        except ValueError: raise GatewayError("server", f"claude CLI returned no JSON (rc={r.returncode})", e["id"], True)
        if j.get("is_error") or r.returncode != 0: raise GatewayError("auth" if "login" in json.dumps(j).lower() else "server", "claude CLI reported an error", e["id"])
        u = j.get("usage") or {}; self._tl.cli_cost = float(j.get("total_cost_usd") or 0)
        return (j.get("result") or ""), [], int(u.get("input_tokens") or 0) + int(u.get("cache_read_input_tokens") or 0) + int(u.get("cache_creation_input_tokens") or 0), int(u.get("output_tokens") or 0), j.get("stop_reason") or "", model
    def _anthropic(self, e, model, messages, tools, rf, max_tokens, temperature, timeout):
        if rf: raise GatewayError("capability_unsupported", "structured output is not available through the Anthropic adapter", e["id"])
        system = "\n".join(m["content"] for m in messages if m["role"] == "system" and isinstance(m["content"], str)); msgs = []
        for m in messages:
            if m["role"] == "system": continue
            if m["role"] == "assistant" and m.get("tool_calls"):                                  # OpenAI-shaped history -> Anthropic blocks (provider switch mid-conversation)
                blocks = ([{"type": "text", "text": m["content"]}] if m.get("content") else []) + [{"type": "tool_use", "id": t["id"], "name": t["function"]["name"], "input": json.loads(t["function"].get("arguments") or "{}")} for t in m["tool_calls"]]
                msgs.append({"role": "assistant", "content": blocks}); continue
            if m["role"] == "tool":
                blk = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": str(m["content"])}
                if msgs and msgs[-1]["role"] == "user" and isinstance(msgs[-1]["content"], list) and msgs[-1]["content"] and msgs[-1]["content"][0].get("type") == "tool_result": msgs[-1]["content"].append(blk)
                else: msgs.append({"role": "user", "content": [blk]})
                continue
            c = m["content"]
            if isinstance(c, list): c = [{"type": "image", "source": {"type": "base64", "media_type": x["image_url"]["url"].split(";")[0][5:], "data": x["image_url"]["url"].split(",", 1)[1]}} if x.get("type") == "image_url" else x for x in c]
            msgs.append({"role": m["role"], "content": c})
        p = {"model": model, "max_tokens": max_tokens, "messages": msgs, "temperature": temperature, **({"system": system} if system else {})}
        if tools: p["tools"] = [{"name": t["function"]["name"], "description": t["function"].get("description", ""), "input_schema": t["function"].get("parameters", {"type": "object"})} for t in tools]
        key = self._key(e["id"]); j = self._post(e, "/v1/messages", p, {"x-api-key": key, "anthropic-version": "2023-06-01"} if key else {"anthropic-version": "2023-06-01"}, timeout); u = j.get("usage") or {}
        self._tl.cache = {"read": int(u.get("cache_read_input_tokens") or 0), "write": int(u.get("cache_creation_input_tokens") or 0), "incl": False}
        return "".join(b.get("text", "") for b in j.get("content", []) if b.get("type") == "text"), [{"id": b["id"], "name": b["name"], "arguments": json.dumps(b.get("input", {}))} for b in j.get("content", []) if b.get("type") == "tool_use"], \
            int(u.get("input_tokens") or 0), int(u.get("output_tokens") or 0), j.get("stop_reason") or "", j.get("model")

def _has_image(messages): return any(isinstance(m.get("content"), list) and any(isinstance(x, dict) and x.get("type") == "image_url" for x in m["content"]) for m in messages)
