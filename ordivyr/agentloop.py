"""Tool loop for API / local-model agents (OpenAI-compatible and Anthropic protocols; Gemini stays text-only).

The model may call only the tools the backend offers for THIS run: file tools confined to one working folder, a web fetch with an SSRF guard,
and tools from MCP servers the agent was granted (stdio transport). Shell is never offered. Steps and tokens are capped; every tool result is
size-limited. Everything network/process related is injectable so tests use stubs.
"""
from __future__ import annotations
import http.client, ipaddress, json, os, re, signal, socket, ssl, subprocess, threading
from pathlib import Path
from urllib.parse import urlparse
from . import providers as PV

MAX_RESULT = 8000
MAX_STEPS = 12


class ToolError(Exception): pass


# --------------------------------------------------------------------------- built-in tools
class ToolBox:
    def __init__(self, root: Path, write=False, web=False, ask=True, mcp=None):
        self.root = Path(os.path.realpath(root)); self.write = write; self.web = web; self.ask = ask; self.mcp = mcp or {}; self.question = None
        self.defs = [self._d("list_files", "List files in a folder of the working directory.", {"path": ("string", "folder, default '.'")}, []),
                     self._d("read_file", "Read a text file from the working directory.", {"path": ("string", "relative path")}, ["path"])]
        if write: self.defs.append(self._d("write_file", "Create or overwrite a file in the working directory.", {"path": ("string", "relative path"), "content": ("string", "full file content")}, ["path", "content"]))
        if web: self.defs.append(self._d("fetch_url", "Fetch a public web page as text (GET).", {"url": ("string", "http(s) URL")}, ["url"]))
        if ask: self.defs.append(self._d("ask_user", "Ask the human one question when you cannot continue without it. Ends your turn.", {"question": ("string", "the question")}, ["question"]))
        for full, (client, spec) in self.mcp.items():
            self.defs.append({"name": full, "description": (spec.get("description") or "")[:300], "schema": spec.get("inputSchema") or {"type": "object", "properties": {}}})

    @staticmethod
    def _d(name, desc, props, req):
        return {"name": name, "description": desc, "schema": {"type": "object", "properties": {k: {"type": t, "description": d} for k, (t, d) in props.items()}, "required": req}}

    def _path(self, rel, must_exist=True):
        rel = str(rel or ".")
        if rel.startswith("/") or "\0" in rel: raise ToolError("use a relative path")
        cur = self.root
        for part in Path(rel).parts:
            if part == "..": raise ToolError("path escapes the working directory")
            cur = cur / part
            if cur.is_symlink(): raise ToolError("symlinks are not followed")
        p = self.root / rel
        if self.root not in Path(os.path.realpath(p)).parents and Path(os.path.realpath(p)) != self.root: raise ToolError("path escapes the working directory")
        if must_exist and not p.exists(): raise ToolError("no such file or folder")
        return p

    def call(self, name, args):
        try:
            if name == "list_files":
                p = self._path(args.get("path") or "."); names = sorted(x.name + ("/" if x.is_dir() else "") for x in p.iterdir() if x.name != ".git")[:300]; return "\n".join(names) or "(empty)"
            if name == "read_file":
                p = self._path(args.get("path"))
                if not p.is_file(): raise ToolError("not a file")
                return p.read_text("utf-8", "replace")[:MAX_RESULT]
            if name == "write_file":
                if not self.write: raise ToolError("not allowed: this agent has no file-write permission")
                p = self._path(args.get("path"), must_exist=False); c = str(args.get("content", ""))
                if len(c) > 400_000: raise ToolError("file too large")
                if p.name == ".git" or ".git" in p.relative_to(self.root).parts: raise ToolError("not allowed")
                p.parent.mkdir(parents=True, exist_ok=True); p.write_text(c); return f"wrote {len(c)} characters to {args.get('path')}"
            if name == "fetch_url":
                if not self.web: raise ToolError("not allowed: this agent has no web permission")
                return fetch_url(str(args.get("url", "")))
            if name == "ask_user":
                self.question = str(args.get("question", ""))[:600]; return "Question recorded. Stop now; the user will answer."
            if name in self.mcp:
                client, spec = self.mcp[name]; return client.call(spec["name"], args)[:MAX_RESULT]
            raise ToolError("unknown tool")
        except ToolError as e: return f"ERROR: {e}"
        except Exception as e: return f"ERROR: {type(e).__name__}: {str(e)[:200]}"


# --------------------------------------------------------------------------- web fetch with an SSRF guard
def _public_ip(host):
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    ips = [ipaddress.ip_address(i[4][0]) for i in infos]
    if not ips or not all(ip.is_global for ip in ips): raise ToolError("that address is private or local; only public web pages can be fetched")
    return str(ips[0])


class _Pinned(http.client.HTTPSConnection):
    """Connects to the IP we already vetted (no second DNS lookup), still verifying the certificate for the real hostname."""
    def __init__(self, host, ip, **kw): super().__init__(host, **kw); self._ip = ip
    def connect(self):
        sock = socket.create_connection((self._ip, self.port or 443), self.timeout); self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch_url(url, _resolve=_public_ip):
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password: raise ToolError("only plain http(s) URLs are allowed")
    ip = _resolve(u.hostname); path = (u.path or "/") + (("?" + u.query) if u.query else "")
    if u.scheme == "https": conn = _Pinned(u.hostname, ip, port=u.port or 443, timeout=15, context=ssl.create_default_context())
    else: conn = http.client.HTTPConnection(ip, u.port or 80, timeout=15)
    try:
        conn.request("GET", path, headers={"Host": u.netloc.split("@")[-1], "User-Agent": "ordivyr", "Accept": "text/*,application/json"})
        r = conn.getresponse()
        if 300 <= r.status < 400: raise ToolError(f"redirected ({r.status}); redirects are not followed - fetch the target URL directly")
        body = r.read(300_000)
        if r.status >= 400: raise ToolError(f"HTTP {r.status}")
        return re.sub(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", " ", body.decode("utf-8", "replace"), flags=re.S)[:MAX_RESULT] if "html" in (r.getheader("content-type") or "") else body.decode("utf-8", "replace")[:MAX_RESULT]
    finally: conn.close()


# --------------------------------------------------------------------------- MCP stdio client (newline-delimited JSON-RPC 2.0)
class McpClient:
    def __init__(self, spec, env_extra, cwd, popen=subprocess.Popen):
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL") if k in os.environ}; env.update(env_extra)
        self.p = popen([spec["command"], *spec.get("args", [])], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, cwd=str(cwd), text=True, bufsize=1, start_new_session=True)
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "ordivyr", "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, m): self.p.stdin.write(json.dumps(m) + "\n"); self.p.stdin.flush()

    def rpc(self, method, params, timeout=30):
        self.n += 1; i = self.n; self._send({"jsonrpc": "2.0", "id": i, "method": method, "params": params}); out = {}
        def rd():
            for line in self.p.stdout:
                try: m = json.loads(line)
                except ValueError: continue
                if m.get("id") == i: out["m"] = m; return
        t = threading.Thread(target=rd, daemon=True); t.start(); t.join(timeout)
        if "m" not in out: raise ToolError(f"MCP server did not answer {method}")
        if "error" in out["m"]: raise ToolError("MCP: " + str(out["m"]["error"].get("message", ""))[:200])
        return out["m"].get("result") or {}

    def tools(self): return self.rpc("tools/list", {}).get("tools", [])

    def call(self, name, args):
        r = self.rpc("tools/call", {"name": name, "arguments": args if isinstance(args, dict) else {}}, 120)
        text = "\n".join(c.get("text", "") for c in r.get("content", []) if c.get("type") == "text")
        return ("ERROR: " if r.get("isError") else "") + text

    def close(self):
        try: os.killpg(self.p.pid, signal.SIGTERM)
        except Exception: pass


# --------------------------------------------------------------------------- the loop
def _norm_openai(j):
    m = (j.get("choices") or [{}])[0].get("message") or {}
    calls = []
    for c in m.get("tool_calls") or []:
        try: a = json.loads(c["function"].get("arguments") or "{}")
        except ValueError: a = {}
        calls.append({"id": c.get("id") or "call", "name": c["function"]["name"], "args": a if isinstance(a, dict) else {}})
    return m, (m.get("content") or ""), calls, int((j.get("usage") or {}).get("total_tokens") or 0)


def _norm_anthropic(j):
    blocks = j.get("content") or []; u = j.get("usage") or {}
    calls = [{"id": b["id"], "name": b["name"], "args": b.get("input") or {}} for b in blocks if b.get("type") == "tool_use"]
    return blocks, "".join(b.get("text", "") for b in blocks if b.get("type") == "text"), calls, int(u.get("input_tokens") or 0) + int(u.get("output_tokens") or 0)


def run(protocol, base, key, model, system, prompt, box: ToolBox, http=None, timeout=90, max_steps=MAX_STEPS, token_budget=0, on_step=None):
    """-> (text, tokens, model, steps, stop_reason). stop_reason: done | question | steps | budget | notools"""
    if protocol not in ("openai", "anthropic"): raise PV.ProviderError("tool use is not available for this provider")
    base = PV.check_base(base); h = PV._headers(protocol, key); tokens = 0; used = model; steps = 0
    if protocol == "openai":
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
        tools = [{"type": "function", "function": {"name": d["name"], "description": d["description"], "parameters": d["schema"]}} for d in box.defs]
    else:
        msgs = [{"role": "user", "content": prompt}]
        tools = [{"name": d["name"], "description": d["description"], "input_schema": d["schema"]} for d in box.defs]
    text = ""
    while True:
        if protocol == "openai": j = PV._call(http, "POST", base + "/chat/completions", h, {"model": model, "max_tokens": 4096, "messages": msgs, "tools": tools, "tool_choice": "auto"}, timeout); raw, text, calls, tk = _norm_openai(j)
        else: j = PV._call(http, "POST", base + "/v1/messages", h, {"model": model, "max_tokens": 4096, "system": system, "messages": msgs, "tools": tools}, timeout); raw, text, calls, tk = _norm_anthropic(j)
        tokens += tk; used = j.get("model") or used; steps += 1
        if not calls: return text, tokens, used, steps, "done"
        if protocol == "openai": msgs.append(raw if isinstance(raw, dict) else {"role": "assistant", "content": text})
        else: msgs.append({"role": "assistant", "content": raw})
        results = []
        for c in calls:
            out = box.call(c["name"], c["args"]); results.append((c, out))
            if on_step: on_step(c["name"], c["args"], out)
        if protocol == "openai": msgs += [{"role": "tool", "tool_call_id": c["id"], "content": out} for c, out in results]
        else: msgs.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": c["id"], "content": out} for c, out in results]})
        if box.question: return "QUESTION: " + box.question, tokens, used, steps, "question"
        if steps >= max_steps: return (text or "") + f"\n\n[stopped: reached the {max_steps}-step limit]", tokens, used, steps, "steps"
        if token_budget and tokens >= token_budget: return (text or "") + "\n\n[stopped: token budget reached]", tokens, used, steps, "budget"
