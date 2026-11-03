"""Plugin host: loads enabled, hash-verified plugins, builds their adapters, and hands agents ONLY the tools they are licensed for.

An agent may use plugin <id> iff its (department-merged) License lists <id> in `mcp` - the same grant mechanism MCP tools already use.
Every call goes through `Guarded`: plugin still enabled + hash still verified, write-capable tools need the `tool.write` grant, per-run call cap,
result size cap, secrets redacted from audit, and an audit line per call. Tool results are returned as data; they are never interpreted as instructions.
"""
from __future__ import annotations
import json, re, time
from pathlib import Path
from . import manifest as MF, sandbox as SB, store as ST
from .adapters import AdapterError, mcp as AMCP, a2a as AA2A, n8n as AN8N, langgraph as ALG, skills as ASK, native as ANAT

MAX_RESULT = 8000
_REDACT = re.compile(r"(?i)(sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{16,}|bearer\s+\S+|(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+)")


def red(x): return _REDACT.sub("[REDACTED]", json.dumps(x, default=str)[:400])


def tool_name(pid, tool): return re.sub(r"[^A-Za-z0-9_-]", "_", f"{pid}__{tool}")[:64]


class Guarded:
    """What an agent's ToolBox holds as `client`: a checked proxy for one plugin."""
    def __init__(self, host, pid): self.host, self.pid = host, pid
    def call(self, tool, args): return self.host.call(self.pid, tool, args)


class Host:
    def __init__(self, store, http=None, popen=None, max_calls=50):
        self.store, self.http, self.popen, self.max_calls = store, http, popen, max_calls
        self.adapters, self.specs, self.counts = {}, {}, {}
    # ------------------------------------------------------------ lifecycle
    def _build(self, pid):
        m = self.store.get(pid); st = self.store.state(pid)
        if not st["enabled"]: raise AdapterError(f"{pid} is not enabled")
        if not self.store.verify(pid): raise AdapterError(f"{pid} changed after install; reinstall to re-verify")
        pol = SB.Policy(st["grants"]); d = self.store.path(pid); rt = m["runtime"]; e = m["entry"]
        try:
            if rt == "mcp": a = AMCP.McpStdio(e, pol, d, self.popen) if e["transport"] == "stdio" else AMCP.McpHttp(e, pol, self.http)
            elif rt == "a2a": a = AA2A.A2AClient(e, pol, self.http)
            elif rt == "n8n": a = AN8N.N8n(e, pol, self.http)
            elif rt == "langgraph": a = ALG.LangGraph(e, pol, self.http)
            elif rt == "declarative": a = ASK.Skills(d, e.get("skills") or None)
            elif rt == "native": a = ANAT.Native(m, d, st["native_trust"])
            else: raise AdapterError(f"unsupported runtime {rt}")
        except SB.Denied as ex: raise AdapterError(f"permission denied: {ex}")
        return a
    def adapter(self, pid):
        if pid not in self.adapters:
            self.adapters[pid] = self._build(pid)
            self.specs[pid] = {t["name"]: t for t in self.adapters[pid].tools()}
        return self.adapters[pid]
    def close(self):
        for a in self.adapters.values():
            try: a.close()
            except Exception: pass
        self.adapters.clear(); self.specs.clear()
    # ------------------------------------------------------------ tools for an agent
    def licensed(self, eff):
        """Plugin ids this agent's License grants that are installed AND enabled."""
        have = {p["id"] for p in self.store.list() if p["enabled"]}
        return [x for x in (eff.get("mcp") or []) if isinstance(x, str) and x in have]
    def toolmap(self, plugin_ids):
        """{tool_name: (client, spec)} in the shape agentloop.ToolBox(mcp=...) expects. A plugin that fails to start is skipped and reported by `errors`."""
        out = {}; self.errors = getattr(self, "errors", {})
        for pid in plugin_ids:
            try: self.adapter(pid)
            except (AdapterError, ST.StoreError, MF.ManifestError) as ex: self.errors[pid] = str(ex)[:200]; self.store.audit("load_failed", pid, {"error": str(ex)[:200]}); continue
            for n, t in self.specs[pid].items():
                out[tool_name(pid, n)] = (Guarded(self, pid), {"name": n, "description": f"[{pid}] {t.get('description', '')}"[:300], "inputSchema": t.get("inputSchema")})
        return out
    def skills_prompt(self, plugin_ids):
        parts = []
        for pid in plugin_ids:
            try: m = self.store.get(pid)
            except ST.StoreError: continue
            if m["runtime"] == "declarative" and m["entry"].get("skills"):
                try: parts.append(f"Skills from {pid} (call {tool_name(pid, 'use_skill')} to read one):\n{self.adapter(pid).catalog()}")
                except AdapterError: pass
        return "\n\n".join(parts)
    def agents(self, pid):
        """Imported agent definitions of a declarative plugin -> list of dicts (see importers.agent_md)."""
        from . import importers as IM
        m = self.store.get(pid); d = self.store.path(pid)
        return [IM.agent_md((d / "agents" / f"{n}.md").read_text("utf-8"), n) for n in m["entry"].get("agents", []) if (d / "agents" / f"{n}.md").is_file()]
    # ------------------------------------------------------------ guarded call
    def call(self, pid, tool, args):
        st = self.store.state(pid)
        try:
            if not st["enabled"]: raise AdapterError("plugin is disabled")
            if not self.store.verify(pid): raise AdapterError("plugin content changed after install")
            a = self.adapter(pid); spec = self.specs[pid].get(tool)
            if not spec: raise AdapterError("unknown tool")
            if not spec.get("readOnly") and self.store.get(pid)["runtime"] not in ("declarative",) and not SB.Policy(st["grants"]).allows_write_tools():
                raise SB.Denied("this tool may change things and the tool.write permission is not granted")
            self.counts[pid] = self.counts.get(pid, 0) + 1
            if self.counts[pid] > self.max_calls: raise AdapterError(f"call cap of {self.max_calls} per run reached")
            t0 = time.time(); out = a.call(tool, args if isinstance(args, dict) else {})
            out = str(out)[:MAX_RESULT]; self.store.audit("call", pid, {"tool": tool, "args": red(args), "ms": int((time.time() - t0) * 1000), "ok": not out.startswith("ERROR")})
            return out
        except (SB.Denied, AdapterError) as ex:
            self.store.audit("denied" if isinstance(ex, SB.Denied) else "error", pid, {"tool": tool, "args": red(args), "error": str(ex)[:200]})
            return f"ERROR: {ex}"
    def reset_run(self): self.counts.clear()
    def sync_license(self, license_mod):
        """Make installed+enabled plugin ids appear in the License tree's MCP list (existing mechanism: license.EXTRA_MCP)."""
        license_mod.EXTRA_MCP[:] = [p["id"] for p in self.store.list() if p["enabled"]]
