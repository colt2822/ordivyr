"""MCP adapters: stdio (reusing the core McpClient, started under the sandbox) and Streamable-HTTP (JSON or SSE replies)."""
from __future__ import annotations
import json
from . import AdapterError, Net
from .. import sandbox as SB
from ... import agentloop as AL

PROTO = "2024-11-05"


def _spec(t): return {"name": t["name"], "description": (t.get("description") or "")[:300], "inputSchema": t.get("inputSchema") or {"type": "object", "properties": {}},
                       "readOnly": bool((t.get("annotations") or {}).get("readOnlyHint"))}


class McpStdio:
    def __init__(self, entry, policy, plugin_dir, popen=None):
        SB.Policy.check_exec(policy, entry["command"])
        argv, self.mode = SB.wrap_command(policy, entry["command"], entry.get("args", []), plugin_dir)
        kw = {"popen": popen} if popen else {}
        try: self.client = AL.McpClient({"command": argv[0], "args": argv[1:]}, policy.env(), plugin_dir, **kw)
        except AL.ToolError as e: raise AdapterError(str(e))
        except OSError as e: raise AdapterError(f"cannot start {entry['command']}: {e}")
    def tools(self):
        try: return [_spec(t) for t in self.client.tools()]
        except AL.ToolError as e: raise AdapterError(str(e))
    def call(self, name, args): return self.client.call(name, args)
    def close(self): self.client.close()


class McpHttp:
    def __init__(self, entry, policy, http=None):
        self.url, self.net, self.sid, self.n = entry["url"], Net(policy, http, 60), None, 0
        self._rpc("initialize", {"protocolVersion": PROTO, "capabilities": {}, "clientInfo": {"name": "ordivyr", "version": "0.4"}})
        try: self.net.request("POST", self.url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, self._h())
        except AdapterError: pass
    def _h(self):
        h = {"Accept": "application/json, text/event-stream"}
        if self.sid: h["Mcp-Session-Id"] = self.sid
        return h
    def _rpc(self, method, params):
        self.n += 1; i = self.n
        st, hd, raw = self.net.request("POST", self.url, {"jsonrpc": "2.0", "id": i, "method": method, "params": params}, self._h())
        if hd.get("mcp-session-id"): self.sid = hd["mcp-session-id"]
        if st >= 400: raise AdapterError(f"MCP http {st}")
        text = raw.decode("utf-8", "replace"); msgs = []
        if "text/event-stream" in hd.get("content-type", ""):
            for line in text.splitlines():
                if line.startswith("data:"):
                    try: msgs.append(json.loads(line[5:].strip()))
                    except ValueError: pass
        else:
            try: j = json.loads(text or "{}"); msgs = j if isinstance(j, list) else [j]
            except ValueError: raise AdapterError("MCP server sent invalid JSON")
        m = next((x for x in msgs if isinstance(x, dict) and x.get("id") == i), None)
        if not m: raise AdapterError(f"MCP server did not answer {method}")
        if "error" in m: raise AdapterError("MCP: " + str((m["error"] or {}).get("message", ""))[:200])
        return m.get("result") or {}
    def tools(self): return [_spec(t) for t in self._rpc("tools/list", {}).get("tools", [])]
    def call(self, name, args):
        r = self._rpc("tools/call", {"name": name, "arguments": args if isinstance(args, dict) else {}})
        return ("ERROR: " if r.get("isError") else "") + "\n".join(c.get("text", "") for c in r.get("content", []) if c.get("type") == "text")
    def close(self): pass
