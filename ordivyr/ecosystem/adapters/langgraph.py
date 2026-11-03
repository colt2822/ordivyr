"""LangGraph Platform / Server client: run an assistant to completion (`POST /runs/wait`) and list assistants (`POST /assistants/search`)."""
from __future__ import annotations
import json, os
from . import AdapterError, Net


def _last_text(out):
    if isinstance(out, dict):
        msgs = out.get("messages")
        if isinstance(msgs, list) and msgs:
            m = msgs[-1]; c = m.get("content") if isinstance(m, dict) else m
            if isinstance(c, list): c = "".join(p.get("text", "") for p in c if isinstance(p, dict))
            return str(c)
    return json.dumps(out)[:8000] if not isinstance(out, str) else out


class LangGraph:
    def __init__(self, entry, policy, http=None):
        self.url, self.aid, self.net = entry["url"], entry["assistant_id"], Net(policy, http, 300)
        self.keyenv = entry.get("api_key_env") or ""; self.policy = policy
    def _h(self):
        k = os.environ.get(self.keyenv, "") if self.keyenv and self.policy.has("env", self.keyenv) else ""
        return {"x-api-key": k} if k else {}
    def tools(self):
        return [{"name": "run", "description": f"Run LangGraph assistant '{self.aid}' and return its final answer", "inputSchema": {"type": "object", "properties": {"input": {"type": "string"}}, "required": ["input"]}, "readOnly": False}]
    def call(self, name, args):
        if name != "run": raise AdapterError("unknown tool")
        inp = args.get("input", ""); inp = {"messages": [{"role": "user", "content": inp}]} if isinstance(inp, str) else inp
        j, _ = self.net.json("POST", self.url + "/runs/wait", {"assistant_id": self.aid, "input": inp}, self._h())
        return _last_text(j)[:8000]
    def discover(self):
        j, _ = self.net.json("POST", self.url + "/assistants/search", {"limit": 50}, self._h())
        return [{"assistant_id": a.get("assistant_id"), "name": a.get("name"), "graph_id": a.get("graph_id")} for a in (j if isinstance(j, list) else [])]
    def close(self): pass
