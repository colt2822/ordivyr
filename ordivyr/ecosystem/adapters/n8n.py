"""n8n: each webhook becomes a tool (POST JSON). `workflow_webhooks` reads an exported workflow JSON and finds its Webhook nodes."""
from __future__ import annotations
import json
from . import AdapterError, Net


class N8n:
    def __init__(self, entry, policy, http=None): self.hooks = {h["name"]: h for h in entry["webhooks"]}; self.net = Net(policy, http, 120)
    def tools(self):
        return [{"name": n, "description": h["description"] or f"Trigger n8n webhook {n}", "inputSchema": {"type": "object", "properties": {"payload": {"type": "object"}}}, "readOnly": False} for n, h in self.hooks.items()]
    def call(self, name, args):
        h = self.hooks.get(name)
        if not h: raise AdapterError("unknown tool")
        st, hd, raw = self.net.request("POST", h["url"], args.get("payload") if isinstance(args.get("payload"), dict) else {k: v for k, v in args.items()})
        body = raw.decode("utf-8", "replace")
        if st >= 400: raise AdapterError(f"n8n webhook returned HTTP {st}: {body[:200]}")
        return body[:8000]
    def close(self): pass


def workflow_webhooks(workflow, base_url):
    """Exported n8n workflow dict -> [{'name','url','description'}] for its Webhook trigger nodes (production URLs: {base}/webhook/{path})."""
    out = []
    for n in workflow.get("nodes", []) if isinstance(workflow, dict) else []:
        if str(n.get("type", "")).endswith(".webhook") or n.get("type") == "n8n-nodes-base.webhook":
            path = str((n.get("parameters") or {}).get("path") or "").strip("/")
            if path: out.append({"name": (n.get("name") or path), "url": base_url.rstrip("/") + "/webhook/" + path, "description": f"n8n workflow '{workflow.get('name', '')}' via {n.get('name', 'webhook')}"})
    return out
