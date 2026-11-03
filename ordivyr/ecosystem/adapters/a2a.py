"""A2A (Agent2Agent) client + a minimal server side.

Client: fetch the agent card (/.well-known/agent-card.json, falling back to /.well-known/agent.json), expose one tool `ask` that sends
JSON-RPC `message/send`, and poll `tasks/get` for non-terminal tasks. Server: `card_for_board` and `handle_rpc` let an ORDIVYR board answer A2A callers.
"""
from __future__ import annotations
import time, uuid
from . import AdapterError, Net

TERMINAL = {"completed", "failed", "canceled", "rejected", "input-required", "auth-required"}


def _text(parts): return "\n".join(p.get("text", "") for p in (parts or []) if isinstance(p, dict) and (p.get("kind") == "text" or "text" in p))


def extract(result):
    """Message or Task -> (text, state)."""
    if not isinstance(result, dict): return "", "unknown"
    if result.get("kind") == "message" or "parts" in result: return _text(result.get("parts")), "completed"
    st = (result.get("status") or {}); state = st.get("state", "unknown"); out = []
    for a in result.get("artifacts") or []: out.append(_text(a.get("parts")))
    if (st.get("message") or {}).get("parts"): out.append(_text(st["message"]["parts"]))
    return "\n".join(x for x in out if x), state


class A2AClient:
    def __init__(self, entry, policy, http=None, poll=(0.5, 8), sleep=time.sleep):
        self.base = entry["url"].rstrip("/"); self.net = Net(policy, http, 60); self.sleep = sleep; self.poll = poll; self.card = None
        for path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
            try: self.card, _ = self.net.json("GET", self.base + path); break
            except AdapterError: continue
        if not isinstance(self.card, dict): raise AdapterError("no A2A agent card found")
        self.rpc_url = self.card.get("url") or self.base
        if not str(self.rpc_url).startswith(("http://", "https://")): self.rpc_url = self.base
    def tools(self):
        skills = ", ".join(s.get("name", "") for s in (self.card.get("skills") or [])[:6] if isinstance(s, dict))
        return [{"name": "ask", "description": f"Ask the remote agent '{self.card.get('name', 'agent')}': {str(self.card.get('description', ''))[:160]}" + (f" Skills: {skills}" if skills else ""),
                 "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}, "readOnly": False}]
    def call(self, name, args):
        if name != "ask": raise AdapterError("unknown tool")
        msg = {"role": "user", "parts": [{"kind": "text", "text": str(args.get("message", ""))[:8000]}], "messageId": uuid.uuid4().hex, "kind": "message"}
        j, _ = self.net.json("POST", self.rpc_url, {"jsonrpc": "2.0", "id": uuid.uuid4().hex, "method": "message/send", "params": {"message": msg}})
        if "error" in j: raise AdapterError("A2A: " + str((j["error"] or {}).get("message", ""))[:200])
        res = j.get("result") or {}; text, state = extract(res); tries = 0
        while state not in TERMINAL and state != "completed" and res.get("id") and tries < self.poll[1]:
            tries += 1; self.sleep(self.poll[0])
            j, _ = self.net.json("POST", self.rpc_url, {"jsonrpc": "2.0", "id": uuid.uuid4().hex, "method": "tasks/get", "params": {"id": res["id"]}}); res = j.get("result") or {}; text, state = extract(res)
        return (text or f"(no text; task state: {state})") + ("" if state in ("completed", "unknown") else f"\n[task state: {state}]")
    def close(self): pass


def card_for_board(board, url, version="0.4.0"):
    """An A2A agent card describing a board: one skill per agent (name + role/instructions summary)."""
    return {"protocolVersion": "0.3.0", "name": board.get("name", "ORDIVYR board"), "description": f"ORDIVYR board with {len(board.get('agents', []))} agents", "url": url, "version": version,
            "capabilities": {"streaming": False}, "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
            "skills": [{"id": a["id"], "name": a.get("name", a["id"]), "description": (a.get("instructions") or a.get("soul") or "")[:160], "tags": list((a.get("license") or {}).get("skills", []))}
                       for a in board.get("agents", [])]}


def handle_rpc(req, run_mission):
    """JSON-RPC handler: `message/send` runs the board via run_mission(text) -> str and returns a completed Message. Nothing else is accepted."""
    rid = req.get("id") if isinstance(req, dict) else None
    if not isinstance(req, dict) or req.get("jsonrpc") != "2.0": return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": "invalid request"}}
    if req.get("method") != "message/send": return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "only message/send is supported"}}
    text = _text(((req.get("params") or {}).get("message") or {}).get("parts"))
    if not text.strip(): return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "message has no text"}}
    try: out = run_mission(text[:8000])
    except Exception as e: return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": f"{type(e).__name__}: {str(e)[:160]}"}}
    return {"jsonrpc": "2.0", "id": rid, "result": {"kind": "message", "role": "agent", "messageId": uuid.uuid4().hex, "parts": [{"kind": "text", "text": str(out)[:20000]}]}}
