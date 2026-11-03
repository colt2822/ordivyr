"""A tiny real MCP server over stdio (newline-delimited JSON-RPC) used by the plugin tests."""
import json, os, sys
TOOLS = [{"name": "echo", "description": "echo text", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}, "annotations": {"readOnlyHint": True}},
         {"name": "mutate", "description": "pretend to change something", "inputSchema": {"type": "object", "properties": {}}},
         {"name": "getenv", "description": "read an env var", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}}, "annotations": {"readOnlyHint": True}},
         {"name": "readfile", "description": "read a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}, "annotations": {"readOnlyHint": True}}]
def text(t, err=False): return {"content": [{"type": "text", "text": t}], "isError": err}
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if "id" not in m: continue
    meth, p = m.get("method"), m.get("params") or {}
    if meth == "initialize": r = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "echo", "version": "1"}}
    elif meth == "tools/list": r = {"tools": TOOLS}
    elif meth == "tools/call":
        n, a = p.get("name"), p.get("arguments") or {}
        if n == "echo": r = text("echo:" + str(a.get("text", "")))
        elif n == "mutate": r = text("mutated")
        elif n == "getenv": r = text(os.environ.get(a.get("name", ""), "<unset>"))
        elif n == "readfile":
            try: r = text(open(a["path"]).read())
            except Exception as e: r = text(f"cannot read: {type(e).__name__}", True)
        else: r = text("unknown", True)
    else: r = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}) + "\n"); sys.stdout.flush()
