"""MCP tool connections: a catalog of one-click servers + the exact config handed to ONE agent run.

The user adds a server once (Settings -> Tools); an agent can use it only if its License grants that server's id. The runner builds a
config containing ONLY the granted, enabled servers and tells Claude to use no others (--strict-mcp-config) - so the grant is enforced by
the runtime, not by the prompt. MCP servers are real programs on this machine (not sandboxed), so they are only added from the UI by the
user (CSRF-protected), never from an imported board, and their secrets live in secrets.json (0600), never in settings.json or the browser.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

ID_RE = re.compile(r"[a-z][a-z0-9_]{0,29}")
KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{0,59}")
# key: label, transport, command, args, env keys it needs, what it gives an agent
CATALOG = {
    "github": {"label": "GitHub", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": ["GITHUB_PERSONAL_ACCESS_TOKEN"], "about": "Read repos, issues and pull requests"},
    "filesystem": {"label": "Files (a folder)", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "{folder}"], "env": [], "about": "Read and write inside ONE folder you pick", "ask": "folder"},
    "fetch": {"label": "Web fetch", "transport": "stdio", "command": "uvx", "args": ["mcp-server-fetch"], "env": [], "about": "Read web pages as text"},
    "brave_search": {"label": "Brave Search", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-brave-search"], "env": ["BRAVE_API_KEY"], "about": "Search the web"},
    "slack": {"label": "Slack", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"], "env": ["SLACK_BOT_TOKEN", "SLACK_TEAM_ID"], "about": "Read and post in channels"},
    "playwright": {"label": "Browser (Playwright)", "transport": "stdio", "command": "npx", "args": ["-y", "@playwright/mcp@latest"], "env": [], "about": "Drive a real browser"},
    "memory": {"label": "Notes (knowledge graph)", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"], "env": [], "about": "Remember facts between runs"},
    "postgres": {"label": "Postgres (read)", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", "{url}"], "env": [], "about": "Query a database", "ask": "url"},
    "custom": {"label": "Custom (command or URL)", "transport": "stdio", "command": "", "args": [], "env": [], "about": "Any MCP server"},
}


class McpError(ValueError): pass


def clean(spec: dict) -> dict:
    """Validate one server record (never trust the client). Returns the stored form."""
    sid = str(spec.get("id", "")).strip()
    if not ID_RE.fullmatch(sid): raise McpError("id: lowercase letters, digits and _ only")
    t = spec.get("transport")
    out = {"id": sid, "label": str(spec.get("label") or sid)[:40], "transport": t, "enabled": bool(spec.get("enabled")), "env": [], "about": str(spec.get("about") or "")[:120]}
    for k in spec.get("env") or []:
        if not KEY_RE.fullmatch(str(k)): raise McpError(f"environment name {k!r} must be UPPER_SNAKE_CASE")
        out["env"].append(str(k))
    if t == "stdio":
        cmd = str(spec.get("command") or "").strip()
        if not cmd or re.search(r"\s|[;&|<>$`]", cmd): raise McpError("command must be one program name or path (no spaces or shell characters); put options in Arguments")
        args = [str(a) for a in (spec.get("args") or [])][:20]
        if any("\n" in a or len(a) > 300 for a in args): raise McpError("bad argument")
        out.update(command=cmd, args=args)
    elif t == "http":
        u = urlparse(str(spec.get("url") or "").strip())
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password: raise McpError("URL must be http(s):// with no credentials in it")
        if u.scheme == "http" and u.hostname not in ("127.0.0.1", "localhost", "::1"): raise McpError("use https for remote servers")
        out["url"] = str(spec["url"]).strip()
    else: raise McpError("transport must be stdio or http")
    return out


def from_catalog(key: str, ask: str = "") -> dict:
    c = CATALOG.get(key)
    if not c: raise McpError("unknown tool")
    spec = {"id": key, "label": c["label"], "transport": c["transport"], "command": c["command"], "args": [a for a in c["args"]], "env": list(c["env"]), "about": c["about"]}
    if c.get("ask"):
        if not ask.strip(): raise McpError({"folder": "pick the folder to share", "url": "enter the connection URL"}[c["ask"]])
        spec["args"] = [ask.strip() if a == "{" + c["ask"] + "}" else a for a in spec["args"]]
    return spec


def claude_config(servers: list, secret) -> dict:
    """The --mcp-config document for exactly these servers. `secret(sid, key)` -> value or ''."""
    cfg = {}
    for s in servers:
        env = {k: secret(s["id"], k) for k in s.get("env", []) if secret(s["id"], k)}
        if s["transport"] == "stdio": cfg[s["id"]] = {"type": "stdio", "command": s["command"], "args": s.get("args", []), **({"env": env} if env else {})}
        else:
            tok = secret(s["id"], "AUTHORIZATION")
            cfg[s["id"]] = {"type": "http", "url": s["url"], **({"headers": {"Authorization": "Bearer " + tok}} if tok else {})}
    return {"mcpServers": cfg}


def missing_secrets(s: dict, secret) -> list:
    return [k for k in s.get("env", []) if not secret(s["id"], k)]


def granted(agent_mcp: list, registry: list) -> list:
    """The enabled registry servers this agent's License names (intersection - an agent cannot reach a server it was not granted)."""
    want = set(agent_mcp or []); return [s for s in registry if s.get("enabled") and s["id"] in want]
