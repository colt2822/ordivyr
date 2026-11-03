"""Importers: turn other ecosystems' artefacts into ORDIVYR plugin manifests (+ text files). Pure parsing - nothing is executed, no secret VALUES are read into manifests.

  Hermes / OpenClaw / Claude-style skill folders (SKILL.md)   -> declarative plugin (only SKILL.md files are copied; bundled scripts are dropped and reported)
  OpenCode config (opencode.json / .jsonc `mcp`)             -> one MCP plugin per server (env NAMES become requested env permissions)
  .mcp.json (Claude Code / Cursor / generic `mcpServers`)    -> one MCP plugin per server
  OpenCode / Claude agent markdown (.opencode/agent/*.md)    -> declarative plugin of agent definitions
  n8n exported workflow JSON                                 -> n8n plugin with a webhook tool per Webhook node
"""
from __future__ import annotations
import json, re
from pathlib import Path
from urllib.parse import urlparse
from . import manifest as MF
from .adapters import skills as SK, n8n as N8

MAX_FILE = 200_000


def slug(name, prefix=""):
    s = re.sub(r"[^a-z0-9_-]+", "-", (prefix + str(name)).lower()).strip("-_")
    s = re.sub(r"-{2,}", "-", s)
    if not s or not s[0].isalpha(): s = "p-" + s
    return s[:40].rstrip("-_") or "plugin"


def _ver(v): return v if isinstance(v, str) and MF.VER_RE.match(v) else "0.0.1"


def _jsonc(text):
    out = []; i = 0; instr = False
    while i < len(text):
        c = text[i]
        if instr:
            out.append(c)
            if c == "\\": out.append(text[i + 1] if i + 1 < len(text) else ""); i += 1
            elif c == '"': instr = False
        elif c == '"': instr = True; out.append(c)
        elif text.startswith("//", i): i = text.find("\n", i); i = len(text) if i < 0 else i; continue
        elif text.startswith("/*", i): j = text.find("*/", i + 2); i = len(text) if j < 0 else j + 2; continue
        else: out.append(c)
        i += 1
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))


def _skill_files(root):
    root = Path(root); found = []
    cands = [root / "SKILL.md"] if (root / "SKILL.md").is_file() else sorted(root.glob("**/SKILL.md"))
    for f in cands[:200]:
        if f.is_symlink() or any(p.is_symlink() for p in f.parents if root in p.parents or p == root): continue
        found.append(f)
    return found


def skills_dir(path, origin="hermes", plugin_id=None):
    """-> (manifest_doc, files, notes). Works for a single skill folder or a whole skills tree."""
    root = Path(path); notes = []; files = {}; names = []; adv = set(); desc = ""
    for f in _skill_files(root):
        text = f.read_text("utf-8", "replace")[:MAX_FILE]; meta, _ = SK.parse_frontmatter(text); name = slug(meta.get("name") or f.parent.name)
        if name in names: continue
        names.append(name); files[f"skills/{name}/SKILL.md"] = text; desc = desc or str(meta.get("description", ""))[:200]
        req = meta.get("prerequisites") or {}
        for c in (req.get("commands") or []) if isinstance(req, dict) else []: adv.add(f"exec:{c}") if MF.CMD_RE.match(str(c)) else None
        md = meta.get("metadata")
        if isinstance(md, str):
            try: md = json.loads(md)
            except ValueError: md = {}
        rq = ((md or {}).get("openclaw") or {}).get("requires") or {} if isinstance(md, dict) else {}
        for b in rq.get("bins") or []: adv.add(f"exec:{b}") if MF.CMD_RE.match(str(b)) else None
        for e in rq.get("env") or []: adv.add(f"env:{e}") if MF.ENV_RE.match(str(e)) else None
        extra = [p.name for p in f.parent.iterdir() if p.name != "SKILL.md"]
        if extra: notes.append(f"{name}: dropped bundled files not imported (scripts are never copied): {', '.join(sorted(extra)[:5])}")
    if not names: raise MF.ManifestError("no SKILL.md found")
    pid = plugin_id or slug(root.name if root.name != "skills" else root.parent.name, origin + "-")
    doc = {"schema": MF.SCHEMA, "id": pid, "name": pid, "version": "0.0.1", "runtime": "declarative", "origin": origin, "description": desc or f"{len(names)} imported skill(s)",
           "entry": {"skills": names}, "permissions": [], "advisory_permissions": sorted(adv)}
    return doc, files, notes


def _mcp_server_doc(name, srv, origin):
    pid = slug(name, "mcp-"); perms = []; notes = []
    env = srv.get("env") or srv.get("environment") or {}
    for k in env if isinstance(env, dict) else []:
        if MF.ENV_RE.match(str(k)): perms.append(f"env:{k}")
    cmd = srv.get("command"); args = list(srv.get("args") or [])
    if isinstance(cmd, list) and cmd: cmd, args = cmd[0], [str(a) for a in cmd[1:]]
    url = srv.get("url")
    if cmd and not url:
        base = {"schema": MF.SCHEMA, "id": pid, "name": name, "version": "0.0.1", "runtime": "mcp", "origin": origin, "entry": {"transport": "stdio", "command": str(cmd), "args": args}}
        perms.append(f"exec:{cmd}")
        if not srv.get("disabled") and srv.get("enabled", True) is False: notes.append("marked disabled in the source config")
    elif url:
        u = urlparse(str(url)); h = u.hostname or ""
        base = {"schema": MF.SCHEMA, "id": pid, "name": name, "version": "0.0.1", "runtime": "mcp", "origin": origin, "entry": {"transport": "http", "url": str(url)}}
        perms.append("net:local" if h in ("127.0.0.1", "localhost", "::1") else f"net:{h}" + (f":{u.port}" if u.port else ""))
    else: raise MF.ManifestError(f"{name}: server has neither command nor url")
    if env and any(not (MF.ENV_RE.match(str(k))) for k in env): notes.append("some env names were not UPPER_SNAKE_CASE and were skipped; secret values are never imported")
    base["permissions"] = perms
    if any(isinstance(v, str) and MF.SECRET_RE.search(v) for v in (env.values() if isinstance(env, dict) else [])): notes.append("the source config embeds a secret value; it was NOT imported - supply it via the environment")
    return base, {}, notes


def mcp_servers(path_or_dict, origin="mcp"):
    """.mcp.json -> [(doc, files, notes)]."""
    d = path_or_dict if isinstance(path_or_dict, dict) else _jsonc(Path(path_or_dict).read_text("utf-8")[:MAX_FILE])
    servers = d.get("mcpServers") or d.get("servers") or {}
    out = []
    for n, s in list(servers.items())[:50]:
        try: out.append(_mcp_server_doc(n, s, origin))
        except MF.ManifestError as e: out.append((None, {}, [str(e)]))
    return out


def opencode_config(path):
    d = _jsonc(Path(path).read_text("utf-8")[:MAX_FILE]); out = []
    for n, s in list((d.get("mcp") or {}).items())[:50]:
        if not isinstance(s, dict): continue
        s = dict(s)
        if s.get("type") == "remote": s["command"] = None
        try: out.append(_mcp_server_doc(n, s, "opencode"))
        except MF.ManifestError as e: out.append((None, {}, [str(e)]))
    return out


OC_TOOLS = {"bash": "shell", "write": "file_write", "edit": "file_write", "webfetch": "http_api", "patch": "file_write"}


def agent_md(text, fallback_name):
    meta, body = SK.parse_frontmatter(text); tools = meta.get("tools") if isinstance(meta.get("tools"), dict) else {}
    on = sorted({OC_TOOLS[k] for k, v in tools.items() if k in OC_TOOLS and str(v).lower() == "true"})
    return {"name": str(meta.get("name") or fallback_name)[:40], "role": str(meta.get("description", ""))[:80], "instructions": body.strip()[:2000], "tools": on,
            "permissions": "workspace-write" if "file_write" in on else "read-only", "source_model": str(meta.get("model", ""))[:80]}


def agents_dir(path, origin="opencode", plugin_id=None):
    root = Path(path); files = {}; names = []
    for f in sorted(root.glob("*.md"))[:50]:
        if f.is_symlink(): continue
        n = slug(f.stem); names.append(n); files[f"agents/{n}.md"] = f.read_text("utf-8", "replace")[:MAX_FILE]
    if not names: raise MF.ManifestError("no agent markdown files found")
    pid = plugin_id or slug(root.parent.name if root.name == "agent" or root.name == "agents" else root.name, origin + "-agents-")
    return {"schema": MF.SCHEMA, "id": pid, "name": pid, "version": "0.0.1", "runtime": "declarative", "origin": origin, "description": f"{len(names)} imported agent definition(s)",
            "entry": {"agents": names}, "permissions": []}, files, []


def n8n_workflow(path, base_url, plugin_id=None):
    wf = json.loads(Path(path).read_text("utf-8")[:2_000_000]); hooks = N8.workflow_webhooks(wf, base_url)
    if not hooks: raise MF.ManifestError("workflow has no Webhook trigger node (only webhook-triggered workflows can be called as tools)")
    u = urlparse(base_url); h = u.hostname or ""
    pid = plugin_id or slug(wf.get("name") or Path(path).stem, "n8n-")
    return {"schema": MF.SCHEMA, "id": pid, "name": str(wf.get("name") or pid)[:60], "version": "0.0.1", "runtime": "n8n", "origin": "n8n", "description": "n8n workflow (webhook-triggered)",
            "entry": {"webhooks": [{**x, "name": slug(x["name"]).replace("-", "_")} for x in hooks]},
            "permissions": ["net:local" if h in ("127.0.0.1", "localhost", "::1") else f"net:{h}" + (f":{u.port}" if u.port else "")]}, {}, []


def agent_to_board_agent(core, a):
    """Imported agent definition -> a normal ORDIVYR agent dict. Model is left on the free deterministic default: foreign model names are never assumed to be connected."""
    ag = core.new_agent(0, 0, a["name"], instructions=a["instructions"], tools=list(a["tools"]), permissions=a["permissions"])
    ag["soul"] = a["role"]; return ag
