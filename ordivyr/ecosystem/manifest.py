"""Plugin manifest (ordivyr-plugin/1), permission vocabulary, tree hashing."""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from urllib.parse import urlparse

SCHEMA = "ordivyr-plugin/1"
MANIFEST = "ordivyr-plugin.json"
RUNTIMES = ("declarative", "native", "mcp", "a2a", "n8n", "langgraph")
ORIGINS = ("ordivyr", "mcp", "hermes", "openclaw", "opencode", "n8n", "langgraph", "a2a", "claude")
ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,39}$")
VER_RE = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,59}$")
CMD_RE = re.compile(r"^[A-Za-z0-9._/+-]{1,120}$")
SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY|xox[abp]-[A-Za-z0-9-]{10,}|ghp_[A-Za-z0-9]{20,})")
MAX_MANIFEST = 200_000
PERM_KINDS = ("net", "fs.read", "fs.write", "exec", "env", "memory", "tool.write", "paid")


class ManifestError(ValueError): pass


def perm(p):
    """'net:api.example.com' -> ('net', 'api.example.com'). Validates shape; bare kinds (tool.write, paid) take no argument."""
    if not isinstance(p, str) or len(p) > 300: raise ManifestError("permissions are short strings like 'net:api.example.com'")
    k, _, a = p.partition(":")
    if k not in PERM_KINDS: raise ManifestError(f"unknown permission {k!r}; expected one of {PERM_KINDS}")
    if k in ("tool.write", "paid"):
        if a: raise ManifestError(f"{k} takes no argument")
    elif not a: raise ManifestError(f"permission {k} needs an argument, e.g. {k}:...")
    elif k == "env" and not ENV_RE.match(a): raise ManifestError("env permission must be an UPPER_SNAKE_CASE name")
    elif k == "exec" and not CMD_RE.match(a): raise ManifestError("exec permission must be one program name or path")
    elif k == "net" and a != "local" and not re.match(r"^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$", a): raise ManifestError("net permission must be a host (optionally :port) or 'local'")
    elif k in ("fs.read", "fs.write") and (not a.startswith("/") or ".." in Path(a).parts): raise ManifestError(f"{k} needs an absolute path without '..'")
    elif k == "memory" and not re.match(r"^[a-z0-9._-]{1,60}$", a): raise ManifestError("memory permission must be a namespace name")
    return k, a


def _s(v, n): return str(v if v is not None else "")[:n]


def _url(u, what):
    p = urlparse(str(u or "").strip())
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password: raise ManifestError(f"{what}: URL must be http(s):// with no credentials")
    if p.scheme == "http" and p.hostname not in ("127.0.0.1", "localhost", "::1"): raise ManifestError(f"{what}: use https for remote servers")
    return str(u).strip().rstrip("/")


def clean(doc):
    """Validate an untrusted manifest -> a new normalised dict (unknown keys dropped). Raises ManifestError with a plain message."""
    if isinstance(doc, (str, bytes)):
        if len(doc) > MAX_MANIFEST: raise ManifestError("manifest is too large")
        try: doc = json.loads(doc)
        except ValueError: raise ManifestError("manifest is not valid JSON")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA: raise ManifestError(f"not an ORDIVYR plugin manifest (expected schema {SCHEMA!r})")
    if SECRET_RE.search(json.dumps(doc)): raise ManifestError("manifest appears to contain a secret; plugins never carry keys - name an env var permission instead")
    pid = _s(doc.get("id"), 40)
    if not ID_RE.match(pid): raise ManifestError("id: lowercase letters, digits, - and _ (2-40, starts with a letter)")
    ver = _s(doc.get("version"), 40)
    if not VER_RE.match(ver): raise ManifestError("version must look like 1.2.3")
    rt = doc.get("runtime")
    if rt not in RUNTIMES: raise ManifestError(f"runtime must be one of {RUNTIMES}")
    origin = doc.get("origin") if doc.get("origin") in ORIGINS else "ordivyr"
    e = doc.get("entry") if isinstance(doc.get("entry"), dict) else {}
    entry = {}
    if rt == "mcp":
        t = e.get("transport")
        if t == "stdio":
            cmd = _s(e.get("command"), 120)
            if not CMD_RE.match(cmd): raise ManifestError("entry.command must be one program name or path (no spaces or shell characters)")
            args = [str(a) for a in (e.get("args") or [])][:30]
            if any("\n" in a or len(a) > 400 for a in args): raise ManifestError("entry.args: bad argument")
            entry = {"transport": "stdio", "command": cmd, "args": args}
        elif t == "http": entry = {"transport": "http", "url": _url(e.get("url"), "entry.url")}
        else: raise ManifestError("entry.transport must be stdio or http")
    elif rt == "a2a": entry = {"url": _url(e.get("url"), "entry.url")}
    elif rt == "langgraph":
        aid = _s(e.get("assistant_id"), 100)
        if not aid: raise ManifestError("entry.assistant_id is required")
        key_env = _s(e.get("api_key_env"), 60)
        if key_env and not ENV_RE.match(key_env): raise ManifestError("entry.api_key_env must be an UPPER_SNAKE_CASE name")
        entry = {"url": _url(e.get("url"), "entry.url"), "assistant_id": aid, "api_key_env": key_env}
    elif rt == "n8n":
        hooks = []
        for h in (e.get("webhooks") or [])[:20]:
            nm = re.sub(r"[^a-z0-9_]+", "_", _s(h.get("name") if isinstance(h, dict) else "", 40).lower()).strip("_")
            if not nm: raise ManifestError("each n8n webhook needs a simple name")
            hooks.append({"name": nm, "url": _url(h.get("url"), "webhook url"), "description": _s(h.get("description"), 200)})
        if not hooks: raise ManifestError("an n8n plugin needs at least one webhook")
        entry = {"webhooks": hooks}
    elif rt == "native":
        mod = _s(e.get("module"), 80)
        if not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\.py$", mod) or "/" in mod: raise ManifestError("entry.module must be a .py file inside the plugin folder")
        entry = {"module": mod}
    else:  # declarative
        entry = {"skills": [_s(x, 80) for x in (e.get("skills") or []) if isinstance(x, str)][:200], "agents": [_s(x, 80) for x in (e.get("agents") or []) if isinstance(x, str)][:50]}
    perms = []
    for p in doc.get("permissions") or []:
        k, a = perm(p); perms.append(f"{k}:{a}" if a else k)
    if rt == "native" and "tool.write" not in perms: pass
    return {"schema": SCHEMA, "id": pid, "name": _s(doc.get("name"), 60) or pid, "version": ver, "runtime": rt, "origin": origin, "description": _s(doc.get("description"), 400),
            "author": _s(doc.get("author"), 80), "license": _s(doc.get("license"), 40), "homepage": _s(doc.get("homepage"), 200), "entry": entry,
            "permissions": sorted(set(perms))[:60], "advisory_permissions": sorted({_s(x, 120) for x in (doc.get("advisory_permissions") or []) if isinstance(x, str)})[:60],
            "ordivyr": _s(doc.get("ordivyr"), 20)}


def tree_hash(root):
    """sha256 over (relative path, content) of every regular file under root except the lock-managed ones. Symlinks are rejected, not followed."""
    root = Path(root); h = hashlib.sha256()
    for f in sorted(root.rglob("*")):
        if "__pycache__" in f.relative_to(root).parts: continue          # interpreter caches are not plugin content
        if f.is_symlink(): raise ManifestError(f"symlink not allowed in a plugin: {f.relative_to(root)}")
        if f.is_file():
            h.update(str(f.relative_to(root)).encode() + b"\0" + hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()
