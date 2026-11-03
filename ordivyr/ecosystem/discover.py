"""Discovery: (1) a read-only scan of this machine for importable artefacts from other ecosystems, (2) a signed-by-hash remote catalog.
Scanning lists and classifies; it never imports, installs, enables or executes anything, and never reads config values (only structure)."""
from __future__ import annotations
import hashlib, json, tempfile
from pathlib import Path
from . import importers as IM, manifest as MF, store as ST

MAX_HITS = 300


def _rel(p, home): 
    try: return "~/" + str(Path(p).relative_to(home))
    except ValueError: return str(p)


def scan_local(home=None, cwd=None, extra_dirs=()):
    home = Path(home or Path.home()); cwd = Path(cwd or Path.cwd()); hits = []
    def add(**k):
        if len(hits) < MAX_HITS: hits.append(k)
    hs = home / ".hermes" / "skills"
    if hs.is_dir():
        for cat in sorted(p for p in hs.iterdir() if p.is_dir())[:60]:
            n = len(list(cat.glob("**/SKILL.md")))
            if n: add(origin="hermes", kind="skills", name=cat.name, path=str(cat), display=_rel(cat, home), items=n, importable=True, how=f"ordivyr plugin import skills {cat} --origin hermes")
    hp = home / ".hermes" / "plugins"
    if hp.is_dir():
        for p in sorted(x for x in hp.iterdir() if x.is_dir())[:40]:
            add(origin="hermes", kind="plugin", name=p.name, path=str(p), display=_rel(p, home), importable=False, note="Hermes Python plugin (plugin.yaml): runs inside Hermes; use it from Hermes, or expose it over MCP")
    oc = home / ".openclaw"
    if oc.is_dir():
        seen = set()
        for f in list(oc.glob("**/SKILL.md"))[:400]:
            d = f.parent.parent
            if d in seen or "node_modules" in f.parts and ".system" not in f.parts and "skills" not in f.parts: continue
            seen.add(d); add(origin="openclaw", kind="skills", name=d.parent.name + "/" + d.name, path=str(d), display=_rel(d, home), items=len(list(d.glob("*/SKILL.md"))) or 1, importable=True, how=f"ordivyr plugin import skills {d} --origin openclaw")
        for f in list(oc.glob("npm/**/openclaw.plugin.json"))[:40]:
            try: pj = json.loads(f.read_text("utf-8")[:200000])
            except (OSError, ValueError): continue
            add(origin="openclaw", kind="plugin", name=str(pj.get("id", f.parent.name)), path=str(f.parent), display=_rel(f.parent, home), importable=False, note="OpenClaw TypeScript plugin: needs the OpenClaw gateway runtime; ORDIVYR can only use its skills or an MCP server it exposes")
    for cfg in [home / ".config/opencode/opencode.json", home / ".config/opencode/opencode.jsonc", cwd / "opencode.json", cwd / "opencode.jsonc"]:
        if cfg.is_file():
            try: n = len(IM.opencode_config(cfg))
            except Exception: n = 0
            add(origin="opencode", kind="mcp-config", name=cfg.name, path=str(cfg), display=_rel(cfg, home), items=n, importable=n > 0, how=f"ordivyr plugin import opencode {cfg}")
    for d in [cwd / ".opencode" / "agent", cwd / ".opencode" / "agents", cwd / ".claude" / "agents", home / ".config/opencode/agent", home / ".claude" / "agents"]:
        if d.is_dir() and list(d.glob("*.md")): add(origin="opencode" if "opencode" in str(d) else "claude", kind="agents", name=str(d.parent.name), path=str(d), display=_rel(d, home), items=len(list(d.glob("*.md"))), importable=True, how=f"ordivyr plugin import agents {d}")
    for f in [cwd / ".mcp.json", home / ".mcp.json", home / ".cursor/mcp.json"]:
        if f.is_file():
            try: n = len(IM.mcp_servers(f))
            except Exception: n = 0
            add(origin="mcp", kind="mcp-config", name=f.name, path=str(f), display=_rel(f, home), items=n, importable=n > 0, how=f"ordivyr plugin import mcp {f}")
    for d in extra_dirs:
        for f in sorted(Path(d).glob("*.json"))[:100]:
            try: j = json.loads(f.read_text("utf-8")[:2_000_000])
            except (OSError, ValueError): continue
            if isinstance(j, dict) and isinstance(j.get("nodes"), list) and any(str(n.get("type", "")).startswith("n8n-nodes-base") for n in j["nodes"] if isinstance(n, dict)):
                add(origin="n8n", kind="workflow", name=str(j.get("name", f.stem)), path=str(f), display=str(f), importable=True, how=f"ordivyr plugin import n8n {f} --base-url http://127.0.0.1:5678")
            elif isinstance(j, dict) and j.get("schema") == MF.SCHEMA: add(origin="ordivyr", kind="manifest", name=str(j.get("id")), path=str(f), display=str(f), importable=False, note="a manifest file - install the folder that contains it")
    return hits


class Catalog:
    """Remote or local JSON index: {"plugins":[{"id","name","version","description","origin","source":{"url","sha256"}}]}. Install is refused unless the archive matches its sha256.
    No default catalog is shipped; you name the one you trust."""
    def __init__(self, index): self.index = index if isinstance(index, dict) else {}
    @classmethod
    def load(cls, location, http=None):
        if str(location).startswith(("http://", "https://")):
            from .adapters import default_http
            st, _, raw = (http or default_http)("GET", location, {"Accept": "application/json", "User-Agent": "ordivyr"}, None, 30)
            if st >= 400: raise ST.StoreError(f"catalog returned HTTP {st}")
        else: raw = Path(location).read_bytes()
        try: return cls(json.loads(raw))
        except ValueError: raise ST.StoreError("catalog is not valid JSON")
    def search(self, q=""):
        q = q.lower(); return [p for p in self.index.get("plugins", []) if isinstance(p, dict) and (not q or q in json.dumps({k: p.get(k) for k in ("id", "name", "description", "origin")}).lower())]
    def install(self, store, pid, http=None):
        e = next((p for p in self.index.get("plugins", []) if p.get("id") == pid), None)
        if not e: raise ST.StoreError(f"{pid} is not in the catalog")
        src = e.get("source") or {}; want = str(src.get("sha256", "")).lower()
        if len(want) != 64: raise ST.StoreError("catalog entry has no sha256 pin; refusing")
        from .adapters import default_http
        st, _, raw = (http or default_http)("GET", src.get("url", ""), {"User-Agent": "ordivyr"}, None, 120)
        if st >= 400: raise ST.StoreError(f"download returned HTTP {st}")
        if hashlib.sha256(raw).hexdigest() != want: raise ST.StoreError("downloaded archive does not match the catalog sha256; not installed")
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "pkg.bin"; f.write_bytes(raw); return store.install(f, sha256=want, origin_note=f"catalog:{pid}")
