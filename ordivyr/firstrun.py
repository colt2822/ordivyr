"""First-run setup, config defaults, diagnostics and task history for self-hosted ORDIVYR. No account, no cloud, no network except an optional endpoint probe you request."""
from __future__ import annotations
import json, os, sqlite3, stat, time, urllib.request
from pathlib import Path

CONFIG = "config.json"


def home_dir(home=None) -> Path: return Path(home or os.environ.get("ORDIVYR_HOME") or Path.home() / ".local/state/ordivyr")


def load_config(home=None):
    p = home_dir(home) / CONFIG
    return json.loads(p.read_text()) if p.exists() else None


def probe(url, key_file=None, timeout=5):
    """Is there an OpenAI-compatible server here? Returns (ok, detail, models). Sends the key only to the URL you configured."""
    h = {"Authorization": "Bearer " + Path(key_file).read_text().strip()} if key_file else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(url.rstrip("/") + "/models", headers=h), timeout=timeout) as r:
            j = json.loads(r.read()); return True, "reachable", [m.get("id") for m in j.get("data", [])][:10]
    except urllib.error.HTTPError as e: return False, f"HTTP {e.code} ({'key rejected or missing' if e.code in (401, 403) else 'unexpected'})", []
    except Exception as e: return False, f"{type(e).__name__}: {e}", []


def init(home=None, provider="none", url=None, key_file=None, model=None, nova=True, check=False, force=False, tenant="local", project="default"):
    h = home_dir(home); cfgp = h / CONFIG
    if cfgp.exists() and not force: raise FileExistsError(f"{cfgp} exists (use --force to overwrite; nothing was changed)")
    if provider in ("openai", "ollama") and not url: raise ValueError(f"--url is required for provider {provider}")
    h.mkdir(parents=True, exist_ok=True); os.chmod(h, 0o700); (h / "memory").mkdir(exist_ok=True, mode=0o700)
    cfg = {"version": 1, "provider": {"kind": provider, "url": url, "key_file": str(Path(key_file).resolve()) if key_file else None, "model": model},
           "memory": {"backend": "nova" if nova else "none", "db": str(h / "memory" / "nova.db"), "tenant": tenant, "project": project}, "durable_db": str(h / "queue.db")}
    report = {"home": str(h), "config": str(cfgp)}
    if check and provider in ("openai", "ollama"):
        ok, detail, models = probe(url if provider == "openai" else url.rstrip("/") + "/v1", key_file); report["endpoint"] = {"ok": ok, "detail": detail, "models": models}
        if ok and not model and models: cfg["provider"]["model"] = models[0]
    if nova:
        from .nova_memory import NovaMemory
        NovaMemory(cfg["memory"]["db"]); report["memory_db"] = cfg["memory"]["db"]               # creates DB, signing key (0600), schema
    fd = os.open(str(cfgp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f: json.dump(cfg, f, indent=2)
    report["next"] = ["ordivyr diagnose", "ordivyr new <template> -o board.json", "ordivyr run board.json --mission \"...\"", "ordivyr memory search \"query\""]
    return report


def apply_defaults(a, cfg):
    """Fill ONLY options the user did not pass. Explicit flags always win."""
    if not cfg: return a
    pv, mem = cfg.get("provider") or {}, cfg.get("memory") or {}
    if pv.get("kind") == "openai" and not getattr(a, "openai", None): a.openai = pv.get("url"); a.key_file = getattr(a, "key_file", None) or pv.get("key_file")
    if pv.get("kind") == "ollama" and not getattr(a, "ollama", None): a.ollama = pv.get("url")
    if hasattr(a, "memory") and not a.memory and mem.get("backend") == "nova": a.memory = mem["db"]; a.memory_backend = "nova"; a.tenant = mem.get("tenant", "local"); a.project = mem.get("project", "default")
    if hasattr(a, "durable") and not a.durable and cfg.get("durable_db"): a.durable = cfg["durable_db"]
    return a


def history(home=None, limit=20):
    cfg = load_config(home); db = (cfg or {}).get("durable_db") or str(home_dir(home) / "queue.db")
    if not Path(db).exists(): return {"db": db, "tasks": []}
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10); c.row_factory = sqlite3.Row
    rows = [dict(r) for r in c.execute("SELECT id, kind, state, attempt, infra, fence, lease_owner, lease_expires, updated, failure FROM tasks ORDER BY id DESC LIMIT ?", (limit,))]
    return {"db": db, "tasks": rows}


def diagnose(home=None, fix=False):
    """Plain-language checks with the exact repair command for each problem. `fix` only performs SAFE repairs (reap expired leases, tighten file modes)."""
    h = home_dir(home); cfg = load_config(home); checks = []
    add = lambda name, ok, detail, repair=None: checks.append({"check": name, "ok": ok, "detail": detail, **({"repair": repair} if repair and not ok else {})})
    add("config", cfg is not None, str(h / CONFIG) if cfg else "not found", "ordivyr init")
    if cfg:
        for f in [h / CONFIG, Path(cfg["memory"]["db"]), Path(cfg["memory"]["db"]).with_suffix(".key")]:
            if f.exists():
                loose = bool(f.stat().st_mode & 0o077)
                if loose and fix: os.chmod(f, 0o600); loose = False
                add(f"private file {f.name}", not loose, "mode 0600" if not loose else f"mode {stat.S_IMODE(f.stat().st_mode):o} is readable by others", f"chmod 600 {f}")
        pv = cfg.get("provider") or {}
        if pv.get("kind") in ("openai", "ollama"):
            ok, detail, models = probe(pv["url"] if pv["kind"] == "openai" else pv["url"].rstrip("/") + "/v1", pv.get("key_file")); add("model endpoint", ok, f"{pv['url']}: {detail}", f"start your model server or re-run: ordivyr init --force --provider {pv['kind']} --url URL --check")
        if cfg["memory"]["backend"] == "nova" and Path(cfg["memory"]["db"]).exists():
            from .nova_memory import NovaMemory
            bad = NovaMemory(cfg["memory"]["db"]).audit(); add("memory integrity", not bad, f"{len(bad)} verified memories fail their signature" if bad else "all verified memories signed", "ordivyr memory audit  (restored from a backup on a new machine? then: ordivyr memory reseal)")
        db = cfg.get("durable_db")
        if db and Path(db).exists():
            from . import durable as D
            st = D.Store(db); viol = st.audit(); add("task store invariants", not viol, "clean" if not viol else f"{len(viol)} violations: {viol[:2]}", f"ordivyr durable audit {db}")
            now = time.time(); stuck = [t for t in history(home, 500)["tasks"] if t["state"] in ("claimed", "running") and t["lease_expires"] and t["lease_expires"] < now]
            if stuck and fix: st.reap(); stuck = []
            add("expired leases", not stuck, f"{len(stuck)} tasks hold expired leases (a worker died)" if stuck else "none", f"ordivyr durable reap {db}   (or: ordivyr diagnose --fix)")
    return {"ok": all(c["ok"] for c in checks), "checks": checks}
