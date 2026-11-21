"""Embedded (stdlib-only) implementations of every hosting contract: what a single developer gets with zero external services."""
from __future__ import annotations
import hashlib, hmac, json, os, secrets, signal, sqlite3, subprocess, threading, time
from pathlib import Path
from .contracts import Principal, Endpoint, ExecSpec, QuotaExceeded, LOCAL_TENANT


# ------------------------------------------------------------------ execution
class _Handle:
    def __init__(self, p, t0): self.p, self.t0, self.rc, self.timer = p, t0, None, None
    def wait(self, timeout=None):
        try: self.rc = self.p.wait(timeout)
        except subprocess.TimeoutExpired: self.kill(); self.rc = self.p.wait()
        if self.timer: self.timer.cancel()
        return self.rc
    def kill(self):
        try: os.killpg(self.p.pid, signal.SIGKILL)
        except OSError: pass
    def usage(self): return {"wall_s": round(time.time() - self.t0, 3), "rc": self.rc}


class LocalProcessExecutor:
    """Child in its own session with rlimits and a parent-death signal. This is NOT a security boundary for untrusted code (isolation='process')."""
    isolation = "process"
    def start(self, spec: ExecSpec):
        def pre():
            import resource
            if spec.max_memory_mb: resource.setrlimit(resource.RLIMIT_AS, (spec.max_memory_mb << 20,) * 2)
            if spec.max_cpu_s: resource.setrlimit(resource.RLIMIT_CPU, (spec.max_cpu_s,) * 2)
            if spec.max_procs: resource.setrlimit(resource.RLIMIT_NPROC, (spec.max_procs,) * 2)
            try:
                import ctypes; ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, 9)
            except Exception: pass
        p = subprocess.Popen(spec.argv, cwd=spec.cwd, env=spec.env or None, start_new_session=True, preexec_fn=pre, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        h = _Handle(p, time.time())
        if spec.timeout_s: h.timer = threading.Timer(spec.timeout_s, h.kill); h.timer.daemon = True; h.timer.start()          # runaway-task protection
        return h


# ------------------------------------------------------------------ storage
class FsStorage:
    """Per-tenant folders under one root. Keys are validated: no absolute paths, no '..', no symlink traversal."""
    def __init__(self, root): self.root = Path(root).resolve(); self.root.mkdir(parents=True, exist_ok=True)
    def _p(self, tenant, key):
        if not tenant or "/" in tenant or tenant.startswith("."): raise ValueError("bad tenant")
        if not key or key.startswith("/") or ".." in Path(key).parts or "\0" in key: raise ValueError("bad key")
        base = (self.root / tenant).resolve(); p = (base / key).resolve()
        if base not in p.parents: raise ValueError("key escapes tenant folder")
        return p
    def put(self, tenant, key, data):
        p = self._p(tenant, key); p.parent.mkdir(parents=True, exist_ok=True); tmp = p.with_name(p.name + ".tmp" + secrets.token_hex(3)); tmp.write_bytes(data); os.replace(tmp, p); return key
    def get(self, tenant, key): return self._p(tenant, key).read_bytes()
    def list(self, tenant, prefix=""):
        base = (self.root / tenant);
        return sorted(str(f.relative_to(base)) for f in base.rglob("*") if f.is_file() and str(f.relative_to(base)).startswith(prefix) and ".tmp" not in f.name) if base.exists() else []
    def delete(self, tenant, key):
        p = self._p(tenant, key)
        if p.is_file(): p.unlink(); return True
        return False
    def expire(self, tenant, older_than_s):
        n = 0; cutoff = time.time() - older_than_s
        for k in self.list(tenant):
            if self._p(tenant, k).stat().st_mtime < cutoff: self.delete(tenant, k); n += 1
        return n


# ------------------------------------------------------------------ models (BYOK)
class ConfigModels:
    """name -> endpoint from config. Keys come from a file or env var reference, never inline in task payloads. Per-tenant overrides model customer-owned credentials."""
    def __init__(self, table): self.table = table
    def resolve(self, tenant, name):
        e = (self.table.get(tenant, {}).get(name)) or self.table.get("*", {}).get(name)
        if not e: raise KeyError(f"no model {name!r} for tenant {tenant!r}")
        key = ""
        if e.get("key_file"): key = Path(e["key_file"]).read_text().strip()
        elif e.get("key_env"): key = os.environ.get(e["key_env"], "")
        return Endpoint(e["base"], key, e.get("kind", "openai"))


# ------------------------------------------------------------------ authentication
def _h(t): return hashlib.sha256(t.encode()).hexdigest()


class LocalAuth:
    """Single-user local access: one admin token in a 0600 file (created on first use). No accounts, no network."""
    def __init__(self, path):
        p = Path(path)
        if not p.exists(): p.parent.mkdir(parents=True, exist_ok=True); p.write_text(secrets.token_hex(24)); p.chmod(0o600)
        self.token_hash = _h(p.read_text().strip())
    def authenticate(self, token): return Principal("local-admin", LOCAL_TENANT, "admin") if token and hmac.compare_digest(_h(token), self.token_hash) else None


class TokenAuth:
    """Multi-tenant bearer tokens, stored ONLY as SHA-256 hashes, revocable, auditable. Backed by SQLite so it survives restarts."""
    def __init__(self, db):
        self.db = str(db); self._l = threading.Lock(); c = self._c(); c.executescript("CREATE TABLE IF NOT EXISTS tokens(h TEXT PRIMARY KEY, pid TEXT, tenant TEXT, role TEXT, created REAL, revoked REAL);"
                                                                                       "CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, detail TEXT);"); c.close()
    def _c(self): c = sqlite3.connect(self.db, timeout=30, isolation_level=None); c.execute("PRAGMA journal_mode=WAL"); return c
    def issue(self, pid, tenant, role="user", actor="system"):
        tok = "ort_" + secrets.token_urlsafe(32); c = self._c()
        c.execute("INSERT INTO tokens VALUES(?,?,?,?,?,NULL)", (_h(tok), pid, tenant, role, time.time())); c.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)", (time.time(), actor, "issue", json.dumps({"pid": pid, "tenant": tenant, "role": role}))); c.close(); return tok
    def revoke(self, pid, actor="system"):
        c = self._c(); n = c.execute("UPDATE tokens SET revoked=? WHERE pid=? AND revoked IS NULL", (time.time(), pid)).rowcount; c.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)", (time.time(), actor, "revoke", json.dumps({"pid": pid, "n": n}))); c.close(); return n
    def authenticate(self, token):
        if not token: return None
        c = self._c(); r = c.execute("SELECT pid,tenant,role FROM tokens WHERE h=? AND revoked IS NULL", (_h(token),)).fetchone(); c.close()
        return Principal(*r) if r else None
    def audit(self): c = self._c(); r = c.execute("SELECT ts,actor,action,detail FROM audit ORDER BY id").fetchall(); c.close(); return r


# ------------------------------------------------------------------ metering + quotas
class NullMeter:
    def record(self, tenant, kind, qty, ref=""): pass
    def usage(self, tenant, since=0.0): return {}


class SqliteMeter:
    def __init__(self, db): self.db = str(db); c = self._c(); c.execute("CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, tenant TEXT, kind TEXT, qty REAL, ref TEXT)"); c.execute("CREATE INDEX IF NOT EXISTS usage_t ON usage(tenant, ts)"); c.close()
    def _c(self): c = sqlite3.connect(self.db, timeout=30, isolation_level=None); c.execute("PRAGMA journal_mode=WAL"); return c
    def record(self, tenant, kind, qty, ref=""): c = self._c(); c.execute("INSERT INTO usage(ts,tenant,kind,qty,ref) VALUES(?,?,?,?,?)", (time.time(), tenant, kind, float(qty), ref)); c.close()
    def usage(self, tenant, since=0.0):
        c = self._c(); r = dict(c.execute("SELECT kind, SUM(qty) FROM usage WHERE tenant=? AND ts>=? GROUP BY kind", (tenant, since)).fetchall()); c.close(); return r


class StaticQuota:
    """limits = {tenant or '*': {kind: max}}. 'concurrent_tasks' is checked against the number currently active."""
    def __init__(self, limits): self.limits = limits
    def check(self, tenant, kind, active, requested=1):
        lim = (self.limits.get(tenant) or self.limits.get("*") or {}).get(kind)
        if lim is not None and active + requested > lim: raise QuotaExceeded(f"tenant {tenant!r}: {kind} limit {lim} reached (active {active})")
