"""Board registry: orgs, projects, keys, agents, workers, jobs, schedules, memory, usage meter, and a hash-chained audit log. One SQLite file (WAL), stdlib only.

Isolation rule used everywhere in Board: every row that belongs to a customer carries (org, project) and EVERY query filters on both. A lookup that misses because the
caller's scope differs from the row's scope is indistinguishable from "does not exist" (callers raise NotFound, never Forbidden, so ids cannot be probed across tenants).
"""
from __future__ import annotations
from .errors import Invalid
from ..durable import SqlitePool
import hashlib, json, os, secrets, sqlite3, threading, time, weakref

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS board_meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS orgs(id TEXT PRIMARY KEY, name TEXT, plan TEXT NOT NULL DEFAULT 'free', status TEXT NOT NULL DEFAULT 'active', billing_ref TEXT, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS projects(org TEXT NOT NULL, id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', budget_usd REAL, created REAL NOT NULL, PRIMARY KEY(org, id));
CREATE TABLE IF NOT EXISTS keys(h TEXT PRIMARY KEY, kid TEXT UNIQUE NOT NULL, org TEXT, project TEXT, role TEXT NOT NULL, label TEXT, created REAL NOT NULL, expires REAL, revoked REAL);
CREATE TABLE IF NOT EXISTS agents(org TEXT NOT NULL, project TEXT NOT NULL, id TEXT NOT NULL, spec TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, created REAL NOT NULL, updated REAL NOT NULL, PRIMARY KEY(org, project, id));
CREATE TABLE IF NOT EXISTS teams(org TEXT NOT NULL, project TEXT NOT NULL, id TEXT NOT NULL, spec TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(org, project, id));
CREATE TABLE IF NOT EXISTS workers(id TEXT PRIMARY KEY, org TEXT, project TEXT, engine TEXT NOT NULL, caps TEXT NOT NULL, kid TEXT NOT NULL, node TEXT, registered REAL NOT NULL, last_seen REAL, drained INTEGER NOT NULL DEFAULT 0, revoked REAL);
CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY, org TEXT NOT NULL, project TEXT NOT NULL, tid INTEGER UNIQUE, spec TEXT NOT NULL, prio INTEGER NOT NULL DEFAULT 0, parent TEXT, root TEXT NOT NULL, depth INTEGER NOT NULL DEFAULT 0, engine TEXT NOT NULL,
  agent_id TEXT, budget REAL, origin TEXT NOT NULL, created REAL NOT NULL, metered INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS jobs_scope ON jobs(org, project, created);
CREATE INDEX IF NOT EXISTS jobs_parent ON jobs(parent);
CREATE TABLE IF NOT EXISTS schedules(id TEXT PRIMARY KEY, org TEXT NOT NULL, project TEXT NOT NULL, name TEXT, spec TEXT NOT NULL, job TEXT NOT NULL, hook_hash TEXT, runs INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS memory(org TEXT NOT NULL, project TEXT NOT NULL, ns TEXT NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, by TEXT, ts REAL NOT NULL, PRIMARY KEY(org, project, ns, k));
CREATE TABLE IF NOT EXISTS meter(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, org TEXT NOT NULL, project TEXT NOT NULL, job_id TEXT NOT NULL, kind TEXT NOT NULL, qty REAL NOT NULL, UNIQUE(job_id, kind));
CREATE INDEX IF NOT EXISTS meter_scope ON meter(org, project, ts);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, org TEXT, project TEXT, action TEXT NOT NULL, detail TEXT, prev TEXT NOT NULL, h TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_scope ON audit(org, id);
"""
ROLES = ("admin", "member", "viewer", "worker", "platform")
GENESIS = "0" * 64


def h(tok): return hashlib.sha256(str(tok).encode()).hexdigest()



SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, pw_hash TEXT, status TEXT NOT NULL DEFAULT 'active', mfa_secret TEXT, mfa_enabled INTEGER NOT NULL DEFAULT 0, mfa_counter INTEGER NOT NULL DEFAULT -1, recovery TEXT, failed INTEGER NOT NULL DEFAULT 0, locked_until REAL, created REAL NOT NULL, last_login REAL);
CREATE TABLE IF NOT EXISTS memberships(org TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, project TEXT, created REAL NOT NULL, PRIMARY KEY(org, user_id));
CREATE TABLE IF NOT EXISTS invites(h TEXT PRIMARY KEY, id TEXT UNIQUE NOT NULL, org TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL, project TEXT, created REAL NOT NULL, expires REAL NOT NULL, used REAL, made_by TEXT);
CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY, id TEXT UNIQUE NOT NULL, user_id TEXT NOT NULL, org TEXT, kind TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, last_used REAL NOT NULL, revoked REAL, ip TEXT);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS sso_providers(org TEXT PRIMARY KEY, issuer TEXT NOT NULL, client_id TEXT NOT NULL, alg TEXT NOT NULL, jwks TEXT NOT NULL, domains TEXT NOT NULL, default_role TEXT NOT NULL, enforce INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sso_nonces(nonce TEXT PRIMARY KEY, org TEXT NOT NULL, expires REAL NOT NULL, used REAL);
ALTER TABLE orgs ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0;
ALTER TABLE keys ADD COLUMN last_used REAL;
ALTER TABLE keys ADD COLUMN created_by TEXT;
ALTER TABLE keys ADD COLUMN rotated_to TEXT
"""

SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS subscriptions(org TEXT PRIMARY KEY, plan TEXT NOT NULL, status TEXT NOT NULL, provider TEXT, customer_ref TEXT, pm_ref TEXT, period_start REAL NOT NULL, period_end REAL NOT NULL, cancel_at_end INTEGER NOT NULL DEFAULT 0, past_due_since REAL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS invoices(id TEXT PRIMARY KEY, org TEXT NOT NULL, period_start REAL NOT NULL, period_end REAL NOT NULL, plan TEXT NOT NULL, lines TEXT NOT NULL, total_cents INTEGER NOT NULL, status TEXT NOT NULL, provider_ref TEXT, attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL, reason TEXT, created REAL NOT NULL, paid_at REAL, UNIQUE(org, period_start));
CREATE TABLE IF NOT EXISTS billing_events(event_id TEXT PRIMARY KEY, provider TEXT NOT NULL, type TEXT NOT NULL, received REAL NOT NULL, outcome TEXT);
CREATE TABLE IF NOT EXISTS spend_limits(org TEXT PRIMARY KEY, soft_cents INTEGER, hard_cents INTEGER, soft_notified REAL);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, org TEXT, kind TEXT NOT NULL, detail TEXT, acked REAL)
"""

SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS secrets(org TEXT NOT NULL, project TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, blob TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, created REAL NOT NULL, updated REAL NOT NULL, made_by TEXT, PRIMARY KEY(org, project, name));
CREATE TABLE IF NOT EXISTS hosted(id TEXT PRIMARY KEY, org TEXT NOT NULL, project TEXT, name TEXT, slots INTEGER NOT NULL DEFAULT 2, endpoints TEXT NOT NULL DEFAULT '[]', desired TEXT NOT NULL DEFAULT 'running', state TEXT NOT NULL DEFAULT 'pending', worker_id TEXT, token_blob TEXT, host TEXT, pid INTEGER, restarts INTEGER NOT NULL DEFAULT 0, window_start REAL, window_restarts INTEGER NOT NULL DEFAULT 0, next_start REAL, last_start REAL, last_exit TEXT, last_error TEXT, lease_owner TEXT, lease_until REAL, created REAL NOT NULL, updated REAL NOT NULL)
"""
SCHEMA_V5 = """
CREATE TABLE auth_throttle (
  user_id TEXT NOT NULL, ipk TEXT NOT NULL, failed INTEGER NOT NULL DEFAULT 0, locked_until REAL, last_fail REAL, last_ok REAL,
  PRIMARY KEY(user_id, ipk)
);
CREATE INDEX auth_throttle_user ON auth_throttle(user_id);
"""

SCHEMA_V6 = """
CREATE TABLE reservations (
  job_id TEXT PRIMARY KEY, org TEXT NOT NULL, project TEXT NOT NULL, compute_s REAL NOT NULL DEFAULT 0, cost_usd REAL NOT NULL DEFAULT 0, created REAL NOT NULL, released REAL
);
CREATE INDEX reservations_open ON reservations(org, released);
CREATE INDEX reservations_proj ON reservations(org, project, released);
"""

SCHEMA_V7 = """
CREATE TABLE refunds (
  id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL, org TEXT NOT NULL, cents INTEGER NOT NULL, status TEXT NOT NULL, provider_ref TEXT, reason TEXT, idem TEXT NOT NULL, created REAL NOT NULL, actor TEXT,
  UNIQUE(invoice_id, idem)
);
CREATE INDEX refunds_invoice ON refunds(invoice_id);
"""

SCHEMA_V8 = """
CREATE TABLE outbox (
  id TEXT PRIMARY KEY, org TEXT, to_addr TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, body TEXT, status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL, created REAL NOT NULL, sent_at REAL, last_error TEXT, dedupe TEXT UNIQUE
);
CREATE INDEX outbox_due ON outbox(status, next_attempt);
"""

SCHEMA_V9 = """
ALTER TABLE jobs ADD COLUMN trace TEXT;
CREATE INDEX jobs_trace ON jobs(trace);
CREATE TABLE retention (org TEXT PRIMARY KEY, job_days INTEGER NOT NULL);
"""

SCHEMA_V10 = """
ALTER TABLE outbox ADD COLUMN sending_since REAL;
ALTER TABLE billing_events ADD COLUMN event_data TEXT;
ALTER TABLE billing_events ADD COLUMN applied REAL;
CREATE INDEX billing_events_pending ON billing_events(applied, received);
ALTER TABLE spend_limits ADD COLUMN gateway_budget_usd REAL;
CREATE TABLE gateway_calls(job_id TEXT NOT NULL, request_id TEXT NOT NULL, org TEXT NOT NULL, project TEXT NOT NULL, reserved_usd REAL NOT NULL, actual_usd REAL NOT NULL DEFAULT 0, status TEXT NOT NULL, prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0, cache_read_tokens INTEGER NOT NULL DEFAULT 0, cache_write_tokens INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL, updated REAL NOT NULL, PRIMARY KEY(job_id, request_id));
CREATE INDEX gateway_calls_tenant ON gateway_calls(org, project, status, created);
"""

MIGRATIONS = [(1, "base schema", SCHEMA_V1), (2, "accounts: users, memberships, invites, sessions, SSO, key lifecycle", SCHEMA_V2), (3, "billing: subscriptions, invoices, webhook idempotency, spend limits, alerts", SCHEMA_V3), (4, "secrets vault + hosted worker lifecycle", SCHEMA_V4), (5, "account/IP-aware auth throttling (replaces the per-account 24h lockout)", SCHEMA_V5), (6, "in-flight spend/compute reservations (limits hold under concurrent work)", SCHEMA_V6), (7, "refunds ledger (idempotent, bounded by the invoice total)", SCHEMA_V7), (8, "transactional email outbox (sealed bodies, retries, dedupe)", SCHEMA_V8), (9, "request/job tracing + per-org retention policy", SCHEMA_V9), (10, "durable webhook and mail recovery", SCHEMA_V10)]        # append-only: a released migration is never edited (its checksum is recorded and verified); schema changes are NEW entries


class _Row(dict):
    """sqlite3.Row-compatible row for PostgreSQL: r['name'], r[0], dict(r)."""
    def __getitem__(self, k): return super().__getitem__(k) if not isinstance(k, int) else list(self.values())[k]


def _row_factory(cur):
    names = [c.name for c in (cur.description or [])]
    return lambda vals: _Row(zip(names, vals))


def _pg_sql(sql):
    """SQLite-flavoured SQL (as written throughout Board) -> PostgreSQL. Board SQL contains no literal '?' or '%'."""
    t = sql.strip(); ign = t.upper().startswith("INSERT OR IGNORE INTO")
    if ign: t = "INSERT INTO" + t[len("INSERT OR IGNORE INTO"):]
    t = t.replace("?", "%s").replace("rowid", "seq").replace("BEGIN IMMEDIATE", "BEGIN")
    return t + (" ON CONFLICT DO NOTHING" if ign else "")


def _pg_schema(sql):
    t = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY").replace("INTEGER", "BIGINT").replace("REAL", "DOUBLE PRECISION")
    return t.replace("CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY,", "CREATE TABLE IF NOT EXISTS jobs(seq BIGSERIAL, job_id TEXT PRIMARY KEY,")


class _PgConn:
    def __init__(self, dsn, psycopg):
        self.dsn, self.pg = dsn, psycopg; self.in_tx = False; self.conn = None; self._open()
    def _open(self): self.conn = self.pg.connect(self.dsn, row_factory=_row_factory, autocommit=True)
    def execute(self, sql, params=()):
        t = _pg_sql(sql)
        for x in params:
            if isinstance(x, str) and "\x00" in x: raise Invalid("NUL bytes are not allowed in text")             # PostgreSQL cannot store them; SQLite can, so refuse uniformly instead of leaking a driver error
        for attempt in (0, 1):
            try:
                if self.conn.closed: self._open()
                return self.conn.execute(t, tuple(params))
            except self.pg.OperationalError:
                if attempt or self.in_tx: raise                     # inside a transaction the caller must see the failure (it rolls back and retries as a unit)
                try: self.conn.close()
                except Exception: pass
                self._open()                                        # server restart / dropped connection: reconnect once for standalone statements
    def close(self):
        try: self.conn.close()
        except Exception: pass


class _ConnHolder:
    """Lives in a thread-local: when its thread dies the storage is released and the connection is closed (no per-thread leak in a long-running server)."""
    def __init__(self, c, release): self.c, self.release, self.pid = c, release, os.getpid()
    def __del__(self):
        if os.getpid() != self.pid: return          # NEVER close in a forked child (subprocess preexec runs GC there): PQfinish would send Terminate down the socket the parent still uses
        try: self.release(self.c)
        except Exception: pass


class DB:
    """Registry store. SQLite file by default; `dsn=` selects PostgreSQL (psycopg 3). Same API, same tests, both backends."""
    def __init__(self, path=None, clock=time.time, dsn=None):
        self.path = str(path) if path else None; self.dsn = dsn; self.clock = clock; self._tl = threading.local(); self._lock = threading.RLock(); self.backend = "postgres" if dsn else "sqlite"; self._conns = []
        if dsn:
            try: import psycopg
            except ImportError as e: raise RuntimeError("PostgreSQL backend needs psycopg (v3): pip install 'psycopg[binary]'") from e
            self._pg = psycopg
        else: self._pool = SqlitePool(self.path)
        self.migrate()

    def c(self):
        c = getattr(self._tl, "c", None)
        if c is None:
            if self.dsn:
                c = _PgConn(self.dsn, self._pg); self._conns.append(c)
                self._tl.holder = _ConnHolder(c, self._release)       # dropped with the thread-local storage when the owning thread exits: closes the connection (HTTP request threads are short-lived)
            else: c, self._tl.holder = self._pool.lease()             # returned to the pool when the owning thread exits
            self._tl.c = c
        return c

    def _release(self, c):
        try: c.close()
        except Exception: pass
        try: self._conns.remove(c)
        except ValueError: pass

    def close(self):
        for c in self._conns:
            try: c.close()
            except Exception: pass
        self._conns = []; self._tl = threading.local()
        if not self.dsn: self._pool.close()

    def xlock(self, key):
        """Cross-thread AND cross-process mutual exclusion for a check-then-write sequence that spans statements (quota, fan-out, budget, single-use consumption).
        PostgreSQL: session advisory lock (READ COMMITTED does not serialise these on its own). SQLite: striped file lock. Re-entrant per thread."""
        import contextlib, zlib
        @contextlib.contextmanager
        def cm():
            if self.dsn:
                c = self.c(); c.execute("SELECT pg_advisory_lock(hashtext(?))", (key,))
                try: yield
                finally: c.execute("SELECT pg_advisory_unlock(hashtext(?))", (key,))
                return
            import fcntl, os
            held = self._tl.__dict__.setdefault("held", {}); i = zlib.crc32(key.encode()) % 16
            if i in held: held[i] += 1; yield; held[i] -= 1; return
            fd = os.open(f"{self.path}.lk{i}", os.O_CREAT | os.O_RDWR, 0o600); fcntl.flock(fd, fcntl.LOCK_EX); held[i] = 1
            try: yield
            finally: del held[i]; fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
        return cm()

    def tx(self):
        db = self
        class T:
            def __enter__(s):
                db._lock.acquire(); s.c = db.c()
                try:
                    s.c.execute("BEGIN IMMEDIATE")
                    if db.dsn: s.c.in_tx = True
                except BaseException: db._lock.release(); raise
                return s.c
            def __exit__(s, et, ev, tb):
                try:
                    try: s.c.execute("ROLLBACK" if et else "COMMIT")
                    except BaseException:
                        if db.dsn:
                            try: s.c.execute("ROLLBACK")
                            except Exception: pass
                        raise
                finally:
                    if db.dsn: s.c.in_tx = False
                    db._lock.release()
        return T()

    # ---------------------------------------------------------------- versioned, checksummed migrations
    def migrate(self):
        import hashlib as _h
        c = self.c(); pg = bool(self.dsn)
        if pg: c.execute("SELECT pg_advisory_lock(7000)")               # two Board processes starting together must not migrate concurrently
        try:
            c.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version BIGINT PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied DOUBLE PRECISION NOT NULL)" if pg else
                      "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied REAL NOT NULL)")
            done = {r["version"]: r["checksum"] for r in c.execute("SELECT version, checksum FROM schema_migrations")}; known = {v: (n, sql) for v, n, sql in MIGRATIONS}
            newer = [v for v in done if v not in known]
            if newer: raise RuntimeError(f"database schema v{max(newer)} is newer than this Board build (knows up to v{max(known)}): refusing to run (downgrade not supported)")
            for v, name, sql in MIGRATIONS:
                ck = _h.sha256(sql.encode()).hexdigest()
                if v in done:
                    if done[v] != ck: raise RuntimeError(f"migration v{v} ({name}) was modified after release (checksum mismatch): refusing to run")
                    continue
                stmts = [x.strip() for x in (_pg_schema(sql) if pg else sql).split(";") if x.strip()]
                with self.tx() as t:
                    for st in stmts: t.execute(st)
                    t.execute("INSERT INTO schema_migrations(version,name,checksum,applied) VALUES(?,?,?,?)", (v, name, ck, self.clock()))
        finally:
            if pg: c.execute("SELECT pg_advisory_unlock(7000)")

    def schema_version(self): return self.c().execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]

    def meta(self, k, v=None):
        if v is None:
            r = self.c().execute("SELECT v FROM board_meta WHERE k=?", (k,)).fetchone(); return r[0] if r else None
        with self.tx() as c: c.execute("INSERT INTO board_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    # ---------------------------------------------------------------- audit (hash-chained: any edit/delete/reorder is detectable)
    def audit(self, actor, action, org=None, project=None, detail=None, c=None):
        """Append inside the caller's transaction when `c` is given (so the audit row commits atomically with the action it records)."""
        def go(c):
            if self.dsn: c.execute("SELECT pg_advisory_xact_lock(7001)")     # one writer at a time extends the hash chain (SQLite gets this from BEGIN IMMEDIATE)
            r = c.execute("SELECT h FROM audit ORDER BY id DESC LIMIT 1").fetchone(); prev = r[0] if r else GENESIS
            ts = self.clock(); d = json.dumps(detail or {}, sort_keys=True, default=str)
            hh = hashlib.sha256("\x1f".join((prev, str(ts), actor, str(org), str(project), action, d)).encode()).hexdigest()
            c.execute("INSERT INTO audit(ts,actor,org,project,action,detail,prev,h) VALUES(?,?,?,?,?,?,?,?)", (ts, actor, org, project, action, d, prev, hh))
        if c is not None: return go(c)
        with self.tx() as c: go(c)

    def audit_rows(self, org=None, project=None, after=0, limit=500):
        q = "SELECT id,ts,actor,org,project,action,detail FROM audit WHERE id>?"; a = [after]
        if org is not None: q += " AND org=?"; a.append(org)
        if project is not None: q += " AND project=?"; a.append(project)
        return [dict(r) | {"detail": json.loads(r["detail"] or "{}")} for r in self.c().execute(q + " ORDER BY id LIMIT ?", (*a, limit))]

    def verify_audit(self):
        """-> (ok, first_bad_id). Recomputes the whole chain."""
        prev = GENESIS
        for r in self.c().execute("SELECT * FROM audit ORDER BY id"):
            hh = hashlib.sha256("\x1f".join((prev, str(r["ts"]), r["actor"], str(r["org"]), str(r["project"]), r["action"], r["detail"] or "")).encode()).hexdigest()
            if r["prev"] != prev or r["h"] != hh: return False, r["id"]
            prev = r["h"]
        return True, None

    # ---------------------------------------------------------------- keys
    def issue_key(self, role, org=None, project=None, label="", ttl_s=None, actor="system", c=None):
        if role not in ROLES: raise ValueError(f"role {role!r}")
        tok = ("ordb_" if role != "worker" else "ordw_") + secrets.token_urlsafe(32); kid = "k-" + secrets.token_hex(5); now = self.clock()
        def go(c):
            c.execute("INSERT INTO keys(h,kid,org,project,role,label,created,expires,created_by) VALUES(?,?,?,?,?,?,?,?,?)", (h(tok), kid, org, project, role, label[:80], now, now + ttl_s if ttl_s else None, actor))
            self.audit(actor, "key.issue", org, project, {"kid": kid, "role": role, "label": label[:80]}, c)
        if c is not None: go(c)
        else:
            with self.tx() as c2: go(c2)
        return tok, kid

    def key_of(self, token):
        """-> row for a live (not revoked, not expired) key, else None. Looked up by hash on EVERY request, so revocation is immediate."""
        if not token: return None
        r = self.c().execute("SELECT * FROM keys WHERE h=? AND revoked IS NULL", (h(token),)).fetchone()
        if r is None or (r["expires"] and r["expires"] < self.clock()): return None
        return r

    def revoke_key(self, kid, actor="system", org=None):
        with self.tx() as c:
            r = c.execute("SELECT * FROM keys WHERE kid=?", (kid,)).fetchone()
            if r is None or (org is not None and r["org"] != org): return False
            c.execute("UPDATE keys SET revoked=? WHERE kid=? AND revoked IS NULL", (self.clock(), kid)); self.audit(actor, "key.revoke", r["org"], r["project"], {"kid": kid}, c); return True
