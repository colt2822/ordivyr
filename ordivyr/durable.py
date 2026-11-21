"""Durable execution core: crash-safe task queue, worker leases with fencing tokens, checkpoints, evidence and side-effect operation records.

One SQLite file (WAL, synchronous=FULL, every write in BEGIN IMMEDIATE). Standard library only.

Task lifecycle:  queued -> claimed -> running -> validating -> completed | failed        (+ cancelled, needs_approval)
  * claim() bumps a global monotonically increasing FENCE and hands it to the worker. Every later write is `... WHERE id=? AND fence=?`,
    so a worker whose lease expired (crash, partition, pause) can never commit: its fence is no longer the task's fence.
  * reap() returns expired leases to `queued` (or finishes a requested cancel / fails exhausted tasks). Nothing is ever dropped silently.
  * At most ONE `commit` event can exist per task (unique partial index) -> no duplicate commits, whatever the workers do.
Side effects: effect() writes an `intent` row BEFORE acting and marks it `committed` after. A crash in between is reconciled on retry against the
external system by idempotency key; if that cannot be decided the task parks in `needs_approval` (explicit human approve()) instead of guessing.
"""
from __future__ import annotations
import contextlib, json, os, sqlite3, threading, time

ACTIVE = ("claimed", "running", "validating")
TERMINAL = ("completed", "failed", "cancelled")
RECOVERABLE = ("queued", "claimed", "running", "validating", "needs_approval")
INFRA_CAP = 50          # transient (model/network) releases a task may take before it is failed for good

class StaleLease(Exception):
    """The caller's fencing token is no longer the task's: its result is rejected."""
class NeedsApproval(Exception):
    """A side effect may or may not have happened and cannot be reconciled automatically."""
class Cancelled(Exception): pass
class Fatal(Exception):
    """Non-retryable failure (bad job, unsupported version, refused policy): the task fails now, without burning further attempts."""
class QuotaExceeded(Exception):
    """A tenant hit its queued-task quota: the submit is refused (nothing is queued), never silently dropped."""
class Transient(Exception):
    """Infrastructure failure (model server down, node unreachable): release the task for retry without burning an attempt."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS tasks(
  id INTEGER PRIMARY KEY AUTOINCREMENT, idem_key TEXT UNIQUE, tenant TEXT NOT NULL DEFAULT 'default', kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
  priority INTEGER NOT NULL DEFAULT 0, attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3, infra INTEGER NOT NULL DEFAULT 0,
  fence INTEGER NOT NULL DEFAULT 0, lease_owner TEXT, lease_node TEXT, lease_expires REAL, not_before REAL NOT NULL DEFAULT 0,
  cancel_requested INTEGER NOT NULL DEFAULT 0, phase TEXT, checkpoint TEXT, result TEXT, failure TEXT, created REAL NOT NULL, updated REAL NOT NULL);
CREATE INDEX IF NOT EXISTS tasks_claim ON tasks(state, not_before, priority);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL, fence INTEGER, worker TEXT, node TEXT, detail TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS one_commit ON events(task_id) WHERE kind='commit';
CREATE INDEX IF NOT EXISTS events_task ON events(task_id);
CREATE TABLE IF NOT EXISTS checkpoints(id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, fence INTEGER NOT NULL, ts REAL NOT NULL, phase TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, fence INTEGER NOT NULL, ts REAL NOT NULL, name TEXT NOT NULL, ok INTEGER NOT NULL, detail TEXT, UNIQUE(task_id, name));
CREATE TABLE IF NOT EXISTS tenants(tenant TEXT PRIMARY KEY, weight REAL NOT NULL DEFAULT 1, max_active INTEGER, max_queued INTEGER);
CREATE TABLE IF NOT EXISTS usage(tenant TEXT PRIMARY KEY, submitted INTEGER NOT NULL DEFAULT 0, claims INTEGER NOT NULL DEFAULT 0, completed INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, lease_seconds REAL NOT NULL DEFAULT 0, quota_rejections INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS nodes(node TEXT PRIMARY KEY, capacity INTEGER, cpu REAL, mem_mb REAL, labels TEXT, reported REAL NOT NULL);
CREATE TABLE IF NOT EXISTS operations(op_key TEXT PRIMARY KEY, task_id INTEGER NOT NULL, fence INTEGER NOT NULL, status TEXT NOT NULL, ts REAL NOT NULL, result TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS outputs(id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, fence INTEGER NOT NULL, ts REAL NOT NULL, tool TEXT NOT NULL, args TEXT, output TEXT);
"""

def _j(x): return json.dumps(x, sort_keys=True, default=str)

class FairRLock:
    """Reentrant lock that grants ownership strictly in arrival order (threading.Lock gives no ordering guarantee)."""
    def __init__(self): self._m = threading.Lock(); self._q = []; self._owner = None; self._depth = 0
    def __enter__(self):
        me = threading.get_ident()
        with self._m:
            if self._owner == me: self._depth += 1; return self
            if self._owner is None and not self._q: self._owner, self._depth = me, 1; return self
            ev = threading.Event(); self._q.append((me, ev))
        ev.wait()                                                  # ownership is handed over directly by __exit__
        return self
    def __exit__(self, *a):
        with self._m:
            self._depth -= 1
            if self._depth: return
            if self._q: self._owner, ev = self._q.pop(0); self._depth = 1; ev.set()
            else: self._owner = None


class Store:
    def __init__(self, path, clock=time.time):
        self.path = str(path); self.clock = clock; self._tl = threading.local(); self._gate = FairRLock(); self._read_gate = threading.Lock(); self.tx_count = 0; self._cv = threading.Condition(); self._ver = 0; self._added = 0; os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        c = self._conn(); c.executescript(SCHEMA)
        if not any(r[1] == "tenant" for r in c.execute("PRAGMA table_info(tasks)")):      # pre-tenancy database: add the column in place (existing tasks belong to 'default')
            c.execute("ALTER TABLE tasks ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default'")
        c.execute("CREATE INDEX IF NOT EXISTS tasks_fair ON tasks(state, tenant, priority DESC, id)"); c.execute("CREATE INDEX IF NOT EXISTS tasks_tenant ON tasks(tenant, state)")
        c.execute("INSERT OR IGNORE INTO meta(k,v) VALUES('fence','0')"); c.execute("INSERT OR IGNORE INTO meta(k,v) VALUES('cap','1000000')")

    def _conn(self):
        c = getattr(self._tl, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=60, isolation_level=None); c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA synchronous=FULL"); c.execute("PRAGMA busy_timeout=60000"); self._tl.c = c
        return c

    @contextlib.contextmanager
    def tx(self):
        # In-process writers queue FIFO here instead of polling SQLite's unfair busy handler (profiled: 3 ms of work but up to 9.8 s of lock wait at 1,000 agents).
        # Cross-process writers still fall back to busy_timeout. Reentrant so a method may call another that opens a tx on the same thread.
        with self._gate:
            c = self._conn(); c.execute("BEGIN IMMEDIATE"); self.tx_count += 1
            try: yield c
            except BaseException: c.execute("ROLLBACK"); self._added = 0; raise
            else:
                c.execute("COMMIT")
                if self._added and self._gate._depth == 1:                                  # outermost commit that queued work: wake that many long-polling claimers
                    n, self._added = self._added, 0
                    with self._cv: self._ver += 1; self._cv.notify(n)

    def _ev(self, c, tid, kind, fence=None, worker=None, node=None, detail=None):
        c.execute("INSERT INTO events(task_id,ts,kind,fence,worker,node,detail) VALUES(?,?,?,?,?,?,?)", (tid, self.clock(), kind, fence, worker, node, None if detail is None else _j(detail)))

    def tenant_of(self, tid):
        r = self._conn().execute("SELECT tenant FROM tasks WHERE id=?", (tid,)).fetchone(); return r[0] if r else None
    def _tenant_of(self, c, tid): return c.execute("SELECT tenant FROM tasks WHERE id=?", (tid,)).fetchone()[0]

    def _own(self, c, tid, fence, states):
        """Fence check. Raises StaleLease unless this fence still owns the task in one of `states`."""
        r = c.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
        if r is None or r["fence"] != fence or r["state"] not in states: raise StaleLease(f"task {tid}: fence {fence} is stale (current {r['fence'] if r else None}, state {r['state'] if r else None})")
        return r

    # -------------------------------------------------------------- submit / claim
    def submit(self, kind, payload, idem_key=None, max_attempts=3, priority=0, tenant="default"):
        """Idempotent on idem_key WITHIN the tenant (another tenant reusing a key neither sees nor collides with this task). Enforces the tenant's queued quota."""
        tenant = str(tenant or "default")
        try: return self._submit(kind, payload, idem_key, max_attempts, priority, tenant)
        except QuotaExceeded:
            with self.tx() as c: self._use(c, tenant, "quota_rejections")       # metered in its own transaction (the refused submit rolled back)
            raise

    def _submit(self, kind, payload, idem_key, max_attempts, priority, tenant):
        with self.tx() as c:
            key = None if not idem_key else (idem_key if tenant == "default" else f"{tenant}\x1f{idem_key}")
            if key:
                r = c.execute("SELECT id FROM tasks WHERE idem_key=?", (key,)).fetchone()
                if r: return r["id"]
            q = c.execute("SELECT max_queued FROM tenants WHERE tenant=?", (tenant,)).fetchone()
            if q and q["max_queued"] is not None and c.execute("SELECT COUNT(*) FROM tasks WHERE tenant=? AND state='queued'", (tenant,)).fetchone()[0] >= q["max_queued"]:
                raise QuotaExceeded(f"tenant {tenant!r}: queued-task quota ({q['max_queued']}) reached")
            now = self.clock(); cur = c.execute("INSERT INTO tasks(idem_key,tenant,kind,payload,priority,max_attempts,created,updated) VALUES(?,?,?,?,?,?,?,?)", (key, tenant, kind, _j(payload), priority, max_attempts, now, now))
            self._ev(c, cur.lastrowid, "submitted", detail={"kind": kind, "tenant": tenant}); self._use(c, tenant, "submitted"); self._added += 1; return cur.lastrowid

    def _use(self, c, tenant, col, n=1):
        c.execute("INSERT INTO usage(tenant) VALUES(?) ON CONFLICT(tenant) DO NOTHING", (tenant,)); c.execute(f"UPDATE usage SET {col}={col}+? WHERE tenant=?", (n, tenant))

    def tenant_set(self, tenant, weight=1.0, max_active=None, max_queued=None):
        with self.tx() as c: c.execute("INSERT INTO tenants(tenant,weight,max_active,max_queued) VALUES(?,?,?,?) ON CONFLICT(tenant) DO UPDATE SET weight=excluded.weight, max_active=excluded.max_active, max_queued=excluded.max_queued", (str(tenant), float(weight), max_active, max_queued))

    def usage_of(self, tenant):
        r = self._conn().execute("SELECT * FROM usage WHERE tenant=?", (str(tenant),)).fetchone(); return dict(r) if r else {"tenant": str(tenant), "submitted": 0, "claims": 0, "completed": 0, "failed": 0, "lease_seconds": 0.0, "quota_rejections": 0}

    # ---- tenant-scoped reads/writes: a tenant principal can only ever see or touch its own tasks (the coordinator maps tenant tokens to these)
    def get_for(self, tenant, tid):
        t = self.get(tid); return t if t and t["tenant"] == str(tenant) else None
    def cancel_for(self, tenant, tid):
        t = self._conn().execute("SELECT tenant FROM tasks WHERE id=?", (tid,)).fetchone()
        return self.cancel(tid) if t and t["tenant"] == str(tenant) else None
    def counts_for(self, tenant):
        return {r[0]: r[1] for r in self._conn().execute("SELECT state, COUNT(*) FROM tasks WHERE tenant=? GROUP BY state", (str(tenant),))}
    def events_for(self, tenant, after=0, limit=200):
        return [dict(r) for r in self._conn().execute("SELECT e.* FROM events e JOIN tasks t ON t.id=e.task_id WHERE t.tenant=? AND e.id>? ORDER BY e.id LIMIT ?", (str(tenant), int(after), min(int(limit), 1000)))]

    def set_cap(self, n):
        with self.tx() as c: c.execute("UPDATE meta SET v=? WHERE k='cap'", (str(int(n)),))
    def cap(self): return int(self._conn().execute("SELECT v FROM meta WHERE k='cap'").fetchone()[0])

    def _nothing_queued(self, now, kinds):
        """Read-only probe (WAL readers never block the writer): an empty queue must not cost a write transaction + fsync per idle poll.
        A false 'something queued' just falls through to the real transactional claim; a task that arrives right after the probe is picked up on the next poll."""
        q = "SELECT 1 FROM tasks WHERE state='queued' AND not_before<=? AND cancel_requested=0" + (" AND kind IN (%s)" % ",".join("?" * len(kinds)) if kinds else "") + " LIMIT 1"
        return self._conn().execute(q, (now, *(kinds or ()))).fetchone() is None

    def _pick(self, c, now, kinds, limit, tenants=None):
        """Fair selection of up to `limit` queued rows: repeatedly serve the tenant with the smallest (leases held + just picked)/weight that is under its max_active,
        so one tenant's backlog cannot starve another's (weighted max-min fairness); within a tenant the order is priority DESC, id (the original FIFO)."""
        act = {r[0]: r[1] for r in c.execute("SELECT tenant, COUNT(*) FROM tasks WHERE state IN ('claimed','running','validating') AND lease_expires>=? GROUP BY tenant", (now,))}
        room = min(limit, self.cap() - sum(act.values()))
        if room <= 0: return []
        kc = (" AND kind IN (%s)" % ",".join("?" * len(kinds))) if kinds else ""; tc = (" AND tenant IN (%s)" % ",".join("?" * len(tenants))) if tenants else ""
        base = "state='queued' AND not_before<=? AND cancel_requested=0" + kc + tc; a0 = [now, *(kinds or ()), *(tenants or ())]
        names = [r[0] for r in c.execute("SELECT DISTINCT tenant FROM tasks WHERE " + base, a0)]
        if not names: return []
        cfg = {r["tenant"]: (r["weight"] or 1.0, r["max_active"]) for r in c.execute("SELECT tenant, weight, max_active FROM tenants")}
        served = {r[0]: r[1] for r in c.execute("SELECT tenant, claims FROM usage")}
        if len(names) == 1 and cfg.get(names[0], (1, None))[1] is None:
            return c.execute("SELECT * FROM tasks WHERE " + base + " ORDER BY priority DESC, id LIMIT ?", (*a0, room)).fetchall()
        cand = {n: [] for n in names}; loaded = set(); picked = {n: 0 for n in names}; out = []
        def rows(n):
            if n not in loaded: loaded.add(n); cand[n] = list(c.execute("SELECT * FROM tasks WHERE tenant=? AND " + base.replace(tc, "", 1) + " ORDER BY priority DESC, id LIMIT ?", (n, *a0[:1 + len(kinds or ())], room)))
            return cand[n]
        while len(out) < room:
            best = None
            for n in names:
                w, mx = cfg.get(n, (1.0, None)); held = act.get(n, 0) + picked[n]
                if mx is not None and held >= mx: continue
                if picked[n] >= len(rows(n)): continue
                k = (held / w, served.get(n, 0), n)
                if best is None or k < best[0]: best = (k, n)
            if best is None: break
            n = best[1]; out.append(cand[n][picked[n]]); picked[n] += 1
        return out

    NODE_FRESH_S = 60.0

    def _node_room(self, c, node, now, limit):
        """A node that reports its capacity is handed at most (capacity - leases it already holds). Nodes that never reported, or whose report is stale, are not limited by this
        (only the global cap applies), and one node's limit never reduces what any other node may claim."""
        r = c.execute("SELECT capacity, reported FROM nodes WHERE node=?", (node,)).fetchone()
        if not r or r["capacity"] is None or now - r["reported"] > self.NODE_FRESH_S: return limit
        held = c.execute("SELECT COUNT(*) FROM tasks WHERE lease_node=? AND state IN ('claimed','running','validating') AND lease_expires>=?", (node, now)).fetchone()[0]
        return max(0, min(limit, r["capacity"] - held))

    def node_report(self, node, capacity=None, cpu=None, mem_mb=None, labels=None):
        """Per-worker-node capacity/health report (slots it can run, optional cpu/mem headroom, free-form labels). Cheap upsert; claims for this node are bounded by it."""
        with self.tx() as c:
            c.execute("INSERT INTO nodes(node,capacity,cpu,mem_mb,labels,reported) VALUES(?,?,?,?,?,?) ON CONFLICT(node) DO UPDATE SET capacity=excluded.capacity, cpu=excluded.cpu, mem_mb=excluded.mem_mb, labels=excluded.labels, reported=excluded.reported",
                      (str(node), None if capacity is None else int(capacity), cpu, mem_mb, _j(labels or {}), self.clock()))

    def nodes(self):
        now = self.clock(); out = []
        for r in self._conn().execute("SELECT * FROM nodes ORDER BY node"):
            d = dict(r); d["labels"] = json.loads(d["labels"] or "{}"); d["stale"] = now - d["reported"] > self.NODE_FRESH_S
            d["leases"] = self._conn().execute("SELECT COUNT(*) FROM tasks WHERE lease_node=? AND state IN ('claimed','running','validating') AND lease_expires>=?", (d["node"], now)).fetchone()[0]; out.append(d)
        return out

    def claim_many_wait(self, worker, node="main", ttl=15.0, kinds=None, limit=16, tenants=None, wait_s=0.0):
        """Long-poll claim: returns as soon as work is queued (a submit/requeue wakes one waiter) or after wait_s with []. A wake-up lost in the race between the empty claim and
        the wait is impossible (version counter), and cross-process writers are covered by re-checking every second."""
        end = time.time() + float(wait_s)
        while True:
            with self._cv: v = self._ver
            ts = self.claim_many(worker, node, ttl, kinds, limit, tenants)
            left = end - time.time()
            if ts or left <= 0: return ts
            with self._cv:
                if self._ver == v: self._cv.wait(min(1.0, left))

    # ---- tenant migration between shards (queued work only; running leases drain first)
    def freeze_tenant(self, tenant):
        """Stop new claims for the tenant (max_active=0). Returns its previous settings so an aborted migration can restore them."""
        with self.tx() as c:
            r = c.execute("SELECT weight, max_active, max_queued FROM tenants WHERE tenant=?", (str(tenant),)).fetchone(); prev = dict(r) if r else None
            c.execute("INSERT INTO tenants(tenant,weight,max_active,max_queued) VALUES(?,?,0,?) ON CONFLICT(tenant) DO UPDATE SET max_active=0", (str(tenant), prev["weight"] if prev else 1.0, prev["max_queued"] if prev else None)); return prev

    def active_of(self, tenant):
        return self._conn().execute("SELECT COUNT(*) FROM tasks WHERE tenant=? AND state IN ('claimed','running','validating') AND lease_expires>=?", (str(tenant), self.clock())).fetchone()[0]

    def export_queued(self, tenant):
        pre = f"{tenant}\x1f"
        return [{"id": r["id"], "kind": r["kind"], "payload": json.loads(r["payload"]), "idem_key": (r["idem_key"][len(pre):] if r["idem_key"] and r["idem_key"].startswith(pre) else r["idem_key"]), "priority": r["priority"], "max_attempts": r["max_attempts"]}
                for r in self._conn().execute("SELECT * FROM tasks WHERE tenant=? AND state='queued' ORDER BY priority DESC, id", (str(tenant),))]

    def retire(self, ids, reason="migrated"):
        """Cancel queued tasks that now live elsewhere. No commit event is written, so the source can never report a completion for them."""
        n = 0
        with self.tx() as c:
            for tid in ids:
                if c.execute("UPDATE tasks SET state='cancelled', failure=?, lease_expires=NULL, updated=? WHERE id=? AND state='queued'", (reason, self.clock(), tid)).rowcount: self._ev(c, tid, "cancelled", detail={"reason": reason}); n += 1
        return n

    def purge(self, ids):
        """Delete FINISHED tasks (completed/failed/cancelled) and everything recorded for them (events, checkpoints, evidence, outputs, operations). Retention/erasure only; live tasks are never touched."""
        n = 0
        with self.tx() as c:
            for tid in ids:
                if c.execute("SELECT 1 FROM tasks WHERE id=? AND state IN ('completed','failed','cancelled')", (tid,)).fetchone() is None: continue
                for t in ("events", "checkpoints", "evidence", "outputs", "operations"): c.execute(f"DELETE FROM {t} WHERE task_id=?", (tid,))
                c.execute("DELETE FROM tasks WHERE id=?", (tid,)); n += 1
        return n

    def claim(self, worker, node="main", ttl=15.0, kinds=None, tenants=None):
        """-> task dict (with its new fence) or None. Respects the adaptive concurrency cap across ALL workers/nodes and per-tenant fairness/quotas."""
        r = self.claim_many(worker, node, ttl, kinds, 1, tenants); return r[0] if r else None

    def claim_many(self, worker, node="main", ttl=15.0, kinds=None, limit=16, tenants=None):
        """Claim up to `limit` tasks in ONE transaction (one fsync instead of `limit`). Every task still gets its own, distinct fencing token; the global cap, per-tenant max_active and fairness are respected."""
        out = []
        if self._nothing_queued(self.clock(), kinds): return out
        with self.tx() as c:
            now = self.clock(); limit = self._node_room(c, node, now, limit)
            if limit <= 0: return out
            rows = self._pick(c, now, kinds, limit, tenants)
            if not rows: return out
            f = int(c.execute("SELECT v FROM meta WHERE k='fence'").fetchone()[0]); per = {}
            for r in rows:
                f += 1; c.execute("UPDATE tasks SET state='claimed', fence=?, attempt=attempt+1, lease_owner=?, lease_node=?, lease_expires=?, updated=? WHERE id=?", (f, worker, node, now + ttl, now, r["id"]))
                self._ev(c, r["id"], "claimed", f, worker, node, {"attempt": r["attempt"] + 1}); per[r["tenant"]] = per.get(r["tenant"], 0) + 1
            c.execute("UPDATE meta SET v=? WHERE k='fence'", (str(f),))
            for t, n in per.items(): self._use(c, t, "claims", n)
            out = [self._task(c, r["id"]) for r in rows]
        return out

    def _task(self, c, tid):
        r = c.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
        if r is None: return None
        return self._decode_task(r)

    @staticmethod
    def _decode_task(r):
        d = dict(r); d["payload"] = json.loads(d["payload"]); d["checkpoint"] = json.loads(d["checkpoint"]) if d["checkpoint"] else None
        d["result"] = json.loads(d["result"]) if d["result"] else None; return d
    def get(self, tid):
        return self._task(self._conn(), tid)

    def get_many(self, tids):
        """Read bounded batches without acquiring SQLite's writer lock."""
        # A separate read gate bounds simultaneous decoding of large batches.
        # It never holds the queue writer gate or a SQLite write transaction.
        with self._read_gate:
            ids = list(dict.fromkeys(tids)); out = {}; c = self._conn()
            for start in range(0, len(ids), 500):
                batch = ids[start:start + 500]
                for row in c.execute("SELECT * FROM tasks WHERE id IN (" + ",".join("?" for _ in batch) + ")", batch):
                    out[row["id"]] = self._decode_task(row)
            return out

    # -------------------------------------------------------------- fenced worker writes
    def heartbeat(self, tid, fence, ttl=15.0):
        """-> 'ok' | 'cancel' (cancellation requested) ; raises StaleLease when the lease is gone."""
        with self.tx() as c:
            r = self._own(c, tid, fence, ACTIVE); c.execute("UPDATE tasks SET lease_expires=?, updated=? WHERE id=?", (self.clock() + ttl, self.clock(), tid))
            return "cancel" if r["cancel_requested"] else "ok"

    def heartbeat_many(self, leases, ttl=15.0):
        """leases: [(tid, fence)] -> {tid: 'ok'|'cancel'|'stale'} in ONE transaction. A stale lease is reported, never extended (fencing unchanged)."""
        res = {}
        with self.tx() as c:
            now = self.clock()
            for tid, fence in leases:
                r = c.execute("SELECT fence, state, cancel_requested FROM tasks WHERE id=?", (tid,)).fetchone()
                if r is None or r["fence"] != fence or r["state"] not in ACTIVE: res[tid] = "stale"; continue
                c.execute("UPDATE tasks SET lease_expires=?, updated=? WHERE id=?", (now + ttl, now, tid)); res[tid] = "cancel" if r["cancel_requested"] else "ok"
        return res

    def begin(self, tid, fence, phase="running"):
        with self.tx() as c:
            self._own(c, tid, fence, ("claimed", "running", "validating")); st = "validating" if phase == "validating" else "running"
            c.execute("UPDATE tasks SET state=?, phase=?, updated=? WHERE id=?", (st, phase, self.clock(), tid)); self._ev(c, tid, "state", fence, detail={"state": st, "phase": phase})

    def checkpoint(self, tid, fence, phase, data):
        with self.tx() as c:
            self._own(c, tid, fence, ACTIVE); now = self.clock()
            c.execute("INSERT INTO checkpoints(task_id,fence,ts,phase,data) VALUES(?,?,?,?,?)", (tid, fence, now, phase, _j(data)))
            c.execute("UPDATE tasks SET phase=?, checkpoint=?, updated=? WHERE id=?", (phase, _j({"phase": phase, **data}) if isinstance(data, dict) else _j({"phase": phase, "data": data}), now, tid))

    def record_output(self, tid, fence, tool, args, output):
        with self.tx() as c: self._own(c, tid, fence, ACTIVE); c.execute("INSERT INTO outputs(task_id,fence,ts,tool,args,output) VALUES(?,?,?,?,?,?)", (tid, fence, self.clock(), tool, _j(args), str(output)[:20000]))

    def task_outputs(self, tid, after=0, limit=100):
        rows = self._conn().execute("SELECT * FROM outputs WHERE task_id=? AND id>? ORDER BY id LIMIT ?",
                                    (tid, max(0, int(after)), max(1, min(int(limit), 200))))
        return [{**dict(r), "args": json.loads(r["args"]) if r["args"] else None} for r in rows]

    def add_evidence(self, tid, fence, name, ok, detail=""):
        """Validation evidence survives crashes and retries: a passing record is never overwritten (only failed ones are re-evaluated), so a resumed validation never loses or rewrites it."""
        with self.tx() as c:
            self._own(c, tid, fence, ACTIVE)
            c.execute("INSERT INTO evidence(task_id,fence,ts,name,ok,detail) VALUES(?,?,?,?,?,?) ON CONFLICT(task_id,name) DO UPDATE SET fence=excluded.fence, ts=excluded.ts, ok=excluded.ok, detail=excluded.detail WHERE evidence.ok=0",
                      (tid, fence, self.clock(), name, 1 if ok else 0, str(detail)[:20000])); self._ev(c, tid, "evidence", fence, detail={"name": name, "ok": bool(ok)})
    def evidence(self, tid): return [dict(r) for r in self._conn().execute("SELECT * FROM evidence WHERE task_id=? ORDER BY id", (tid,))]

    def apply(self, tid, fence, ops):
        """Several fenced worker writes in ONE transaction (one fsync, synchronous=FULL unchanged): the fence is checked once, then every op lands or none does.
        ops: [{"op": "begin", "phase"} | {"op": "checkpoint", "phase", "data"} | {"op": "output", "tool", "args", "output"} | {"op": "evidence", "name", "ok", "detail"}]"""
        with self.tx() as c:
            self._own(c, tid, fence, ACTIVE); now = self.clock()
            for o in ops:
                k = o.get("op")
                if k == "begin":
                    st = "validating" if o.get("phase") == "validating" else "running"; c.execute("UPDATE tasks SET state=?, phase=?, updated=? WHERE id=?", (st, o.get("phase", "running"), now, tid)); self._ev(c, tid, "state", fence, detail={"state": st, "phase": o.get("phase", "running")})
                elif k == "checkpoint":
                    data = o.get("data"); c.execute("INSERT INTO checkpoints(task_id,fence,ts,phase,data) VALUES(?,?,?,?,?)", (tid, fence, now, o["phase"], _j(data)))
                    c.execute("UPDATE tasks SET phase=?, checkpoint=?, updated=? WHERE id=?", (o["phase"], _j({"phase": o["phase"], **data}) if isinstance(data, dict) else _j({"phase": o["phase"], "data": data}), now, tid))
                elif k == "output": c.execute("INSERT INTO outputs(task_id,fence,ts,tool,args,output) VALUES(?,?,?,?,?,?)", (tid, fence, now, o["tool"], _j(o.get("args")), str(o.get("output"))[:20000]))
                elif k == "evidence":
                    c.execute("INSERT INTO evidence(task_id,fence,ts,name,ok,detail) VALUES(?,?,?,?,?,?) ON CONFLICT(task_id,name) DO UPDATE SET fence=excluded.fence, ts=excluded.ts, ok=excluded.ok, detail=excluded.detail WHERE evidence.ok=0",
                              (tid, fence, now, o["name"], 1 if o.get("ok") else 0, str(o.get("detail", ""))[:20000])); self._ev(c, tid, "evidence", fence, detail={"name": o["name"], "ok": bool(o.get("ok"))})
                else: raise ValueError(f"unknown op {k!r}")

    def complete(self, tid, fence, result, promote=None):
        """Commit the result. `promote` (e.g. rename attempt dir -> final dir) runs inside the fenced transaction, only if the fence still holds."""
        with self.tx() as c:
            self._own(c, tid, fence, ("running", "validating")); now = self.clock()
            if promote: promote()
            c.execute("UPDATE tasks SET state='completed', result=?, lease_expires=NULL, updated=? WHERE id=?", (_j(result), now, tid)); self._ev(c, tid, "commit", fence, detail={"result_bytes": len(_j(result))})
            cl = c.execute("SELECT ts FROM events WHERE task_id=? AND kind='claimed' ORDER BY id DESC LIMIT 1", (tid,)).fetchone()
            self._use(c, self._tenant_of(c, tid), "completed"); self._use(c, self._tenant_of(c, tid), "lease_seconds", max(0.0, now - cl["ts"]) if cl else 0.0)

    def fail(self, tid, fence, reason, retry=True, backoff=1.0):
        """Validation/handler failure. Retries (attempt budget) unless retry=False or exhausted; always keeps the reason."""
        with self.tx() as c:
            r = self._own(c, tid, fence, ACTIVE); now = self.clock(); self._ev(c, tid, "attempt_failed", fence, detail={"reason": str(reason)[:2000], "attempt": r["attempt"]})
            if retry and r["attempt"] < r["max_attempts"] and not r["cancel_requested"]:
                self._added += 1; c.execute("UPDATE tasks SET state='queued', lease_owner=NULL, lease_expires=NULL, not_before=?, failure=?, updated=? WHERE id=?", (now + backoff * r["attempt"], str(reason)[:2000], now, tid)); return "queued"
            c.execute("UPDATE tasks SET state='failed', failure=?, lease_expires=NULL, updated=? WHERE id=?", (str(reason)[:2000], now, tid)); self._ev(c, tid, "failed", fence, detail={"reason": str(reason)[:2000]}); self._use(c, self._tenant_of(c, tid), "failed"); return "failed"

    def release(self, tid, fence, reason, delay=2.0):
        """Transient infrastructure failure: back to the queue, attempt not consumed (bounded by INFRA_CAP)."""
        with self.tx() as c:
            r = self._own(c, tid, fence, ACTIVE); now = self.clock(); self._ev(c, tid, "released", fence, detail={"reason": str(reason)[:500]})
            if r["cancel_requested"]:                           # a cancelled task must never go back to a queue that refuses to claim it (it would sit 'queued' forever)
                c.execute("UPDATE tasks SET state='cancelled', lease_expires=NULL, updated=? WHERE id=?", (now, tid)); self._ev(c, tid, "cancelled", fence); return "cancelled"
            if r["infra"] + 1 > INFRA_CAP:
                c.execute("UPDATE tasks SET state='failed', failure=?, lease_expires=NULL, updated=? WHERE id=?", ("infra retry cap: " + str(reason)[:500], now, tid)); return "failed"
            self._added += 1; c.execute("UPDATE tasks SET state='queued', infra=infra+1, attempt=MAX(attempt-1,0), lease_owner=NULL, lease_expires=NULL, not_before=?, updated=? WHERE id=?", (now + delay, now, tid)); return "queued"

    def hold(self, tid, fence, reason):
        with self.tx() as c:
            self._own(c, tid, fence, ACTIVE); c.execute("UPDATE tasks SET state='needs_approval', failure=?, lease_expires=NULL, updated=? WHERE id=?", (str(reason)[:2000], self.clock(), tid)); self._ev(c, tid, "needs_approval", fence, detail={"reason": str(reason)[:500]})

    def cancelled(self, tid, fence):
        with self.tx() as c:
            self._own(c, tid, fence, ACTIVE); c.execute("UPDATE tasks SET state='cancelled', lease_expires=NULL, updated=? WHERE id=?", (self.clock(), tid)); self._ev(c, tid, "cancelled", fence)

    # -------------------------------------------------------------- operator / supervisor
    def cancel(self, tid):
        with self.tx() as c:
            r = c.execute("SELECT state FROM tasks WHERE id=?", (tid,)).fetchone()
            if r is None or r["state"] in TERMINAL: return r["state"] if r else None
            if r["state"] in ("queued", "needs_approval"): c.execute("UPDATE tasks SET state='cancelled', cancel_requested=1, updated=? WHERE id=?", (self.clock(), tid)); self._ev(c, tid, "cancelled"); return "cancelled"
            c.execute("UPDATE tasks SET cancel_requested=1, updated=? WHERE id=?", (self.clock(), tid)); self._ev(c, tid, "cancel_requested"); return "cancelling"

    def approve(self, tid, resolution="retry"):
        """Explicit human decision for a parked task. 'retry' re-runs the unreconciled operations; 'skip' marks them committed (operator verified they happened)."""
        with self.tx() as c:
            r = c.execute("SELECT state,attempt,checkpoint FROM tasks WHERE id=?", (tid,)).fetchone()
            if r is None or r["state"] != "needs_approval": return False
            c.execute("UPDATE operations SET status=?, note='operator '||?, ts=? WHERE task_id=? AND status IN ('intent','unknown')", ("committed" if resolution == "skip" else "approved_retry", resolution, self.clock(), tid))
            checkpoint = json.loads(r['checkpoint']) if r['checkpoint'] else {}
            checkpoint['owner_approval'] = {'attempt': r['attempt'], 'resolution': resolution}
            self._added += 1; c.execute("UPDATE tasks SET state='queued', not_before=0, updated=?,checkpoint=? WHERE id=?", (self.clock(), _j(checkpoint), tid)); self._ev(c, tid, "approved", detail={"resolution": resolution}); return True

    def reap(self):
        """Expire dead leases. -> list of (task_id, new_state). Safe to call from any process at any time (also on supervisor start = restart/reboot recovery)."""
        out = []
        with self.tx() as c:
            now = self.clock()
            for r in c.execute("SELECT * FROM tasks WHERE state IN ('claimed','running','validating') AND lease_expires<?", (now,)).fetchall():
                self._ev(c, r["id"], "lease_expired", r["fence"], r["lease_owner"], r["lease_node"], {"phase": r["phase"], "attempt": r["attempt"]})
                if r["cancel_requested"]: st = "cancelled"; c.execute("UPDATE tasks SET state='cancelled', lease_expires=NULL, updated=? WHERE id=?", (now, r["id"]))
                elif r["attempt"] >= r["max_attempts"]: st = "failed"; c.execute("UPDATE tasks SET state='failed', failure=COALESCE(failure,'')||' lease expired on final attempt', lease_expires=NULL, updated=? WHERE id=?", (now, r["id"]))
                else: st = "queued"; self._added += 1; c.execute("UPDATE tasks SET state='queued', lease_owner=NULL, lease_expires=NULL, not_before=0, updated=? WHERE id=?", (now, r["id"]))
                out.append((r["id"], st))
        return out

    def expire_node(self, node, reason="node restarted"):
        """Every lease held by workers on `node` is dead (host reboot / node declared down): expire them now instead of waiting for the TTL."""
        with self.tx() as c:
            n = c.execute("UPDATE tasks SET lease_expires=0 WHERE state IN ('claimed','running','validating') AND lease_node=?", (node,)).rowcount
            if n: self._ev(c, 0, "node_expired", node=node, detail={"reason": reason, "leases": n})
        return n
    def meta(self, k, v=None):
        with self.tx() as c:
            old = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone(); old = old[0] if old else None
            if v is not None: c.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
            return old

    # -------------------------------------------------------------- side effects (primitives; use run_effect() below)
    def op_begin(self, tid, fence, op_key):
        """-> ('committed', result) | ('fresh', None) intent recorded, safe to act | ('stale', None) an earlier attempt left an unfinished intent."""
        with self.tx() as c:
            self._own(c, tid, fence, ("running", "validating")); row = c.execute("SELECT * FROM operations WHERE op_key=?", (op_key,)).fetchone()
            if row and row["status"] == "committed": return ("committed", json.loads(row["result"]) if row["result"] else None)
            if row is None: c.execute("INSERT INTO operations(op_key,task_id,fence,status,ts) VALUES(?,?,?,'intent',?)", (op_key, tid, fence, self.clock())); return ("fresh", None)
            if row["status"] == "approved_retry": c.execute("UPDATE operations SET status='intent', fence=?, ts=? WHERE op_key=?", (fence, self.clock(), op_key)); return ("fresh", None)
            c.execute("UPDATE operations SET fence=?, ts=? WHERE op_key=?", (fence, self.clock(), op_key)); return ("stale", None)
    def op_resolve(self, tid, fence, op_key, verdict, result=None):
        """Record the outcome of reconciling a stale intent: committed -> done; absent -> safe to act; anything else -> parked as unknown."""
        with self.tx() as c:
            self._own(c, tid, fence, ("running", "validating"))
            if verdict == "committed": c.execute("UPDATE operations SET status='committed', result=?, note='reconciled', ts=? WHERE op_key=?", (_j(result), self.clock(), op_key)); self._ev(c, tid, "effect_reconciled", fence, detail={"op": op_key})
            elif verdict != "absent": c.execute("UPDATE operations SET status='unknown', ts=? WHERE op_key=?", (self.clock(), op_key))
    def op_commit(self, tid, fence, op_key, result):
        with self.tx() as c:
            self._own(c, tid, fence, ("running", "validating")); c.execute("UPDATE operations SET status='committed', result=?, ts=? WHERE op_key=?", (_j(result), self.clock(), op_key)); self._ev(c, tid, "effect_committed", fence, detail={"op": op_key})
    def operations(self, tid): return [dict(r) for r in self._conn().execute("SELECT * FROM operations WHERE task_id=? ORDER BY ts", (tid,))]
    def effect(self, tid, fence, op_key, do, reconcile=None): return run_effect(self, tid, fence, op_key, do, reconcile)

    # -------------------------------------------------------------- inspection / invariants
    def history(self, tid): return [dict(r) for r in self._conn().execute("SELECT * FROM events WHERE task_id=? ORDER BY id", (tid,))]
    def oldest_queued(self):
        r = self._conn().execute("SELECT MIN(created) FROM tasks WHERE state='queued'").fetchone(); return r[0]
    def counts(self):
        return {r[0]: r[1] for r in self._conn().execute("SELECT state, COUNT(*) FROM tasks GROUP BY state")}
    def tasks(self, states=None):
        with self.tx() as c: return [t for t in (self._task(c, r[0]) for r in c.execute("SELECT id FROM tasks ORDER BY id").fetchall()) if states is None or t["state"] in states]
    def audit(self):
        """Invariants that must hold at every instant. -> list of violations (empty = healthy)."""
        bad = []; c = self._conn()
        for r in c.execute("SELECT id,state FROM tasks"):
            if r["state"] not in TERMINAL + RECOVERABLE: bad.append(f"task {r['id']}: unknown state {r['state']}")
        for r in c.execute("SELECT task_id, COUNT(*) n FROM events WHERE kind='commit' GROUP BY task_id HAVING n>1"): bad.append(f"task {r['task_id']}: {r['n']} commits")
        for r in c.execute("SELECT id FROM tasks WHERE state='completed' AND id NOT IN (SELECT task_id FROM events WHERE kind='commit')"): bad.append(f"task {r['id']}: completed without a commit event")
        for r in c.execute("SELECT id FROM tasks WHERE state!='completed' AND id IN (SELECT task_id FROM events WHERE kind='commit')"): bad.append(f"task {r['id']}: commit event but state != completed")
        for r in c.execute("SELECT id FROM tasks WHERE state IN ('failed') AND (failure IS NULL OR failure='')"): bad.append(f"task {r['id']}: failed without a reason")
        return bad


def run_effect(store, tid, fence, op_key, do, reconcile=None):
    """Run an external side effect at most once per op_key (works on a Store or a RemoteStore). do(op_key) must pass op_key to the external system as its
    idempotency key. reconcile(op_key) -> ('committed', result) | ('absent', None) | ('unknown', None) is consulted when an earlier attempt left an intent behind.
    Undecidable -> task parks in needs_approval (NeedsApproval); a human approve()s retry/skip."""
    st, res = store.op_begin(tid, fence, op_key)
    if st == "committed": return res
    if st == "stale":
        verdict, res = reconcile(op_key) if reconcile else ("unknown", None)
        store.op_resolve(tid, fence, op_key, verdict, res)
        if verdict == "committed": return res
        if verdict != "absent": raise NeedsApproval(f"operation {op_key}: an earlier attempt may have run and cannot be reconciled automatically")
    res = do(op_key); store.op_commit(tid, fence, op_key, res); return res
