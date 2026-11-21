"""PostgreSQL TaskStore adapter (shared distributed database backend for the durable queue).

STATUS: VERIFIED against a real PostgreSQL 16.15 server (2026-11-04): the shared conformance suite (12 tests, same file that gates SQLite) plus ordivyr/tests/test_p3_pg_realdb.py
(multi-coordinator and multi-process claim races, exactly-once commit races, lease expiry + fencing, backend termination between statements and mid-transaction, `pg_ctl -m immediate`
crash/restart, idempotent-submit races, tenant isolation, SQLite-vs-PostgreSQL differential transcript). Both suites SKIP unless ORDIVYR_PG_DSN is set and `psycopg` (v3) is importable.
Not verified: managed/cloud PostgreSQL, replicas/failover, pgbouncer in transaction-pooling mode, PostgreSQL versions other than 16, sustained load (see docs/scalability/COMMERCIAL_SCALE.md).
First real run found and fixed one defect: read-only paths left the connection `idle in transaction`, which held locks and blocked TRUNCATE/DDL (`_read()`).

Design (differences from SQLite, all deliberate):
  * Fences come from a SEQUENCE (nextval), globally monotonic across any number of coordinators; every write is `UPDATE ... WHERE id=%s AND fence=%s AND state IN (...)` and the
    rowcount decides, so a stale holder can never write regardless of which coordinator it reaches.
  * Claiming selects candidate ids with a window query (per-tenant ranks -> weighted fair order) and then locks exactly those rows with `FOR UPDATE SKIP LOCKED`, so concurrent
    coordinators never block each other and never hand the same task out twice (window functions cannot be combined with FOR UPDATE in one statement).
  * At most one commit per task: partial unique index on events(task_id) WHERE kind='commit'.
  * READ COMMITTED + short transactions; no advisory locks required.
"""
from __future__ import annotations
import json, os, threading, time, weakref

import importlib
try:                                                 # optional driver, loaded dynamically so the package stays stdlib-only (boundary test) and imports cleanly without it
    psycopg = importlib.import_module("psycopg"); dict_row = importlib.import_module("psycopg.rows").dict_row
except Exception:
    psycopg = dict_row = None

from .. import durable as D

DDL = """
CREATE SEQUENCE IF NOT EXISTS ordivyr_fence;
CREATE TABLE IF NOT EXISTS tasks(
  id BIGSERIAL PRIMARY KEY, idem_key TEXT UNIQUE, tenant TEXT NOT NULL DEFAULT 'default', kind TEXT NOT NULL, payload JSONB NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
  priority INTEGER NOT NULL DEFAULT 0, attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3, infra INTEGER NOT NULL DEFAULT 0, fence BIGINT NOT NULL DEFAULT 0,
  lease_owner TEXT, lease_node TEXT, lease_expires DOUBLE PRECISION, not_before DOUBLE PRECISION NOT NULL DEFAULT 0, cancel_requested INTEGER NOT NULL DEFAULT 0,
  phase TEXT, checkpoint JSONB, result JSONB, failure TEXT, created DOUBLE PRECISION NOT NULL, updated DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS tasks_fair ON tasks(state, tenant, priority DESC, id);
CREATE TABLE IF NOT EXISTS events(id BIGSERIAL PRIMARY KEY, task_id BIGINT NOT NULL, ts DOUBLE PRECISION NOT NULL, kind TEXT NOT NULL, fence BIGINT, worker TEXT, node TEXT, detail JSONB);
CREATE UNIQUE INDEX IF NOT EXISTS one_commit ON events(task_id) WHERE kind='commit';
CREATE TABLE IF NOT EXISTS checkpoints(id BIGSERIAL PRIMARY KEY, task_id BIGINT NOT NULL, fence BIGINT NOT NULL, ts DOUBLE PRECISION NOT NULL, phase TEXT NOT NULL, data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(id BIGSERIAL PRIMARY KEY, task_id BIGINT NOT NULL, fence BIGINT NOT NULL, ts DOUBLE PRECISION NOT NULL, name TEXT NOT NULL, ok INTEGER NOT NULL, detail TEXT, UNIQUE(task_id, name));
CREATE TABLE IF NOT EXISTS outputs(id BIGSERIAL PRIMARY KEY, task_id BIGINT NOT NULL, fence BIGINT NOT NULL, ts DOUBLE PRECISION NOT NULL, tool TEXT NOT NULL, args JSONB, output TEXT);
CREATE TABLE IF NOT EXISTS tenants(tenant TEXT PRIMARY KEY, weight DOUBLE PRECISION NOT NULL DEFAULT 1, max_active INTEGER, max_queued INTEGER);
CREATE TABLE IF NOT EXISTS usage(tenant TEXT PRIMARY KEY, submitted BIGINT NOT NULL DEFAULT 0, claims BIGINT NOT NULL DEFAULT 0, completed BIGINT NOT NULL DEFAULT 0, failed BIGINT NOT NULL DEFAULT 0, lease_seconds DOUBLE PRECISION NOT NULL DEFAULT 0, quota_rejections BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS nodes(node TEXT PRIMARY KEY, capacity INTEGER, cpu DOUBLE PRECISION, mem_mb DOUBLE PRECISION, labels JSONB, reported DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""
ACTIVE = ("claimed", "running", "validating")
TERMINAL = ("completed", "failed", "cancelled")


class _ConnHolder:
    def __init__(self, c, release): self.c, self.release, self.pid = c, release, os.getpid()
    def __del__(self):
        if os.getpid() != self.pid: return          # NEVER close in a forked child (subprocess preexec runs GC there): PQfinish would send Terminate down the socket the parent still uses
        try: self.release(self.c)
        except Exception: pass


class PgStore:
    NODE_FRESH_S = 60.0

    def __init__(self, dsn, clock=time.time):
        if psycopg is None: raise RuntimeError("psycopg (v3) is not installed")
        self.dsn, self.clock, self._tl = dsn, clock, threading.local(); self.tx_count = 0; self._conns = []; self._cl = threading.Lock()
        with self.tx() as c: c.execute(DDL); c.execute("INSERT INTO meta VALUES('cap','1000000') ON CONFLICT DO NOTHING")

    # ---- plumbing
    def _conn(self):
        c = getattr(self._tl, "c", None); now = time.monotonic()
        if c is not None and not c.closed and now - getattr(self._tl, "t", now) > 0.5:      # a connection idle across a server restart looks open until used: verify it before handing it out
            try: c.execute("SELECT 1"); c.rollback()
            except psycopg.OperationalError:
                try: c.close()
                except Exception: pass
        self._tl.t = now
        if c is None or c.closed:
            c = psycopg.connect(self.dsn, row_factory=dict_row, autocommit=False); self._tl.c = c
            with self._cl: self._conns = [x for x in self._conns if not x.closed] + [c]
            self._tl.holder = _ConnHolder(c, self._release)           # closed when the owning thread exits (request threads are short-lived)
        return c

    def _release(self, c):
        try: c.close()
        except Exception: pass
        with self._cl:
            try: self._conns.remove(c)
            except ValueError: pass

    def close(self):
        """Close every connection this store opened (one per thread), e.g. at shutdown or in test teardown."""
        with self._cl: cs, self._conns = self._conns, []
        for c in cs:
            try: c.close()
            except Exception: pass

    def _read(self, fn):
        """Run read-only queries and END the transaction. psycopg opens one implicitly on the first statement; without this the thread's pooled
        connection stays `idle in transaction`, holding locks that block TRUNCATE/DDL/maintenance (found by the real-PostgreSQL conformance run)."""
        for attempt in (0, 1):
            c = self._conn()
            try: return fn(c)
            except psycopg.OperationalError:
                try: c.close()
                except Exception: pass
                if attempt: raise                                       # reads are idempotent: reconnect once
            finally:
                if not c.closed: c.rollback()

    def tx(self):
        import contextlib
        @contextlib.contextmanager
        def cm():
            c = self._conn()
            try: yield c; c.commit(); self.tx_count += 1
            except BaseException as e:
                if isinstance(e, psycopg.OperationalError):
                    try: c.close()                                      # dead connection: drop it so the NEXT call reconnects; this call fails loudly (outcome unknown, never replayed)
                    except Exception: pass
                else: c.rollback()
                raise
        return cm()

    def _ev(self, c, tid, kind, fence=None, worker=None, node=None, detail=None):
        c.execute("INSERT INTO events(task_id,ts,kind,fence,worker,node,detail) VALUES(%s,%s,%s,%s,%s,%s,%s)", (tid, self.clock(), kind, fence, worker, node, None if detail is None else json.dumps(detail)))

    def _use(self, c, tenant, col, n=1):
        c.execute(f"INSERT INTO usage(tenant,{col}) VALUES(%s,%s) ON CONFLICT(tenant) DO UPDATE SET {col}=usage.{col}+EXCLUDED.{col}", (tenant, n))

    def _own(self, c, tid, fence, states):
        """Lock the row and check the fence. Raises StaleLease unless this fence still owns the task in one of `states`."""
        r = c.execute("SELECT * FROM tasks WHERE id=%s FOR UPDATE", (tid,)).fetchone()
        if r is None or r["fence"] != fence or r["state"] not in states: raise D.StaleLease(f"task {tid}: fence {fence} is stale (current {r['fence'] if r else None}, state {r['state'] if r else None})")
        return r

    # ---- submit / claim
    def submit(self, kind, payload, idem_key=None, max_attempts=3, priority=0, tenant="default"):
        tenant = str(tenant or "default"); key = None if not idem_key else (idem_key if tenant == "default" else f"{tenant}\x1f{idem_key}")
        try:
            with self.tx() as c:
                if key:
                    r = c.execute("SELECT id FROM tasks WHERE idem_key=%s", (key,)).fetchone()
                    if r: return r["id"]
                q = c.execute("SELECT max_queued FROM tenants WHERE tenant=%s", (tenant,)).fetchone()
                if q and q["max_queued"] is not None and c.execute("SELECT COUNT(*) AS n FROM tasks WHERE tenant=%s AND state='queued'", (tenant,)).fetchone()["n"] >= q["max_queued"]:
                    raise D.QuotaExceeded(f"tenant {tenant!r}: queued-task quota ({q['max_queued']}) reached")
                now = self.clock()
                tid = c.execute("INSERT INTO tasks(idem_key,tenant,kind,payload,priority,max_attempts,created,updated) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(idem_key) DO NOTHING RETURNING id",
                                (key, tenant, kind, json.dumps(payload), priority, max_attempts, now, now)).fetchone()
                if tid is None: return c.execute("SELECT id FROM tasks WHERE idem_key=%s", (key,)).fetchone()["id"]      # lost a race with a concurrent identical submit
                self._ev(c, tid["id"], "submitted", detail={"kind": kind, "tenant": tenant}); self._use(c, tenant, "submitted"); return tid["id"]
        except D.QuotaExceeded:
            with self.tx() as c: self._use(c, tenant, "quota_rejections")
            raise

    def cap(self, c=None):
        q = lambda c: int(c.execute("SELECT v FROM meta WHERE k='cap'").fetchone()["v"])
        return q(c) if c is not None else self._read(q)          # pass the open tx's connection when already inside one (a read here must not end it)
    def set_cap(self, n):
        with self.tx() as c: c.execute("UPDATE meta SET v=%s WHERE k='cap'", (str(int(n)),))

    def claim_many(self, worker, node="main", ttl=15.0, kinds=None, limit=16, tenants=None):
        out = []
        with self.tx() as c:
            # Disjoint kind/tenant filters can lock different tasks while both
            # observing the same free capacity. SKIP LOCKED alone cannot make
            # the aggregate global/node/tenant admission decision atomic.
            c.execute("SELECT pg_advisory_xact_lock(7002)")
            now = self.clock()
            act = {r["tenant"]: r["n"] for r in c.execute("SELECT tenant, COUNT(*) AS n FROM tasks WHERE state IN ('claimed','running','validating') AND lease_expires>=%s GROUP BY tenant", (now,))}
            room = min(limit, self.cap(c) - sum(act.values()))
            nd = c.execute("SELECT capacity, reported FROM nodes WHERE node=%s", (node,)).fetchone()
            if nd and nd["capacity"] is not None and now - nd["reported"] <= self.NODE_FRESH_S:
                held = c.execute("SELECT COUNT(*) AS n FROM tasks WHERE lease_node=%s AND state IN ('claimed','running','validating') AND lease_expires>=%s", (node, now)).fetchone()["n"]; room = min(room, nd["capacity"] - held)
            if room <= 0: return out
            # weighted fair order: rank each tenant's queued tasks, order by (leases held + rank-1)/weight, honour max_active
            rows = c.execute("""
                WITH q AS (
                  SELECT t.id, t.tenant, ROW_NUMBER() OVER (PARTITION BY t.tenant ORDER BY t.priority DESC, t.id) AS rk
                  FROM tasks t WHERE t.state='queued' AND t.not_before<=%s AND t.cancel_requested=0
                    AND (%s::text[] IS NULL OR t.kind = ANY(%s)) AND (%s::text[] IS NULL OR t.tenant = ANY(%s))),
                a AS (SELECT tenant, COUNT(*) AS n FROM tasks WHERE state IN ('claimed','running','validating') AND lease_expires>=%s GROUP BY tenant)
                SELECT q.id FROM q LEFT JOIN a USING(tenant) LEFT JOIN tenants tn USING(tenant)
                WHERE tn.max_active IS NULL OR COALESCE(a.n,0) + q.rk <= tn.max_active
                ORDER BY (COALESCE(a.n,0) + q.rk - 1) / COALESCE(NULLIF(tn.weight,0),1), q.tenant, q.rk LIMIT %s""", (now, kinds, kinds, tenants, tenants, now, room)).fetchall()
            if not rows: return out
            ids = [r["id"] for r in rows]
            locked = c.execute("SELECT * FROM tasks WHERE id = ANY(%s) AND state='queued' FOR UPDATE SKIP LOCKED", (ids,)).fetchall()
            order = {i: n for n, i in enumerate(ids)}; per = {}
            for r in sorted(locked, key=lambda r: order[r["id"]]):
                f = c.execute("SELECT nextval('ordivyr_fence') AS f").fetchone()["f"]
                c.execute("UPDATE tasks SET state='claimed', fence=%s, attempt=attempt+1, lease_owner=%s, lease_node=%s, lease_expires=%s, updated=%s WHERE id=%s", (f, worker, node, now + ttl, now, r["id"]))
                self._ev(c, r["id"], "claimed", f, worker, node, {"attempt": r["attempt"] + 1}); per[r["tenant"]] = per.get(r["tenant"], 0) + 1
                out.append(self._task(c, r["id"]))
            for t, n in per.items(): self._use(c, t, "claims", n)
        return out

    def claim(self, worker, node="main", ttl=15.0, kinds=None, tenants=None):
        r = self.claim_many(worker, node, ttl, kinds, 1, tenants); return r[0] if r else None

    def claim_many_wait(self, worker, node="main", ttl=15.0, kinds=None, limit=16, tenants=None, wait_s=0.0):
        end = time.time() + wait_s                    # LISTEN/NOTIFY would make this push-based; a short poll keeps the adapter simple until measured necessary
        while True:
            ts = self.claim_many(worker, node, ttl, kinds, limit, tenants)
            if ts or time.time() >= end: return ts
            time.sleep(min(0.2, max(0.0, end - time.time())))

    def _task(self, c, tid):
        r = c.execute("SELECT * FROM tasks WHERE id=%s", (tid,)).fetchone()
        return dict(r) if r else None
    def get(self, tid):
        return self._read(lambda c: self._task(c, tid))

    def get_many(self, tids):
        """One read transaction per bounded batch; never retain an idle transaction."""
        ids = list(dict.fromkeys(tids)); out = {}
        for start in range(0, len(ids), 500):
            batch = ids[start:start + 500]
            rows = self._read(lambda c: c.execute("SELECT * FROM tasks WHERE id = ANY(%s)", (batch,)).fetchall())
            out.update((row["id"], dict(row)) for row in rows)
        return out

    # ---- fenced worker writes
    def heartbeat(self, tid, fence, ttl=15.0):
        with self.tx() as c:
            r = self._own(c, tid, fence, ACTIVE); c.execute("UPDATE tasks SET lease_expires=%s, updated=%s WHERE id=%s", (self.clock() + ttl, self.clock(), tid)); return "cancel" if r["cancel_requested"] else "ok"

    def heartbeat_many(self, leases, ttl=15.0):
        res = {}
        with self.tx() as c:
            now = self.clock()
            for tid, fence in leases:
                r = c.execute("UPDATE tasks SET lease_expires=%s, updated=%s WHERE id=%s AND fence=%s AND state IN ('claimed','running','validating') RETURNING cancel_requested", (now + ttl, now, tid, fence)).fetchone()
                res[tid] = "stale" if r is None else ("cancel" if r["cancel_requested"] else "ok")
        return res

    def begin(self, tid, fence, phase="running"):
        with self.tx() as c:
            self._own(c, tid, fence, ("claimed", "running", "validating")); st = "validating" if phase == "validating" else "running"
            c.execute("UPDATE tasks SET state=%s, phase=%s, updated=%s WHERE id=%s", (st, phase, self.clock(), tid)); self._ev(c, tid, "state", fence, detail={"state": st, "phase": phase})

    def _w_checkpoint(self, c, tid, fence, phase, data, now):
        c.execute("INSERT INTO checkpoints(task_id,fence,ts,phase,data) VALUES(%s,%s,%s,%s,%s)", (tid, fence, now, phase, json.dumps(data)))
        c.execute("UPDATE tasks SET phase=%s, checkpoint=%s, updated=%s WHERE id=%s", (phase, json.dumps({"phase": phase, **data} if isinstance(data, dict) else {"phase": phase, "data": data}), now, tid))

    def checkpoint(self, tid, fence, phase, data):
        with self.tx() as c: self._own(c, tid, fence, ACTIVE); self._w_checkpoint(c, tid, fence, phase, data, self.clock())

    def record_output(self, tid, fence, tool, args, output):
        with self.tx() as c: self._own(c, tid, fence, ACTIVE); c.execute("INSERT INTO outputs(task_id,fence,ts,tool,args,output) VALUES(%s,%s,%s,%s,%s,%s)", (tid, fence, self.clock(), tool, json.dumps(args), str(output)[:20000]))

    def task_outputs(self, tid, after=0, limit=100):
        with self.tx() as c:
            return [dict(r) for r in c.execute("SELECT * FROM outputs WHERE task_id=%s AND id>%s ORDER BY id LIMIT %s",
                (tid, max(0, int(after)), max(1, min(int(limit), 200)))).fetchall()]

    def _w_evidence(self, c, tid, fence, name, ok, detail, now):
        c.execute("INSERT INTO evidence(task_id,fence,ts,name,ok,detail) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(task_id,name) DO UPDATE SET fence=EXCLUDED.fence, ts=EXCLUDED.ts, ok=EXCLUDED.ok, detail=EXCLUDED.detail WHERE evidence.ok=0",
                  (tid, fence, now, name, 1 if ok else 0, str(detail)[:20000])); self._ev(c, tid, "evidence", fence, detail={"name": name, "ok": bool(ok)})

    def add_evidence(self, tid, fence, name, ok, detail=""):
        with self.tx() as c: self._own(c, tid, fence, ACTIVE); self._w_evidence(c, tid, fence, name, ok, detail, self.clock())
    def evidence(self, tid): return self._read(lambda c: [dict(r) for r in c.execute("SELECT * FROM evidence WHERE task_id=%s ORDER BY id", (tid,))])

    def apply(self, tid, fence, ops):
        with self.tx() as c:
            self._own(c, tid, fence, ACTIVE); now = self.clock()
            for o in ops:
                k = o.get("op")
                if k == "begin":
                    st = "validating" if o.get("phase") == "validating" else "running"; c.execute("UPDATE tasks SET state=%s, phase=%s, updated=%s WHERE id=%s", (st, o.get("phase", "running"), now, tid)); self._ev(c, tid, "state", fence, detail={"state": st, "phase": o.get("phase", "running")})
                elif k == "checkpoint": self._w_checkpoint(c, tid, fence, o["phase"], o.get("data"), now)
                elif k == "output": c.execute("INSERT INTO outputs(task_id,fence,ts,tool,args,output) VALUES(%s,%s,%s,%s,%s,%s)", (tid, fence, now, o["tool"], json.dumps(o.get("args")), str(o.get("output"))[:20000]))
                elif k == "evidence": self._w_evidence(c, tid, fence, o["name"], o.get("ok"), o.get("detail", ""), now)
                else: raise ValueError(f"unknown op {k!r}")

    def complete(self, tid, fence, result, promote=None):
        with self.tx() as c:
            r = self._own(c, tid, fence, ("running", "validating")); now = self.clock()
            if promote: promote()
            c.execute("UPDATE tasks SET state='completed', result=%s, lease_expires=NULL, updated=%s WHERE id=%s", (json.dumps(result), now, tid))
            self._ev(c, tid, "commit", fence, detail={"result_bytes": len(json.dumps(result))})            # unique partial index: a second commit event for this task cannot exist
            cl = c.execute("SELECT ts FROM events WHERE task_id=%s AND kind='claimed' ORDER BY id DESC LIMIT 1", (tid,)).fetchone()
            self._use(c, r["tenant"], "completed"); self._use(c, r["tenant"], "lease_seconds", max(0.0, now - cl["ts"]) if cl else 0.0)

    def fail(self, tid, fence, reason, retry=True, backoff=1.0):
        with self.tx() as c:
            r = self._own(c, tid, fence, ACTIVE); now = self.clock(); self._ev(c, tid, "attempt_failed", fence, detail={"reason": str(reason)[:2000], "attempt": r["attempt"]})
            if retry and r["attempt"] < r["max_attempts"] and not r["cancel_requested"]:
                c.execute("UPDATE tasks SET state='queued', lease_owner=NULL, lease_expires=NULL, not_before=%s, failure=%s, updated=%s WHERE id=%s", (now + backoff * r["attempt"], str(reason)[:2000], now, tid)); return "queued"
            c.execute("UPDATE tasks SET state='failed', failure=%s, lease_expires=NULL, updated=%s WHERE id=%s", (str(reason)[:2000], now, tid)); self._ev(c, tid, "failed", fence, detail={"reason": str(reason)[:2000]}); self._use(c, r["tenant"], "failed"); return "failed"

    def release(self, tid, fence, reason, delay=2.0):
        with self.tx() as c:
            r = self._own(c, tid, fence, ACTIVE); now = self.clock()
            if r["cancel_requested"]:                              # same rule as the SQLite store: a cancelled task must never be re-queued (the queue refuses to claim it)
                c.execute("UPDATE tasks SET state='cancelled', lease_expires=NULL, updated=%s WHERE id=%s", (now, tid)); self._ev(c, tid, "cancelled", fence); return "cancelled"
            c.execute("UPDATE tasks SET state='queued', infra=infra+1, attempt=GREATEST(attempt-1,0), lease_owner=NULL, lease_expires=NULL, not_before=%s, failure=%s, updated=%s WHERE id=%s", (now + delay, str(reason)[:2000], now, tid)); self._ev(c, tid, "released", fence, detail={"reason": str(reason)[:2000]})

    def purge(self, ids):
        """Delete FINISHED tasks and everything recorded for them (retention / erasure). Live tasks are never touched."""
        n = 0
        with self.tx() as c:
            for tid in ids:
                if c.execute("SELECT 1 FROM tasks WHERE id=%s AND state IN ('completed','failed','cancelled')", (tid,)).fetchone() is None: continue
                for t in ("events", "checkpoints", "evidence", "outputs"): c.execute(f"DELETE FROM {t} WHERE task_id=%s", (tid,))
                c.execute("DELETE FROM tasks WHERE id=%s", (tid,)); n += 1
        return n

    def cancel(self, tid):
        with self.tx() as c:
            r = c.execute("SELECT state FROM tasks WHERE id=%s FOR UPDATE", (tid,)).fetchone()
            if r is None or r["state"] in TERMINAL: return r["state"] if r else None
            if r["state"] in ("queued", "needs_approval"): c.execute("UPDATE tasks SET state='cancelled', cancel_requested=1, updated=%s WHERE id=%s", (self.clock(), tid)); self._ev(c, tid, "cancelled"); return "cancelled"
            c.execute("UPDATE tasks SET cancel_requested=1, updated=%s WHERE id=%s", (self.clock(), tid)); self._ev(c, tid, "cancel_requested"); return "cancelling"

    def reap(self):
        out = []
        with self.tx() as c:
            now = self.clock()
            for r in c.execute("SELECT * FROM tasks WHERE state IN ('claimed','running','validating') AND lease_expires<%s FOR UPDATE SKIP LOCKED", (now,)).fetchall():
                self._ev(c, r["id"], "lease_expired", r["fence"], r["lease_owner"], r["lease_node"], {"phase": r["phase"], "attempt": r["attempt"]})
                if r["cancel_requested"]: st = "cancelled"; c.execute("UPDATE tasks SET state='cancelled', lease_expires=NULL, updated=%s WHERE id=%s", (now, r["id"]))
                elif r["attempt"] >= r["max_attempts"]: st = "failed"; c.execute("UPDATE tasks SET state='failed', failure=COALESCE(failure,'')||' lease expired on final attempt', lease_expires=NULL, updated=%s WHERE id=%s", (now, r["id"]))
                else: st = "queued"; c.execute("UPDATE tasks SET state='queued', lease_owner=NULL, lease_expires=NULL, not_before=0, updated=%s WHERE id=%s", (now, r["id"]))
                out.append((r["id"], st))
        return out

    # ---- tenancy / nodes / introspection
    def tenant_set(self, tenant, weight=1.0, max_active=None, max_queued=None):
        with self.tx() as c: c.execute("INSERT INTO tenants VALUES(%s,%s,%s,%s) ON CONFLICT(tenant) DO UPDATE SET weight=EXCLUDED.weight, max_active=EXCLUDED.max_active, max_queued=EXCLUDED.max_queued", (str(tenant), float(weight), max_active, max_queued))
    def usage_of(self, tenant):
        r = self._read(lambda c: c.execute("SELECT * FROM usage WHERE tenant=%s", (str(tenant),)).fetchone()); return dict(r) if r else {"tenant": str(tenant), "submitted": 0, "claims": 0, "completed": 0, "failed": 0, "lease_seconds": 0.0, "quota_rejections": 0}
    def node_report(self, node, capacity=None, cpu=None, mem_mb=None, labels=None):
        with self.tx() as c: c.execute("INSERT INTO nodes VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(node) DO UPDATE SET capacity=EXCLUDED.capacity, cpu=EXCLUDED.cpu, mem_mb=EXCLUDED.mem_mb, labels=EXCLUDED.labels, reported=EXCLUDED.reported", (str(node), capacity, cpu, mem_mb, json.dumps(labels or {}), self.clock()))
    def oldest_queued(self): return self._read(lambda c: c.execute("SELECT MIN(created) AS m FROM tasks WHERE state='queued'").fetchone()["m"])
    def counts(self): return self._read(lambda c: {r["state"]: r["n"] for r in c.execute("SELECT state, COUNT(*) AS n FROM tasks GROUP BY state")})
    def counts_for(self, tenant): return self._read(lambda c: {r["state"]: r["n"] for r in c.execute("SELECT state, COUNT(*) AS n FROM tasks WHERE tenant=%s GROUP BY state", (str(tenant),))})
    def get_for(self, tenant, tid):
        t = self.get(tid); return t if t and t["tenant"] == str(tenant) else None

    def audit(self):
        """Invariant violations (should be empty): more than one commit per task, completed without a commit, commit on a non-completed task."""
        return self._read(self._audit)
    def _audit(self, c):
        v = []
        v += [f"task {r['task_id']} has {r['n']} commits" for r in c.execute("SELECT task_id, COUNT(*) AS n FROM events WHERE kind='commit' GROUP BY task_id HAVING COUNT(*)>1")]
        v += [f"task {r['id']} completed without commit" for r in c.execute("SELECT t.id FROM tasks t WHERE t.state='completed' AND NOT EXISTS (SELECT 1 FROM events e WHERE e.task_id=t.id AND e.kind='commit')")]
        v += [f"task {r['id']} has a commit but state {r['state']}" for r in c.execute("SELECT t.id, t.state FROM tasks t WHERE t.state<>'completed' AND EXISTS (SELECT 1 FROM events e WHERE e.task_id=t.id AND e.kind='commit')")]
        return v

    # ---- parity with Store for what Board needs
    def hold(self, tid, fence, reason):
        with self.tx() as c:
            self._own(c, tid, fence, ACTIVE); c.execute("UPDATE tasks SET state='needs_approval', failure=%s, lease_expires=NULL, updated=%s WHERE id=%s", (str(reason)[:2000], self.clock(), tid)); self._ev(c, tid, "needs_approval", fence, detail={"reason": str(reason)[:500]})

    def cancelled(self, tid, fence):
        with self.tx() as c:
            self._own(c, tid, fence, ACTIVE); c.execute("UPDATE tasks SET state='cancelled', lease_expires=NULL, updated=%s WHERE id=%s", (self.clock(), tid)); self._ev(c, tid, "cancelled", fence)

    def approve(self, tid, resolution="retry"):
        with self.tx() as c:
            r = c.execute("SELECT state,attempt,checkpoint FROM tasks WHERE id=%s FOR UPDATE", (tid,)).fetchone()
            if r is None or r["state"] != "needs_approval": return False
            checkpoint = dict(r['checkpoint'] or {})
            checkpoint['owner_approval'] = {'attempt': r['attempt'], 'resolution': resolution}
            c.execute("UPDATE tasks SET state='queued', not_before=0, updated=%s,checkpoint=%s WHERE id=%s", (self.clock(), json.dumps(checkpoint), tid)); self._ev(c, tid, "approved", detail={"resolution": resolution}); return True

    def history(self, tid):
        def rows(c):
            out = []
            for r in c.execute("SELECT * FROM events WHERE task_id=%s ORDER BY id", (tid,)):
                d = dict(r); d["detail"] = None if d.get("detail") is None else json.dumps(d["detail"]); out.append(d)      # SQLite parity: detail is a JSON string
            return out
        return self._read(rows)

    def tenant_of(self, tid):
        r = self._read(lambda c: c.execute("SELECT tenant FROM tasks WHERE id=%s", (tid,)).fetchone()); return r["tenant"] if r else None
