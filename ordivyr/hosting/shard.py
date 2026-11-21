"""Coordinator sharding: stable tenant -> shard routing over several independent coordinators (each its own durable Store), presented to workers as ONE store.

* Routing is deterministic and persistent: a tenant's shard is chosen once with SHA-256 (never Python's per-process randomized hash()), written to the shard map
  (atomic replace + fsync) BEFORE the first task is submitted, and never changes implicitly: adding shards does not move existing tenants.
* Task ids are global: gid = local_id * 1024 + shard. Fences are per shard, so (gid, fence) is unique cluster-wide and every fenced call is routed to the shard that issued it.
* A dead shard degrades only its own tenants: claims skip it (with a cool-down), its leases report 'unknown' (not 'stale'), and when it returns its durable state is intact.
* migrate_tenant moves a tenant's QUEUED work to another shard with no duplicate execution (see the method for the exact protocol and its crash behaviour).
"""
from __future__ import annotations
import hashlib, json, os, tempfile, threading, time
from pathlib import Path
from .. import durable as D
from ..durable_net import RemoteError

SHARD_BITS = 1024


def stable_hash(tenant, n): return int(hashlib.sha256(str(tenant).encode()).hexdigest(), 16) % n


class ShardMap:
    def __init__(self, path, n=None):
        self.path = Path(path); self.lock = threading.Lock()
        if self.path.exists(): self.d = json.loads(self.path.read_text())
        else:
            if not n: raise ValueError("a new shard map needs the number of shards")
            self.d = {"n": int(n), "tenants": {}}; self._save()
        if n and int(n) < self.d["n"]: raise ValueError("cannot shrink the shard count while tenants are mapped")
        if n and int(n) > self.d["n"]: self.d["n"] = int(n); self._save()                         # growing is safe: existing tenants keep their shard
    def _save(self):
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".shardmap"); 
        with os.fdopen(fd, "w") as f: f.write(json.dumps(self.d, sort_keys=True)); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, self.path)
    @property
    def n(self): return self.d["n"]
    def shard_of(self, tenant):
        with self.lock:
            t = str(tenant)
            if t not in self.d["tenants"]: self.d["tenants"][t] = stable_hash(t, self.d["n"]); self._save()
            return self.d["tenants"][t]
    def assign(self, tenant, shard):
        with self.lock: self.d["tenants"][str(tenant)] = int(shard); self._save()


class ShardedStore:
    """Store-compatible facade. `shards` = list of Store/RemoteStore (index = shard number)."""
    FENCED = ("heartbeat", "begin", "checkpoint", "apply", "record_output", "add_evidence", "evidence", "complete", "fail", "release", "hold", "cancelled", "op_begin", "op_resolve", "op_commit", "get", "cancel", "operations", "history")

    def __init__(self, shards, smap, cooldown=2.0):
        if len(shards) > SHARD_BITS: raise ValueError("too many shards")
        self.shards, self.map, self.cooldown = list(shards), smap, cooldown; self._down = {}; self._rr = 0; self._lk = threading.Lock(); self.skipped = 0

    # ---- ids
    @staticmethod
    def gid(lid, shard): return lid * SHARD_BITS + shard
    @staticmethod
    def split(gid): return gid // SHARD_BITS, gid % SHARD_BITS
    def _out(self, t, shard):
        if t is None: return None
        t = dict(t); t["lid"] = t["id"]; t["shard"] = shard; t["id"] = self.gid(t["id"], shard); return t

    def _up(self, shard):
        with self._lk: return self._down.get(shard, 0) <= time.time()
    def _mark_down(self, shard):
        with self._lk: self._down[shard] = time.time() + self.cooldown

    # ---- tenant API
    def submit(self, kind, payload, idem_key=None, max_attempts=3, priority=0, tenant="default"):
        sh = self.map.shard_of(tenant); lid = self.shards[sh].submit(kind, payload, idem_key, max_attempts, priority, tenant=tenant); return self.gid(lid, sh)

    def counts(self):
        out = {}
        for i, s in enumerate(self.shards):
            try:
                for k, v in s.counts().items(): out[k] = out.get(k, 0) + v
            except RemoteError: pass
        return out

    # ---- worker API
    def _order(self):
        with self._lk: start = self._rr; self._rr = (self._rr + 1) % max(1, len(self.shards))
        return [(start + i) % len(self.shards) for i in range(len(self.shards))]

    def claim_many(self, worker, node="main", ttl=15.0, kinds=None, limit=16, tenants=None):
        out = []
        for i in self._order():
            if len(out) >= limit: break
            if not self._up(i): self.skipped += 1; continue
            try: ts = self.shards[i].claim_many(worker, node, ttl, kinds, limit - len(out), tenants)
            except RemoteError: self._mark_down(i); continue
            out += [self._out(t, i) for t in ts]
        return out

    def claim(self, worker, node="main", ttl=15.0, kinds=None, tenants=None):
        r = self.claim_many(worker, node, ttl, kinds, 1, tenants); return r[0] if r else None

    def claim_many_wait(self, worker, node="main", ttl=15.0, kinds=None, limit=16, tenants=None, wait_s=0.0, slice_s=0.25):
        """One shard: a true long-poll. Several: poll all, then long-poll each shard for a short slice in turn (a result from a slice is returned immediately), so wake-up latency is
        bounded by shards x slice. (Waiting on all shards concurrently could lease a task nobody receives.)"""
        end = time.time() + wait_s
        while True:
            ts = self.claim_many(worker, node, ttl, kinds, limit, tenants)
            if ts or time.time() >= end: return ts
            for i in self._order():
                if not self._up(i): continue
                left = end - time.time()
                if left <= 0: return []
                try: r = self.shards[i].claim_many_wait(worker, node, ttl, kinds, limit, tenants, min(left, slice_s if len(self.shards) > 1 else left))
                except RemoteError: self._mark_down(i); continue
                if r: return [self._out(t, i) for t in r]
            if len(self.shards) == 1: continue

    def heartbeat_many(self, leases, ttl=15.0):
        by = {}
        for gid, fence in leases: lid, sh = self.split(gid); by.setdefault(sh, []).append((lid, fence, gid))
        out = {}
        for sh, items in by.items():
            try: r = self.shards[sh].heartbeat_many([(l, f) for l, f, _ in items], ttl)
            except RemoteError:
                self._mark_down(sh)
                for _, _, g in items: out[g] = "unknown"
                continue
            for l, f, g in items: out[g] = r.get(l, "stale")
        return out

    def __getattr__(self, name):
        if name not in self.FENCED: raise AttributeError(name)
        def call(gid, *a, **k):
            lid, sh = self.split(gid); r = getattr(self.shards[sh], name)(lid, *a, **k)
            return self._out(r, sh) if name in ("get",) else r
        return call

    def effect(self, tid, fence, op_key, do, reconcile=None): return D.run_effect(self, tid, fence, op_key, do, reconcile)

    # ---- tenant migration
    def migrate_tenant(self, tenant, to_shard, drain_s=30.0, poll=0.1):
        """Move a tenant's QUEUED tasks to another shard. Protocol (each step idempotent, ordered so a crash can never run a task twice):
        1 freeze the tenant on the source (no new claims)  2 wait for its in-flight leases to finish or expire (abort + unfreeze on timeout)
        3 copy queued tasks to the destination with deterministic idempotency keys (a re-run returns the same ids)  4 retire the source copies (cancelled, NO commit event)
        5 flip the shard map.  Crash before 5: tenant is still routed to the (frozen) source, the destination has harmless idempotent copies; re-running resumes.
        Crash between 3 and 4: the source copies are frozen out of claiming; re-running retires them. Completed/failed history stays on the source and remains readable by gid."""
        src = self.map.shard_of(tenant)
        if src == to_shard: return {"moved": 0, "from": src, "to": to_shard}
        s, d = self.shards[src], self.shards[to_shard]; prev = s.freeze_tenant(tenant); end = time.time() + drain_s
        while s.active_of(tenant):
            if hasattr(s, "reap"): s.reap()
            if time.time() > end:
                s.tenant_set(tenant, **(prev or {"weight": 1.0, "max_active": None, "max_queued": None})); raise TimeoutError(f"tenant {tenant!r} still has leases on shard {src}; migration aborted and unfrozen")
            time.sleep(poll)
        rows = s.export_queued(tenant); moved = 0
        for r in rows:
            d.submit(r["kind"], r["payload"], idem_key=r["idem_key"] or f"mig:{src}:{r['id']}", max_attempts=r["max_attempts"], priority=r["priority"], tenant=tenant); moved += 1
        s.retire([r["id"] for r in rows], f"migrated to shard {to_shard}")
        self.map.assign(tenant, to_shard); return {"moved": moved, "from": src, "to": to_shard}
