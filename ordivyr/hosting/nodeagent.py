"""NodeAgent: ONE lease holder per worker node. Local workers talk to a Store-compatible `NodeStore`; the node talks to the coordinator.

Aggregates (the coordinator sees one client per node, not one per worker):
  claiming   : a single claim_many sized to free capacity feeds every local worker from a small prefetch buffer
  heartbeats : a single heartbeat_many for every lease the node holds (workers' own heartbeats are answered locally)
  capacity   : node_report(capacity) so the coordinator never hands this node more than it can run
  health     : a worker silent for `worker_timeout` has its leases released upstream at once (fast recovery), logged as a recovery event
Lease safety is unchanged: tokens (fences) come from the coordinator and every state-changing call is forwarded to it, which still checks the fence. A task whose lease
the coordinator reports stale, or whose renewal cannot be proven for > ttl, is marked lost here and local workers see StaleLease on their next heartbeat/commit attempt.
Prefetched-but-unhanded tasks are real leases (renewed like any other) and are released if the node shuts down.
"""
from __future__ import annotations
import threading, time
from collections import deque
from .. import durable as D
from ..durable_net import RemoteError

PASS_THROUGH = ("begin", "checkpoint", "apply", "record_output", "add_evidence", "evidence", "op_begin", "op_resolve", "op_commit", "get")


class NodeStore:
    def __init__(self, upstream, node, capacity=32, ttl=15.0, kinds=None, worker_timeout=None, report_every=10.0, log=lambda *a: None, clock=time.time, prefetch=32, longpoll=2.0, idle_poll=0.25, sync=False):
        self.up, self.node, self.capacity, self.ttl, self.kinds, self.log, self.clock = upstream, node, int(capacity), float(ttl), kinds, log, clock
        self.worker_timeout = worker_timeout or 3 * ttl; self.report_every = report_every; self.prefetch, self.longpoll, self.idle_poll, self.sync = prefetch, longpoll, idle_poll, sync; self.cv = threading.Condition()
        self.buf = deque(); self.held = {}; self.workers = {}; self.events = []; self.lk = threading.RLock(); self.stop = threading.Event(); self.t = None
        self.stats = {"upstream_claims": 0, "upstream_heartbeats": 0, "local_heartbeats": 0, "released_for_dead_worker": 0, "lost": 0}
        self.agent = f"node:{node}"

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        self.t = threading.Thread(target=self._loop, daemon=True, name=f"nodeagent-{self.node}"); self.t.start()
        self.pf = threading.Thread(target=self._prefetch_loop, daemon=True, name=f"nodeagent-prefetch-{self.node}"); self.pf.start(); return self
    def close(self):
        self.stop.set()
        with self.cv: self.cv.notify_all()
        if getattr(self, "pf", None): self.pf.join(timeout=self.longpoll + 3)
        with self.lk: pending, self.buf = list(self.buf), deque()
        for t in pending:
            try: self.up.release(t["id"], t["fence"], "node shutting down", 0.0)
            except Exception: pass
            self.held.pop(t["id"], None)
    def _event(self, kind, **kw): self.events.append({"t": self.clock(), "kind": kind, **kw}); self.log(kind, kw)

    def _loop(self):
        last_rep = 0.0
        while not self.stop.wait(self.ttl / 3.0):
            try: self.beat()
            except Exception as e: self.log("nodeagent-loop-error", repr(e))
            if self.clock() - last_rep >= self.report_every:
                last_rep = self.clock()
                try: self.up.node_report(self.node, self.capacity)
                except Exception: pass
            self.sweep()

    def beat(self):
        """One upstream heartbeat_many for everything the node holds."""
        with self.lk: items = [(tid, h["fence"]) for tid, h in self.held.items()]
        if not items: return
        now = self.clock()
        try: self.stats["upstream_heartbeats"] += 1; res = self.up.heartbeat_many(items, self.ttl)
        except RemoteError:
            with self.lk:
                for tid, _ in items:
                    h = self.held.get(tid)
                    if h and now - h["ok"] > self.ttl: h["lost"] = True; self.stats["lost"] += 1
            return
        with self.lk:
            for tid, _ in items:
                h = self.held.get(tid)
                if not h: continue
                v = res.get(tid, "stale")
                if v == "stale":
                    if not h["lost"]: self.stats["lost"] += 1
                    h["lost"] = True
                else:
                    h["ok"] = now
                    if v == "cancel": h["cancel"] = True

    def sweep(self):
        """Release leases whose worker went silent: the task is requeued now instead of after the full lease timeout."""
        now = self.clock(); dead = []
        with self.lk:
            for tid, h in list(self.held.items()):
                if h["worker"] is not None and now - self.workers.get(h["worker"], now) > self.worker_timeout and not h["lost"]: dead.append((tid, h["fence"], h["worker"]))
        for tid, fence, w in dead:
            try: self.up.release(tid, fence, f"worker {w} on {self.node} stopped responding", 0.0)
            except (D.StaleLease, RemoteError): pass
            with self.lk: self.held.pop(tid, None)
            self.stats["released_for_dead_worker"] += 1; self._event("worker-lost", task=tid, worker=w)

    # ------------------------------------------------------------------ worker-facing store API
    def _seen(self, worker):
        with self.lk: self.workers[worker] = self.clock()

    def _take(self, ts):
        with self.lk:
            for t in ts: self.held[t["id"]] = {"fence": t["fence"], "worker": None, "ok": self.clock(), "lost": False, "cancel": False}; self.buf.append(t)
        with self.cv: self.cv.notify_all()

    def _refill(self, want, wait_s=0.0):
        """One upstream claim sized to free capacity (used by the prefetcher, and directly by tests)."""
        with self.lk: room = self.capacity - len(self.held)
        n = min(room, max(want, 1))
        if n <= 0: return 0
        self.stats["upstream_claims"] += 1
        ts = self.up.claim_many_wait(self.agent, self.node, self.ttl, self.kinds, n, None, wait_s) if wait_s and hasattr(self.up, "claim_many_wait") else self.up.claim_many(self.agent, self.node, self.ttl, self.kinds, n)
        self._take(ts); return len(ts)

    def _prefetch_loop(self):
        """The only thing that asks the coordinator for work: one outstanding long-poll sized to free capacity. Local workers never trigger upstream claims, so 100 idle
        workers cost the coordinator one pending request, not 100 polls."""
        while not self.stop.is_set():
            try:
                with self.lk: free = self.capacity - len(self.held)
                if free <= 0: self.stop.wait(0.05); continue
                if self._refill(min(free, self.prefetch), self.longpoll) == 0 and not hasattr(self.up, "claim_many_wait"): self.stop.wait(self.idle_poll)
            except RemoteError: self.stop.wait(1.0)
            except Exception as e: self.log("prefetch-error", repr(e)); self.stop.wait(1.0)

    def claim_many(self, worker, node="main", ttl=15.0, kinds=None, limit=16, tenants=None, _wait=0.0):
        self._seen(worker); end = self.clock() + _wait
        if self.sync and len(self.buf) < limit:                       # deterministic single-threaded mode (tests / embedded use without start()): refill inline
            try: self._refill(limit - len(self.buf))
            except RemoteError: pass
        while True:
            out = []
            with self.lk:
                keep = deque()
                while self.buf and len(out) < limit:
                    t = self.buf.popleft()
                    if (kinds and t["kind"] not in kinds) or (tenants and t.get("tenant") not in tenants): keep.append(t); continue
                    if self.held.get(t["id"], {}).get("lost"): continue
                    self.held[t["id"]]["worker"] = worker; out.append(t)
                self.buf.extendleft(reversed(keep))
            if out or self.clock() >= end or self.stop.is_set(): break
            with self.cv: self.cv.wait(min(0.5, max(0.0, end - self.clock())))
        return out

    def claim(self, worker, node="main", ttl=15.0, kinds=None, tenants=None):
        r = self.claim_many(worker, node, ttl, kinds, 1, tenants); return r[0] if r else None

    def claim_many_wait(self, worker, node="main", ttl=15.0, kinds=None, limit=16, tenants=None, wait_s=0.0):
        return self.claim_many(worker, node, ttl, kinds, limit, tenants, _wait=wait_s)

    def _check(self, tid, fence):
        with self.lk:
            h = self.held.get(tid)
            if h is None or h["fence"] != fence or h["lost"]: raise D.StaleLease(f"task {tid}: lease not held by node {self.node}")
            if h["worker"] is not None: self.workers[h["worker"]] = self.clock()
            return h

    def heartbeat(self, tid, fence, ttl=15.0):
        h = self._check(tid, fence); self.stats["local_heartbeats"] += 1; return "cancel" if h["cancel"] else "ok"

    def heartbeat_many(self, leases, ttl=15.0):
        out = {}
        for tid, fence in leases:
            try: out[tid] = self.heartbeat(tid, fence, ttl)
            except D.StaleLease: out[tid] = "stale"
        return out

    def _done(self, tid): 
        with self.lk: self.held.pop(tid, None)

    def complete(self, tid, fence, result, promote=None):
        self._check(tid, fence)
        try: return self.up.complete(tid, fence, result) if promote is None else self.up.complete(tid, fence, result, promote=promote)
        except D.StaleLease: self._done(tid); raise
        finally:
            with self.lk: self.held.pop(tid, None)

    def _terminal(name):
        def f(self, tid, fence, *a, **k):
            self._check(tid, fence)
            try: return getattr(self.up, name)(tid, fence, *a, **k)
            finally: self._done(tid)
        f.__name__ = name; return f
    fail = _terminal("fail"); release = _terminal("release"); hold = _terminal("hold"); cancelled = _terminal("cancelled")

    def __getattr__(self, name):
        if name in PASS_THROUGH:
            def f(tid, *a, **k):
                if name != "get":
                    fence = a[0] if a else k.get("fence"); self._check(tid, fence)
                return getattr(self.up, name)(tid, *a, **k)
            return f
        raise AttributeError(name)

    def effect(self, tid, fence, op_key, do, reconcile=None): return D.run_effect(self, tid, fence, op_key, do, reconcile)
    def counts(self): return self.up.counts()
    def cap(self): return self.up.cap()
