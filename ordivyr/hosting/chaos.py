"""Failure-injection scenarios for the distributed execution stack, runnable and reproducible on one machine.

  python -m ordivyr.hosting.chaos --scenario coordinator_crash,partition,... [--tasks N] [--out FILE]

Every scenario uses REAL processes (coordinator, worker nodes), the real durable Store on disk, and the independent validator from workbench (the harness recomputes every
result). A scenario PASSES only if: every task is completed exactly once with the right digest, audit() is clean, and scenario-specific recovery bounds hold. Reported:
recovery times, stale-lease rejections (zombie commits that the fence refused), duplicates, per-tenant fairness. Nothing is simulated that can be done for real, and
what cannot (real WAN partitions, cloud disks, many hosts) is listed in docs/scalability/COMMERCIAL_SCALE.md as unverified.
"""
from __future__ import annotations
import argparse, json, os, signal, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path
from .. import durable as D
from ..durable_net import Coordinator, RemoteStore, RemoteError
from .workbench import expect
from .bench import pct

PY = sys.executable


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def spawn(*args, **kw): return subprocess.Popen([PY, "-m", *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, **kw)
def killpg(p, sig=signal.SIGKILL):
    try: os.killpg(p.pid, sig)
    except OSError: pass
    try: p.wait(10)
    except Exception: pass


def wait(pred, t, step=0.1):
    end = time.time() + t
    while time.time() < end:
        v = pred()
        if v: return v
        time.sleep(step)
    return False


class Proxy:
    """TCP forwarder with a switch: `blackhole` makes new connections hang and kills existing ones (a network partition); `dup` replays each client request to the server twice."""
    def __init__(self, target_port, bind="127.0.0.1", target_host="127.0.0.1"):
        self.t, self.th, self.blackhole, self.srv, self.conns = target_port, target_host, False, socket.socket(), set(); self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); self.srv.bind((bind, 0)); self.srv.listen(512); self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
    def _accept(self):
        while True:
            try: c, _ = self.srv.accept()
            except OSError: return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()
    def _serve(self, c):
        if self.blackhole:
            time.sleep(30); c.close(); return
        try: u = socket.create_connection((self.th, self.t), timeout=5)
        except OSError: c.close(); return
        self.conns.update((c, u))
        def pipe(a, b):
            try:
                while not self.blackhole:
                    d = a.recv(65536)
                    if not d: break
                    b.sendall(d)
            except OSError: pass
            for x in (a, b):
                try: x.close()
                except OSError: pass
        threading.Thread(target=pipe, args=(c, u), daemon=True).start(); threading.Thread(target=pipe, args=(u, c), daemon=True).start()
    def partition(self, on):
        self.blackhole = on
        if on:
            for c in list(self.conns):
                try: c.shutdown(2); c.close()
                except OSError: pass
            self.conns.clear()
    def close(self):
        try: self.srv.close()
        except OSError: pass


class Env:
    """A coordinator process on a durable DB + helper to start worker-node processes against some URL."""
    def __init__(self, tasks, think=0.3, rounds=200, ttl=2.0, tenants=("default",), per_tenant=None):
        self.d = Path(tempfile.mkdtemp(prefix="ordchaos-")); self.db = self.d / "q.db"; self.port = free_port(); self.tok = self.d / "tok"; self.tok.write_text("t"); self.ttl = ttl
        self.st = D.Store(self.db); self.seeds = {}; self.procs = []; self.coord = None
        for ti, t in enumerate(tenants):
            for i in range(per_tenant[t] if per_tenant else tasks // len(tenants)):
                tid = self.st.submit("compute", {"seed": f"{t}-{i}", "rounds": rounds, "think_s": think}, f"{t}-{i}", tenant=t); self.seeds[tid] = (f"{t}-{i}", rounds)
    def start_coordinator(self):
        code = f"from ordivyr import durable as D; from ordivyr.durable_net import Coordinator; import time; Coordinator(D.Store({str(self.db)!r}), 't', port={self.port}, reap_every=0.5).start(); time.sleep(10**6)"
        self.coord = subprocess.Popen([PY, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True); wait(lambda: self._up(self.port), 15)
    def _up(self, port):
        try: socket.create_connection(("127.0.0.1", port), timeout=0.3).close(); return True
        except OSError: return False
    def start_node(self, name, port=None, slots=8, extra=()):
        p = spawn("ordivyr.durable_worker", "--url", f"http://127.0.0.1:{port or self.port}", "--token-file", str(self.tok), "--name", name, "--node", name, "--ws", str(self.d / "ws" / name), "--ttl", str(self.ttl), "--slots", str(slots), "--longpoll", "1.0", "--kinds", "compute", *extra)
        self.procs.append(p); return p
    def done(self): return self.st._conn().execute("SELECT COUNT(*) FROM tasks WHERE state='completed'").fetchone()[0]
    def verify(self):
        c = self.st._conn(); rows = {r["id"]: dict(r) for r in c.execute("SELECT id, state, result, tenant FROM tasks")}; commits = {r[0]: r[1] for r in c.execute("SELECT task_id, COUNT(*) FROM events WHERE kind='commit' GROUP BY task_id")}
        valid = sum(1 for t, (seed, rounds) in self.seeds.items() if rows[t]["state"] == "completed" and json.loads(rows[t]["result"]).get("digest") == expect(seed, rounds) and commits.get(t) == 1)
        stale = c.execute("SELECT COUNT(*) FROM events WHERE kind='attempt_failed' OR kind='lease_expired'").fetchone()[0]
        return {"tasks": len(self.seeds), "validated": valid, "duplicate_commits": sum(1 for v in commits.values() if v > 1), "audit_violations": len(self.st.audit()), "attempts_total": c.execute("SELECT SUM(attempt) FROM tasks").fetchone()[0], "lease_expiry_events": stale}
    def close(self):
        for p in self.procs: killpg(p)
        if self.coord: killpg(self.coord)


def finish(name, env, t0, ok, **extra):
    v = env.verify(); passed = ok and v["validated"] == v["tasks"] and not v["duplicate_commits"] and not v["audit_violations"]
    return {"scenario": name, "passed": bool(passed), "wall_s": round(time.time() - t0, 2), **v, **extra}


# ---------------------------------------------------------------- scenarios
def coordinator_crash(n=120):
    e = Env(n); t0 = time.time(); e.start_coordinator(); e.start_node("n1"); e.start_node("n2")
    wait(lambda: e.done() >= n // 4, 60); mid = e.done(); killpg(e.coord); tk = time.time(); time.sleep(3.0)               # SIGKILL mid-flight; workers keep retrying
    e.start_coordinator(); base = e.done(); rec = wait(lambda: e.done() > base, 60) and time.time() - tk; ok = wait(lambda: e.done() == n, 120)
    r = finish("coordinator_crash", e, t0, ok, completed_before_crash=mid, recovery_s_from_kill_to_first_new_completion=round(rec, 2) if rec else None); e.close(); return r


def partition(n=60):
    e = Env(n, think=0.4, ttl=1.5); t0 = time.time(); e.start_coordinator(); px = Proxy(e.port); e.start_node("far", port=px.port, slots=6, extra=("--no-self-abort",)); e.start_node("near", slots=2)
    wait(lambda: e.done() >= 10, 60); px.partition(True); tp = time.time(); time.sleep(5.0)                               # 'far' is cut off for 3x the lease; its zombies keep working
    expired = e.st._conn().execute("SELECT COUNT(*) FROM events WHERE kind='lease_expired' OR kind='requeued'").fetchone()[0]
    px.partition(False); heal = time.time(); ok = wait(lambda: e.done() == n, 120)
    r = finish("partition", e, t0, ok, partition_s=round(heal - tp, 1), recovered_s_after_heal=round(time.time() - heal, 2)); px.close(); e.close(); return r


def worker_node_loss(n=120):
    e = Env(n, think=0.5, ttl=1.5); t0 = time.time(); e.start_coordinator(); a = e.start_node("doomed", slots=10); e.start_node("survivor", slots=3)
    wait(lambda: e.st.counts().get("running", 0) + e.st.counts().get("claimed", 0) >= 8, 30); leased = e.st.counts().get("running", 0) + e.st.counts().get("claimed", 0); killpg(a); tk = time.time()
    freed = wait(lambda: e.st._conn().execute("SELECT COUNT(*) FROM tasks WHERE lease_node='doomed' AND state IN ('claimed','running','validating')").fetchone()[0] == 0, 30)      # reaper has re-queued every lease the dead node held
    requeued = time.time() - tk if freed else None; ok = wait(lambda: e.done() == n, 180)
    r = finish("worker_node_loss", e, t0, ok, leases_on_dead_node_at_kill=leased, seconds_until_dead_nodes_leases_requeued=round(requeued, 2) if requeued else None, total_recovery_s=round(time.time() - tk, 2)); e.close(); return r


def duplicate_messages(n=80):
    """Every RPC delivered twice (at-least-once transport). Safe because writes are fenced/idempotent: the second delivery is refused or returns the same answer."""
    class Dup(RemoteStore):
        def _rpc(self, m, a, k):
            r = RemoteStore._rpc(self, m, a, k)
            if m in ("submit", "complete", "begin", "apply", "heartbeat", "heartbeat_many", "fail", "release"):
                try: RemoteStore._rpc(self, m, a, k); Dup.replays += 1
                except (D.StaleLease, D.Cancelled, D.NeedsApproval): Dup.refused += 1
                except RemoteError: pass
            return r
    Dup.replays = Dup.refused = 0
    e = Env(0); t0 = time.time(); e.start_coordinator(); ds = Dup(f"http://127.0.0.1:{e.port}", "t", timeout=10)
    for i in range(n): tid = ds.submit("compute", {"seed": f"d{i}", "rounds": 100, "think_s": 0.05}, f"d{i}"); e.seeds[tid] = (f"d{i}", 100)
    from .. import durable_worker as W
    stop = threading.Event(); th = threading.Thread(target=W.serve_pool, args=(ds, "dupworker", "n", e.d / "ws"), kwargs={"slots": 6, "ttl": 3.0, "stop": stop, "longpoll": 0.5}, daemon=True); th.start()
    ok = wait(lambda: e.done() == n, 120); stop.set(); th.join(20)
    r = finish("duplicate_messages", e, t0, ok, replayed_rpcs=Dup.replays, refused_replays=Dup.refused, tasks_submitted_once=len(e.seeds) == n and e.st.counts().get("queued", 0) + sum(e.st.counts().values()) >= n); e.close(); return r


def tenant_overload(flood=3000, small=40, tenants_small=4):
    pt = {"flood": flood, **{f"small{i}": small for i in range(tenants_small)}}
    e = Env(0, think=0.2, ttl=3.0, tenants=tuple(pt), per_tenant=pt); t0 = time.time()
    e.st.tenant_set("flood", weight=1.0, max_active=None, max_queued=None)
    e.start_coordinator(); e.start_node("n1", slots=16); e.start_node("n2", slots=16)
    smalls = [t for t in e.seeds if e.st.get(t)["payload"]["seed"].startswith("small")]
    ok = wait(lambda: all(e.st.get(t)["state"] == "completed" for t in smalls), 180); t_small = time.time() - t0
    small_done_s = round(t_small, 2); flood_done_at_that_time = e.st.counts_for("flood").get("completed", 0)
    lat = [e.st.get(t)["updated"] - e.st.get(t)["created"] for t in smalls if e.st.get(t)["state"] == "completed"]
    e.st.tenant_set("flood", weight=1.0, max_active=None, max_queued=None)
    ok2 = ok and flood_done_at_that_time < flood * 0.5                                                                  # small tenants finished while most of the flood was still waiting
    for p in e.procs: pass
    r = finish("tenant_overload", e, t0, ok2 and wait(lambda: e.done() == len(e.seeds), 600), small_tenants_done_s=small_done_s, flood_completed_when_small_done=flood_done_at_that_time, flood_total=flood, small_latency_ms={"p50": pct(lat, 50), "p95": pct(lat, 95), "p99": pct(lat, 99)}); e.close(); return r


def db_lock_stall(n=60):
    """Another process holds the database write lock (BEGIN IMMEDIATE) for 4 s - a stand-in for a stalled disk/backup. Writers must wait, not fail or lose work."""
    e = Env(n, think=0.2, ttl=8.0); t0 = time.time(); e.start_coordinator(); e.start_node("n1", slots=8); wait(lambda: e.done() >= 5, 30)
    holder = subprocess.Popen([PY, "-c", f"import sqlite3,time; c=sqlite3.connect({str(e.db)!r}, isolation_level=None); c.execute('BEGIN IMMEDIATE'); time.sleep(4); c.execute('ROLLBACK')"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    holder.wait(15); ok = wait(lambda: e.done() == n, 120); integ = e.st._conn().execute("PRAGMA integrity_check").fetchone()[0]
    r = finish("db_lock_stall", e, t0, ok and integ == "ok", integrity_check=integ); e.close(); return r


def db_crash_midwrite(n=100):
    """SIGKILL the coordinator repeatedly while it is writing; synchronous=FULL + WAL must leave an intact database and lose no acknowledged commit."""
    e = Env(n, think=0.1, ttl=2.0); t0 = time.time(); e.start_coordinator(); e.start_node("n1", slots=8); acked = 0
    for _ in range(3):
        wait(lambda: e.done() > acked + 5, 60); acked = e.done(); killpg(e.coord); time.sleep(0.5)
        integ = D.Store(e.db)._conn().execute("PRAGMA integrity_check").fetchone()[0]
        if integ != "ok" or e.done() < acked: return finish("db_crash_midwrite", e, t0, False, integrity_check=integ, acked_before_kill=acked)
        e.start_coordinator()
    ok = wait(lambda: e.done() == n, 120); r = finish("db_crash_midwrite", e, t0, ok, kills=3); e.close(); return r


def lease10k(n=10000):
    from . import bench
    r = bench.level(n, transport="http", drivers=64, hold=3.0, ttl=300.0, hb_every=1.0, batch=64)
    return {"scenario": "lease10k_http", "passed": bool(r["passed"]), "kind": "synthetic leases (NOT useful work): proves coordinator can hold and heartbeat 10,000 simultaneous fenced leases", **r}


SCENARIOS = {f.__name__: f for f in (coordinator_crash, partition, worker_node_loss, duplicate_messages, tenant_overload, db_lock_stall, db_crash_midwrite, lease10k)}


def main(argv=None):
    a = argparse.ArgumentParser(); a.add_argument("--scenario", default="all"); a.add_argument("--out"); a = a.parse_args(argv)
    names = list(SCENARIOS) if a.scenario == "all" else a.scenario.split(","); res = []
    for n in names:
        try: r = SCENARIOS[n]()
        except Exception as ex: r = {"scenario": n, "passed": False, "error": f"{type(ex).__name__}: {ex}"}
        res.append(r); print(json.dumps(r), flush=True)
    if a.out: Path(a.out).parent.mkdir(parents=True, exist_ok=True); Path(a.out).write_text(json.dumps(res, indent=1))
    return 0 if all(r["passed"] for r in res) else 1


if __name__ == "__main__": sys.exit(main())
