"""Useful-work benchmark: real tasks through the real durable stack, validated INDEPENDENTLY, legacy vs optimized worker paths.

  python -m ordivyr.hosting.workbench --tasks 1000 --procs 4 --threads 25 --mode optimized|legacy --think 0.5 [--transport http|embedded] [--out F.json]

Each task is a `compute` task (iterated SHA-256, plus an optional `think` wait that stands in for model latency - synthetic, labelled in the output). A task counts as
VALIDATED only if the harness recomputes the digest itself from the payload and it equals the committed result, the task has exactly one commit event, and a clean audit().
Concurrency = procs x threads. Worker processes are real OS processes (so CPU/RSS are attributable); the coordinator + store live in this process.
  legacy    : one claim per task, one heartbeat thread + RPC per task, one RPC per write, connect-per-call HTTP        (the pre-P0 behaviour, kept for A/B)
  optimized : claim_many sized to free slots, one shared heartbeat_many, writes batched into one fenced tx, keep-alive  (P0)
Measured quantities are reported as measured; nothing is extrapolated. Registered / active-lease / executing / validated-complete are reported separately.
"""
from __future__ import annotations
import argparse, hashlib, json, os, resource, subprocess, sys, tempfile, threading, time
from pathlib import Path
from .. import durable as D
from ..durable_net import Coordinator, RemoteStore
from .bench import pct


def expect(seed, rounds):
    h = str(seed).encode()
    for _ in range(int(rounds)): h = hashlib.sha256(h).digest()
    return h.hex()


def worker_main(a):
    from .. import durable_worker as W
    store = RemoteStore(a.url, a.token, keepalive=(a.mode == "optimized"), timeout=30) if a.url else D.Store(a.db)
    stop = threading.Event()
    import signal; signal.signal(signal.SIGTERM, lambda *_: stop.set())
    if a.mode == "optimized": W.serve_pool(store, f"w{os.getpid()}", "main", a.ws, a.threads, a.ttl, ["compute"], stop)
    else:
        ts = [threading.Thread(target=W.serve, args=(store, f"w{os.getpid()}-{i}", "main", a.ws, a.ttl, ["compute"], stop), kwargs={"poll": 0.1}, daemon=True) for i in range(a.threads)]
        for t in ts: t.start()
        stop.wait()
    return 0


def run(a):
    d = Path(tempfile.mkdtemp(prefix="ordwb-")); st = D.Store(d / "q.db"); coord = Coordinator(st, "t").start() if a.transport == "http" else None; ws = d / "ws"; ws.mkdir()
    rounds, think = a.rounds, a.think; seeds = {}
    t_sub = time.time()
    for i in range(a.tasks):
        tid = st.submit("compute", {"seed": f"s{i}", "rounds": rounds, "think_s": think}, f"w{i}"); seeds[tid] = f"s{i}"
    sub_s = time.time() - t_sub; tx0 = st.tx_count; rpc0 = coord.rpcs if coord else 0; cpu0 = time.process_time(); t0 = time.time()
    cmd = [sys.executable, "-m", "ordivyr.hosting.workbench", "--_worker", "--mode", a.mode, "--threads", str(a.threads), "--ws", str(ws), "--ttl", str(a.ttl)] + (["--url", f"http://127.0.0.1:{coord.port}", "--token", "t"] if coord else ["--db", str(d / "q.db")])
    procs = [subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(a.procs)]
    peak_active = peak_exec = 0; c = st._conn(); deadline = t0 + a.timeout
    while time.time() < deadline:
        row = c.execute("SELECT SUM(state IN ('claimed','running','validating')), SUM(state='running'), SUM(state='completed') FROM tasks").fetchone()
        peak_active = max(peak_active, row[0] or 0); peak_exec = max(peak_exec, row[1] or 0)
        if (row[2] or 0) >= a.tasks: break
        time.sleep(0.2)
    wall = time.time() - t0; cpu_coord = time.process_time() - cpu0; rpcs = (coord.rpcs - rpc0) if coord else None; txs = st.tx_count - tx0
    for p in procs: p.terminate()
    for p in procs:
        try: p.wait(15)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
    ru = resource.getrusage(resource.RUSAGE_CHILDREN); cpu_workers = ru.ru_utime + ru.ru_stime
    rows = {r["id"]: dict(r) for r in c.execute("SELECT id, state, result, created, updated FROM tasks")}
    commits = {r[0]: r[1] for r in c.execute("SELECT task_id, COUNT(*) FROM events WHERE kind='commit' GROUP BY task_id")}
    valid = 0; bad = []; lat = []
    for tid, seed in seeds.items():
        r = rows[tid]
        if r["state"] != "completed": continue
        ok = json.loads(r["result"]).get("digest") == expect(seed, rounds) and commits.get(tid) == 1
        if ok: valid += 1; lat.append(r["updated"] - r["created"])
        else: bad.append(tid)
    viol = st.audit(); dup = sum(1 for v in commits.values() if v > 1)
    res = {"mode": a.mode, "transport": a.transport, "tasks": a.tasks, "procs": a.procs, "threads_per_proc": a.threads, "concurrency": a.procs * a.threads, "think_s_synthetic_wait": think, "rounds": rounds,
           "registered": a.tasks, "peak_active_leases": int(peak_active), "peak_executing": int(peak_exec), "validated_complete": valid, "wall_s": round(wall, 2),
           "validated_tasks_per_s": round(valid / wall, 2) if wall else None, "latency_ms": {"p50": pct(lat, 50), "p95": pct(lat, 95), "p99": pct(lat, 99)},
           "db_write_tx_per_task": round(txs / a.tasks, 2), "coordinator_rpcs_per_task": round(rpcs / a.tasks, 2) if rpcs is not None else None,
           "coordinator_cpu_ms_per_task": round(cpu_coord * 1000 / a.tasks, 2), "worker_cpu_ms_per_task": round(cpu_workers * 1000 / a.tasks, 2),
           "worker_peak_rss_mb_largest_proc": round(ru.ru_maxrss / 1024, 1), "coordinator_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
           "duplicate_commits": dup, "invalid_results": len(bad), "audit_violations": len(viol), "passed": valid == a.tasks and not dup and not viol and not bad, "submit_s": round(sub_s, 2)}
    if coord: coord.stop()
    return res


def main(argv=None):
    p = argparse.ArgumentParser(); p.add_argument("--tasks", type=int, default=200); p.add_argument("--procs", type=int, default=4); p.add_argument("--threads", type=int, default=25)
    p.add_argument("--mode", choices=("legacy", "optimized"), default="optimized"); p.add_argument("--transport", choices=("http", "embedded"), default="http")
    p.add_argument("--rounds", type=int, default=2000); p.add_argument("--think", type=float, default=0.5); p.add_argument("--ttl", type=float, default=6.0); p.add_argument("--timeout", type=float, default=300)
    p.add_argument("--out"); p.add_argument("--_worker", action="store_true"); p.add_argument("--url"); p.add_argument("--token"); p.add_argument("--db"); p.add_argument("--ws"); a = p.parse_args(argv)
    if a._worker: return worker_main(a)
    r = run(a); print(json.dumps(r))
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True); prev = json.loads(Path(a.out).read_text()) if Path(a.out).exists() else []
        Path(a.out).write_text(json.dumps(prev + [r], indent=1))
    return 0 if r["passed"] else 1


if __name__ == "__main__": sys.exit(main())
