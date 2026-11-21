"""Durable-queue write-amplification benchmark: commits (= WAL fsyncs under synchronous=FULL) and wall time per task lifecycle.

python -m ordivyr.bench_durable [--tasks 200] [--workers 4] [--json]
Counts COMMIT statements through a sqlite trace hook, so it measures what the store actually does, not what it claims.
"""
from __future__ import annotations
import argparse, json, os, tempfile, threading, time
from pathlib import Path
from . import durable as D


def run(tasks=200, workers=4, steps=3, batch=False):
    d = Path(tempfile.mkdtemp(prefix="ordivyr-bench-")); s = D.Store(d / "q.db"); commits = [0]; lock = threading.Lock()
    orig = s._conn; seen = set()
    def counted():
        c = orig()
        if id(c) not in seen:
            def tr(sql):
                if sql.strip().upper().startswith("COMMIT"):
                    with lock: commits[0] += 1
            c.set_trace_callback(tr); seen.add(id(c))
        return c
    s._conn = counted
    t0 = time.perf_counter()
    for i in range(tasks): s.submit("bench", {"i": i}, idem_key=f"k{i}")
    submit_commits = commits[0]; done = [0]

    def worker(w):
        while True:
            got = s.claim_many(f"w{w}", limit=1)
            if not got:
                with lock:
                    if done[0] >= tasks: return
                time.sleep(0.001); continue
            for t in got:
                tid, fence = t["id"], t["fence"]
                s.begin(tid, fence)
                for k in range(steps):
                    s.heartbeat(tid, fence)
                    if batch: s.apply(tid, fence, [{"op": "output", "tool": "tool", "args": {"k": k}, "output": "out"}, {"op": "checkpoint", "phase": "running", "data": {"step": k}}])
                    else: s.record_output(tid, fence, "tool", {"k": k}, "out"); s.checkpoint(tid, fence, "running", {"step": k})
                s.add_evidence(tid, fence, "tests", True, "ok"); s.complete(tid, fence, {"ok": True})
                with lock: done[0] += 1
    ths = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    [t.start() for t in ths]; [t.join() for t in ths]
    dt = time.perf_counter() - t0
    return {"tasks": tasks, "workers": workers, "steps": steps, "seconds": round(dt, 3), "tasks_per_s": round(tasks / dt, 1),
            "commits_total": commits[0], "commits_per_task": round(commits[0] / tasks, 2), "submit_commits_per_task": round(submit_commits / tasks, 2)}


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--tasks", type=int, default=200); ap.add_argument("--workers", type=int, default=4); ap.add_argument("--steps", type=int, default=3)
    ap.add_argument("--batched", action="store_true", help="output+checkpoint in one fenced transaction (Store.apply)"); ap.add_argument("--json", action="store_true"); a = ap.parse_args(argv)
    r = run(a.tasks, a.workers, a.steps, a.batched); print(json.dumps(r) if a.json else r)


if __name__ == "__main__":
    main()
