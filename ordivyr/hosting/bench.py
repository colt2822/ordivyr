"""Scalability benchmark for the coordinator/queue layer, independent of model inference.

  python -m ordivyr.hosting.bench --agents 10,100,1000 [--transport embedded|http] [--drivers 32] [--hold 2.0] [--out FILE]

An 'agent' here is a synthetic worker holding a REAL fenced lease on a REAL task for `hold` seconds with periodic heartbeats, then committing a result - exactly the
store operations a real agent performs, with zero inference. Reported per level: submit throughput, dispatch latency (submit->claim) p50/p95/p99, heartbeat latency,
commit latency, end-to-end tasks/s, coordinator CPU seconds and peak RSS, store invariants (audit), duplicate/lost commits. A level is reported as passed ONLY if every task
committed exactly once and audit() is clean; otherwise it is reported as FAILED with the reason. Nothing is extrapolated.
"""
from __future__ import annotations
import argparse, json, resource, statistics, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .. import durable as D
from ..durable_net import Coordinator, RemoteStore


def pct(xs, q):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(len(xs) * q / 100))] * 1000, 2) if xs else None


def level(n, transport="embedded", drivers=32, hold=2.0, ttl=120.0, hb_every=1.0, batch=1):
    d = Path(tempfile.mkdtemp(prefix="ordbench-")); st = D.Store(d / "q.db"); coord = None
    if transport == "http":
        coord = Coordinator(st, "t").start(); mk = lambda: RemoteStore(f"http://127.0.0.1:{coord.port}", "t")
    else: mk = lambda: st
    cpu0 = time.process_time(); t0 = time.time(); sub_t = {}; lat_claim, lat_hb, lat_commit = [], [], []; lock = threading.Lock(); held = []; errors = []
    api = mk()
    def sub(i):
        s = time.time(); tid = api.submit("synthetic", {"i": i}, f"b{i}"); sub_t[tid] = s
    with ThreadPoolExecutor(drivers) as ex: list(ex.map(sub, range(n)))
    t_sub = time.time() - t0
    def claim_one(_):
        c = mk() if transport == "http" else st
        for _ in range(400):
            ts = c.claim_many("bw", "main", ttl, None, batch) if batch > 1 else [x for x in [c.claim("bw", "main", ttl)] if x]
            if ts: break
            time.sleep(0.01)
        else: errors.append("claim exhausted"); return
        e = time.time()
        with lock: lat_claim.extend(e - sub_t[t["id"]] for t in ts); held.extend(ts)
        for t in ts: c.begin(t["id"], t["fence"])
    t1 = time.time()
    with ThreadPoolExecutor(drivers) as ex: list(ex.map(claim_one, range(-(-n // batch))))
    t_claim = time.time() - t1; peak_concurrent = len(held)
    end_hold = time.time() + hold; sweeps = 0
    while time.time() < end_hold:                                          # all n leases are live at once; heartbeat them all, as real agents would
        def hb(chunk):
            c = mk() if transport == "http" else st; s = time.time()
            try:
                if batch > 1:
                    bad = [k for k, v in c.heartbeat_many([(t["id"], t["fence"]) for t in chunk], ttl).items() if v != "ok"]
                    if bad: errors.append("hb stale")
                else: c.heartbeat(chunk[0]["id"], chunk[0]["fence"], ttl)
            except Exception as ex_: errors.append(f"hb {type(ex_).__name__}")
            with lock: lat_hb.append((time.time() - s) / len(chunk) if False else time.time() - s)
        chunks = [held[i:i + batch] for i in range(0, len(held), batch)]
        with ThreadPoolExecutor(drivers) as ex: list(ex.map(hb, chunks))
        sweeps += 1; time.sleep(max(0, min(hb_every, end_hold - time.time())))
    def commit(t):
        c = mk() if transport == "http" else st; s = time.time()
        try: c.complete(t["id"], t["fence"], {"ok": 1})
        except Exception as ex_: errors.append(f"commit {type(ex_).__name__}")
        with lock: lat_commit.append(time.time() - s)
    t2 = time.time()
    with ThreadPoolExecutor(drivers) as ex: list(ex.map(commit, held))
    t_commit = time.time() - t2; total = time.time() - t0; counts = st.counts(); viol = st.audit()
    commits = st._conn().execute("SELECT COUNT(*) FROM events WHERE kind='commit'").fetchone()[0]; fences = {t["fence"] for t in held}
    ok = counts.get("completed") == n and commits == n and not viol and not errors and len(fences) == n
    r = {"agents": n, "transport": transport, "drivers": drivers, "passed": bool(ok), "peak_concurrent_leases": peak_concurrent, "submit_per_s": round(n / t_sub, 1), "claim_per_s": round(n / t_claim, 1), "commit_per_s": round(n / t_commit, 1),
         "dispatch_latency_ms": {"p50": pct(lat_claim, 50), "p95": pct(lat_claim, 95), "p99": pct(lat_claim, 99)}, "heartbeat_ms": {"p50": pct(lat_hb, 50), "p95": pct(lat_hb, 95), "p99": pct(lat_hb, 99), "sweeps": sweeps},
         "commit_ms": {"p50": pct(lat_commit, 50), "p95": pct(lat_commit, 95), "p99": pct(lat_commit, 99)}, "batch": batch,
         "end_to_end_s": round(total, 2), "coordinator_cpu_s": round(time.process_time() - cpu0, 2), "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1), "db_mb": round(sum(f.stat().st_size for f in d.glob("q.db*")) / 1048576, 1),
         "completed": counts.get("completed", 0), "commit_events": commits, "unique_fences": len(fences), "audit_violations": viol[:3], "errors": sorted(set(errors))[:5]}
    if coord: coord.stop()
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--agents", default="10,100,1000"); ap.add_argument("--transport", default="embedded"); ap.add_argument("--drivers", type=int, default=32); ap.add_argument("--hold", type=float, default=2.0); ap.add_argument("--batch", type=int, default=1); ap.add_argument("--out")
    a = ap.parse_args(argv); res = []
    for n in [int(x) for x in a.agents.split(",")]:
        r = level(n, a.transport, a.drivers, a.hold, batch=a.batch); res.append(r); print(json.dumps(r), flush=True)
    if a.out: Path(a.out).write_text(json.dumps(res, indent=1))
    return 0 if all(r["passed"] for r in res) else 1


if __name__ == "__main__": raise SystemExit(main())
