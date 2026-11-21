"""Real-model useful-work benchmark: `agent` tasks (model writes code with file tools) through the real durable stack, validated by independent test commands.

  python -m ordivyr.hosting.realbench --base http://127.0.0.1:PORT/v1 --key-file F --model NAME --tasks 16 --slots 2 --out R.json [--gpu-index 1]

Every task: model must create a file; a validator process (separate from the model) executes assertions against it. Counted VALIDATED only if validators pass,
one commit event, clean audit(). GPU memory and utilisation are sampled with nvidia-smi (only the chosen --gpu-index). Nothing is extrapolated; this is NOT comparable
to the synthetic `workbench` numbers (those wait a fixed 1 s and hash).
"""
from __future__ import annotations
import argparse, json, subprocess, tempfile, threading, time
from pathlib import Path
from .. import durable as D, durable_worker as W
from .bench import pct

CASES = [
 ("fib.py", "Write fib.py defining fib(n) returning the n-th Fibonacci number (fib(0)=0, fib(1)=1).", "from fib import fib; assert [fib(i) for i in range(10)]==[0,1,1,2,3,5,8,13,21,34]"),
 ("rev.py", "Write rev.py defining reverse_words(s) that reverses the order of whitespace-separated words, joined by single spaces.", "from rev import reverse_words as r; assert r('a b  c')=='c b a'; assert r('')==''"),
 ("prime.py", "Write prime.py defining is_prime(n) returning True for primes, False otherwise (n<2 is False).", "from prime import is_prime as p; assert [i for i in range(30) if p(i)]==[2,3,5,7,11,13,17,19,23,29]"),
 ("flat.py", "Write flat.py defining flatten(x) that flattens arbitrarily nested lists of ints into one flat list.", "from flat import flatten as f; assert f([1,[2,[3,[4]]],5])==[1,2,3,4,5]; assert f([])==[]"),
 ("anag.py", "Write anag.py defining is_anagram(a,b) ignoring case and spaces.", "from anag import is_anagram as a; assert a('Dormitory','dirty room'); assert not a('abc','abd')"),
 ("roman.py", "Write roman.py defining to_roman(n) for 1..3999.", "from roman import to_roman as r; assert r(1994)=='MCMXCIV' and r(4)=='IV' and r(3999)=='MMMCMXCIX'"),
 ("gcd.py", "Write gcd.py defining gcd(a,b) (Euclid) and lcm(a,b).", "from gcd import gcd, lcm; assert gcd(48,18)==6 and lcm(4,6)==12"),
 ("bal.py", "Write bal.py defining balanced(s) True if the brackets ()[]{} in s are balanced.", "from bal import balanced as b; assert b('{[()]}') and not b('([)]') and not b('(')"),
]

def gpu_sampler(idx, stop, out):
    while not stop.is_set():
        try:
            r = subprocess.run(["nvidia-smi", "-i", str(idx), "--query-gpu=memory.used,utilization.gpu,temperature.gpu,power.draw", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=5).stdout.split(",")
            out.append(tuple(float(x) for x in r))
        except Exception: pass
        stop.wait(0.5)

def main(argv=None):
    a = argparse.ArgumentParser(); a.add_argument("--base", required=True); a.add_argument("--key-file"); a.add_argument("--model", required=True); a.add_argument("--tasks", type=int, default=16)
    a.add_argument("--slots", type=int, default=2); a.add_argument("--timeout", type=float, default=900); a.add_argument("--gpu-index", type=int, default=1); a.add_argument("--out"); a.add_argument("--request-timeout", type=float, default=180)
    a = a.parse_args(argv); key = Path(a.key_file).read_text().strip() if a.key_file else ""
    d = Path(tempfile.mkdtemp(prefix="ordreal-")); st = D.Store(d / "q.db"); ws = d / "ws"; ws.mkdir(); meta = {}
    for i in range(a.tasks):
        fn, prompt, test = CASES[i % len(CASES)]
        tid = st.submit("agent", {"base": a.base, "key": key, "model": a.model, "prompt": prompt + " Use the file-writing tool; do not just print code. Then stop.", "max_steps": 6, "request_timeout": a.request_timeout,
                                  "validators": [{"name": "assert", "cmd": ["python3", "-c", "import sys;sys.path.insert(0,'.');" + test], "timeout": 30}, {"name": "exists", "cmd": ["python3", "-c", f"import os;assert os.path.getsize({fn!r})>20"]}]}, f"real{i}", max_attempts=2); meta[tid] = fn
    stop = threading.Event(); gs = []; th = threading.Thread(target=gpu_sampler, args=(a.gpu_index, stop, gs), daemon=True); th.start()
    t0 = time.time(); wt = threading.Thread(target=W.serve_pool, args=(st, "rb", "main", str(ws), a.slots, 60.0, ["agent"], stop), daemon=True); wt.start(); c = st._conn()
    while time.time() - t0 < a.timeout:
        n = c.execute("SELECT COUNT(*) FROM tasks WHERE state IN ('completed','failed','dead','cancelled')").fetchone()[0]
        if n >= a.tasks: break
        time.sleep(1)
    wall = time.time() - t0; stop.set(); time.sleep(1)
    rows = {r["id"]: dict(r) for r in c.execute("SELECT * FROM tasks")}; commits = {r[0]: r[1] for r in c.execute("SELECT task_id, COUNT(*) FROM events WHERE kind='commit' GROUP BY task_id")}
    valid = 0; lat = []; toks = 0; fails = []
    for tid, fn in meta.items():
        r = rows[tid]; ev = st.evidence(tid)
        if r["state"] == "completed" and commits.get(tid) == 1 and ev and all(e["ok"] for e in ev): valid += 1; lat.append(r["updated"] - r["created"])
        else: fails.append({"task": tid, "file": fn, "state": r["state"], "error": str(r.get("failure") or "")[:200]})
    mem = [g[0] for g in gs]; util = [g[1] for g in gs]; pw = [g[3] for g in gs]; temp = [g[2] for g in gs]
    res = {"model": a.model, "base": a.base, "tasks": a.tasks, "slots": a.slots, "validated_complete": valid, "failed_or_unvalidated": len(fails), "failures": fails, "wall_s": round(wall, 1),
           "validated_tasks_per_min": round(valid * 60 / wall, 2), "latency_ms": {"p50": pct(lat, 50), "p95": pct(lat, 95), "max": round(max(lat) * 1000) if lat else None},
           "gpu": {"index": a.gpu_index, "peak_mem_mib": max(mem) if mem else None, "mean_util_pct": round(sum(util) / len(util), 1) if util else None, "peak_temp_c": max(temp) if temp else None, "peak_power_w": max(pw) if pw else None},
           "duplicate_commits": sum(1 for v in commits.values() if v > 1), "audit_violations": st.audit(), "kind": "REAL_MODEL_USEFUL_WORK (not comparable to synthetic 1.0s-wait compute)"}
    print(json.dumps(res, indent=1))
    if a.out: Path(a.out).write_text(json.dumps(res, indent=1))
    return 0 if valid == a.tasks else 1
if __name__ == "__main__": raise SystemExit(main())
