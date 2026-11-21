"""ordivyr arena - competitive benchmark arena.

  ordivyr arena doctor                                   which harnesses are runnable here (NOT_TESTED + reason otherwise), tooling check
  ordivyr arena run --name N [--suite synthetic|mini|smoke|delegation|repo] [--scenario tasks|recovery|concurrency|all] [--harness a,b|all]
                    [--model-url URL --key-file F --model NAME --ctx N] [--seed-offset K] [--limit N] [--no-preflight]
  ordivyr arena results [NAME] [--json]                  list runs, or print one run's summary (pass rate + Wilson CI, latency p50/p95/p99, tokens, recovery, ...)
  ordivyr arena compare A [B] [--harness x,y]            paired comparison (exact McNemar) of two harnesses inside run A, or the same harness across runs A vs B
  ordivyr arena backlog NAME                             data-driven improvement backlog (ORDIVYR vs best competitor)
  ordivyr arena baseline NAME [--out FILE]               promote a run to the versioned baseline for its suite
  ordivyr arena regressions [--run NAME] [--baseline FILE] [--ci]     exit 1 when a verified capability degraded; --ci runs the GPU-free stub regression suite itself
  ordivyr arena report NAME                              write docs/arena/REPORT-<NAME>.md
Environment: ORDIVYR_ARENA_RUNS (results root, default docs/arena/runs), ORDIVYR_ARENA_WS (lane scratch, default ~/ordivyr-arena-20261103/ws), ORDIVYR_ARENA_ADAPTERS (plugin adapters dir).
"""
from __future__ import annotations
import argparse, json, os, shutil, subprocess, sys, time
from pathlib import Path
from . import suite as SU, results as R, runs as RU, engine, adapters as AD, stats as S

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs" / "arena"


def runs_root(): return Path(os.environ.get("ORDIVYR_ARENA_RUNS") or DOCS / "runs")
def ws_root(): return Path(os.environ.get("ORDIVYR_ARENA_WS") or Path.home() / "ordivyr-arena-20261103" / "ws")
def baseline_path(suite): return DOCS / "baselines" / f"{suite}.json"
def out(o): print(json.dumps(o, indent=2, default=str))


def pct(x): return "n/a" if x is None else f"{x:.0%}"
def ci(c): return f"[{c[0]:.0%}-{c[1]:.0%}]"
def f1(x): return "n/a" if x is None else f"{x:.1f}"


def doctor():
    rows = [a.describe() for a in AD.all_adapters()]
    tools = {t: bool(shutil.which(t)) for t in ("bwrap", "systemd-run", "nvidia-smi")}
    import importlib.util; tools["pytest"] = importlib.util.find_spec("pytest") is not None
    out({"harnesses": rows, "tools": tools, "runs_root": str(runs_root()), "ws_root": str(ws_root())}); return 0 if all(tools.get(t) for t in ("bwrap", "systemd-run", "pytest")) else 1


def pick_adapters(spec):
    allv = AD.all_adapters(); names = [a.name for a in allv]
    want = names if spec in (None, "all") else spec.split(",")
    sel = []
    for n in want:
        if n not in names: raise ValueError(f"unknown harness {n!r}; known: {names}")
        sel.append(next(a for a in allv if a.name == n))
    return sel


def cmd_run(a):
    tasks = SU.build(a.suite, a.seed_offset) if a.suite != "repo" else __import__("ordivyr.arena.repo_tasks", fromlist=["x"]).build()
    if a.limit: tasks = tasks[:a.limit]
    if not a.no_preflight:
        bad = SU.preflight(tasks)
        if bad: print("PREFLIGHT FAILED:\n" + "\n".join(bad[:5])); return 2
    adapters_all = pick_adapters(a.harness); runnable = []
    for ad in adapters_all:
        ok, why = ad.available()
        if ok: runnable.append(ad)
        else: print(f"NOT_TESTED {ad.name}: {why}")
    key = open(a.key_file).read().strip() if a.key_file else os.environ.get("ORDIVYR_ARENA_KEY", "")
    base = a.model_url.rstrip("/"); model = engine.Model(name=a.model, base=base, key=key, ctx=a.ctx, kind="llama", metrics=base.replace("/v1", "") + "/metrics")
    r = RU.Run(a.name, runs_root(), ws_root(), a.suite, tasks, model, runnable, a.scenario, notes=a.notes)
    before = RU.protected_snapshot(); not_tested = [{"name": x.name, "reason": x.available()[1]} for x in adapters_all if x not in runnable]
    r.meta({"not_tested": not_tested, "protected_before": before, "started": time.time(), "seed_offset": a.seed_offset, "command": "ordivyr arena " + " ".join(sys.argv[2:] if len(sys.argv) > 2 else [])})
    gpu = None
    if not a.no_gpu and shutil.which("nvidia-smi"): gpu = engine.GpuSampler(a.gpu_index); gpu.start()
    try:
        if a.scenario in ("tasks", "all"): r.run_tasks(gpu, repeats=a.repeats)
        if a.scenario in ("recovery", "all"): r.run_recovery(a.stub_delay)
        if a.scenario in ("concurrency", "all"): r.run_concurrency(a.concurrency)
    finally:
        if gpu: gpu.stop_ev.set()
        after = RU.protected_snapshot(); orphans = subprocess.run("pgrep -af 'ordivyr.arena.scoperun|arena-.*scope' | grep -v pgrep | wc -l", shell=True, capture_output=True, text=True).stdout.strip()
        r.meta({"not_tested": not_tested, "protected_before": before, "protected_after": after, "protected_unchanged": before == after, "ended": time.time(), "leftover_arena_processes": orphans, "seed_offset": a.seed_offset})
        r.log("protected files unchanged:", before == after, "| leftover arena processes:", orphans)
    return 0


# ------------------------------------------------------------------ presentation
def print_summary(meta, recs):
    sm = R.summarize(recs)
    if sm:
        print(f"\n== {meta.get('name')}  suite={meta.get('suite')} ({meta.get('n_tasks')} tasks, hash {meta.get('suite_hash')})  git={meta.get('git', {}).get('sha')} model={meta.get('model', {}).get('name')}")
        print(f"{'harness':10} {'pass':>9} {'rate':>6} {'95% CI':>11} {'p50s':>6} {'p95s':>6} {'p99s':>6} {'valid/h':>8} {'tok/valid':>9} {'cpu_s':>6} {'memMB':>6} {'tool%':>6} {'viol':>5} {'orph':>5}")
        for h, v in sm.items():
            l = v["latency_s"]; print(f"{h:10} {v['pass']:>4}/{v['n']:<4} {pct(v['rate']):>6} {ci(v['ci']):>11} {f1(l['p50']):>6} {f1(l['p95']):>6} {f1(l['p99']):>6} {v['validated_per_hour']:>8.1f} {f1(v['tokens_per_validated']):>9} {f1(v['cpu_s_per_run']):>6} {f1(v['mem_peak_mb']['mean']):>6} {pct(v['tool_success']):>6} {v['violations']:>5} {v['orphans']:>5}")
        cats = sorted({c for v in sm.values() for c in v["by_category"]})
        print("\nby category (pass/n):"); print(f"{'harness':10} " + " ".join(f"{c:>10}" for c in cats))
        for h, v in sm.items(): print(f"{h:10} " + " ".join(f"{(str(v['by_category'][c]['pass']) + '/' + str(v['by_category'][c]['n'])) if c in v['by_category'] else '-':>10}" for c in cats))
    rc = R.recovery_summary(recs)
    if rc:
        print("\nrecovery (stub model; SIGKILL of the whole invocation, then native resume):")
        for h, d in rc.items():
            for kp, m in d.items(): print(f"  {h:9} kill-{kp:5} recovered {m['recovered']}/{m['n']} {ci(m['ci'])} recovery p50 {f1(m['recovery_s_p50'])}s dup-requests {f1(m['dup_model_requests_mean'])} lost {m['lost']} corrupt {m['corrupted']} orphans {m['orphans']} kill-missed {m['kill_missed']}")
    cc = R.concurrency_summary(recs)
    if cc:
        print("\nconcurrency (stub model, 4 parallel invocations):")
        for h, m in cc.items(): print(f"  {h:9} {m['passed']}/{m['n']} ok {ci(m['ci'])} wall {m['wall_s']}s -> {m['tasks_per_hour']} tasks/h  cpu {m['cpu_s_sum']}s  peakRAM {m['mem_peak_mb_max']}MB  orphans {m['orphans']}")
    ov = R.overhead_summary(recs)
    if ov: print("\ncontext overhead (first request, ~tokens incl. system prompt + tool schemas + task): " + ", ".join(f"{h} {m['first_request_tokens_est']}" for h, m in ov.items()))
    nt = meta.get("not_tested") or []
    for n in nt: print(f"NOT_TESTED {n['name']}: {n['reason']}")


def resolve_run(name):
    p = Path(name)
    return p if (p / "records.jsonl").exists() else runs_root() / name


def cmd_results(a):
    root = runs_root()
    if not a.name:
        rows = []
        for d in sorted(root.glob("*/")):
            if (d / "meta.json").exists():
                m, recs = R.load(d); rows.append({"run": d.name, "suite": m.get("suite"), "hash": m.get("suite_hash"), "git": (m.get("git") or {}).get("sha"), "records": len(recs), "harnesses": [h["name"] for h in m.get("harnesses", [])]})
        out(rows) if a.json else [print(f"{r['run']:34} suite={r['suite']:10} hash={r['hash']} git={r['git']} records={r['records']} harnesses={','.join(r['harnesses'])}") for r in rows]; return 0
    m, recs = R.load(resolve_run(a.name))
    if a.json: out({"meta": m, "summary": R.summarize(recs), "recovery": R.recovery_summary(recs), "concurrency": R.concurrency_summary(recs), "overhead": R.overhead_summary(recs)}); return 0
    print_summary(m, recs); return 0


def cmd_compare(a):
    ma, ra = R.load(resolve_run(a.a))
    if a.b:
        mb, rb = R.load(resolve_run(a.b)); h = (a.harness or "ordivyr").split(",")[0]
        pa, pb = R.pass_map(ra, h), R.pass_map(rb, h); pr = S.paired(pa, pb); pr["verdict"] = S.verdict(pr)
        print(f"{h}: {a.a} vs {a.b} (same tasks: {pr['n']}; suite hashes {ma.get('suite_hash')} / {mb.get('suite_hash')})")
        print(f"  A {pr['a_pass']}/{pr['n']} {ci(pr['a_ci'])}   B {pr['b_pass']}/{pr['n']} {ci(pr['b_ci'])}   A-only {pr['a_only']}  B-only {pr['b_only']}  McNemar exact p={pr['p']:.3f}  => {pr['verdict']}")
        sa, sb = R.summarize(ra).get(h), R.summarize(rb).get(h)
        if sa and sb:
            for k in ("tokens_per_validated", "cpu_s_per_run"): print(f"  {k}: {f1(sa.get(k))} -> {f1(sb.get(k))}")
            print(f"  latency p50/p95: {f1(sa['latency_s']['p50'])}/{f1(sa['latency_s']['p95'])} -> {f1(sb['latency_s']['p50'])}/{f1(sb['latency_s']['p95'])}")
        return 0
    hs = (a.harness or "ordivyr,hermes").split(","); x = R.compare(ra, hs[0], hs[1])
    print(f"{hs[0]} (A) vs {hs[1]} (B), paired over {x['n']} common tasks"); print(f"  A {x['a_pass']}/{x['n']} {ci(x['a_ci'])}   B {x['b_pass']}/{x['n']} {ci(x['b_ci'])}   A-only {x['a_only']} B-only {x['b_only']}  exact McNemar p={x['p']:.3f}\n  verdict: {x['verdict']}")
    for c, v in x["categories"].items(): print(f"    {c:10} n={v['n']:>2} {hs[0]} {v[hs[0]]:>2}  {hs[1]} {v[hs[1]]:>2}  p={v['p']:.2f}")
    print("  (per-category counts are descriptive only: samples are too small for category-level significance claims)"); return 0


def cmd_backlog(a):
    m, recs = R.load(resolve_run(a.name)); items = R.backlog(R.summarize(recs), R.recovery_summary(recs), R.concurrency_summary(recs), R.overhead_summary(recs))
    if a.json: out(items); return 0
    if not items: print("no data-supported backlog items (no measurable deficiency vs the best competitor)"); return 0
    for i, it in enumerate(items, 1):
        print(f"{i}. [{it['area']}] complexity {it['complexity']}\n   competitor advantage : {it['competitor_advantage']}\n   ORDIVYR deficiency    : {it['deficiency']}\n   proposed solution     : {it['solution']}\n   expected improvement  : {it['expected_improvement']}\n   acceptance test       : {it['acceptance_test']}")
    return 0


def cmd_baseline(a):
    m, recs = R.load(resolve_run(a.name)); b = R.baseline_of(m, recs); p = Path(a.out) if a.out else baseline_path(m.get("suite")); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(b, indent=1)); print(f"baseline written: {p}"); return 0


def stub_ci_run(name="ci-stub"):
    """GPU-free regression suite: ORDIVYR only, scripted oracle model: 14 tasks + recovery(early/late) + concurrency. Deterministic -> exact comparison against baselines/ci-stub.json."""
    tasks = SU.build("mini"); ad = [AD.get("ordivyr")]; model = engine.Model(name="stub-oracle", base="", key="x", ctx=65536, kind="stub", metrics=None)
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="arena-ci-")); r = RU.Run(name, root, root / "ws", "ci-stub", tasks, model, ad, "ci")
    stub_tasks = [t for t in tasks]; from .stubserver import Stub
    stub = Stub(stub_tasks, delay=0.0).start(); m2 = engine.Model(model, base=stub.base)
    try:
        for t in tasks:
            if t["category"] == "delegation": continue
            r.add(engine.execute(ad[0], t, m2, r.lanes, tag="t", stub=stub, label="task"))
    finally: stub.stop()
    r.run_recovery(delay=2.0, n_tasks=3); r.run_concurrency(4, delay=0.3, n_tasks=4)
    meta = r.meta(); _, recs = R.load(r.dir); return meta, recs


def cmd_regressions(a):
    if a.ci:
        meta, recs = stub_ci_run(); bp = Path(a.baseline) if a.baseline else baseline_path("ci-stub"); exact = True
    else:
        m_, recs = R.load(resolve_run(a.run)); meta = m_; bp = Path(a.baseline) if a.baseline else baseline_path(meta.get("suite")); exact = (meta.get("model") or {}).get("kind") == "stub"
    cur = R.baseline_of(meta, recs)
    if not bp.exists():
        if a.ci and a.update: bp.parent.mkdir(parents=True, exist_ok=True); bp.write_text(json.dumps(cur, indent=1)); print(f"baseline created: {bp}"); return 0
        print(f"no baseline at {bp} (create with: ordivyr arena baseline NAME  /  regressions --ci --update)"); return 2
    base = json.loads(bp.read_text()); bad = R.check(base, cur, exact=exact)
    print(f"baseline {bp.name} (from {base.get('from_run')}, git {(base.get('git') or {}).get('sha')}) vs current ({cur.get('n')} tasks, pass {cur.get('pass')})")
    if bad: print("REGRESSIONS:"); [print("  - " + b) for b in bad]; return 1
    print("REGRESSIONS=PASS (no previously verified capability degraded)"); return 0


def cmd_report(a):
    m, recs = R.load(resolve_run(a.name)); import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf): print_summary(m, recs)
    p = DOCS / f"REPORT-{a.name}.md"; p.write_text(f"# Arena report: {a.name}\n\n```\n{buf.getvalue()}\n```\n"); print(p); return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ordivyr arena", description="ORDIVYR competitive benchmark arena"); sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor"); s = sub.add_parser("run")
    s.add_argument("--name", required=True); s.add_argument("--suite", default="synthetic", choices=["synthetic", "mini", "smoke", "delegation", "repo"]); s.add_argument("--scenario", default="tasks", choices=["tasks", "recovery", "concurrency", "all"])
    s.add_argument("--harness", default="all"); s.add_argument("--model-url", default="http://127.0.0.1:18471/v1"); s.add_argument("--key-file"); s.add_argument("--model", default="arena-qwen3-30b-a3b"); s.add_argument("--ctx", type=int, default=65536)
    s.add_argument("--seed-offset", type=int, default=0); s.add_argument("--limit", type=int); s.add_argument("--repeats", type=int, default=1); s.add_argument("--no-preflight", action="store_true"); s.add_argument("--no-gpu", action="store_true")
    s.add_argument("--gpu-index", type=int, default=1); s.add_argument("--stub-delay", type=float, default=3.0); s.add_argument("--concurrency", type=int, default=4); s.add_argument("--notes", default="")
    s = sub.add_parser("results"); s.add_argument("name", nargs="?"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("compare"); s.add_argument("a"); s.add_argument("b", nargs="?"); s.add_argument("--harness")
    s = sub.add_parser("backlog"); s.add_argument("name"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("baseline"); s.add_argument("name"); s.add_argument("--out")
    s = sub.add_parser("regressions"); s.add_argument("--run"); s.add_argument("--baseline"); s.add_argument("--ci", action="store_true"); s.add_argument("--update", action="store_true")
    s = sub.add_parser("report"); s.add_argument("name")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "doctor": return doctor()
        if a.cmd == "run": return cmd_run(a)
        if a.cmd == "results": return cmd_results(a)
        if a.cmd == "compare": return cmd_compare(a)
        if a.cmd == "backlog": return cmd_backlog(a)
        if a.cmd == "baseline": return cmd_baseline(a)
        if a.cmd == "regressions":
            if not a.ci and not a.run: print("regressions needs --run NAME or --ci"); return 2
            return cmd_regressions(a)
        if a.cmd == "report": return cmd_report(a)
    except (ValueError, KeyError, OSError) as e:
        print(f"ordivyr arena: {e}", file=sys.stderr); return 1


if __name__ == "__main__": sys.exit(main())
