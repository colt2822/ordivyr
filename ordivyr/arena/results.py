"""Results: load, summarise (always with uncertainty), compare (paired), deterministic improvement backlog, regression checks against versioned baselines."""
from __future__ import annotations
import json
from collections import defaultdict
from pathlib import Path
from . import stats as S

REAL = ("task",)                      # label of the real-model scenario
CATS = ("bugfix", "implement", "multifile", "longrun", "toolcall", "context", "security")


def load(run_dir):
    d = Path(run_dir); meta = json.loads((d / "meta.json").read_text()) if (d / "meta.json").exists() else {}
    recs = [json.loads(l) for l in (d / "records.jsonl").read_text().splitlines() if l.strip()] if (d / "records.jsonl").exists() else []
    return meta, recs


def _med(xs): return S.percentile(xs, 50)


def summarize(recs, labels=REAL):
    """-> {harness: {...}} for the real-model task scenario. Every rate carries a Wilson interval; every latency has p50/p95/p99."""
    by = defaultdict(list)
    for r in recs:
        if r.get("label") in labels or (labels == REAL and str(r.get("label", "")).startswith("task")): by[r["harness"]].append(r)
    out = {}
    for h, rs in by.items():
        tested = [r for r in rs if r.get("status") != "NOT_TESTED"]; nt = [r for r in rs if r.get("status") == "NOT_TESTED"]; n = len(tested); k = sum(1 for r in tested if r["passed"])
        wall = [r["wall_s"] for r in tested]; okr = [r for r in tested if r["passed"]]
        def tok(r): return (r.get("prompt_tokens") or 0) + (r.get("completion_tokens") or 0)
        calls = sum(r.get("tool_calls") or 0 for r in tested); errs = sum(r.get("tool_errors") or 0 for r in tested)
        cats = {}
        for c in CATS + ("delegation",):
            cr = [r for r in tested if r["category"] == c]
            if cr: kk = sum(1 for r in cr if r["passed"]); cats[c] = {"n": len(cr), "pass": kk, "rate": kk / len(cr), "ci": S.wilson(kk, len(cr))}
        out[h] = {"n": n, "pass": k, "rate": k / n if n else None, "ci": S.wilson(k, n), "not_tested": len(nt), "not_tested_reason": nt[0]["reason"] if nt else None, "by_category": cats,
                  "latency_s": {"p50": S.percentile(wall, 50), "p95": S.percentile(wall, 95), "p99": S.percentile(wall, 99), "mean": S.mean(wall), "mean_ci": S.bootstrap_ci(wall)},
                  "validated_per_hour": (k / (sum(wall) / 3600)) if sum(wall) and k else 0.0,
                  "tokens_per_validated": (sum(tok(r) for r in tested) / k) if k and any(tok(r) for r in tested) else None, "evaluated_tokens_per_run": S.mean([tok(r) for r in tested if tok(r)]),
                  "reported_tokens_per_run": S.mean([r.get("reported_tokens") for r in tested if r.get("reported_tokens")]),
                  "gpu_busy_s_per_validated": (sum(r.get("gpu_busy_s") or 0 for r in tested) / k) if k else None, "api_cost_usd_per_validated": 0.0,
                  "cpu_s_per_run": S.mean([r.get("cpu_s") for r in tested]), "mem_peak_mb": {"mean": S.mean([r.get("mem_peak_mb") for r in tested]), "max": max([r.get("mem_peak_mb") or 0 for r in tested] or [0])},
                  "gpu_util_mean": S.mean([r.get("gpu_util_mean") for r in tested]), "tool_calls": calls, "tool_success": (1 - errs / calls) if calls else None,
                  "violations": sum(len(r.get("violations") or []) for r in tested), "runs_with_violation": sum(1 for r in tested if r.get("violations")), "orphans": sum(r.get("orphans") or 0 for r in tested),
                  "protocol_errors": sum(r.get("protocol_errors") or 0 for r in tested), "timeouts": sum(1 for r in tested if r.get("timed_out"))}
    return out


def recovery_summary(recs):
    out = {}
    base = defaultdict(list)
    for r in recs:
        if r["label"] == "stub-base": base[(r["harness"], r["task"])].append(r.get("model_requests") or 0)
    for h in sorted({r["harness"] for r in recs}):
        for kp in ("early", "late"):
            rs = [r for r in recs if r["harness"] == h and r["label"] == f"recover-{kp}" and r.get("status") != "NOT_TESTED"]
            if not rs: continue
            k = sum(1 for r in rs if r["passed"]); dup = [max(0, (r.get("model_requests") or 0) - (_med(base.get((h, r["task"]), [0])) or 0)) for r in rs]
            out.setdefault(h, {})[kp] = {"n": len(rs), "killed": sum(1 for r in rs if r.get("killed")), "recovered": k, "ci": S.wilson(k, len(rs)), "recovery_s_p50": _med([r["recovery_s"] for r in rs if r.get("recovery_s")]),
                                         "dup_model_requests_mean": S.mean(dup), "lost": sum(1 for r in rs if not r["passed"] and not r.get("files_present")), "corrupted": sum(1 for r in rs if not r["passed"] and r.get("files_present")),
                                         "orphans": sum(r.get("orphans") or 0 for r in rs), "kill_missed": sum(1 for r in rs if not r.get("killed"))}
    return out


def concurrency_summary(recs, label="conc4"):
    out = {}
    for h in sorted({r["harness"] for r in recs}):
        rs = [r for r in recs if r["harness"] == h and r["label"] == label]
        if not rs: continue
        t0 = min(r["ts"] for r in rs); t1 = max(r["ts"] + r["wall_s"] for r in rs); k = sum(1 for r in rs if r["passed"])
        out[h] = {"n": len(rs), "passed": k, "ci": S.wilson(k, len(rs)), "wall_s": round(t1 - t0, 1), "tasks_per_hour": round(len(rs) / ((t1 - t0) / 3600), 1) if t1 > t0 else None,
                  "lost_or_corrupt": len(rs) - k, "cpu_s_sum": round(sum(r.get("cpu_s") or 0 for r in rs), 1), "mem_peak_mb_max": max(r.get("mem_peak_mb") or 0 for r in rs), "orphans": sum(r.get("orphans") or 0 for r in rs)}
    return out


def overhead_summary(recs):
    """Context overhead: size of the FIRST model request minus the task text itself (system prompt + tool schemas), measured at the model endpoint, chars/4 ~ tokens."""
    out = {}
    for h in sorted({r["harness"] for r in recs}):
        xs = [r["first_request_chars"] for r in recs if r["harness"] == h and r["label"] == "stub-base" and r.get("first_request_chars")]
        if xs: out[h] = {"first_request_tokens_est": round(_med(xs) / 4), "n": len(xs)}
    return out


def pass_map(recs, harness, labels=REAL):
    return {r["task"]: bool(r["passed"]) for r in recs if r["harness"] == harness and (r.get("label") in labels or str(r.get("label", "")).startswith("task")) and r.get("status") != "NOT_TESTED"}


def compare(recs, a, b):
    pr = S.paired(pass_map(recs, a), pass_map(recs, b)); pr["verdict"] = S.verdict(pr); pr["a"], pr["b"] = a, b
    cats = {}
    for c in CATS:
        ids = {r["task"] for r in recs if r["category"] == c}
        pa, pb = {k: v for k, v in pass_map(recs, a).items() if k in ids}, {k: v for k, v in pass_map(recs, b).items() if k in ids}
        if pa and pb: x = S.paired(pa, pb); cats[c] = {"n": x["n"], a: x["a_pass"], b: x["b_pass"], "p": x["p"]}
    pr["categories"] = cats; return pr


# ------------------------------------------------------------------ competitive advantage engine: deterministic metric -> backlog rules
RULES = [
    ("context", "pass", "read_file returns at most 8000 characters and has no offset/limit, so facts past that point are unreachable",
     "Add `offset`/`limit` (line or char window) to read_file and a truncation notice that names the next offset; add a `grep`-style search tool", "needle-in-a-long-file tasks (+gap x n), first-attempt reads",
     "context-category tasks with the needle past char 8000 pass on a stub that only answers when the tool is paged", "S"),
    ("toolcall", "pass", "whole-file rewrites (only write_file) disturb unrelated lines; competitors expose edit/patch tools that change only the named lines",
     "Add `edit_file(path, old, new)` exact-replace tool (fails closed on 0 or >1 matches)", "instruction-adherence tasks (+gap x n) and fewer collateral changes",
     "config-edit task passes with a stub that only emits edit_file calls; collateral-change check stays green", "S"),
    ("longrun", "pass", "default step budget and weak guidance cause early stops on tasks needing many sequential tool calls",
     "Raise the default tool-step budget with a progress-aware stop (stop only after N steps with no new write/read)", "long-running tasks (+gap x n)", "6-module chain task completes within budget with a stub emitting 13 calls", "S"),
    ("bugfix", "pass", "single-file fixes fail when the model writes without re-reading its own output", "Add an automatic post-write verification read-back + syntax check (py_compile) fed to the model before finishing", "bugfix/implement categories (+gap x n)", "a write with a syntax error is surfaced to the model and repaired on the next step", "M"),
    ("implement", "pass", "implementation tasks fail on syntax errors in written files", "Add an automatic post-write syntax check for known file types and return it as the tool result", "implement category (+gap x n)", "stub writes invalid python first; second step repairs it", "M"),
    ("security", "violations", "file-tool scope is enforced only for ORDIVYR; competitors recorded violations", "(none needed: keep fail-closed ToolBox; add regression test)", "violations stay 0", "security tasks: 0 violations", "S"),
]


def backlog(sumry, rec_sum, conc_sum, over, subject="ordivyr"):
    """Compare `subject` with the best competitor on every measured dimension; emit only items the DATA supports."""
    items = []; me = sumry.get(subject)
    comps = {h: v for h, v in sumry.items() if h != subject and v["n"]}
    if not me or not comps: return items
    for cat, kind, why, fix, gain, accept, cx in RULES:
        if kind != "pass": continue
        mine = me["by_category"].get(cat)
        best = max(((h, v["by_category"].get(cat)) for h, v in comps.items() if v["by_category"].get(cat)), key=lambda x: x[1]["rate"], default=None)
        if mine and best:
            gap = best[1]["rate"] - mine["rate"]
            if gap >= 0.10 or (mine["rate"] < 0.6 and gap > 0): items.append({"area": cat, "competitor": best[0], "competitor_advantage": f"{best[0]} passes {best[1]['pass']}/{best[1]['n']} ({best[1]['rate']:.0%}) vs ORDIVYR {mine['pass']}/{mine['n']} ({mine['rate']:.0%}) in {cat}", "deficiency": why, "solution": fix,
                                                                      "expected_improvement": f"up to +{gap * mine['n']:.1f} tasks of {mine['n']} in {cat} ({gain})", "acceptance_test": accept, "complexity": cx, "priority": gap * mine["n"], "evidence": {"gap": gap}})
    ob = rec_sum.get(subject, {}); best_rec = {h: v for h, v in rec_sum.items() if h != subject}
    for kp in ("early", "late"):
        m = ob.get(kp)
        if not m: continue
        for h, v in best_rec.items():
            c = v.get(kp)
            if c and (m["dup_model_requests_mean"] or 0) > (c["dup_model_requests_mean"] or 0) + 0.5:
                items.append({"area": f"recovery-{kp}", "competitor": h, "competitor_advantage": f"{h} repeats {c['dup_model_requests_mean']:.1f} model requests after a {kp} kill vs ORDIVYR {m['dup_model_requests_mean']:.1f}", "deficiency": "a resumed agent task restarts its tool loop from scratch (checkpoints exist but are not replayed)",
                              "solution": "Persist the assistant/tool message history per step in the durable store and resume the loop from it (replay recorded tool results instead of calling the model again)", "expected_improvement": f"-{(m['dup_model_requests_mean'] - c['dup_model_requests_mean']):.1f} duplicated model requests per recovered task",
                              "acceptance_test": "kill-late recovery on the stub completes with 0 duplicated model requests and a valid result", "complexity": "M", "priority": (m['dup_model_requests_mean'] - c['dup_model_requests_mean']) * 0.5, "evidence": {}})
                break
    for key, label, fix, cx in (("tokens_per_validated", "tokens per validated task", "Trim repeated context (already deduped) and cap read results", "M"), ("cpu_s_per_run", "CPU seconds per task", "Avoid per-run interpreter start-up work", "S")):
        mv = me.get(key); cands = [(h, v[key]) for h, v in comps.items() if v.get(key)]
        if mv and cands:
            h, bv = min(cands, key=lambda x: x[1])
            if mv > bv * 1.25: items.append({"area": label, "competitor": h, "competitor_advantage": f"{h}: {bv:.0f} vs ORDIVYR {mv:.0f} {label}", "deficiency": f"ORDIVYR uses {mv / bv:.1f}x more {label}", "solution": fix, "expected_improvement": f"-{(1 - bv / mv):.0%} {label}", "acceptance_test": f"{label} <= competitor median on the same suite", "complexity": cx, "priority": mv / bv, "evidence": {}})
    if me["violations"] > 0: items.append({"area": "security", "competitor": "-", "competitor_advantage": "-", "deficiency": f"ORDIVYR recorded {me['violations']} scope violation(s)", "solution": "Fix the escaping path in ToolBox and add a regression test", "expected_improvement": "0 violations", "acceptance_test": "security category: 0 violations", "complexity": "S", "priority": 100.0, "evidence": {}})
    items.sort(key=lambda x: -x["priority"]); return items


# ------------------------------------------------------------------ regression arena
def baseline_of(meta, recs, subject="ordivyr"):
    sm = summarize(recs).get(subject, {}); rec = recovery_summary(recs).get(subject, {}); conc = concurrency_summary(recs).get(subject, {})
    return {"subject": subject, "suite": meta.get("suite"), "suite_hash": meta.get("suite_hash"), "git": meta.get("git"), "from_run": meta.get("name"), "scenario_model": (meta.get("model") or {}).get("kind"),
            "n": sm.get("n"), "pass": sm.get("pass"), "rate": sm.get("rate"), "by_category": {c: {"n": v["n"], "pass": v["pass"]} for c, v in sm.get("by_category", {}).items()}, "violations": sm.get("violations"), "orphans": sm.get("orphans"),
            "tokens_per_validated": sm.get("tokens_per_validated"), "p95_latency_s": (sm.get("latency_s") or {}).get("p95"), "recovery": {k: {"recovered": v["recovered"], "n": v["n"], "dup": v["dup_model_requests_mean"]} for k, v in rec.items()},
            "concurrency": {"passed": conc.get("passed"), "n": conc.get("n")} if conc else None}


def check(base, cur, exact=False):
    """-> list of regression messages (empty = no regression). exact=True for the deterministic stub suite (any drop counts); otherwise a drop must also be statistically visible."""
    bad = []
    if base.get("suite_hash") and cur.get("suite_hash") and base["suite_hash"] != cur["suite_hash"]: bad.append(f"SUITE CHANGED: baseline suite hash {base['suite_hash']} != current {cur['suite_hash']} (results are not comparable; re-baseline deliberately)"); return bad
    def drop(b, c, n, label):
        if c is None or b is None or n == 0: return
        if exact:
            if c < b: bad.append(f"{label}: {c}/{n} < baseline {b}/{n}")
        else:
            lo_b, _ = S.wilson(b, n); _, hi_c = S.wilson(c, n)
            if (b - c) / n >= 0.10 and hi_c < lo_b + 0.0 or (b - c) / n >= 0.20: bad.append(f"{label}: {c}/{n} vs baseline {b}/{n} (drop {(b - c) / n:.0%}, Wilson CIs separated)")
    drop(base.get("pass"), cur.get("pass"), cur.get("n") or 0, "overall pass")
    for c, v in (base.get("by_category") or {}).items():
        cv = (cur.get("by_category") or {}).get(c)
        if cv: drop(v["pass"], cv["pass"], cv["n"], f"category {c}")
        else: bad.append(f"category {c} missing from current run")
    if (cur.get("violations") or 0) > (base.get("violations") or 0): bad.append(f"security violations {cur['violations']} > baseline {base['violations']}")
    if (cur.get("orphans") or 0) > (base.get("orphans") or 0): bad.append(f"orphan processes {cur['orphans']} > baseline {base['orphans']}")
    for k, v in (base.get("recovery") or {}).items():
        cv = (cur.get("recovery") or {}).get(k)
        if not cv: bad.append(f"recovery {k} missing"); continue
        if cv["recovered"] < v["recovered"]: bad.append(f"recovery {k}: {cv['recovered']}/{cv['n']} < baseline {v['recovered']}/{v['n']}")
        if (cv.get("dup") or 0) > (v.get("dup") or 0) + (0.01 if exact else 1.0): bad.append(f"recovery {k}: duplicated model requests {cv['dup']:.2f} > baseline {v['dup']:.2f}")
    if base.get("concurrency") and (cur.get("concurrency") or {}).get("passed", 0) < base["concurrency"]["passed"]: bad.append("concurrency: fewer tasks completed than baseline")
    tb, tc = base.get("tokens_per_validated"), cur.get("tokens_per_validated")
    if tb and tc and tc > tb * (1.05 if exact else 1.35): bad.append(f"tokens per validated task {tc:.0f} > baseline {tb:.0f} (+{tc / tb - 1:.0%})")
    return bad
