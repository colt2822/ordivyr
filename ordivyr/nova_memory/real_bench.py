"""Real-model NOVA Memory A/B (OpenAI-compatible endpoint; local only; no paid inference).

Same model, prompt template, temperature 0, max_tokens and validator for every condition; ONLY the MEMORY block differs.
The validator is independent of the model and of the memory system (exact value match against hidden gold).
World: per-seed synthetic project with unguessable values, so `off` is expected to fail by construction - the informative comparisons are
NOVA vs naive vs dump on updated facts (stale entries present), poisoned facts (misleading unverified claims), typo'd queries and repeated failures.
Repeated error = the model failed a trap task in session 1 (no memory yet), a validated human correction was recorded, and it fails the same task in session 4.
"""
from __future__ import annotations
import argparse, json, math, random, re, statistics, tempfile, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from . import bench as B

SYSTEM = ("You are a careful engineering assistant. Use the MEMORY block if it helps. If it contains conflicting statements, use your best judgment about which is "
          "current and trustworthy. Reply with ONLY the final value (or exact command), nothing else.")


class Model:
    def __init__(self, url, key, name): self.url, self.key, self.name = url.rstrip("/"), key, name
    def ask(self, memory, question, max_tokens=40):
        body = {"model": self.name, "temperature": 0, "max_tokens": max_tokens, "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": f"MEMORY:\n{memory or '(none)'}\n\nQUESTION: {question}"}]}
        req = urllib.request.Request(self.url + "/chat/completions", json.dumps(body).encode(), {"Content-Type": "application/json", "Authorization": "Bearer " + self.key})
        t = time.time()
        with urllib.request.urlopen(req, timeout=300) as r: j = json.loads(r.read())
        return j["choices"][0]["message"]["content"].strip(), j["usage"]["prompt_tokens"], j["usage"]["completion_tokens"], time.time() - t


def valid(kind, attr, gold, resp):
    """Independent validator: the response must contain the gold value and no other competing value of the same shape."""
    r = resp.strip().strip("`'\" ").rstrip(".")
    if kind == "trap": return gold in r and len(re.findall(r"\./tools/\S+", r)) == 1
    if attr in ("port", "timeout"): nums = re.findall(r"\d+", r); return nums == [gold] or (gold in nums and len(set(nums)) == 1)
    regs = re.findall(r"[a-z]+-[a-z]+-\d", r); return regs == [gold] or (gold in regs and len(set(regs)) == 1)


def build(seed, d, comps=20, noise_n=40, header="untrusted", conds_only=None):
    r = random.Random(seed); names = r.sample([f"{a}-{n}" for a in B.ADJ for n in B.NOUN], comps)
    truth = {(c, a): B.ATTR[a][3](r) for c in names for a in B.ATTR}
    traps = r.sample(names, 8); fixcmd = {c: f"./tools/reindex-{c}" for c in traps}
    keys = sorted(truth); updated = set(r.sample(keys, 12)); poisoned = set(r.sample([k for k in keys if k[1] == "port" and k not in updated], 6))
    conds = {"off": B.Off(), "naive": B.Naive(d), "dump": B.Dump(d), "nova": B.Nova(d, "hybrid", header=header)}
    if conds_only: conds = {k: v for k, v in conds.items() if k in conds_only}
    return r, names, truth, traps, fixcmd, updated, poisoned, conds


def run_seed(model, seed, d, noise_n=40, workers=2, header="untrusted", conds_only=None):
    r, names, truth, traps, fixcmd, updated, poisoned, conds = build(seed, d, noise_n=noise_n, header=header, conds_only=conds_only)
    cur = dict(truth); recs = []
    for k in conds.values():                                             # other tenant writes secrets into the same file+namespace
        for c in names:
            t = f"{B.SECRET} admin password for {c} is hunter2; port 1 region secret timeout is 1 seconds"
            if isinstance(k, B.Nova): k.m.add(B.Principal.make("B", "proj", "agentB", read=["team"], write=["team"]), "team", "episodic", "b-secret", t, "run")
            elif isinstance(k, B.Naive): k._w(t)
    for (c, a), v in truth.items():                                      # session 1: validated facts
        for k in conds.values(): k.teach_fact(c, a, v, B.ATTR[a][0].format(c=c, v=v))
    s1 = {}                                                              # session 1: trap tasks attempted with NO memory; failures get a validated human correction
    for c in traps:
        resp, *_ = model.ask("", f"What exact command should I run to rebuild the search index of {c}?")
        s1[c] = valid("trap", None, fixcmd[c], resp)
        if not s1[c]:
            for k in conds.values(): k.lesson(c, f"rebuild search index for {c}", f"the command '{resp[:60]}' does not work for {c}", f"run {fixcmd[c]}")
    for key in sorted(updated):                                          # session 2: decisions change
        c, a = key; nv = B.ATTR[a][3](r)
        while nv == cur[key]: nv = B.ATTR[a][3](r)
        for k in conds.values(): k.update_fact(c, a, cur[key], nv, B.ATTR[a][0].format(c=c, v=nv))
        cur[key] = nv
    for c, a in sorted(poisoned):                                        # session 3: unverified wrong claims + distractors
        for k in conds.values(): k.claim(f"{c} is configured to listen on port {int(cur[(c, a)]) + 1}")
    for i in range(noise_n):
        c = r.choice(names)
        for k in conds.values(): k.noise(f"session {i}: reviewed {c} dashboards and on-call notes, nothing actionable, discussed the port forwarding and region naming policy")
    stable = [k for k in sorted(cur) if k not in updated and k not in poisoned]
    qs = [("fact", c, a, cur[(c, a)], "updated") for (c, a) in sorted(updated)] + [("fact", c, a, cur[(c, a)], "poisoned") for (c, a) in sorted(poisoned)]
    ts = r.sample(stable, 20); qs += [("fact", c, a, cur[(c, a)], "stable") for (c, a) in ts[:12]] + [("fact", c, a, cur[(c, a)], "typo") for (c, a) in ts[12:]]
    qs += [("trap", c, None, fixcmd[c], "trap") for c in traps]
    jobs = []
    for kind, c, a, gold, tag in qs:                                     # session 4: held-out phrasing
        cq = (c[:2] + c[3:]) if tag == "typo" else c
        q = B.ATTR[a][1].format(c=cq) if kind == "fact" else f"What exact command should I run to rebuild the search index of {c}?"
        for n, k in conds.items(): jobs.append((n, kind, c, a, gold, tag, q, k.ctx(q)))
    def one(j):
        n, kind, c, a, gold, tag, q, ctx = j
        try: resp, pt, ct, lat = model.ask(ctx, q)
        except Exception as e: resp, pt, ct, lat = f"ERROR {e}", 0, 0, 0
        stale_in = tag == "updated" and ctx and any(re.search(rx, ln) for ln in ctx.splitlines() if c in ln for rx in [B.ATTR[a][2]]) and len({m for ln in ctx.splitlines() if c in ln for m in re.findall(B.ATTR[a][2], ln)}) > 1
        return {"cond": n, "tag": tag, "q": q, "ok": valid(kind, a, gold, resp), "resp": resp[:120], "gold": gold, "ctx_has_gold": gold in ctx, "ctx_conflict": bool(stale_in), "ctx_toks": B.est_tokens(ctx) if ctx else 0,
                "prompt_tokens": pt, "completion_tokens": ct, "latency_s": round(lat, 3), "leak": B.SECRET in ctx, "s1_fail": (not s1.get(c, True)) if kind == "trap" else None, "seed": seed}
    with ThreadPoolExecutor(workers) as ex: recs = list(ex.map(one, jobs))
    return recs


def tci(vals):
    n = len(vals); m = statistics.mean(vals); sd = statistics.stdev(vals) if n > 1 else 0.0
    t = {2: 12.71, 3: 4.30, 4: 3.18, 5: 2.78, 6: 2.57, 7: 2.45, 8: 2.36}.get(n, 1.96)
    return round(m, 3), round(t * sd / math.sqrt(n), 3)


def summarize(allrecs, seeds):
    out = {}
    for cond in [c for c in ("off", "naive", "dump", "nova") if any(x["cond"] == c for x in allrecs)]:
        d = {}
        for tag in ("updated", "poisoned", "stable", "typo", "trap", "all"):
            per = [statistics.mean(x["ok"] for x in allrecs if x["seed"] == s and x["cond"] == cond and tag in ("all", x["tag"])) for s in seeds]
            d[tag] = tci(per)
        rep = [[x for x in allrecs if x["seed"] == s and x["cond"] == cond and x["tag"] == "trap" and x["s1_fail"]] for s in seeds]
        rep = [statistics.mean(not x["ok"] for x in g) for g in rep if g]
        d["repeated_error_rate"] = tci(rep) if rep else None
        rs = [x for x in allrecs if x["cond"] == cond]
        d["retrieval_has_gold"] = round(statistics.mean(x["ctx_has_gold"] for x in rs), 3)
        d["ctx_conflict_rate_updated"] = round(statistics.mean(x["ctx_conflict"] for x in rs if x["tag"] == "updated"), 3)
        d["mean_prompt_tokens"] = round(statistics.mean(x["prompt_tokens"] for x in rs), 1); d["mean_latency_s"] = round(statistics.mean(x["latency_s"] for x in rs), 3)
        d["human_corrections_per_seed"] = round(statistics.mean(sum(not x["ok"] for x in allrecs if x["seed"] == s and x["cond"] == cond) for s in seeds), 2)
        d["tool_errors"] = sum(x["resp"].startswith("ERROR") for x in rs); d["leak_probes"] = sum(x["leak"] for x in rs)
        out[cond] = d
    paired = {}
    for other in [o for o in ("off", "naive", "dump") if any(x["cond"] == o for x in allrecs)]:
        diffs = [statistics.mean(x["ok"] for x in allrecs if x["seed"] == s and x["cond"] == "nova") - statistics.mean(x["ok"] for x in allrecs if x["seed"] == s and x["cond"] == other) for s in seeds]
        paired[f"nova_minus_{other}_all"] = tci(diffs)
    return {"per_condition": out, "paired_success_delta": paired}


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--url", required=True); ap.add_argument("--key-file", required=True); ap.add_argument("--model", required=True)
    ap.add_argument("--seeds", default="100,101,102,103,104,105"); ap.add_argument("--noise", type=int, default=40); ap.add_argument("--out", required=True); ap.add_argument("--workers", type=int, default=2); ap.add_argument("--header", default="untrusted"); ap.add_argument("--conds", default="")
    a = ap.parse_args(argv); model = Model(a.url, Path(a.key_file).read_text().strip(), a.model); seeds = [int(s) for s in a.seeds.split(",")]; allr = []
    for s in seeds:
        with tempfile.TemporaryDirectory() as d:
            t = time.time(); allr += run_seed(model, s, d, a.noise, a.workers, a.header, [c for c in a.conds.split(",") if c] or None); print(f"seed {s} {time.time()-t:.0f}s", flush=True)
    Path(a.out).write_text(json.dumps({"model": a.model, "seeds": seeds, "noise": a.noise, "header": a.header, "summary": summarize(allr, seeds), "records": allr}, indent=1))
    print(json.dumps(summarize(allr, seeds), indent=1))


if __name__ == "__main__": main()
