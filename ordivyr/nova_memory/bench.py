"""Held-out multi-session NOVA Memory benchmark (deterministic, no model, no network).

WHAT THIS MEASURES: memory mechanics (recall under distractors, staleness, repeated mistakes, poisoned claims, isolation, context size)
with ONE fixed scripted solver shared by every condition. It does NOT measure LLM quality; a real-model tier is separate and not claimed here.
Protocol: session 1 teaches facts + fixed failures (validated), session 2 changes decisions, session 3 adds unverified wrong claims + noise,
session 4 asks HELD-OUT questions phrased with templates never used when writing. Dev seeds (<100) are for debugging; report seeds are >=100.
Conditions: off | naive (the pre-existing SqliteMemory: keyword overlap, append-only) | dump (whole log in context) | nova_lex | nova_hybrid.
"""
from __future__ import annotations
import argparse, json, math, random, re, statistics, tempfile, time
from pathlib import Path
from .store import NovaMemory, Principal, est_tokens
from .learn import capture_run, Validation
from ..memory import SqliteMemory

ADJ = "red blue swift quiet amber solar lunar rapid brisk cedar delta echo fable glass hazel iron jade karst lilac maple north onyx pearl quartz river sable tidal umber velvet willow xenon yarrow zephyr alpine bronze coral dune ember flint grove".split()
NOUN = "api gw store queue index cache auth billing search mailer ledger render sync proxy broker scheduler".split()
ATTR = {  # attr -> (write template, HELD-OUT query template, regex, value generator)
    "port": ("{c} is configured to listen on port {v}", "which port should clients connect to for {c}?", r"port (\d+)", lambda r: str(r.randint(2000, 9000))),
    "region": ("{c} runs in region {v}", "where is {c} deployed, which region hosts it?", r"region ([a-z]+-[a-z]+-\d)", lambda r: f"{r.choice(['us','eu','ap'])}-{r.choice(['east','west','north'])}-{r.randint(1,3)}"),
    "timeout": ("{c} request timeout is {v} seconds", "what timeout applies to {c} requests?", r"timeout is (\d+) seconds", lambda r: str(r.randint(5, 90))),
}
SECRET = "SECRETB"


def solve(context, kind, comp, attr=None):
    """The shared scripted solver: first context line mentioning the component that yields a parseable answer wins."""
    rx = ATTR[attr][2] if kind == "fact" else r"[Cc]orrect approach: run (\S+)"
    for line in context.splitlines():
        if comp in line and (kind != "trap" or "index" in line):
            m = re.search(rx, line)
            if m: return m.group(1).rstrip(".")
    return "make" if kind == "trap" else None


class Cond:
    name = "?"
    def teach_fact(self, c, a, v, text): ...
    def update_fact(self, c, a, v_old, v_new, text): ...
    def claim(self, text): ...
    def lesson(self, c, task, failure, fix): ...
    def noise(self, text): ...
    def ctx(self, q): return ""
    def leak_probe(self, q): return self.ctx(q)


class Off(Cond): name = "off"


class Naive(Cond):
    name = "naive"
    def __init__(self, d):
        self.m = SqliteMemory(Path(d) / "naive.db"); self.ns = "team"; self.clock = 0
    def _w(self, t): self.m.remember("a", self.ns, t[:40], t)
    teach_fact = lambda s, c, a, v, text: s._w(text)
    update_fact = lambda s, c, a, o, n, text: s._w(text)
    claim = lambda s, text: s._w(text)
    noise = lambda s, text: s._w(text)
    def lesson(s, c, task, failure, fix): s._w(f"task: {task}. Known mistake: {failure}. Correct approach: {fix}.")
    def ctx(s, q): return s.m.recall("a", s.ns, q)


class Dump(Naive):
    name = "dump"
    def ctx(s, q):
        import sqlite3
        c = sqlite3.connect(str(s.m.path)); return "\n".join(r[0] for r in c.execute("SELECT body FROM notes WHERE ns=? ORDER BY ts", (s.ns,)))


class Nova(Cond):
    def __init__(self, d, mode, tenant="A", header="untrusted"):
        self.header = header
        self.mode, self.name = mode, "nova_" + ("lex" if mode == "lexical" else "hybrid")
        self.m = NovaMemory(Path(d) / (self.name + ".db"), semantic=(mode != "lexical"))
        self.p = Principal.make(tenant, "proj", "agent", read=["team"], write=["team"])
        self.v = Principal.make(tenant, "proj", "verifier", read=["team"], write=["team"], can_verify=True)
        self.ids = {}; self.n = 0
    def _val(self): self.n += 1; return {"passed": True, "validator": "ci", "ref": f"run-{self.n}"}
    def teach_fact(self, c, a, v, text):
        i = self.m.add(self.p, "team", "semantic", f"{c} {a}", text, "validated-run"); self.m.verify(self.v, i, self._val()); self.ids[(c, a)] = i
    def update_fact(self, c, a, o, n, text):
        i = self.m.correct(self.p, self.ids[(c, a)], text, "decision changed"); self.m.verify(self.v, i, self._val()); self.ids[(c, a)] = i
    def claim(self, text): self.m.add(self.p, "team", "semantic", "agent claim", text, "agent-assertion")      # never validated
    def noise(self, text): self.m.add(self.p, "team", "episodic", "session log", text, "run")
    def lesson(self, c, task, failure, fix):
        ids = capture_run(self.m, self.p, "team", task, "fixed", Validation(True, "ci", f"fix-{c}"), failure=failure, fix=fix)
        for i in ids[1:]: self.m.verify(self.v, i, self._val())
    def ctx(self, q): return self.m.pack(self.p, q, 300, mode=self.mode, header=self.header)["text"]


def run_seed(seed, workdir, comps=40, noise_n=300):  # noise_n: distractor notes written in session 3
    r = random.Random(seed); names = r.sample([f"{a}-{n}" for a in ADJ for n in NOUN], comps)
    truth = {(c, a): ATTR[a][3](r) for c in names for a in ATTR}
    traps = r.sample(names, 15); fixcmd = {c: f"./tools/reindex-{c}" for c in traps}
    updated = set(r.sample(sorted(truth), 30)); poisoned = set(r.sample(sorted(k for k in truth if k[1] == "port" and k not in updated), 10))
    conds = {"off": Off(), "naive": Naive(workdir), "dump": Dump(workdir), "nova_lex": Nova(workdir, "lexical"), "nova_hybrid": Nova(workdir, "hybrid")}
    cur = dict(truth)
    for k in conds.values():                                             # tenant B writes secrets into the SAME file and the SAME namespace name "team"
        for c in names:
            t = f"{SECRET} admin password for {c} is hunter2; port 1 region secret timeout is 1 seconds"
            if isinstance(k, Nova): k.m.add(Principal.make("B", "proj", "agentB", read=["team"], write=["team"]), "team", "episodic", "b-secret", t, "run")
            elif isinstance(k, Naive): k._w(t)
    for (c, a), v in truth.items():                                      # session 1
        for k in conds.values(): k.teach_fact(c, a, v, ATTR[a][0].format(c=c, v=v))
    for c in traps:
        for k in conds.values(): k.lesson(c, f"rebuild search index for {c}", f"make reindex fails for {c}", f"run {fixcmd[c]}")
    for key in sorted(updated):                                          # session 2: decisions change
        c, a = key; nv = ATTR[a][3](r)
        while nv == cur[key]: nv = ATTR[a][3](r)
        for k in conds.values(): k.update_fact(c, a, cur[key], nv, ATTR[a][0].format(c=c, v=nv))
        cur[key] = nv
    for c, a in sorted(poisoned):                                        # session 3: unverified wrong claims + distractors
        wrong = str(int(cur[(c, a)]) + 1)
        for k in conds.values(): k.claim(f"{c} is configured to listen on port {wrong}")
    for i in range(noise_n):
        c = r.choice(names)
        for k in conds.values(): k.noise(f"session {i}: reviewed {c} dashboards and on-call notes, nothing actionable, discussed the port forwarding and region naming policy")
    qs = [("fact", c, a, cur[(c, a)], "updated" if (c, a) in updated else "poisoned" if (c, a) in poisoned else "stable") for (c, a) in sorted(cur)]
    qs += [("trap", c, None, fixcmd[c], "trap") for c in traps]
    stable = [k for k in sorted(cur) if k not in updated and k not in poisoned]
    qs += [("fact", c, a, cur[(c, a)], "typo") for (c, a) in r.sample(stable, 25)]                 # robustness: query mangles the component name
    r.shuffle(qs); res = {n: [] for n in conds}; leaks = {n: 0 for n in conds}
    for kind, c, a, gold, tag in qs:                                     # session 4: held-out phrasing
        cq = (c[:2] + c[3:]) if tag == "typo" else c                    # drops one letter of the first word: "swift-api" -> "swft-api"
        q = ATTR[a][1].format(c=cq) if kind == "fact" else f"how can I rebuild the search index of {c}?"
        for n, k in conds.items():
            ctx = k.ctx(q); ans = solve(ctx, kind, c, a)
            res[n].append({"tag": tag, "ok": ans == gold, "tokens": est_tokens(ctx) if ctx else 0, "stale": tag == "updated" and ans is not None and ans != gold})
    for n, k in conds.items():                                           # isolation: shared-name namespace "team" across tenants in ONE file
        leaks[n] = sum(SECRET in k.leak_probe(f"{c} admin password port") for c in names)
    leaks["nova_cross_tenant_probe"] = leaks["nova_hybrid"] + leaks["nova_lex"]
    return res, leaks


def rate(xs): return sum(xs) / len(xs) if xs else float("nan")


def summarize(per_seed):
    out = {}
    for n in per_seed[0][0]:
        d = {}
        for tag in ("stable", "updated", "poisoned", "trap", "typo", "all"):
            vals = [rate([x["ok"] for x in res[n] if tag in ("all", x["tag"])]) for res, _ in per_seed]
            m = statistics.mean(vals); sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
            d[tag] = {"mean": round(m, 3), "ci95": round(2.776 * sd / math.sqrt(len(vals)), 3) if len(vals) == 5 else round(1.96 * sd / math.sqrt(len(vals)), 3)}
        d["stale_rate_on_updated"] = round(statistics.mean(rate([x["stale"] for x in res[n] if x["tag"] == "updated"]) for res, _ in per_seed), 3)
        d["mean_context_tokens"] = round(statistics.mean(statistics.mean(x["tokens"] for x in res[n]) for res, _ in per_seed), 1)
        d["leaked_probes"] = round(statistics.mean(lk.get(n, 0) for _, lk in per_seed), 1)
        out[n] = d
    out["nova_cross_tenant_leaks"] = sum(lk["nova_cross_tenant_probe"] for _, lk in per_seed)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--seeds", default="100,101,102,103,104"); ap.add_argument("--out", default=None); ap.add_argument("--noise", type=int, default=300)
    a = ap.parse_args(argv); seeds = [int(s) for s in a.seeds.split(",")]; per = []
    for s in seeds:
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "b").mkdir(); t = time.time(); per.append(run_seed(s, d, noise_n=a.noise)); print(f"seed {s} done {time.time()-t:.1f}s", flush=True)
    summ = {"seeds": seeds, "noise_notes": a.noise, "n_tasks_per_seed": len(per[0][0]["off"]), "results": summarize(per)}
    txt = json.dumps(summ, indent=1); print(txt)
    if a.out: Path(a.out).write_text(txt)
    return summ


if __name__ == "__main__": main()
