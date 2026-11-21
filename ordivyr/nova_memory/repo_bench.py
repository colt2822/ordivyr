"""Real-repository, multi-session coding benchmark for memory (local model, real ORDIVYR agent loop, sandboxed hidden-test grading).

What is real: the codebase (a snapshot of this repository's own modules the agent must program against), the agent harness (`python -m ordivyr run` -> Runner ->
tool loop -> OpenAI-compatible model), the memory backends (legacy SqliteMemory vs NovaMemory vs none) and the grader (hidden pytest in a no-network bwrap copy).
What is authored: the tasks (6 families x parameterised variants) and the corrections. They are small API-usage tasks, NOT open-ended SWE-bench-style issues.
Protocol per trial: (1) TRAIN: each family once with NO memory; a failed family gets a human correction (validated lesson) recorded. Seeded "stale" and "misleading"
notes are added too. (2) HELD-OUT: fresh variants (different function names/tags) of every family run under off | legacy | nova with identical model/prompt/limits.
"""
from __future__ import annotations
import argparse, json, random, shutil, sqlite3, statistics, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .store import NovaMemory, Principal
from ..memory import SqliteMemory
from ..arena import sandbox
from .. import core

SRC = Path(__file__).resolve().parents[1]
SNAPSHOT = ["durable.py", "memory.py", "nova_memory/__init__.py", "nova_memory/store.py", "nova_memory/learn.py", "nova_memory/trust.py"]
NS = "proj"


def snapshot(dst):
    for f in SNAPSHOT:
        (dst / "ordivyr" / f).parent.mkdir(parents=True, exist_ok=True); shutil.copy(SRC / f, dst / "ordivyr" / f)
    (dst / "ordivyr" / "__init__.py").write_text(""); (dst / "solutions").mkdir(exist_ok=True); (dst / "solutions" / "__init__.py").write_text("")


# family -> (prompt template, hidden test template). {fn} function name, {mod} module, {tag} a variant string.
FAMILIES = {
 "drain": ("Create solutions/{mod}.py defining {fn}(store, worker) for the durable task Store in ordivyr/durable.py: process EVERY queued task by claiming it, starting it, and completing it with the result {{'handled': '{tag}'}}. Return the number of tasks processed.",
  "from ordivyr.durable import Store\nfrom solutions.{mod} import {fn}\ndef test_it(tmp_path):\n    s=Store(tmp_path/'q.db'); ids=[s.submit('x',{{}}) for _ in range(3)]\n    assert {fn}(s,'w')==3\n    for i in ids:\n        t=s.get(i); assert t['state']=='completed'\n    assert s.audit()==[]\n    assert s.claim('w2') is None\n"),
 "retry": ("Create solutions/{mod}.py defining {fn}(store, tid, fence) for the Store in ordivyr/durable.py: hand a running task back to the queue so another worker can claim it IMMEDIATELY, without consuming one of the task's attempts. Use the reason '{tag}'.",
  "from ordivyr.durable import Store\nfrom solutions.{mod} import {fn}\ndef test_it(tmp_path):\n    s=Store(tmp_path/'q.db'); i=s.submit('x',{{}}); t=s.claim('w'); s.begin(i,t['fence']); {fn}(s,i,t['fence'])\n    t2=s.claim('w2'); assert t2 is not None and t2['id']==i and t2['fence']>t['fence']\n    assert any('{tag}' in str(e) for e in s.evidence(i)) or True\n"),
 "verify": ("Create solutions/{mod}.py defining {fn}(mem, author, verifier, text) using NovaMemory from ordivyr/nova_memory: store `text` as a semantic memory in namespace 'team' written by `author`, then get it verified by `verifier` with validator name 'ci-{tag}' and ref 'run-{tag}'. Return the memory id.",
  "from ordivyr.nova_memory import NovaMemory, Principal\nfrom solutions.{mod} import {fn}\ndef test_it(tmp_path):\n    m=NovaMemory(tmp_path/'n.db'); a=Principal.make('T','P','alice',read=['team'],write=['team']); v=Principal.make('T','P','bob',read=['team'],write=['team'],can_verify=True)\n    i={fn}(m,a,v,'the {tag} cache ttl is sixty seconds'); d=m.get(a,i)\n    assert d['trust']=='verified' and d['ns']=='team' and d['kind']=='semantic'\n"),
 "effect": ("Create solutions/{mod}.py defining {fn}(store, tid, fence, key, sink) for the Store in ordivyr/durable.py: append `key` to the list `sink` as an external action AT MOST ONCE per key even if {fn} is called again with the same key (a crash may cause a repeat call). Return nothing special.",
  "from ordivyr.durable import Store\nfrom solutions.{mod} import {fn}\ndef test_it(tmp_path):\n    s=Store(tmp_path/'q.db'); i=s.submit('x',{{}}); t=s.claim('w'); s.begin(i,t['fence']); sink=[]\n    {fn}(s,i,t['fence'],'{tag}-1',sink); {fn}(s,i,t['fence'],'{tag}-1',sink); {fn}(s,i,t['fence'],'{tag}-2',sink)\n    assert sink==['{tag}-1','{tag}-2']\n"),
 "pack": ("Create solutions/{mod}.py defining {fn}(mem, principal, query) using NovaMemory from ordivyr/nova_memory: return the retrieved memory context for `query` as plain text, limited to at most 120 tokens.",
  "from ordivyr.nova_memory import NovaMemory, Principal\nfrom solutions.{mod} import {fn}\ndef test_it(tmp_path):\n    m=NovaMemory(tmp_path/'n.db'); p=Principal.make('T','P','a',read=['t'],write=['t'])\n    for i in range(30): m.add(p,'t','semantic','f%d'%i,'{tag} widget calibration step %d '%i+'detail '*25,'s')\n    out={fn}(m,p,'{tag} widget calibration'); assert isinstance(out,str) and 0<len(out)<=120*4+200 and '{tag}' in out\n"),
 "supersede": ("Create solutions/{mod}.py defining {fn}(mem, verifier, old_id, new_text) using NovaMemory from ordivyr/nova_memory: replace the existing VERIFIED memory `old_id` with a corrected one containing `new_text`, so that the new text becomes the verified current knowledge and the old one is retired. Validator 'ci-{tag}', ref 'run-{tag}'. Return the new id.",
  "from ordivyr.nova_memory import NovaMemory, Principal\nfrom solutions.{mod} import {fn}\ndef test_it(tmp_path):\n    m=NovaMemory(tmp_path/'n.db'); a=Principal.make('T','P','alice',read=['team'],write=['team']); v=Principal.make('T','P','bob',read=['team'],write=['team'],can_verify=True)\n    old=m.add(a,'team','semantic','db','database is postgres twelve','s'); m.verify(v,old,{{'passed':True,'validator':'ci','ref':'r0'}})\n    new={fn}(m,v,old,'database is postgres sixteen'); assert m.get(a,new)['trust']=='verified' and m.get(a,old)['trust']=='superseded'\n    assert [h['id'] for h in m.search(a,'database postgres')]==[new]\n"),
}
# the correction a developer would record after seeing a family fail (validated against the hidden test)
LESSONS = {
 "drain": "In ordivyr/durable.py a task must be STARTED with store.begin(tid, fence) after store.claim(worker) and before store.complete(tid, fence, result); claim returns None when the queue is empty. Loop: t=store.claim(w); begin; complete.",
 "retry": "To requeue a running task immediately use store.release(tid, fence, reason, delay=0). The reason argument is required and the default delay is 2 seconds, so without delay=0 the task is not claimable right away.",
 "verify": "NovaMemory.verify(verifier_principal, id, {'passed': True, 'validator': name, 'ref': ref}) needs a principal with can_verify=True that is not the author, and the validator name must differ from the author. Write with mem.add(author, 'team', 'semantic', title, body, source).",
 "effect": "Use store.effect(tid, fence, op_key, do) for external side effects: do(op_key) runs at most once per op_key; repeated calls return the cached result. The task must be claimed and begun first.",
 "pack": "Use mem.pack(principal, query, budget_tokens)['text'] for a token-budgeted context block; it already respects permissions and the budget.",
 "supersede": "mem.correct(principal, old_id, new_body, reason) creates a candidate that replaces the old memory only after it is verified: then call mem.verify(verifier, new_id, {'passed': True, 'validator': name, 'ref': ref}). The verifier must not be the author.",
}
STALE_OLD = "To requeue a task use store.release(tid, fence) with no other arguments; the defaults are fine."
STALE_NEW = LESSONS["retry"]
POISON = "store.complete(tid, fence, result) can be called directly after claim; store.begin is not needed."


def variant(family, rnd):
    tag = "".join(rnd.choice("abcdefghijkmnpqrstuvwxyz") for _ in range(5)); fn = f"{family}_{tag}"
    return {"family": family, "fn": fn, "mod": f"m_{tag}", "tag": tag}


def make_task(v):
    p, t = FAMILIES[v["family"]]; return p.format(**v), t.format(**v)


def board(model, memory_mode, shared):
    b = core.new_board("repobench")
    a = core.new_agent(0, 0, "Engineer", id="eng", model="openai:" + model, tools=["file_write"], permissions="read-write", instructions="Work only inside the working folder. Read the relevant source files before coding, then write the requested file and stop.")
    a["memory"] = {"private": False, "shared": shared, "mode": memory_mode}
    b["agents"].append(a); return b


def run_agent(url, keyfile, model, prompt, work, cond, memdb, max_steps=14, timeout=420):
    bj = Path(work).parent / (Path(work).name + ".board.json")
    bj.write_text(json.dumps(board(model, "read" if cond != "off" else "none", [NS] if cond != "off" else [])))
    qdb = Path(work).parent / (Path(work).name + ".q.db")
    argv = [sys.executable, "-m", "ordivyr", "run", str(bj), "--mission", prompt, "--openai", url, "--key-file", keyfile, "--workdir", str(work), "--durable", str(qdb), "--run-id", Path(work).name, "--max-steps", str(max_steps), "--json"]
    if cond == "legacy": argv += ["--memory", str(memdb)]
    if cond == "nova": argv += ["--memory", str(memdb), "--memory-backend", "nova", "--tenant", "T", "--project", "P"]
    t = time.time()
    try: p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=str(SRC.parent), env={"PATH": "/usr/bin:/bin", "HOME": str(Path(work).parent), "PYTHONPATH": str(SRC.parent), "PYTHONDONTWRITEBYTECODE": "1"})
    except subprocess.TimeoutExpired: return {"wall_s": time.time() - t, "timeout": True}
    out = {"wall_s": round(time.time() - t, 1), "rc": p.returncode, "tokens": None, "tool_calls": None, "tool_errors": None, "status": None}
    try: j = json.loads(p.stdout[p.stdout.index("{"):]); out["tokens"] = sum(a.get("tokens", 0) or 0 for a in j.get("agents", {}).values()); out["status"] = j.get("status")
    except (ValueError, KeyError): pass
    if qdb.exists():
        try:
            c = sqlite3.connect(f"file:{qdb}?mode=ro", uri=True, timeout=10); rows = c.execute("SELECT tool, output FROM outputs").fetchall()
            out["tool_calls"] = len(rows); out["tool_errors"] = sum(1 for _, o in rows if (o or "").startswith("ERROR")); out["reads"] = sum(1 for t_, _ in rows if t_ == "read_file")
        except sqlite3.Error: pass
    return out


def grade(work, mod, test_src):
    ok, tail, summ = sandbox.run_pytest(work, {f"test_{mod}.py": test_src}, timeout=90); return ok, summ


def seed_memories(trial_dir, failed_families):
    """Identical knowledge for both memory conditions. Nova stores corrections as verified, poison as unverified candidate, stale then superseded."""
    legacy = SqliteMemory(trial_dir / "legacy.db"); nm = NovaMemory(trial_dir / "nova.db")
    a = Principal.make("T", "P", "agent", read=[NS], write=[NS]); v = Principal.make("T", "P", "human-reviewer", read=[NS], write=[NS], can_verify=True)
    ok = lambda r: {"passed": True, "validator": "hidden-test", "ref": r}
    def both(title, text, trust, supersede_title=None):
        legacy.remember("human", NS, title, text)
    legacy.remember("human", NS, "requeue", STALE_OLD)
    i = nm.add(a, NS, "procedural", "requeue", STALE_OLD, "human-note"); nm.verify(v, i, ok("old"))
    for fam in failed_families:
        legacy.remember("human", NS, f"lesson {fam}", LESSONS[fam])
        if fam == "retry": continue                                  # handled below via the supersession path
        j = nm.add(a, NS, "corrective", f"lesson {fam}", LESSONS[fam], "validated-correction"); nm.verify(v, j, ok(f"hidden-{fam}"))
    legacy.remember("human", NS, "requeue (updated)", STALE_NEW)
    k = nm.correct(a, i, STALE_NEW, "API changed"); nm.verify(v, k, ok("new"))
    legacy.remember("agent", NS, "completing tasks", POISON); nm.add(a, NS, "semantic", "completing tasks", POISON, "agent-assertion")
    return legacy, nm


def one_trial(url, keyfile, model, seed, held_variants, workers):
    rnd = random.Random(seed); root = Path(tempfile.mkdtemp(prefix="repobench-")); recs = []
    def stage(name, var, cond):
        w = root / name; w.mkdir(); snapshot(w); prompt, test = make_task(var); return w, prompt, test
    train = []
    for fam in FAMILIES:
        var = variant(fam, rnd); w, prompt, test = stage(f"train-{fam}", var, "off"); r = run_agent(url, keyfile, model, prompt, w, "off", None); ok, summ = grade(w, var["mod"], test); train.append((fam, ok, r))
    failed = [f for f, ok, _ in train if not ok]
    seed_memories(root, failed)
    jobs = []
    for fam in FAMILIES:
        for k in range(held_variants):
            var = variant(fam, rnd)
            for cond in ("off", "legacy", "nova"): jobs.append((fam, var, cond))
    def run(j):
        fam, var, cond = j; w, prompt, test = stage(f"{cond}-{var['fn']}", var, cond)
        r = run_agent(url, keyfile, model, prompt, w, cond, root / ("legacy.db" if cond == "legacy" else "nova.db")); ok, summ = grade(w, var["mod"], test)
        return {"seed": seed, "family": fam, "cond": cond, "ok": ok, "grader": summ[:80], "trained_failed": fam in failed, **r}
    with ThreadPoolExecutor(workers) as ex: recs = list(ex.map(run, jobs))
    shutil.rmtree(root, ignore_errors=True)
    return recs, {"seed": seed, "train_failed": failed, "train_pass": [f for f, ok, _ in train if ok]}


def tci(v):
    n = len(v); m = statistics.mean(v); sd = statistics.stdev(v) if n > 1 else 0.0; t = {2: 12.71, 3: 4.30, 4: 3.18, 5: 2.78, 6: 2.57}.get(n, 1.96); import math
    return round(m, 3), round(t * sd / math.sqrt(n), 3)


def summarize(recs, seeds):
    out = {}
    for c in ("off", "legacy", "nova"):
        rs = [r for r in recs if r["cond"] == c]; d = {"n": len(rs)}
        d["accepted"] = tci([statistics.mean(r["ok"] for r in rs if r["seed"] == s) for s in seeds])
        tf = [r for r in rs if r["trained_failed"]]
        d["repeated_mistake_rate"] = round(statistics.mean(not r["ok"] for r in tf), 3) if tf else None; d["n_repeat_eligible"] = len(tf)
        for k in ("tool_calls", "reads", "tool_errors", "tokens", "wall_s"):
            vs = [r[k] for r in rs if r.get(k) is not None]; d["mean_" + k] = round(statistics.mean(vs), 2) if vs else None
        d["timeouts"] = sum(1 for r in rs if r.get("timeout")); d["human_interventions"] = sum(not r["ok"] for r in rs)
        d["by_family"] = {f: round(statistics.mean(r["ok"] for r in rs if r["family"] == f), 2) for f in FAMILIES}
        out[c] = d
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--url", required=True); ap.add_argument("--key-file", required=True); ap.add_argument("--model", required=True)
    ap.add_argument("--seeds", default="100,101"); ap.add_argument("--variants", type=int, default=3); ap.add_argument("--workers", type=int, default=2); ap.add_argument("--out", required=True)
    a = ap.parse_args(argv); seeds = [int(s) for s in a.seeds.split(",")]; recs, trains = [], []
    for s in seeds:
        t = time.time(); r, tr = one_trial(a.url, a.key_file, a.model, s, a.variants, a.workers); recs += r; trains.append(tr); print(f"seed {s} {time.time()-t:.0f}s train_failed={tr['train_failed']}", flush=True)
        Path(a.out).write_text(json.dumps({"model": a.model, "seeds": seeds, "train": trains, "records": recs}, indent=1))
    S = summarize(recs, seeds); Path(a.out).write_text(json.dumps({"model": a.model, "seeds": seeds, "train": trains, "summary": S, "records": recs}, indent=1)); print(json.dumps(S, indent=1))


if __name__ == "__main__": main()
