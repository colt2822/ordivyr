"""NOVA Memory scale benchmark: retrieval latency and accuracy at 1k / 10k / 50k / 100k records, exact full scan vs indexed candidate path.

  python -m ordivyr.nova_memory.scale_bench --sizes 1000,10000,50000,100000 [--queries 40] [--out FILE]

SYNTHETIC corpus (deterministic, seeded): topic vocabularies of pronounceable pseudo-words, every note carries the same task-frame boilerplate (the case IDF exists for),
and PLANTED notes hold a unique marker word. A query = topic words of the planted note + its marker. Reported per size:
  latency  : p50/p95/p99 ms of search() for the exact path (INDEX_MIN forced huge) and the indexed path (default), same queries, warm
  recall@5 : fraction of queries whose planted note is in the top 5     agreement@8 : mean overlap of the two paths' top-8 id sets (fidelity of the indexed path to the exact one)
  also     : build seconds (bulk add_many), db size, audit() seconds with 1% verified rows, delete-then-search leak check.
Synthetic text says nothing about real-world retrieval quality; the real-text ranking benchmark is nova_memory.retrieval_bench.
"""
from __future__ import annotations
import argparse, json, random, statistics, tempfile, time
from pathlib import Path
from . import store as S

BOILER = "task frame when running the agent workflow check the repository status then report the result back to the team lead"


def word(rng, n=6):
    cs, vs = "bcdfghklmnprstvz", "aeiou"; return "".join(rng.choice(cs) + rng.choice(vs) for _ in range(n // 2))


def corpus(n, seed=7, topics=300, per_topic=40, planted=40):
    rng = random.Random(seed); vocab = [[word(rng, rng.choice((6, 8))) for _ in range(per_topic)] for _ in range(topics)]
    items = []; marks = {}
    for i in range(n):
        ts = rng.sample(range(topics), 2); ws = rng.sample(vocab[ts[0]], 7) + rng.sample(vocab[ts[1]], 5); rng.shuffle(ws)
        items.append({"ns": "team", "kind": "semantic", "title": " ".join(ws[:3]), "body": f"{BOILER}. " + " ".join(ws) + f" record {i}", "source": "synthetic"})
    for k in range(planted):
        idx = rng.randrange(n); ts = rng.sample(range(topics), 2); ws = rng.sample(vocab[ts[0]], 6) + rng.sample(vocab[ts[1]], 4); mk = "qx" + word(rng, 8)
        items[idx]["body"] = f"{BOILER}. " + " ".join(ws) + f" {mk} planted {k}"; items[idx]["title"] = " ".join(ws[:2]) + " " + mk
        marks[k] = (idx, " ".join(rng.sample(ws, 5)) + " " + mk)
    return items, marks


def pct(xs, q):
    xs = sorted(xs); return round(xs[min(len(xs) - 1, int(len(xs) * q / 100))] * 1000, 2) if xs else None


def level(n, queries, root):
    d = Path(tempfile.mkdtemp(prefix="nova-scale-", dir=root)); m = S.NovaMemory(d / "m.db", key_path=d / "k.key"); p = S.Principal.make("T", "P", "bench", read=["team"], write=["team"])
    v = S.Principal.make("T", "P", "ver", read=["team"], write=["team"], can_verify=True)
    items, marks = corpus(n); t0 = time.time(); ids = []
    for i in range(0, n, 5000): ids += m.add_many(p, items[i:i + 5000])
    build = time.time() - t0; qs = list(marks.items())[:queries]; res = {"records": n, "build_s": round(build, 1), "db_mb": round(sum(f.stat().st_size for f in d.glob("m.db*")) / 1048576, 1)}
    for kk in range(max(1, n // 100)):
        if kk >= 500: break
        m.verify(v, ids[kk], {"passed": True, "validator": "ci", "ref": f"r{kk}"})
    t = time.time(); bad = m.audit(); res["audit_s_with_verified"] = round(time.time() - t, 3); res["audit_bad"] = len(bad)
    keep = S.INDEX_MIN; out = {}
    for label, im in (("exact", 10 ** 9), ("indexed", keep)):
        S.INDEX_MIN = im; lat = []; found = []; top8 = {}
        for _ in range(2): m.search(p, qs[0][1][1], k=8)                                         # warm
        for k, (idx, q) in qs:
            t = time.time(); hits = m.search(p, q, k=8); lat.append(time.time() - t); got = [h["id"] for h in hits]; top8[k] = set(got)
            found.append(ids[idx] in got[:5])
        out[label] = {"p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99), "recall_at_5": round(sum(found) / len(found), 3), "path": m.last_path, "top8": top8}
    S.INDEX_MIN = keep
    agree = [len(out["exact"]["top8"][k] & out["indexed"]["top8"][k]) / max(1, len(out["exact"]["top8"][k] | out["indexed"]["top8"][k])) for k in out["exact"]["top8"]]
    for lbl in out: out[lbl].pop("top8")
    res.update(out); res["agreement_at_8_jaccard"] = round(statistics.mean(agree), 3)
    victim = ids[marks[qs[0][0]][0]]; m.delete(v, victim, "bench"); S.INDEX_MIN = keep
    res["deleted_note_still_returned"] = victim in [h["id"] for h in m.search(p, qs[0][1][1], k=8)]
    with m._c() as c: res["vdf_rows"] = c.execute("SELECT COUNT(*) FROM vdf").fetchone()[0]
    return res


def main(argv=None):
    a = argparse.ArgumentParser(); a.add_argument("--sizes", default="1000,10000"); a.add_argument("--queries", type=int, default=30); a.add_argument("--out"); a.add_argument("--root", default=None); a = a.parse_args(argv)
    rs = []
    for n in map(int, a.sizes.split(",")):
        r = level(n, a.queries, a.root); rs.append(r); print(json.dumps(r), flush=True)
    if a.out: Path(a.out).parent.mkdir(parents=True, exist_ok=True); Path(a.out).write_text(json.dumps(rs, indent=1))


if __name__ == "__main__": main()
