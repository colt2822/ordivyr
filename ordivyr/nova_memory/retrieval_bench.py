"""Retrieval-ranking benchmark for project memory (deterministic; NO model, NO network).

Question it answers: when an agent gets a task phrased in *user words*, does the memory backend put the right lesson in the context block, ahead of
distractors, without serving superseded notes or unverified claims that contradict it?  It does NOT measure whether a model then solves the task.

Fixtures are authored cases (lesson written in API/ops words, task written in plain words with little lexical overlap), embedded in a corpus of generated
distractor notes that reuse the same boilerplate vocabulary as the task frame. Two disjoint case sets exist: DEV (used while changing code) and HELD
(authored after the code under test was frozen and run once). Usage:
    python3 -m ordivyr.nova_memory.retrieval_bench --set dev|held [--seeds 5] [--sizes 20,120,400] [--json out.json]
"""
from __future__ import annotations
import argparse, json, random, statistics, sys, tempfile, pathlib
from .store import NovaMemory, Principal
from ..memory import SqliteMemory

NS = "proj"
FRAME = "Task for the {svc} service: {task} Add tests and keep the change small."
SERVICES = ["billing", "catalog", "scheduler", "gateway", "notifier", "reports"]

# (key, title, lesson, task, stale|None, failed_approach|None, poison|None)
DEV = [
 ("webhook", "webhook signing", "Webhook signatures must be computed over the raw request body bytes with HMAC-SHA256 and compared with hmac.compare_digest; re-serialising the parsed JSON changes whitespace and breaks verification.",
  "Our partner says some of their callbacks keep getting rejected as forged even though the shared secret is right. Make the receiver accept the genuine ones.", None,
  "Tried re-encoding the decoded payload with sorted keys before hashing; genuine callbacks were still rejected.", None),
 ("paging", "pagination", "List endpoints paginate with an opaque cursor token returned as next_cursor; passing page=N is ignored and silently returns the first page.",
  "Write a loop that fetches every customer record from the API, not just the first batch.", "List endpoints take page and per_page query parameters; iterate page until the response is empty.", None, None),
 ("tz", "timezone", "Store all timestamps as UTC epoch seconds; the job runner interprets naive datetimes in the server's local zone, which shifted runs by an hour at DST changes.",
  "Nightly reports started going out at the wrong time after the clocks changed in March. Fix it.", None, "Hard-coded a +1 hour offset in the cron expression; it broke again in autumn.", None),
 ("cache", "cache invalidation", "After writing a product call cache.invalidate(prefix='product:'+id); the 24h TTL is not shortened by writes.",
  "Shoppers keep seeing the old price after an editor updates an item.", "Cached product entries expire automatically a few seconds after the database changes, no action needed.", None, None),
 ("upload", "large uploads", "Uploads above 8 MB must use the multipart session endpoint (create_session, put_part, complete); a single PUT returns 413.",
  "Users cannot attach their long videos to a ticket, though small pictures work fine.", None, None, "Raising the proxy body limit to 100 MB is enough for big attachments."),
 ("migrate", "schema migrations", "Run schema migrations with the advisory lock enabled (--lock); two deploys running alembic concurrently once corrupted the version table.",
  "Two engineers rolled out at the very same moment and the database ended up in a strange state. Make sure that cannot happen.", None,
  "Added a sleep before the migration step hoping deploys would not overlap; they still collided.", None),
 ("ratelimit", "vendor rate limit", "The vendor API allows 50 requests per 10-second window per key and answers 429 with a Retry-After header; honour the header instead of fixed sleeps.",
  "Our bulk sync gets blocked after a few seconds. Make it finish reliably.", "The vendor API has no request limits, send as fast as you like.", None, None),
 ("keyrot", "signing key rotation", "Rotate the signing key by adding the new key as secondary first (kid header), deploy, then promote it; replacing it in one step invalidates live sessions.",
  "We need to change the key that protects user logins without kicking everybody out.", None, None, None),
 ("csvbom", "csv import encoding", "CSV imports must open files with encoding='utf-8-sig'; Excel exports include a byte-order mark that becomes part of the first column name.",
  "The first column of the spreadsheet we receive from finance is never recognised by the importer.", None, None, "Strip whitespace from every cell and the header problem goes away."),
 ("probes", "readiness vs liveness", "The readiness probe should check the database connection pool but the liveness probe must not; failing liveness on a database blip restarts every pod and prolongs the outage.",
  "During a short database hiccup all of our containers kept being restarted. Adjust the checks.", None, None, None),
 ("dedupe", "message deduplication", "Queue messages are delivered at least once; deduplicate consumers on message_id stored in a processed table inside the same transaction as the side effect.",
  "Customers occasionally get two confirmation emails for a single order.", "The queue guarantees exactly-once delivery, so consumers need no extra checks.", None, None),
 ("flags", "feature flags", "Feature flags are evaluated once per request and cached on the request context; toggling one mid-request has no effect until the next request.",
  "I flipped the new checkout switch while testing and the page I had open still behaved the old way.", None, None, None),
 ("logrot", "log rotation", "Use logrotate with copytruncate for the worker process; it keeps its file handle open, and a plain move leaves it writing into the rotated file.",
  "After the weekly cleanup the application logs vanished from the live file even though the app is still running.", None, "Restarted the app after every rotation; works but drops requests during restart.", None),
 ("collate", "name sorting", "Sort user-facing names with locale.strxfrm or ICU collation; the default code-point sort places accented names after Z.",
  "Names starting with É or Ö show up at the very end of the alphabetical directory.", None, None, None),
]

NOISE_A = ["service", "task", "worker", "queue", "config", "deploy", "tests", "change", "module", "request", "timeout", "retry", "handler", "schema", "release", "review"]
NOISE_B = ["metrics dashboard", "invoice template", "onboarding email", "search index", "audit export", "admin banner", "session cookie", "image resizer", "report footer",
           "tenant settings", "backup window", "alert threshold", "user avatar", "API explorer", "sandbox account", "changelog page"]
NOISE_T = ["The {b} uses the {a} defaults unless the {a} option is overridden in the {b} file.",
           "When the {a} fails the {b} logs a warning and continues; nobody has needed to change the {a} before.",
           "Documented in the wiki: the {b} is owned by the platform team and its {a} is reviewed every quarter.",
           "Ticket history: the {b} {a} was renamed last year; old scripts may still mention the previous {a} name.",
           "For the {b}, prefer small {a} changes with tests; large {a} rewrites were rejected in review.",
           "The {b} {a} runs nightly. Its {a} output is archived with the other {a} reports."]

def noise(rnd, n):
    out = []
    for _ in range(n):
        t = rnd.choice(NOISE_T); out.append((rnd.choice(NOISE_B), t.format(a=rnd.choice(NOISE_A), b=rnd.choice(NOISE_B))))
    return out

def load_cases(which):
    cases = DEV if which == "dev" else __import__("ordivyr.nova_memory.retrieval_heldout", fromlist=["HELD"]).HELD
    return cases

def build(cases, size, seed, lesson_trust="verified", backend="nova"):
    """Returns (backend_obj, ids) where ids[key] = lesson memory id (nova) or None."""
    rnd = random.Random(seed); d = pathlib.Path(tempfile.mkdtemp(prefix="rb-"))
    P = Principal.make("T", "P", "agent", read=[NS], write=[NS]); V = Principal.make("T", "P", "reviewer", read=[NS], write=[NS], can_verify=True)
    ok = lambda r: {"passed": True, "validator": "review", "ref": r}
    items = [("lesson", c) for c in cases]; extra = noise(rnd, size)
    order = [(0, ("n", e)) for e in extra] + [(1, ("l", c)) for c in cases]; rnd.shuffle(order)
    if backend == "legacy":
        m = SqliteMemory(d / "legacy.db")
        for _, (k, x) in order:
            if k == "n": m.remember("n", NS, x[0], x[1])
            else:
                key, title, lesson, task, stale, failed, poison = x
                if stale: m.remember("h", NS, title, stale)
                m.remember("h", NS, title + " (updated)" if stale else title, lesson)
                if failed: m.remember("a", NS, "failed approach: " + title, failed)
                if poison: m.remember("a", NS, title, poison)
        return m, {}
    m = NovaMemory(d / "nova.db", query_idf=(backend != "nova-noidf")); ids = {}
    for _, (k, x) in order:
        if k == "n": m.add(P, NS, "semantic", x[0], x[1], "note")
        else:
            key, title, lesson, task, stale, failed, poison = x
            if stale:
                si = m.add(P, NS, "procedural", title, stale, "human-note"); m.verify(V, si, ok("old"))
                li = m.correct(P, si, lesson, "api changed")
            else:
                li = m.add(P, NS, "corrective", title, lesson, "validated-correction")
            if lesson_trust == "verified": m.verify(V, li, ok("v-" + key))
            ids[key] = li
            if failed: m.add(P, NS, "corrective", "failed approach: " + title, failed, "run-log")
            if poison: m.add(P, NS, "semantic", title, poison, "agent-assertion")
    return (m, P), ids

def evaluate(cases, size, seed, lesson_trust, backend, budget=500):
    obj, ids = build(cases, size, seed, lesson_trust, backend)
    rnd = random.Random(seed * 7 + 1); res = []
    for c in cases:
        key, title, lesson, task, stale, failed, poison = c
        q = FRAME.format(svc=rnd.choice(SERVICES), task=task)
        if backend == "legacy":
            txt = obj.recall("a", NS, q); present = lesson[:50] in txt
            order = [r for r in [(txt.find(lesson[:50]), 0)] if r[0] >= 0]
            pos = txt.find(lesson[:50]); hit1 = present and not any(0 <= txt.find(o[2][:50]) < pos for o in cases if o is not c)
            res.append({"hit1": hit1, "pack": present, "rr": 1.0 if hit1 else (0.5 if present else 0.0),
                        "stale": bool(stale) and stale[:50] in txt, "poison": bool(poison) and poison[:50] in txt and (txt.find(poison[:50]) < pos if present else True),
                        "failed": bool(failed) and failed[:50] in txt})
            continue
        m, P = obj; hits = m.search(P, q, k=20, namespaces=[NS]); idl = [h["id"] for h in hits]; lid = ids[key]
        rank = idl.index(lid) + 1 if lid in idl else None
        pk = m.pack(P, q, budget, namespaces=[NS]); txt = pk["text"]
        res.append({"hit1": rank == 1, "pack": lid in pk["ids"], "rr": 1.0 / rank if rank else 0.0,
                    "stale": bool(stale) and stale[:50] in txt, "poison": bool(poison) and poison[:50] in txt and (lid not in pk["ids"] or txt.find(poison[:50]) < txt.find(lesson[:50])),
                    "failed": bool(failed) and failed[:50] in txt})
    n = len(res)
    return {"hit1": sum(r["hit1"] for r in res) / n, "pack": sum(r["pack"] for r in res) / n, "mrr": sum(r["rr"] for r in res) / n,
            "stale_leak": sum(r["stale"] for r in res) / max(1, sum(1 for c in cases if c[4])), "poison_first": sum(r["poison"] for r in res) / max(1, sum(1 for c in cases if c[6])),
            "failed_in_pack": sum(r["failed"] for r in res) / max(1, sum(1 for c in cases if c[5]))}

def run(which, seeds, sizes, trusts=("verified", "candidate")):
    cases = load_cases(which); out = {}
    for backend in ("legacy", "nova-noidf", "nova"):
        for trust in (trusts if backend != "legacy" else ("-",)):
            for size in sizes:
                rs = [evaluate(cases, size, 1000 + s, trust, backend) for s in range(seeds)]
                key = f"{backend}/{trust}/N={size}"
                out[key] = {m: round(statistics.mean(r[m] for r in rs), 3) for m in rs[0]}
                out[key]["_sd_hit1"] = round(statistics.pstdev(r["hit1"] for r in rs), 3)
    return out

def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--set", choices=["dev", "held"], default="dev"); ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--sizes", default="20,120,400"); ap.add_argument("--json"); a = ap.parse_args(argv)
    res = run(a.set, a.seeds, [int(x) for x in a.sizes.split(",")])
    print(f"set={a.set} cases={len(load_cases(a.set))} seeds={a.seeds}")
    print(f"{'backend/lesson-trust/corpus':28} {'hit@1':>6} {'in-pack':>8} {'MRR':>6} {'stale-leak':>11} {'poison-first':>13} {'failed-in-pack':>15}")
    for k, v in res.items(): print(f"{k:28} {v['hit1']:6.3f} {v['pack']:8.3f} {v['mrr']:6.3f} {v['stale_leak']:11.3f} {v['poison_first']:13.3f} {v['failed_in_pack']:15.3f}")
    if a.json: pathlib.Path(a.json).write_text(json.dumps({"set": a.set, "results": res}, indent=1))

if __name__ == "__main__":
    main()
