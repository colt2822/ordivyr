"""Durable worker: claims tasks from a Store/RemoteStore, keeps its lease alive, checkpoints, validates, and commits through the fence.

  python -m ordivyr.durable_worker --db FILE | --url URL --token-file F  --name W --node main --ws DIR [--ttl 6] [--kinds exec,agent]

Handlers: `exec` (run Python code in an isolated scratch dir) and `agent` (tool-using model loop -> files -> validator commands -> optional idempotent publish).
Self-fencing: if the worker cannot prove its lease for `ttl` seconds it abandons the task locally; the store rejects any late commit regardless (--no-self-abort is
a TEST switch that disables only the local abandon so the server-side fence can be demonstrated).
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess, sys, threading, time, traceback, urllib.error, urllib.request
from pathlib import Path
from . import agentloop as AL, durable as D, providers as PV
from .durable_net import RemoteError, RemoteStore

class ValidationFailed(Exception): pass

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
SKIP_DIRS = {".git"}          # integrity-critical (resume check + pre-promotion hash): only VCS metadata is excluded, exactly as before
def manifest(d):
    """sha256 of every file under d (VCS metadata excluded)."""
    d = Path(d); out = {}
    for root, dirs, files in os.walk(d):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for f in sorted(files):
            p = Path(root) / f
            if p.is_file(): out[str(p.relative_to(d))] = sha(p)
    return dict(sorted(out.items()))

class Ctx:
    def __init__(self, store, task, worker, node, ws, ttl, selfabort=True, batch=True):
        self.batch = batch; self.store, self.task, self.worker, self.node, self.ws, self.ttl, self.selfabort = store, task, worker, node, Path(ws), ttl, selfabort
        self.tid, self.fence, self.payload, self.checkpoint = task["id"], task["fence"], task["payload"], task["checkpoint"]
        self.lost, self.cancel, self.last_ok, self.stop = threading.Event(), threading.Event(), time.time(), threading.Event()
        self.dir = self.ws / str(self.tid) / f"a{self.fence}"; self.dir.mkdir(parents=True, exist_ok=True)
        self.local = isinstance(store, D.Store)
    def check(self):
        if self.lost.is_set(): raise D.StaleLease(f"task {self.tid}: lease lost (fence {self.fence})")
        if self.cancel.is_set(): raise D.Cancelled()
    def beat_loop(self):
        while not self.stop.wait(self.ttl / 3.0):
            try:
                if self.store.heartbeat(self.tid, self.fence, self.ttl) == "cancel": self.cancel.set()
                self.last_ok = time.time()
            except D.StaleLease: self.lost.set(); return
            except RemoteError:
                if self.selfabort and time.time() - self.last_ok > self.ttl: self.lost.set(); return      # cannot prove the lease -> stop acting on it
    def out(self, tool, args, output): self.store.record_output(self.tid, self.fence, tool, args, output)
    def write(self, *ops):
        """Adjacent fenced writes: ONE transaction when batching (same durability, one fsync), else the original one-call-per-op sequence (legacy/A-B)."""
        if self.batch: return self.store.apply(self.tid, self.fence, list(ops))
        for o in ops:
            k = o["op"]
            if k == "output": self.store.record_output(self.tid, self.fence, o["tool"], o.get("args"), o.get("output"))
            elif k == "checkpoint": self.store.checkpoint(self.tid, self.fence, o["phase"], o.get("data"))
            elif k == "evidence": self.store.add_evidence(self.tid, self.fence, o["name"], o.get("ok"), o.get("detail", ""))
            elif k == "begin": self.store.begin(self.tid, self.fence, o.get("phase", "running"))


class HeartbeatHub:
    """One thread renews EVERY live lease of a worker pool with a single heartbeat_many (instead of a thread + RPC per task). Fencing is unchanged: the store
    answers per lease; 'stale' marks that task lost, 'cancel' flags it, and a coordinator we cannot reach for > ttl makes the affected tasks abandon themselves."""
    def __init__(self, store, ttl, selfabort=True, log=lambda *a: None):
        self.store, self.ttl, self.selfabort, self.log = store, ttl, selfabort, log; self.ctxs = {}; self.lock = threading.Lock(); self.stop = threading.Event(); self.thread = None; self.rpcs = 0
    def start(self): self.thread = threading.Thread(target=self._run, daemon=True, name="ordivyr-hb-hub"); self.thread.start(); return self
    def add(self, ctx):
        with self.lock: self.ctxs[ctx.tid] = ctx
    def remove(self, ctx):
        with self.lock: self.ctxs.pop(ctx.tid, None)
    def beat_once(self):
        with self.lock: snap = list(self.ctxs.values())
        if not snap: return
        now = time.time()
        try:
            self.rpcs += 1; t0 = time.monotonic(); res = self.store.heartbeat_many([(c.tid, c.fence) for c in snap], self.ttl); dt = time.monotonic() - t0
            if dt > self.ttl / 2: self.log("heartbeat-slow", round(dt, 2), "leases", len(snap))             # a renewal that takes a large fraction of the TTL is how leases silently expire
        except RemoteError as e:
            self.log("heartbeat-failed", repr(e)[:200])
            for c in snap:
                if self.selfabort and now - c.last_ok > self.ttl: c.lost.set()
            return
        for c in snap:
            v = res.get(c.tid, "stale")
            if v == "stale": c.lost.set()
            elif v == "unknown":                                         # the shard that holds this lease is unreachable: not provably lost, not provably held
                if self.selfabort and now - c.last_ok > self.ttl: c.lost.set()
            else:
                c.last_ok = now
                if v == "cancel": c.cancel.set()
    def _run(self):
        while not self.stop.wait(self.ttl / 3.0):
            try: self.beat_once()
            except Exception as e: self.log("heartbeat-hub-error", repr(e))      # never let the renewal thread die: a dead hub would silently expire every lease
    def close(self): self.stop.set()

# ------------------------------------------------------------------ handlers
def _pdeathsig():
    """Child dies with the worker (Linux PR_SET_PDEATHSIG): a SIGKILLed worker never leaves a running subprocess behind."""
    try:
        import ctypes; ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, 9)
    except Exception: pass

def _run(ctx, argv, cwd, timeout, env=None):
    """Run a real subprocess, abandoning (killing) it the moment the lease is lost or cancel arrives."""
    p = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True, env=env, preexec_fn=_pdeathsig); t0 = time.time()
    try:
        while True:
            try: out, _ = p.communicate(timeout=0.2); return p.returncode, out
            except subprocess.TimeoutExpired: pass
            try: ctx.check()
            except (D.StaleLease, D.Cancelled): raise
            if time.time() - t0 > timeout: raise subprocess.TimeoutExpired(argv, timeout)
    except BaseException:
        try: os.killpg(p.pid, 9)
        except OSError: pass
        p.wait(); raise

def _env(): return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
def _argv(a): return [sys.executable, "-I"] + a[1:] if a and a[0] in ("python", "python3") else list(a)

def _sink_effect(ctx, key, body):
    sk = ctx.payload["sink"]; url = PV.check_base(sk["url"])
    if not PV.is_local(url): raise D.NeedsApproval("sink is not a local endpoint; publishing off-box needs explicit approval")
    def do(k):
        req = urllib.request.Request(url + "/effect", json.dumps(body).encode(), {"Content-Type": "application/json", "Idempotency-Key": k, "X-Delay-After": str(sk.get("delay_after", 0))}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r: return {"seq": json.loads(r.read())["seq"]}
        except (urllib.error.URLError, OSError) as e: raise D.Transient(f"sink unreachable: {e}")
    def reconcile(k):
        try:
            with urllib.request.urlopen(url + "/lookup?key=" + k, timeout=10) as r: j = json.loads(r.read())
            return ("committed", j["result"]) if j.get("found") else ("absent", None)
        except (urllib.error.URLError, OSError, ValueError): return ("unknown", None)
    return ctx.store.effect(ctx.tid, ctx.fence, key, do, reconcile)

def h_exec(ctx):
    p = ctx.payload; ctx.check()
    rc, out = _run(ctx, _argv(["python3", "-c", p["code"]]), ctx.dir, p.get("timeout", 120), _env())
    if rc != 0: ctx.out("exec", {"rc": rc}, out); ctx.check(); raise ValidationFailed(f"exec exit {rc}: {out[-500:]}")
    ctx.write({"op": "output", "tool": "exec", "args": {"rc": rc}, "output": out}, {"op": "checkpoint", "phase": "executed", "data": {"rc": rc}}); ctx.check()
    res = {"stdout": out, "rc": rc}
    if p.get("sink"): res["sink"] = _sink_effect(ctx, f"{ctx.task['idem_key'] or 'task-' + str(ctx.tid)}:publish", {"task": ctx.tid, "stdout": out})
    return res, None

def h_agent(ctx):
    p = ctx.payload; cp = ctx.checkpoint or {}; d = ctx.dir; steps = [0]
    prev = cp.get("dir") if cp.get("phase") in ("generated", "validated") else None
    if prev and Path(prev).is_dir() and manifest(prev) == cp.get("manifest"):
        if Path(prev) != d: shutil.rmtree(d, ignore_errors=True); shutil.copytree(prev, d)
        ctx.write({"op": "checkpoint", "phase": "generated", "data": {"dir": str(d), "manifest": cp["manifest"], "resumed_from": prev}}, {"op": "begin", "phase": "validating"})
    else:
        def on_step(name, args, out):
            ctx.check(); steps[0] += 1; ctx.write({"op": "output", "tool": name, "args": args, "output": out}, {"op": "checkpoint", "phase": "generating", "data": {"step": steps[0], "tool": name}})
        try:
            text, tokens, model, n, stop = AL.run("openai", p["base"], p.get("key", ""), p["model"], p.get("system", "You are a careful engineer. Use the tools."), p["prompt"],
                                                 AL.ToolBox(d, write=True, web=False, ask=False), timeout=p.get("request_timeout", 30), max_steps=p.get("max_steps", AL.MAX_STEPS), on_step=on_step)
        except PV.ProviderError as e:
            m = str(e)
            if "cannot reach" in m or "provider error 5" in m: raise D.Transient(m)
            raise
        ctx.check(); ctx.write({"op": "checkpoint", "phase": "generated", "data": {"dir": str(d), "manifest": manifest(d), "text": text[:2000], "tokens": tokens, "stop": stop}}, {"op": "begin", "phase": "validating"})
    done = {e["name"] for e in ctx.store.evidence(ctx.tid) if e["ok"]}; bad = []
    for v in p.get("validators", []):
        ctx.check()
        if v["name"] in done: continue                                    # evidence from an interrupted earlier attempt is kept, not recomputed
        try: rc, out = _run(ctx, _argv(v["cmd"]), d, v.get("timeout", 60), _env())
        except subprocess.TimeoutExpired: rc, out = 124, "validator timed out"
        ctx.store.add_evidence(ctx.tid, ctx.fence, v["name"], rc == 0, out[-4000:])
        if rc != 0: bad.append(f"{v['name']}: rc={rc}")
    if bad:
        ctx.store.checkpoint(ctx.tid, ctx.fence, "validation_failed", {"failed": bad}); raise ValidationFailed("validation failed: " + "; ".join(bad))
    mf = manifest(d); ctx.store.checkpoint(ctx.tid, ctx.fence, "validated", {"dir": str(d), "manifest": mf})
    res = {"files": mf, "validators": [v["name"] for v in p.get("validators", [])]}
    if p.get("sink"): res["sink"] = _sink_effect(ctx, f"{ctx.task['idem_key'] or 'task-' + str(ctx.tid)}:publish", {"task": ctx.tid, "files": mf})
    final = ctx.ws / str(ctx.tid) / "final"
    return res, (lambda: os.replace(d, final)) if ctx.local else None

def h_compute(ctx):
    """Deterministic CPU work (iterated SHA-256) with an optional wait standing in for model latency; the benchmark recomputes the digest independently to validate it."""
    p = ctx.payload; ctx.check(); h = str(p["seed"]).encode()
    for _ in range(int(p.get("rounds", 1000))): h = hashlib.sha256(h).digest()
    if p.get("think_s"): time.sleep(float(p["think_s"]))
    ctx.check(); d = h.hex()
    ctx.write({"op": "output", "tool": "compute", "args": {"rounds": p.get("rounds")}, "output": d}, {"op": "checkpoint", "phase": "computed", "data": {"digest": d}}, {"op": "evidence", "name": "digest_len", "ok": len(d) == 64})
    return {"digest": d}, None

def h_gw_agent(ctx):
    from .selfhost.agents import h_gw_agent as h
    return h(ctx)

HANDLERS = {"exec": h_exec, "agent": h_agent, "compute": h_compute, "gw_agent": h_gw_agent}

# ------------------------------------------------------------------ worker loop
def process(store, task, worker, node, ws, ttl, selfabort=True, log=lambda *a: None, hub=None, batch=True):
    ctx = Ctx(store, task, worker, node, ws, ttl, selfabort, batch); tid, fence = ctx.tid, ctx.fence
    if hub: hub.add(ctx)
    else: threading.Thread(target=ctx.beat_loop, daemon=True).start()
    try:
        h = HANDLERS.get(task["kind"])
        if h is None: return store.fail(tid, fence, f"no handler for kind {task['kind']!r}", retry=False)
        store.begin(tid, fence, "running"); res, promote = h(ctx); ctx.check()
        store.complete(tid, fence, res, promote=promote) if promote else store.complete(tid, fence, res); log("completed", tid)
    except D.StaleLease as e: log("stale", tid, str(e))                    # never commit: somebody else owns this task now
    except D.Cancelled: _safe(lambda: store.cancelled(tid, fence))
    except D.NeedsApproval as e: _safe(lambda: store.hold(tid, fence, str(e)))
    except D.Fatal as e: _safe(lambda: store.fail(tid, fence, str(e), retry=False))
    except D.Transient as e: _safe(lambda: store.release(tid, fence, str(e)))
    except ValidationFailed as e: _safe(lambda: store.fail(tid, fence, str(e)))
    except RemoteError as e: log("remote-unreachable", tid, str(e))        # lease will expire server-side; the task is re-assigned
    except subprocess.TimeoutExpired as e: _safe(lambda: store.fail(tid, fence, f"timeout: {e}"))
    except Exception as e: _safe(lambda: store.fail(tid, fence, f"{type(e).__name__}: {e}\n{traceback.format_exc()[-1500:]}"))
    finally:
        ctx.stop.set()
        if hub: hub.remove(ctx)

def _safe(fn):
    try: return fn()
    except (D.StaleLease, RemoteError): return None

def serve(store, name, node, ws, ttl=6.0, kinds=None, stop=None, selfabort=True, poll=0.25, log=lambda *a: None, longpoll=0.0):
    stop = stop or threading.Event()
    while not stop.is_set():
        try:
            if longpoll and hasattr(store, "claim_many_wait"): r = store.claim_many_wait(name, node, ttl, kinds, 1, wait_s=longpoll); t = r[0] if r else None
            else: t = store.claim(name, node, ttl, kinds)
        except RemoteError: stop.wait(1.0); continue
        if not t: stop.wait(poll); continue
        process(store, t, name, node, ws, ttl, selfabort, log)

def serve_pool(store, name, node, ws, slots=8, ttl=6.0, kinds=None, stop=None, selfabort=True, poll_min=0.05, poll_max=1.0, batch=True, log=lambda *a: None, longpoll=0.0, capacity_report=False):
    """Multi-slot worker: ONE claimer asks for exactly as many tasks as it has free slots (claim_many), a bounded thread pool executes them, and one HeartbeatHub renews
    all their leases. Idle polling backs off exponentially (poll_min -> poll_max) instead of hammering the coordinator; a task that dies cannot leak its slot."""
    from concurrent.futures import ThreadPoolExecutor
    stop = stop or threading.Event(); cv = threading.Condition(); inflight = [0]; hub = HeartbeatHub(store, ttl, selfabort, log).start(); ex = ThreadPoolExecutor(slots, thread_name_prefix="ordivyr-slot"); wait = poll_min; last_rep = [0.0]
    def one(t):
        try: process(store, t, name, node, ws, ttl, selfabort, log, hub, batch)
        except BaseException as e: log("slot-crash", t.get("id"), repr(e))          # lease is left to expire server-side and the task is re-queued
        finally:
            with cv: inflight[0] -= 1; cv.notify_all()
    try:
        while not stop.is_set():
            with cv:
                while inflight[0] >= slots and not stop.is_set(): cv.wait(0.5)
                free = slots - inflight[0]
            if stop.is_set(): break
            if capacity_report and time.time() - last_rep[0] > 15 and hasattr(store, "node_report"):          # tell the coordinator how much this node can run (best effort)
                last_rep[0] = time.time()
                try: store.node_report(node, slots)
                except Exception: pass
            try: ts = store.claim_many_wait(name, node, ttl, kinds, free, wait_s=longpoll) if longpoll and hasattr(store, "claim_many_wait") else store.claim_many(name, node, ttl, kinds, free)
            except (RemoteError, AttributeError): stop.wait(1.0); continue
            if not ts:
                if not (longpoll and hasattr(store, "claim_many_wait")): stop.wait(wait); wait = min(poll_max, wait * 2)
                continue
            wait = poll_min
            with cv: inflight[0] += len(ts)
            for t in ts: ex.submit(one, t)
    finally:
        ex.shutdown(wait=True); hub.close()

def main(argv=None):
    a = argparse.ArgumentParser(); a.add_argument("--db"); a.add_argument("--url"); a.add_argument("--token-file"); a.add_argument("--name", required=True); a.add_argument("--node", default="main")
    a.add_argument("--ws", required=True); a.add_argument("--ttl", type=float, default=6.0); a.add_argument("--kinds"); a.add_argument("--slots", type=int, default=1); a.add_argument("--longpoll", type=float, default=0.0); a.add_argument("--no-self-abort", action="store_true"); a = a.parse_args(argv)
    store = RemoteStore(a.url, Path(a.token_file).read_text().strip()) if a.url else D.Store(a.db)
    stop = threading.Event()
    import signal; signal.signal(signal.SIGTERM, lambda *_: stop.set()); signal.signal(signal.SIGINT, lambda *_: stop.set())
    kinds = a.kinds.split(",") if a.kinds else None; lg = lambda *x: print(*x, flush=True)
    if a.slots > 1 or a.longpoll: serve_pool(store, a.name, a.node, a.ws, a.slots, a.ttl, kinds, stop, not a.no_self_abort, log=lg, longpoll=a.longpoll)
    else: serve(store, a.name, a.node, a.ws, a.ttl, kinds, stop, not a.no_self_abort, log=lg)

if __name__ == "__main__": main()
