"""Run orchestration: scenarios (tasks | recovery | concurrency), interleaving, resumable records, run metadata, production-data guard.

Design rules (also in docs/arena/METHODOLOGY.md):
  * paired design: every harness gets the SAME tasks; harness order rotates per task so drift (thermal, cache) is not attributed to one harness;
  * real-model runs are strictly sequential (the server has one slot) so token/GPU attribution per run is exact;
  * recovery and concurrency scenarios use the scripted stub model on purpose: they measure the HARNESS, not the model;
  * a record is appended after EVERY invocation; re-running with the same --name skips finished (label, harness, task) triples.
"""
from __future__ import annotations
import hashlib, json, os, platform, socket, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from . import engine, suite as SU, adapters as AD
from .stubserver import Stub

HOME = Path.home()
PROTECTED = [HOME / ".hermes/config.yaml", HOME / ".hermes/auth.json", HOME / ".hermes/.env", HOME / ".openclaw/openclaw.json", HOME / ".openclaw/agents",
             HOME / ".local/state/ordivyr", HOME / ".codex/config.toml", HOME / ".claude/settings.json"]


def _hash_path(p):
    p = Path(p)
    if not p.exists(): return None
    if p.is_file(): return hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    h = hashlib.sha256()
    for f in sorted(x for x in p.rglob("*") if x.is_file() and x.stat().st_size < 20_000_000):
        h.update(str(f.relative_to(p)).encode()); h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()[:16]


def protected_snapshot(extra=()):
    """Hash of the configuration/state files a benchmark must never touch (the live ~/.hermes data root is excluded as a whole: the user's desktop Hermes writes to it continuously)."""
    return {str(p): _hash_path(p) for p in list(PROTECTED) + [Path(x) for x in extra]}


def git_info(root):
    try:
        sha = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=10).stdout.strip()
        dirty = bool(subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--", "ordivyr"], capture_output=True, text=True, timeout=20).stdout.strip())
        br = subprocess.run(["git", "-C", str(root), "branch", "--show-current"], capture_output=True, text=True, timeout=10).stdout.strip()
        return {"sha": sha, "dirty": dirty, "branch": br}
    except Exception: return {"sha": "unknown", "dirty": None, "branch": ""}


def server_info(model):
    if model.get("kind") != "llama": return {"kind": model.get("kind")}
    try:
        import urllib.request
        req = urllib.request.Request(model["base"].replace("/v1", "") + "/props", headers={"Authorization": "Bearer " + model["key"]}); j = json.loads(urllib.request.urlopen(req, timeout=5).read())
        return {"kind": "llama.cpp", "n_ctx": j.get("default_generation_settings", {}).get("n_ctx"), "slots": j.get("total_slots"), "model_path": os.path.basename(j.get("model_path", "") or ""), "name": model["name"]}
    except Exception as e: return {"kind": "llama.cpp", "error": str(e)[:100]}


class Run:
    def __init__(self, name, root, lanes_root, suite_name, tasks, model, adapters, scenario, notes=""):
        self.name, self.dir, self.lanes = name, Path(root) / name, Path(lanes_root) / name; self.dir.mkdir(parents=True, exist_ok=True); self.lanes.mkdir(parents=True, exist_ok=True)
        self.suite_name, self.tasks, self.model, self.adapters, self.scenario = suite_name, tasks, model, adapters, scenario
        self.rec_path = self.dir / "records.jsonl"; self.lock = threading.Lock(); self.log_f = open(self.dir / "run.log", "a", buffering=1); self.notes = notes
        self.done = set()
        if self.rec_path.exists():
            for l in self.rec_path.read_text().splitlines():
                try: r = json.loads(l); self.done.add((r["label"], r["harness"], r["task"]))
                except ValueError: pass

    def log(self, *a):
        line = time.strftime("%H:%M:%S ") + " ".join(str(x) for x in a); print(line, flush=True); self.log_f.write(line + "\n")

    def add(self, rec):
        with self.lock:
            with open(self.rec_path, "a") as f: f.write(json.dumps(rec, default=str) + "\n")
            self.done.add((rec["label"], rec["harness"], rec["task"]))
        self.log(f"{rec['label']:>11} {rec['harness']:9} {rec['task']:38} {'PASS' if rec['passed'] else 'fail'} {rec['wall_s']:6.1f}s tok={rec.get('prompt_tokens')}+{rec.get('completion_tokens')} viol={len(rec['violations'])} orph={rec['orphans']}"
                 + (f" recovery={rec['recovery_s']}s" if rec.get("recovery_s") else ""))

    def meta(self, extra=None):
        m = {"name": self.name, "suite": self.suite_name, "suite_hash": SU.suite_hash(self.tasks), "n_tasks": len(self.tasks), "scenario": self.scenario, "git": git_info(Path(__file__).resolve().parents[2]),
             "model": {k: v for k, v in self.model.items() if k != "key"}, "server": server_info(self.model), "host": {"node": socket.gethostname(), "cpus": os.cpu_count(), "kernel": platform.release()},
             "harnesses": [a.describe() for a in self.adapters], "notes": self.notes, **(extra or {})}
        (self.dir / "meta.json").write_text(json.dumps(m, indent=1, default=str)); return m

    # ------------------------------------------------------------------ scenarios
    def run_tasks(self, gpu, label="task", repeats=1):
        order = list(self.adapters)
        for ti, t in enumerate(self.tasks):
            rot = order[ti % len(order):] + order[:ti % len(order)]
            for rep in range(repeats):
                for a in rot:
                    lab = label if repeats == 1 else f"{label}{rep}"
                    if (lab, a.name, t["id"]) in self.done: continue
                    if t["category"] == "delegation" and not a.capabilities.get("delegation"): self.add(self._nt(a, t, lab, "multi-agent delegation requires sub-agent tools (Hermes delegate_task, OpenClaw sessions_spawn) which the file-tools-only permission profile disables; not enabled to avoid broadening permissions")); continue
                    self.add(engine.execute(a, t, self.model, self.lanes, tag=f"{ti}", gpu=gpu, label=lab))

    def _nt(self, a, t, lab, why):
        return {"run_id": "-", "harness": a.name, "task": t["id"], "category": t["category"], "suite": t["suite"], "label": lab, "status": "NOT_TESTED", "reason": why, "passed": False, "wall_s": 0.0, "violations": [], "orphans": 0, "ts": time.time()}

    def run_recovery(self, delay=3.0, n_tasks=4):
        tasks = [t for t in self.tasks if t["category"] in ("bugfix", "implement")][:n_tasks]
        stub = Stub(tasks, delay=delay).start(); m = engine.Model(self.model, base=stub.base, name="stub-oracle", kind="stub", metrics=None, key="x")
        self.log(f"stub model on {stub.base} delay={delay}s")
        try:
            for t in tasks:
                for a in self.adapters:
                    if ("stub-base", a.name, t["id"]) not in self.done: self.add(engine.execute(a, t, m, self.lanes, tag="b", stub=stub, label="stub-base"))
                    for kp in ("early", "late"):
                        lab = f"recover-{kp}"
                        if (lab, a.name, t["id"]) not in self.done: self.add(engine.execute(a, t, m, self.lanes, tag="r", stub=stub, kill_at=kp, label=lab))
        finally: stub.stop()

    def run_concurrency(self, k=4, delay=1.0, n_tasks=8):
        tasks = [t for t in self.tasks if t["category"] in ("bugfix", "implement")][:n_tasks]
        stub = Stub(tasks, delay=delay).start(); m = engine.Model(self.model, base=stub.base, name="stub-oracle", kind="stub", metrics=None, key="x")
        try:
            for a in self.adapters:
                lab = f"conc{k}"; todo = [t for t in tasks if (lab, a.name, t["id"]) not in self.done]
                if not todo: continue
                t0 = time.time()
                with ThreadPoolExecutor(k) as ex:
                    futs = [ex.submit(engine.execute, a, t, m, self.lanes, f"c{i}", stub, None, 0, None, lab) for i, t in enumerate(todo)]
                    for f in futs: self.add(f.result())
                self.log(f"concurrency {a.name}: {len(todo)} tasks, k={k}, wall {time.time() - t0:.1f}s")
        finally: stub.stop()
