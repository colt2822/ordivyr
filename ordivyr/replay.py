"""Zero-cost replay: re-run a board through the real Runner (scheduling, dependencies, gambits, memory, bookkeeping) with every agent's model call answered from a recorded
transcript. No network, no model, no spend; use it to test harness changes (scheduler, gambits, plugins) against a known run."""
from __future__ import annotations
import json
from pathlib import Path
from .runner import Runner, RunError


def load(ref, home=None):
    """ref = path to a transcript, or a run id under <home>/runs/."""
    p = Path(ref)
    if not p.is_file() and home: p = Path(home) / "runs" / f"{ref}.json"
    if not p.is_file(): raise RunError(f"no transcript at {p}")
    t = json.loads(p.read_text())
    if not isinstance(t.get("agents"), dict): raise RunError("not a run transcript (no agents)")
    return t


class ReplayRunner(Runner):
    def __init__(self, board, mission, transcript, **kw):
        kw.setdefault("run_id", f"replay-{transcript.get('run_id', 'x')}")
        super().__init__(board, mission, **kw); self.rec = transcript["agents"]; self.replayed = []
    def _execute(self, aid):
        r = self.rec.get(aid)
        if r is None: raise RunError(f"agent {aid} is not in the recorded run")
        self.replayed.append(aid)
        if r.get("status") != "done": raise RunError(r.get("output") or f"recorded status {r.get('status')}")
        return r.get("output", ""), int(r.get("tokens") or 0), r.get("model") or "replay"
    _durable_execute = _execute
    def _paid(self, aid): return False          # nothing is spent, so no paid exclusivity or approval


def replay(board, transcript, mission=None, **kw):
    """-> (result, diff). diff lists agents whose status or output differs from the recording (empty = harness behaves identically)."""
    rr = ReplayRunner(board, mission or transcript.get("mission") or "replay", transcript, **kw); res = rr.run(); diff = []
    for aid, st in res["agents"].items():
        rec = transcript["agents"].get(aid, {})
        if rec.get("status") != st["status"] or (rec.get("status") == "done" and rec.get("output") != st["output"]): diff.append({"agent": aid, "recorded": rec.get("status"), "replayed": st["status"]})
    return res, diff
