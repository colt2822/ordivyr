"""Agent boards on the ONE task protocol (the durable Store): a board is a DAG of steps; every step is an ordinary `gw_agent` task, so local, cloud and hybrid teams, and
agents on other machines, all use leases + fencing + retries + validators + idempotent commit regardless of provider.

  * dependencies: a step is submitted only when every `needs` step is COMPLETED; its prompt may reference `{{step.text}}` (the upstream result) - that is the handoff
  * duplicate prevention: idempotency key = run_id:step, so re-running the same run_id after a crash/restart attaches to the existing tasks instead of executing twice
  * failure: a failed/held step BLOCKS its dependents (never runs them on missing input); independent branches continue
  * spending: board budget is checked from the gateway ledger BEFORE each submit; paid endpoints still need their own authorisation + caps (gateway), so a board cannot spend what its endpoints are not allowed to
  * validation: per-step validators (separate processes) decide success, not the model's words
"""
from __future__ import annotations
import json, re, time
from .. import durable as D
from .. import agentloop as AL
from .placement import task_tenant

_REF = re.compile(r"\{\{\s*([a-zA-Z0-9_\-]+)\.text\s*\}\}")

class BoardError(ValueError): pass

def validate_board(board, agents):
    ids = [s["id"] for s in board["steps"]]
    if len(set(ids)) != len(ids): raise BoardError("duplicate step id")
    for s in board["steps"]:
        if s["agent"] not in agents: raise BoardError(f"step {s['id']}: unknown agent {s['agent']}")
        for n in s.get("needs", []):
            if n not in ids: raise BoardError(f"step {s['id']}: needs unknown step {n}")
        for r in _REF.findall(s["prompt"]):
            if r not in s.get("needs", []): raise BoardError(f"step {s['id']}: references {{{{{r}.text}}}} without listing it in needs")
    seen, stack = set(), set()
    def dfs(i):
        if i in stack: raise BoardError("dependency cycle")
        if i in seen: return
        stack.add(i); [dfs(n) for n in next(s for s in board["steps"] if s["id"] == i).get("needs", [])]; stack.discard(i); seen.add(i)
    for i in ids: dfs(i)

class BoardRunner:
    def __init__(self, store, agents, gateway=None, tenant="default", poll=0.3):
        self.store, self.agents, self.gw, self.tenant, self.poll = store, agents, gateway, tenant, poll
    def run(self, board, run_id, timeout=600, shared_dir=None, on_event=None, cancelled=None, interrupted=None):
        """Drive a board to a terminal state. Safe to call again with the same run_id (resumes; never double-submits)."""
        ag = {a["id"]: a for a in self.agents.list()}; validate_board(board, ag); steps = {s["id"]: s for s in board["steps"]}; tasks = {}; out = {}; state = {i: "pending" for i in steps}; t0 = time.time()
        budget = board.get("budget_usd"); base_spend = self._spend(board, ag) if budget else 0.0
        while time.time() - t0 < timeout:
            if interrupted and interrupted(): break
            if cancelled and cancelled():
                for tid in tasks.values(): self.store.cancel(tid)
                for sid in state:
                    if state[sid] in ("pending", "submitted"): state[sid] = "cancelled"
                break
            for sid, s in steps.items():
                if state[sid] != "pending": continue
                deps = [state[n] for n in s.get("needs", [])]
                if any(d in ("failed", "blocked", "held", "cancelled") for d in deps): state[sid] = "blocked"; on_event and on_event(sid, "blocked"); continue
                if any(d != "completed" for d in deps): continue
                if budget and self._spend(board, ag) - base_spend >= budget: state[sid] = "blocked"; out[sid] = {"error": "board budget reached"}; on_event and on_event(sid, "budget"); continue
                prompt = _REF.sub(lambda m: str(out[m.group(1)]["text"]), s["prompt"]); a = dict(ag[s["agent"]])
                if s.get('agent_overrides'): a.update(s['agent_overrides'])
                limits = s.get('limits') or {}
                for limit, field, fallback in [('max_seconds', 'max_seconds', AL.MAX_SECONDS), ('token_budget', 'token_budget', 0), ('spend_cap_usd', 'budget_usd', 0)]:
                    if limits.get(limit):
                        existing = a.get(field) or fallback
                        a[field] = min(existing, limits[limit]) if existing else limits[limit]
                payload = {"agent": a, "prompt": prompt, "board": board["id"], "step": sid, "validators": s.get("validators", []), **({"endpoint": s["endpoint"]} if s.get("endpoint") else {}), **({"model": s["model"]} if s.get("model") else {}), **({"shared_dir": shared_dir} if shared_dir else {})}
                if board.get("hold_uncertain"): payload["hold_uncertain"] = True
                if s.get('endpoint_binding'): payload['endpoint_binding'] = s['endpoint_binding']
                tasks[sid] = self.store.submit("gw_agent", payload, f"{run_id}:{sid}", max_attempts=s.get("max_attempts", 2), tenant=task_tenant(s, self.tenant)); state[sid] = "submitted"; on_event and on_event(sid, "submitted")
            for sid, tid in tasks.items():
                if state[sid] != "submitted": continue
                t = self.store.get(tid); st = t["state"]
                if st == "completed": out[sid] = t["result"] if isinstance(t["result"], dict) else json.loads(t["result"]); state[sid] = "completed"; on_event and on_event(sid, "completed")
                elif st in ("failed", "dead", "cancelled", "held", "needs_approval"): out[sid] = {"error": t.get("failure")}; state[sid] = "held" if st in ("held", "needs_approval") else "failed"; on_event and on_event(sid, state[sid])
            if all(v in ("completed", "failed", "blocked", "held", "cancelled") for v in state.values()): break
            time.sleep(self.poll)
        else:
            if cancelled is not None:
                for tid in tasks.values(): self.store.cancel(tid)
            for sid in state:
                if state[sid] in ("pending", "submitted"): state[sid] = "timeout"
        cost = sum((o.get("cost_usd") or 0) for o in out.values()); hist = {sid: {"state": state[sid], "task": tasks.get(sid), "text": (out.get(sid) or {}).get("text"), "endpoint": (out.get(sid) or {}).get("endpoint"), "model": (out.get(sid) or {}).get("model"),
                "cost_usd": (out.get(sid) or {}).get("cost_usd"), "attempts": self.store.get(tasks[sid])["attempt"] if sid in tasks else 0, "error": (out.get(sid) or {}).get("error")} for sid in steps}
        return {"board": board["id"], "run_id": run_id, "ok": all(v == "completed" for v in state.values()), "steps": hist, "cost_usd": round(cost, 6), "wall_s": round(time.time() - t0, 2),
                "duplicate_commits": sum(1 for tid in tasks.values() if self._commits(tid) > 1)}
    def _commits(self, tid): return self.store._conn().execute("SELECT COUNT(*) FROM events WHERE task_id=? AND kind='commit'", (tid,)).fetchone()[0]
    def _spend(self, board, ag):
        if not self.gw: return 0.0
        ids = {board_agent for board_agent in (s["agent"] for s in board["steps"])}
        return sum(r["usd"] for r in self.gw.usage(by="agent") if r["agent"] in ids)
