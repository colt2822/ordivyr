"""Owner approval before chosen tools (agent `permissions.approve`). The decision is made on the TRUSTED worker side (in-process handler or sandbox broker).

A gated call parks the job `held`; an org admin resolves it with retry (= run exactly that call) or skip (= refuse it). The job then runs again from the start, so
decisions are kept per call digest (tool + arguments) in the task checkpoint: a different call, or the same tool with different arguments, holds again."""
from __future__ import annotations
import hashlib, json
from . import contract as C
from .. import durable as D

FEATURE = "approval_gate"
GATEABLE = C.WRITE_TOOLS | C.WEB_TOOLS | C.MEMORY_WRITE_TOOLS | frozenset({"delegate"})


def gated(job):
    """The tools this job must ask about. Gating either file-writing tool gates both, otherwise one is a way around the other."""
    names = set(((job.get("agent") or {}).get("permissions") or {}).get("approve") or ())
    if names & C.WRITE_TOOLS: names |= C.WRITE_TOOLS
    return frozenset(names)


def queue_kind(engine, job):
    """Gated jobs get their own queue kind: workers claim by kind, so a runtime that does not know the gate can never receive one."""
    return f"board.{engine}.gated" if gated(job) else f"board.{engine}"


def digest(name, args):
    return hashlib.sha256(json.dumps([name, args], sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class Gate:
    """check(name, args) -> None (run it) | error text (refused by the owner); raises NeedsApproval to park the job."""
    def __init__(self, job, checkpoint, attempt, save):
        self.job, self.attempt, self.save, self.tools = job, attempt, save, gated(job)
        cp = checkpoint or {}; self.decided = dict(cp.get("decided") or {}); p = cp.get("pending"); a = cp.get("owner_approval")
        if p and a and a.get("attempt") == p.get("attempt"):          # the approval answers THIS pending call, not some earlier hold
            self.decided[p["digest"]] = "allow" if a.get("resolution") == "retry" else "deny"; self.save({"decided": self.decided})

    def check(self, name, args):
        if name not in self.tools or not C.tool_allowed(self.job, name): return None          # an ungranted tool is refused by the permission check as before
        d = digest(name, args); v = self.decided.get(d)
        if v == "allow": return None
        if v == "deny": return f"ERROR: the owner declined this {name} call. Do not repeat it."
        self.save({"decided": self.decided, "pending": {"digest": d, "tool": name, "attempt": self.attempt}})
        raise D.NeedsApproval(f"needs_owner: approval required for {name} {json.dumps(args, sort_keys=True, default=str)[:600]} (retry = run this call, skip = refuse it)")


def for_ctx(ctx, job):
    if not gated(job): return None
    return Gate(job, ctx.checkpoint, ctx.task["attempt"], lambda data: ctx.write({"op": "checkpoint", "phase": "gate", "data": data}))
