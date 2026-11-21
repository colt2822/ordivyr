"""Learning loop: Execution -> Validation -> Evidence -> Candidate Memory -> Verification -> Future Retrieval.

capture_run() turns a finished run into CANDIDATE memories only. A candidate is promoted to verified by a separate verifier
principal using an independent validation record (e.g. hidden acceptance tests), never by the agent's own claim.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class Validation:
    passed: bool
    validator: str          # identity of the independent checker (not the authoring agent)
    ref: str                # inspectable evidence: test report path / run id / hash

    def as_dict(self): return {"passed": self.passed, "validator": self.validator, "ref": self.ref}


def capture_run(mem, p, ns, task, outcome, validation=None, failure=None, fix=None, decision=None, version=None, procedure=None):
    """Record what a run taught us. Returns the ids created.

    - always: an episodic record of the task and outcome (with evidence refs)
    - failure + fix, with a PASSING validation of the fix: a corrective candidate ("do not X; do Y")
    - procedure from a validated success: a procedural candidate
    - decision: a semantic candidate (decisions are claims until a verifier confirms them)
    Unvalidated runs produce episodic notes only; unvalidated fixes are never written as lessons.
    """
    ev = [{"run": task[:120], "outcome": outcome}] + ([{"validation": validation.as_dict()}] if validation else [])
    ids = [mem.add(p, ns, "episodic", f"task: {task[:80]}", f"{task}. Outcome: {outcome}." + (f" Failure: {failure}." if failure else ""), "run", ev, version)]
    ok = bool(validation and validation.passed)
    if failure and fix and ok:
        ids.append(mem.add(p, ns, "corrective", f"avoid: {failure[:80]}", f"Known mistake: {failure}. Correct approach: {fix}.", "validated-fix", ev, version))
    if procedure and ok:
        ids.append(mem.add(p, ns, "procedural", f"how to: {task[:80]}", procedure, "validated-run", ev, version))
    if decision:
        ids.append(mem.add(p, ns, "semantic", f"decision: {decision[:80]}", decision, "run", ev, version))
    return ids
