"""Hunt Board: pure model + validation. Execution lives in the Floor queue (tasks); this adds the marketplace metadata."""
from __future__ import annotations
import time, uuid
from . import gambits as G, license as L

PERMS = ("read-only", "workspace-write", "network")
HUNT_STATUS = ("POSTED", "CLAIMED", "IN_PROGRESS", "REVIEW", "APPROVAL", "DONE", "FAILED", "EXPIRED", "CANCELLED", "OVER_BUDGET")


def new_hunt_id(): return "H-" + uuid.uuid4().hex[:8].upper()


def normalize(spec, board, now=None, verification_kinds=()):
    """Validate untrusted hunt input -> clean doc. Raises ValueError with a readable message."""
    now = now or time.time()
    title = str(spec.get("title") or "").strip()
    if not title: raise ValueError("title is required")
    if len(title) > 120: raise ValueError("title is too long (120 max)")
    objectives = [str(x).strip() for x in (spec.get("objectives") or []) if str(x).strip()][:10]
    pr = int(spec.get("priority", 2)); df = int(spec.get("difficulty", 2))
    if not 0 <= pr <= 9: raise ValueError("priority must be 0..9")
    if not 1 <= df <= 5: raise ValueError("difficulty must be 1..5")
    known = {n[0] for a in board["agents"] for n in L.catalog(a)}
    caps = [str(c) for c in (spec.get("required_caps") or [])]
    for c in caps:
        if c not in known: raise ValueError(f"unknown capability {c!r}")
    perm = spec.get("permission") or "read-only"
    if perm not in PERMS: raise ValueError(f"permission must be one of {PERMS}")
    asg = spec.get("assignee") or {"type": "auto"}
    if asg.get("type") not in ("auto", "agent", "dept"): raise ValueError("assignee type must be auto, agent or dept")
    if asg["type"] == "agent" and asg.get("id") not in {a["id"] for a in board["agents"]}: raise ValueError("assignee agent does not exist")
    if asg["type"] == "dept" and asg.get("id") not in {d["id"] for d in board["departments"]}: raise ValueError("assignee department does not exist")
    tb = float(spec.get("token_budget") or 0)
    if tb < 0: raise ValueError("token budget cannot be negative")
    dl = spec.get("deadline")
    if dl in ("", None): dl = None
    else:
        dl = float(dl)
        if dl <= now: raise ValueError("deadline is in the past")
    crit = str(spec.get("criteria") or "").strip()
    for item in [x.strip() for x in crit.split(";") if x.strip()]:
        if verification_kinds and item.partition(":")[0].strip() not in verification_kinds: raise ValueError(f"unknown completion check {item!r}")
    ttype = spec.get("task_type") or None
    if ttype and ttype not in G.TASK_TYPES: raise ValueError(f"task type must be one of {G.TASK_TYPES}")
    desc = str(spec.get("description") or "").strip()
    return {"title": title, "description": desc, "objectives": objectives, "priority": pr, "difficulty": df, "required_caps": caps, "permission": perm,
            "assignee": asg, "simulate_failure": bool(spec.get("simulate_failure")), "token_budget": tb, "deadline": dl, "criteria": crit, "task_type": ttype or G.classify(title, desc), "history": []}


def task_description(doc):
    parts = [doc["description"] or doc["title"]]
    if doc["objectives"]: parts.append("OBJECTIVES:\n" + "\n".join(f"- {o}" for o in doc["objectives"]))
    if doc["criteria"]: parts.append(f"COMPLETION CRITERIA (independently verified): {doc['criteria']}")
    parts.append(f"Difficulty {doc['difficulty']}/5, priority {doc['priority']}, permission {doc['permission']}.")
    return "\n\n".join(parts)


def perm_rank(p): return PERMS.index(p) if p in PERMS else 0
