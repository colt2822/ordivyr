"""Hardware-aware template selection: which team templates can THIS machine run, and with which local models?

Reads (never changes) the detected hardware, the local model inventory and the role plan, and reports for each template one of
  ready    - every required role has a model that fits and the VRAM/GPU minimums are met
  degraded - runnable, but a minimum is unmet or some roles fall back (reasons listed)
  unfit    - cannot run locally here (reasons listed)
Templates with no `hardware` requirements (the cloud/BYOK ones) report `n/a-cloud`.
"""
from __future__ import annotations
from . import teams as T, roles as R


def evaluate(t, hw, plan):
    req = t.get("hardware") or {}
    if not any(req.get(k) for k in ("min_vram_mb", "min_gpus", "local_only", "needs_roles")): return {"key": t["key"], "status": "n/a-cloud", "reasons": ["no local hardware requirements"], "roles": {}}
    reasons, status = [], "ready"
    if req.get("min_gpus") and len(hw.gpus) < req["min_gpus"]:
        if hw.total_vram_mb < req.get("min_vram_mb", 0): status = "unfit"
        elif status != "unfit": status = "degraded"
        reasons.append(f"wants {req['min_gpus']} GPUs, found {len(hw.gpus)}")
    if req.get("min_vram_mb") and hw.total_vram_mb < req["min_vram_mb"]:
        status = "unfit" if hw.total_vram_mb < req["min_vram_mb"] * 0.5 else ("degraded" if status != "unfit" else status)
        reasons.append(f"wants {req['min_vram_mb']} MB VRAM, found {hw.total_vram_mb} MB")
    used = {}
    for r in req.get("needs_roles", []):
        m = (plan.get(r) or {}).get("model")
        used[r] = m
        if not m: reasons.append(f"no local model for role '{r}': {(plan.get(r) or {}).get('why', 'unknown')}"); status = "unfit" if status == "unfit" else "degraded"
    notes = [n for g in hw.gpus for n in g.notes]
    return {"key": t["key"], "title": t["title"], "status": status, "reasons": reasons or ["all requirements met"], "roles": used, "hardware_notes": notes}


def recommend(hw, plan, templates=None):
    """Ranked: ready first, then degraded, then cloud, then unfit; within a group, more demanding templates first (they use the machine best)."""
    templates = templates or T.builtin()
    order = {"ready": 0, "degraded": 1, "n/a-cloud": 2, "unfit": 3}
    out = [evaluate(t, hw, plan) for t in templates.values()]
    return sorted(out, key=lambda e: (order[e["status"]], -(templates[e["key"]].get("hardware") or {}).get("min_vram_mb", 0), e["key"]))


def instantiate(key, plan, templates=None, name=None):
    """Template -> board whose role-tagged agents use `role:<role>` (resolved by the runner). Refuses 'unfit' templates."""
    templates = templates or T.builtin()
    if key not in templates: raise T.TemplateError("unknown template")
    return T.build(templates[key], role_plan=plan, name=name)
