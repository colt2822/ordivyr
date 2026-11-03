"""Gambits: ordered IF -> THEN rules per agent (first enabled match wins, top = highest priority).

Pure and deterministic: evaluating a rule never calls a model. Only the explicit `ask_drex` action may, and the
orchestrator caps and audits that. Static validation catches conflicts, unauthorised targets and delegation loops;
the orchestrator re-checks authorisation, depth, lineage and budgets at run time.
"""
from __future__ import annotations
import datetime as _dt, json, uuid

TASK_TYPES = ("coding", "research", "qa", "outreach", "media", "general")
_KEYWORDS = (("coding", ("code", "bug", "implement", "refactor", "function", "api", "deploy", "build", "fix", "script")),
             ("research", ("research", "investigate", "find out", "analy", "survey", "compare", "sources")),
             ("qa", ("test", "qa", "verify", "review", "audit", "validate")),
             ("outreach", ("outreach", "email", "prospect", "campaign", "lead", "follow-up", "follow up")),
             ("media", ("video", "image", "podcast", "thumbnail", "script for", "edit footage", "media")))
STATUSES = ("idle", "working", "waiting", "error", "done", "paused")
COND_KINDS = {
    "task_type": {"label": "task type is", "phases": {"routing"}},
    "no_worker": {"label": "no suitable worker exists", "phases": {"routing"}},
    "task_completed": {"label": "my task completed", "phases": {"done"}},
    "task_failed": {"label": "my task failed N times", "phases": {"failed"}},
    "budget": {"label": "budget reached", "phases": {"routing", "active", "failed"}},
    "agent_status": {"label": "agent status is", "phases": {"routing", "active", "failed", "done"}},
    "schedule": {"label": "time window", "phases": {"routing", "active", "failed", "done"}},
    "custom_event": {"label": "approved event", "phases": {"routing", "active", "failed", "done"}},
}
ACTION_KINDS = {
    "claim": "claim the task myself", "delegate": "delegate to", "send_to": "send result to", "escalate": "escalate to",
    "stop_paid": "stop paid execution", "ask_drex": "ask DREX to route", "pause_self": "pause myself", "spawn_subagent": "spawn a subagent", "notify": "log a notice",
}
TARGET_ACTIONS = ("delegate", "send_to", "escalate")
AI_ACTIONS = ("ask_drex",)           # the only actions allowed to spend model tokens


def classify(title="", description="", explicit=None):
    if explicit in TASK_TYPES: return explicit
    text = f"{title} {description}".lower()
    for t, kws in _KEYWORDS:
        if any(k in text for k in kws): return t
    return "general"


def new_rule(cond_kind="task_type", then_kind="delegate", **kw):
    cond = {"kind": cond_kind, **({"value": "coding"} if cond_kind == "task_type" else {})}
    if cond_kind == "task_failed": cond["count"] = 2
    if cond_kind == "budget": cond.update(metric="tokens", pct=100)
    if cond_kind == "agent_status": cond.update(agent="self", status="error")
    if cond_kind == "schedule": cond.update(days=[0, 1, 2, 3, 4], from_hour=9, to_hour=17)
    if cond_kind == "custom_event": cond["name"] = ""
    if cond_kind == "task_completed": pass
    r = {"id": "g-" + uuid.uuid4().hex[:8], "enabled": True, "name": "", "if": cond, "then": {"kind": then_kind, "target": ""}}
    r.update(kw); return r


def describe(rule):
    c, t = rule["if"], rule["then"]
    cond = {"task_type": lambda: f"task is {c.get('value')}", "no_worker": lambda: "no suitable worker exists", "task_completed": lambda: "my task completes",
            "task_failed": lambda: f"my task fails {c.get('count', 1)}x", "budget": lambda: f"{c.get('metric')} used >= {c.get('pct')}%",
            "agent_status": lambda: f"{c.get('agent')} is {c.get('status')}", "schedule": lambda: f"between {c.get('from_hour')}:00-{c.get('to_hour')}:00",
            "custom_event": lambda: f"event '{c.get('name')}'"}.get(c.get("kind"), lambda: "?")()
    return f"IF {cond} THEN {ACTION_KINDS.get(t.get('kind'), '?')}" + (f" {t.get('target')}" if t.get("target") else "")


# ------------------------------------------------------------------ evaluation (pure)
def cond_matches(c, ctx):
    k = c.get("kind"); spec = COND_KINDS.get(k)
    if not spec or ctx["phase"] not in spec["phases"]: return False
    if k == "task_type": return ctx.get("task_type") == c.get("value")
    if k == "no_worker": return bool(ctx.get("no_worker"))
    if k == "task_completed": return ctx["phase"] == "done"
    if k == "task_failed": return ctx["phase"] == "failed" and ctx.get("failures", 0) >= int(c.get("count", 1))
    if k == "budget":
        used, cap = (ctx.get("tokens_used", 0), ctx.get("token_budget", 0)) if c.get("metric", "tokens") == "tokens" else (ctx.get("spend_used", 0.0), ctx.get("spend_cap", 0.0))
        return cap > 0 and used >= cap * float(c.get("pct", 100)) / 100.0
    if k == "agent_status":
        who = ctx["agent_id"] if c.get("agent") in ("self", None) else c.get("agent")
        return ctx.get("statuses", {}).get(who) == c.get("status")
    if k == "schedule":
        now = ctx["now"]; days = c.get("days") or list(range(7)); lo, hi = int(c.get("from_hour", 0)), int(c.get("to_hour", 24))
        in_hours = lo <= now.hour < hi if lo <= hi else (now.hour >= lo or now.hour < hi)
        return now.weekday() in days and in_hours
    if k == "custom_event": return bool(c.get("name")) and c.get("name") in ctx.get("events", ())
    return False


def evaluate(rules, ctx):
    """First enabled matching rule in list order (priority = position). Returns the rule or None."""
    for r in rules or []:
        if r.get("enabled", True) and cond_matches(r.get("if") or {}, ctx): return r
    return None


def ctx_now(ts=None): return _dt.datetime.fromtimestamp(ts) if ts else _dt.datetime.now()


# ------------------------------------------------------------------ authorisation (shared by validation + runtime)
def edge_between(board, a, b, kinds):
    return next((e for e in board.get("edges", []) if e["from"] == a and e["to"] == b and e.get("kind", "delegate") in kinds), None)


def managers_of(board, agent_id):
    """Agents this one reports/escalates to: delegators (incoming delegate/both) and explicit report targets."""
    out = [e["from"] for e in board.get("edges", []) if e["to"] == agent_id and e.get("kind", "delegate") in ("delegate", "both")]
    out += [e["to"] for e in board.get("edges", []) if e["from"] == agent_id and e.get("kind") in ("report", "both")]
    return list(dict.fromkeys(out))


def delegate_targets(board, agent_id):
    return [e["to"] for e in board.get("edges", []) if e["from"] == agent_id and e.get("kind", "delegate") in ("delegate", "both")]


def authorise(board, eff, kind, target_id, effective_of):
    """(ok, reason). `eff` = effective source agent; connections define who may delegate/report to whom."""
    if kind == "delegate" or kind == "send_to":
        if target_id not in delegate_targets(board, eff["id"]): return False, "no delegation connection to that agent"
        if not eff["license"]["comms"].get("delegate"): return False, "License Board: delegation not granted"
        if not effective_of(target_id)["license"]["comms"].get("receive"): return False, "target does not accept delegated work"
    elif kind == "escalate":
        if target_id not in managers_of(board, eff["id"]): return False, "no reporting/delegation connection to that manager"
        if not eff["license"]["comms"].get("escalate"): return False, "License Board: escalation not granted"
    return True, ""


def resolve_target(board, eff, rule, ctx_type="general", eligible=lambda aid: True, effective_of=None):
    """Turn 'auto' / 'manager' into a concrete agent id (deterministic, no model)."""
    t = (rule["then"].get("target") or ""); kind = rule["then"]["kind"]
    if t == "manager" and kind == "escalate":
        ms = managers_of(board, eff["id"]); return ms[0] if ms else None
    if t in ("", "auto") and kind in ("delegate", "send_to"):
        cands = [a for a in delegate_targets(board, eff["id"]) if eligible(a)]
        if effective_of:
            skilled = [a for a in cands if f"{ctx_type}" in effective_of(a)["license"].get("skills", [])]
            if skilled: return skilled[0]
        return cands[0] if cands else None
    return t or None


# ------------------------------------------------------------------ static validation
def _canon(c): return json.dumps(c, sort_keys=True)


def validate_rules(board, agent, effective_of=None):
    errs, warns = [], []
    who = f"agent '{agent.get('name') or agent.get('id')}'"; rules = agent.get("gambits") or []
    amap = {a["id"]: a for a in board.get("agents", [])}; seen = {}; ids = set()
    for i, r in enumerate(rules, 1):
        tag = f"{who} gambit #{i}"
        if r.get("id") in ids: errs.append(f"{tag}: duplicate rule id")
        ids.add(r.get("id")); c = r.get("if") or {}; t = r.get("then") or {}
        if not r.get("enabled", True): continue            # a disabled rule can never fire, so it cannot block Play
        if c.get("kind") not in COND_KINDS: errs.append(f"{tag}: unknown condition {c.get('kind')!r}"); continue
        if t.get("kind") not in ACTION_KINDS: errs.append(f"{tag}: unknown action {t.get('kind')!r}"); continue
        k = c["kind"]
        if k == "task_type" and c.get("value") not in TASK_TYPES: errs.append(f"{tag}: task type must be one of {TASK_TYPES}")
        if k == "task_failed" and not 1 <= int(c.get("count", 0) or 0) <= 20: errs.append(f"{tag}: failure count must be 1..20")
        if k == "budget":
            if c.get("metric") not in ("tokens", "spend"): errs.append(f"{tag}: budget metric must be tokens or spend")
            if not 1 <= float(c.get("pct", 0) or 0) <= 100: errs.append(f"{tag}: budget percent must be 1..100")
        if k == "agent_status":
            if c.get("status") not in STATUSES: errs.append(f"{tag}: unknown status")
            if c.get("agent") not in ("self", None) and c.get("agent") not in amap: errs.append(f"{tag}: condition references a missing agent")
        if k == "schedule" and not (0 <= int(c.get("from_hour", -1)) <= 24 and 0 <= int(c.get("to_hour", -1)) <= 24): errs.append(f"{tag}: hours must be 0..24")
        if k == "custom_event":
            if c.get("name") not in (board.get("events") or []): errs.append(f"{tag}: event {c.get('name')!r} is not in the board's approved events")
        if k == "budget" and c.get("metric") == "spend" and not float((agent.get("limits") or {}).get("spend_cap_usd") or 0): warns.append(f"{tag}: spend condition needs a spending cap to ever match")
        tk, tg = t["kind"], t.get("target") or ""
        if tk == "spawn_subagent" and not (agent.get("subagents") or {}).get("enabled"): errs.append(f"{tag}: subagents are not enabled for this agent (License Board: spawn subagents)")
        if tk in TARGET_ACTIONS:
            if tg in ("", "auto", "manager"):
                ok_special = (tk == "escalate" and tg in ("", "manager")) or (tk != "escalate" and tg in ("", "auto"))
                if not ok_special: errs.append(f"{tag}: '{tg}' is not valid for {tk}")
                elif tk == "escalate" and not managers_of(board, agent["id"]): errs.append(f"{tag}: nobody to escalate to; draw a connection to a manager")
                elif tk != "escalate" and not delegate_targets(board, agent["id"]): errs.append(f"{tag}: no delegation connection; draw a line from this agent to a worker")
            elif tg not in amap: errs.append(f"{tag}: target agent no longer exists")
            elif tg == agent["id"]: errs.append(f"{tag}: an agent cannot target itself")
            elif effective_of:
                ok, why = authorise(board, effective_of(agent["id"]), tk, tg, effective_of)
                if not ok: errs.append(f"{tag}: unauthorised {tk} to {amap[tg]['name']}: {why}")
        if tk == "ask_drex" and k in ("task_completed",): warns.append(f"{tag}: asking DREX after completion rarely needs AI; consider a deterministic action")
        key = _canon(c)
        if r.get("enabled", True):
            if key in seen:
                prev = seen[key]
                if _canon(prev["then"]) != _canon(t): errs.append(f"{tag}: conflicts with an earlier rule with the same condition but a different action ({describe(prev)}); disable or change one")
                else: warns.append(f"{tag}: exact duplicate of an earlier rule")
            else: seen[key] = r
    # delegation loops: same-trigger delegate/send_to cycles can bounce a task forever
    groups = {}
    for a in board.get("agents", []):
        for r in a.get("gambits") or []:
            c, t = r.get("if") or {}, r.get("then") or {}
            if not r.get("enabled", True) or t.get("kind") not in ("delegate", "send_to") or c.get("kind") not in ("task_type", "task_completed"): continue
            gk = (c["kind"], c.get("value", ""))
            tg = t.get("target") or "auto"
            targets = delegate_targets(board, a["id"]) if tg == "auto" else [tg]
            groups.setdefault(gk, {}).setdefault(a["id"], set()).update(x for x in targets if x in amap)
    for gk, g in groups.items():
        cyc = _cycle(g)
        if cyc:
            errs.append("infinite delegation loop for " + (f"{gk[0]}={gk[1]}" if gk[1] else gk[0]) + ": " + " -> ".join(amap[x]["name"] for x in cyc))
    return errs, warns


def _cycle(g):
    state = {}
    def dfs(n, path):
        state[n] = 1; path.append(n)
        for m in g.get(n, ()):
            if state.get(m) == 1: return path[path.index(m):] + [m]
            if state.get(m) is None:
                r = dfs(m, path)
                if r: return r
        state[n] = 2; path.pop(); return None
    for n in list(g):
        if state.get(n) is None:
            r = dfs(n, [])
            if r: return r
    return None


def matches(rules, ctx):
    """All enabled matching rules in priority order (the orchestrator walks them: a refused rule falls through to the next)."""
    return [r for r in rules or [] if r.get("enabled", True) and cond_matches(r.get("if") or {}, ctx)]
