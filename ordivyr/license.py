"""License Board: the capability graph of one agent.

Every node reads/writes the agent's REAL configuration (tools, mcp, memory, subagents, license.*), so toggling
a node changes what compile/gambits/hunts enforce. Department policies lock nodes and cap limits (inheritance).
"""
from __future__ import annotations
import copy

AUTONOMY = ("manual", "supervised", "autonomous")
SKILLS = ("coding", "research", "qa", "outreach", "media")
DEFAULT_TOOLS = ("shell", "browser", "file_write", "code_exec", "http_api")
DEFAULT_MCP = ("github", "slack", "drive", "calendar")
EXTRA_MCP = []      # ids of the user's registered tools (Settings -> Tools); when present they replace the generic list in the License tree
COMMS = ("delegate", "receive", "report", "escalate")
HUBS = [("skills", "Skills"), ("tools", "Tools & APIs"), ("mcp", "MCP servers"), ("memory", "Memory"), ("comms", "Communication"),
        ("subagents", "Subagents"), ("models", "Models"), ("compute", "Compute & autonomy")]
REQUIRES = {"tool:code_exec": ["tool:shell"], "mem:write": ["mem:read"], "comm:escalate": ["comm:report"], "sub:spawn": ["comm:delegate"]}
LIMIT_KEYS = ("token_budget", "spend_cap_usd", "max_seconds", "concurrency")


def default_license():
    return {"skills": [], "comms": {c: True for c in COMMS}, "paid_allowed": False, "gpu": False, "autonomy": "supervised", "fallbacks": []}


def rank(level): return AUTONOMY.index(level) if level in AUTONOMY else 1


def dept_of(board, agent):
    return next((d for d in board.get("departments", []) if d["id"] == agent.get("dept")), None)


def _policy(d): return (d or {}).get("policy") or {}


def effective(board, agent):
    """Agent config after department policy inheritance. Stricter of agent/department wins."""
    e = copy.deepcopy(agent); lic = e.setdefault("license", default_license()); notes = []
    pol = _policy(dept_of(board, agent))
    for k in ("tools", "mcp"):
        deny = set(pol.get(k + "_deny") or [])
        gone = [x for x in e.get(k, []) if x in deny]
        if gone: notes.append(f"department denies {k}: {', '.join(gone)}")
        e[k] = [x for x in e.get(k, []) if x not in deny]
    if pol.get("paid_allowed") is False and lic.get("paid_allowed"):
        lic["paid_allowed"] = False; notes.append("department forbids paid execution")
    if pol.get("max_autonomy") and rank(lic.get("autonomy")) > rank(pol["max_autonomy"]):
        lic["autonomy"] = pol["max_autonomy"]; notes.append(f"autonomy capped at {pol['max_autonomy']}")
    if pol.get("shared_memory") is False and (e.get("memory") or {}).get("mode", "read") != "none":
        e["memory"]["mode"] = "none"; notes.append("department forbids shared memory")
    ceil = pol.get("agent_limits") or {}
    for k in LIMIT_KEYS:
        c = float(ceil.get(k) or 0); v = float((e.get("limits") or {}).get(k) or 0)
        if c > 0 and (v == 0 or v > c):
            e["limits"][k] = c; notes.append(f"{k} capped at {c:g} by department")
    e["_notes"] = notes
    return e


def granted(agent):
    """Set of capability ids the (effective) agent holds. Used for Hunt eligibility and gambit authorization."""
    lic = agent.get("license") or default_license(); g = set()
    g |= {f"skill:{s}" for s in lic.get("skills", [])}
    g |= {f"tool:{t}" for t in agent.get("tools", [])}
    g |= {f"mcp:{m}" for m in agent.get("mcp", [])}
    g |= {f"comm:{c}" for c, on in (lic.get("comms") or {}).items() if on}
    mem = agent.get("memory") or {}
    if mem.get("private"): g.add("mem:private")
    if mem.get("mode") in ("read", "readwrite"): g.add("mem:read")
    if mem.get("mode") == "readwrite": g.add("mem:write")
    if (agent.get("subagents") or {}).get("enabled"): g.add("sub:spawn")
    if lic.get("paid_allowed"): g.add("model:paid")
    if lic.get("gpu"): g.add("compute:gpu")
    return g


def catalog(agent):
    tools = list(dict.fromkeys(list(DEFAULT_TOOLS) + [t for t in agent.get("tools", []) if not t.startswith("mcp:")]))
    mcps = list(dict.fromkeys((EXTRA_MCP or list(DEFAULT_MCP)) + list(agent.get("mcp", []))))
    nodes = [(f"skill:{s}", f"{s}", "skills") for s in SKILLS] + [(f"tool:{t}", t, "tools") for t in tools] + [(f"mcp:{m}", m, "mcp") for m in mcps]
    nodes += [("mem:private", "private memory", "memory"), ("mem:read", "shared read", "memory"), ("mem:write", "shared write", "memory")]
    nodes += [(f"comm:{c}", c, "comms") for c in COMMS] + [("sub:spawn", "spawn subagents", "subagents")]
    nodes += [("model:fallback", "fallback providers", "models"), ("model:paid", "paid execution", "models")]
    nodes += [("compute:gpu", "GPU access", "compute"), ("compute:autonomy", "autonomy level", "compute"), ("compute:limits", "limits & budget", "compute")]
    return nodes


def lock_reason(board, agent, node_id):
    pol = _policy(dept_of(board, agent))
    kind, _, name = node_id.partition(":")
    if kind == "tool" and name in (pol.get("tools_deny") or []): return "denied by department policy"
    if kind == "mcp" and name in (pol.get("mcp_deny") or []): return "denied by department policy"
    if node_id == "model:paid" and pol.get("paid_allowed") is False: return "department forbids paid execution"
    if node_id in ("mem:read", "mem:write") and pol.get("shared_memory") is False: return "department forbids shared memory"
    return ""


def is_on(agent, node_id):
    lic = agent.get("license") or default_license()
    if node_id in ("compute:autonomy", "compute:limits"): return True
    if node_id == "model:fallback": return bool(lic.get("fallbacks"))
    return node_id in granted(agent)


def nodes(board, agent):
    out = []
    for nid, label, cat in catalog(agent):
        lic = agent.get("license") or default_license(); params = {}
        if nid == "sub:spawn": params = {"max": (agent.get("subagents") or {}).get("max", 0), "limits": (agent.get("subagents") or {}).get("limits")}
        if nid == "model:fallback": params = {"fallbacks": lic.get("fallbacks", []), "primary": agent.get("model")}
        if nid == "compute:autonomy": params = {"level": lic.get("autonomy", "supervised")}
        if nid == "compute:limits": params = {"limits": agent.get("limits")}
        if nid == "mem:read": params = {"shared": (agent.get("memory") or {}).get("shared", [])}
        out.append({"id": nid, "label": label, "cat": cat, "requires": REQUIRES.get(nid, []), "on": is_on(agent, nid),
                    "locked": lock_reason(board, agent, nid), "params": params})
    return out


def _dependents(node_id): return [k for k, v in REQUIRES.items() if node_id in v]


def set_node(board, agent, node_id, on=None, params=None):
    """Mutate the agent's real configuration. Enforces prerequisites, cascades disables, honours department locks."""
    if node_id not in {n[0] for n in catalog(agent)}: raise ValueError(f"unknown capability {node_id!r}")
    params = params or {}
    lic = agent.setdefault("license", default_license()); mem = agent.setdefault("memory", {"private": True, "shared": [], "mode": "read"})
    kind, _, name = node_id.partition(":")
    if on is True:
        why = lock_reason(board, agent, node_id)
        if why: raise ValueError(f"{node_id} is locked: {why}")
        for r in REQUIRES.get(node_id, []):
            if not is_on(agent, r): raise ValueError(f"{node_id} requires {r} first")
    if on is False:
        for d in _dependents(node_id):
            if is_on(agent, d): set_node(board, agent, d, False)
    if kind == "skill":
        s = set(lic.get("skills", [])); (s.add if on else s.discard)(name); lic["skills"] = [x for x in SKILLS if x in s]
    elif kind in ("tool", "mcp"):
        key = "tools" if kind == "tool" else "mcp"; cur = [x for x in agent.get(key, []) if x != name]
        agent[key] = cur + [name] if on else cur
    elif node_id == "mem:private": mem["private"] = bool(on)
    elif node_id == "mem:read":
        if on is not None: mem["mode"] = "read" if on else "none"
        if "shared" in params: mem["shared"] = [str(x) for x in params["shared"]]
    elif node_id == "mem:write": mem["mode"] = "readwrite" if on else ("read" if mem.get("mode") == "readwrite" else mem.get("mode", "none"))
    elif kind == "comm": lic.setdefault("comms", {})[name] = bool(on)
    elif node_id == "sub:spawn":
        sub = agent.setdefault("subagents", {"enabled": False, "max": 0, "limits": {}})
        if on is not None: sub["enabled"] = bool(on)
        if on and not sub.get("max"): sub["max"] = 1
        if "max" in params: sub["max"] = int(params["max"])
        if "limits" in params: sub["limits"] = {**(sub.get("limits") or {}), **params["limits"]}
    elif node_id == "model:fallback":
        if on is False: lic["fallbacks"] = []
        if "fallbacks" in params: lic["fallbacks"] = [str(x) for x in params["fallbacks"] if str(x) != agent.get("model")]
    elif node_id == "model:paid": lic["paid_allowed"] = bool(on)
    elif node_id == "compute:gpu": lic["gpu"] = bool(on)
    elif node_id == "compute:autonomy":
        lvl = params.get("level")
        if lvl not in AUTONOMY: raise ValueError(f"autonomy must be one of {AUTONOMY}")
        pol = _policy(dept_of(board, agent))
        if pol.get("max_autonomy") and rank(lvl) > rank(pol["max_autonomy"]): raise ValueError(f"department caps autonomy at {pol['max_autonomy']}")
        lic["autonomy"] = lvl
    elif node_id == "compute:limits":
        agent["limits"] = {**(agent.get("limits") or {}), **{k: params[k] for k in LIMIT_KEYS if k in params}}
    return agent


def validate_license(board, agent, workers=None, paid=lambda m: False):
    errs, warns = [], []
    who = f"agent '{agent.get('name') or agent.get('id')}'"
    lic = agent.get("license") or default_license(); eff = effective(board, agent)
    if lic.get("autonomy") not in AUTONOMY: errs.append(f"{who}: autonomy must be one of {AUTONOMY}")
    for s in lic.get("skills", []):
        if s not in SKILLS: errs.append(f"{who}: unknown skill {s!r}")
    for nid, req in REQUIRES.items():
        if is_on(agent, nid) and not all(is_on(agent, r) for r in req): errs.append(f"{who}: {nid} requires {', '.join(req)}")
    for fb in lic.get("fallbacks", []):
        if workers is not None and fb not in workers: errs.append(f"{who}: fallback {fb!r} is not a connected worker")
        elif paid(fb) and not eff["license"].get("paid_allowed"): errs.append(f"{who}: fallback {fb} is paid; enable paid execution on its License Board (and the department must allow it)")
    if agent.get("model") and paid(agent["model"]) and not eff["license"].get("paid_allowed"):
        errs.append(f"{who}: model {agent['model']} is paid; enable 'paid execution' on its License Board" +
                    (" (department policy forbids it)" if lic.get("paid_allowed") else ""))
    for n in eff["_notes"]: warns.append(f"{who}: {n}")
    return errs, warns
