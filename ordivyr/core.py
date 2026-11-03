"""Board model, validation, compilation and templates. Pure functions, no runtime import."""
from __future__ import annotations
import copy, json, re, uuid
from . import license as L, gambits as G

SCHEMA = 1
SCOPE_PREFIX = "ordivyr"       # task scope / request-id prefixes; a host product may override these at start-up
REQUEST_PREFIX = "ordivyr"
EDGE_KINDS = ("delegate", "report", "both")
MEM_MODES = ("none", "read", "readwrite")
LIMIT_KEYS = ("token_budget", "spend_cap_usd", "max_seconds", "concurrency")
ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
DEFAULT_MODEL = "det.01"          # zero-cost deterministic worker: a beginner's Play always completes


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def default_limits(**kw):
    d = {"token_budget": 50000, "spend_cap_usd": 0.0, "max_seconds": 300, "concurrency": 1}
    d.update(kw)
    return d


def new_agent(x=0, y=0, name="New agent", **kw):
    a = {
        "id": new_id("a"), "name": name, "x": x, "y": y, "model": DEFAULT_MODEL,
        "soul": "", "instructions": "", "tools": [], "mcp": [], "permissions": "read-only",
        "limits": default_limits(),
        "subagents": {"enabled": False, "max": 0, "limits": default_limits(token_budget=10000, max_seconds=120)},
        "memory": {"private": True, "shared": [], "mode": "read"},
        "dept": None, "paused": False, "verification": "",
        "license": L.default_license(), "gambits": [], "look": {},
    }
    a.update(kw)
    return a


BOARD_SETTINGS = {"max_depth": 4, "max_actions": 40, "max_drex_calls": 5, "auto_claim": True}


def new_board(name="Untitled room"):
    return {"schema": SCHEMA, "name": name, "version": 1, "agents": [], "edges": [], "departments": [],
            "events": [], "settings": dict(BOARD_SETTINGS), "stickers": [], "doodles": [], "notes": []}


def default_policy():
    return {"paid_allowed": None, "tools_deny": [], "mcp_deny": [], "max_autonomy": None, "shared_memory": None,
            "agent_limits": {"token_budget": 0, "spend_cap_usd": 0.0, "max_seconds": 0, "concurrency": 0}}


PENS = ("ink", "blue", "red", "green", "purple", "orange")      # theme-neutral names; the UI maps them to marker (light) or chalk (dark) colours


def normalize(board):
    """Fill defaults on boards saved before License/Gambit/Hunt existed. Never drops user data."""
    if not isinstance(board.get("events"), list): board["events"] = []
    if not isinstance(board.get("settings"), dict): board["settings"] = {}
    for k, v in BOARD_SETTINGS.items(): board["settings"].setdefault(k, v)
    for k, lo, hi in (("max_depth", 1, 8), ("max_actions", 0, 200), ("max_drex_calls", 0, 50)):
        try: board["settings"][k] = max(lo, min(hi, int(board["settings"][k])))
        except (TypeError, ValueError): board["settings"][k] = BOARD_SETTINGS[k]
    board["settings"]["auto_claim"] = bool(board["settings"].get("auto_claim", True))
    for a in board.get("agents", []):
        for k, kind in (("license", dict), ("memory", dict), ("limits", dict), ("subagents", dict), ("tools", list), ("mcp", list), ("gambits", list)):
            if not isinstance(a.get(k), kind): a[k] = kind() if k not in ("license", "memory", "limits", "subagents") else {}
        a["gambits"] = [r for r in a["gambits"] if isinstance(r, dict) and isinstance(r.get("if"), dict) and isinstance(r.get("then"), dict)]
        if not isinstance(a["license"].get("comms"), dict): a["license"]["comms"] = {}
        if not isinstance(a["license"].get("skills"), list): a["license"]["skills"] = []
        if not isinstance(a["license"].get("fallbacks"), list): a["license"]["fallbacks"] = []
        lic = a.setdefault("license", L.default_license())
        for k, v in L.default_license().items():
            if k == "comms": lic.setdefault("comms", {}); [lic["comms"].setdefault(c, True) for c in L.COMMS]
            else: lic.setdefault(k, copy.deepcopy(v))
        a.setdefault("gambits", [])
    for e in board.get("edges", []):
        if isinstance(e, dict) and e.get("color") not in PENS: e["color"] = ""        # never store arbitrary CSS from imports
    sanitize_looks(board)
    for d in board.get("departments", []):
        if not isinstance(d.get("policy"), dict): d["policy"] = {}
        pol = d["policy"]
        if not isinstance(pol.get("agent_limits"), dict): pol["agent_limits"] = {}
        for k, v in default_policy().items(): pol.setdefault(k, copy.deepcopy(v))
    return board


SHAPES = ("box", "round", "hex", "terminal", "note")
LINE_STYLES = ("solid", "dashed", "dotted", "sketchy")
LINE_ANIMS = ("none", "flow")


def _emoji(v):
    """A sticker is a short run of non-ASCII characters (emoji / ZWJ sequences). Anything else is dropped; it is only ever rendered as text."""
    v = v.strip() if isinstance(v, str) else ""
    return v if v and len(v) <= 12 and any(ord(c) > 127 for c in v) and not any(c in v for c in "<>&\"'`") else ""


def _clamp(v, lo, hi, d=0):
    try: return max(lo, min(hi, float(v)))
    except (TypeError, ValueError): return d


def sanitize_looks(board):
    """Cosmetics only (shape, colour, emoji, line style, hand-drawn waypoints, board stickers). Every value is clamped to an allow-list/range so an import can never smuggle CSS/markup."""
    for a in board.get("agents", []):
        lk = a.get("look") if isinstance(a.get("look"), dict) else {}
        a["look"] = {"shape": lk.get("shape") if lk.get("shape") in SHAPES else "box", "color": lk.get("color") if lk.get("color") in PENS else "",
                     "emoji": _emoji(lk.get("emoji")), "stickers": [x for x in (_emoji(v) for v in (lk.get("stickers") or [])[:8]) if x][:4]}
    for e in board.get("edges", []):
        if not isinstance(e, dict): continue
        lk = e.get("look") if isinstance(e.get("look"), dict) else {}
        e["look"] = {"style": lk.get("style") if lk.get("style") in LINE_STYLES else "solid", "width": int(_clamp(lk.get("width"), 2, 8, 4)), "anim": lk.get("anim") if lk.get("anim") in LINE_ANIMS else "none"}
        pts = e.get("pts") if isinstance(e.get("pts"), list) else []
        e["pts"] = [[round(_clamp(p[0], -20000, 20000), 1), round(_clamp(p[1], -20000, 20000), 1)] for p in pts[:48] if isinstance(p, (list, tuple)) and len(p) == 2]
    st = board.get("stickers") if isinstance(board.get("stickers"), list) else []
    board["stickers"] = [{"id": str(s.get("id") or new_id("s"))[:40], "e": _emoji(s.get("e")), "x": round(_clamp(s.get("x"), -20000, 20000), 1), "y": round(_clamp(s.get("y"), -20000, 20000), 1),
                          "s": int(_clamp(s.get("s"), 16, 120, 40))} for s in st[:200] if isinstance(s, dict) and _emoji(s.get("e"))]
    dd = board.get("doodles") if isinstance(board.get("doodles"), list) else []
    board["doodles"] = [{"id": str(d.get("id") or new_id("w"))[:40], "c": d.get("c") if d.get("c") in PENS else "ink", "w": int(_clamp(d.get("w"), 2, 12, 4)),
                         "pts": [[round(_clamp(p[0], -20000, 20000), 1), round(_clamp(p[1], -20000, 20000), 1)] for p in (d.get("pts") or [])[:160] if isinstance(p, (list, tuple)) and len(p) == 2]}
                        for d in dd[:150] if isinstance(d, dict) and isinstance(d.get("pts"), list) and len(d["pts"]) >= 2]
    nn = board.get("notes") if isinstance(board.get("notes"), list) else []
    board["notes"] = [{"id": str(n.get("id") or new_id("n"))[:40], "t": n["t"][:400], "x": round(_clamp(n.get("x"), -20000, 20000), 1), "y": round(_clamp(n.get("y"), -20000, 20000), 1),
                       "c": n.get("c") if n.get("c") in PENS else "ink"} for n in nn[:100] if isinstance(n, dict) and isinstance(n.get("t"), str) and n["t"].strip()]
    return board


def effective_of(board):
    amap = {a["id"]: a for a in board.get("agents", [])}
    cache = {}
    def f(aid):
        if aid not in cache: cache[aid] = L.effective(board, amap[aid]); cache[aid]["_board_id"] = board.get("board_id") or ""
        return cache[aid]
    return f


def new_edge(src, dst, **kw):
    e = {"id": new_id("e"), "from": src, "to": dst, "kind": "delegate", "handoff": True,
         "report": False, "memory": "none", "approval": False, "two_way": False, "max_messages": 20, "note": "", "look": {}, "pts": []}
    e.update(kw)
    return e


def new_department(name="Department", x=0, y=0, w=320, h=220, **kw):
    d = {"id": new_id("d"), "name": name, "x": x, "y": y, "w": w, "h": h, "collapsed": False,
         "limits": {"token_budget": 0, "spend_cap_usd": 0.0, "max_seconds": 0, "concurrency": 0},  # 0 = no collective cap
         "policy": default_policy()}
    d.update(kw)
    return d


def _num(v, lo, hi, label, errs, who, integer=False):
    try:
        f = float(v)
    except (TypeError, ValueError):
        errs.append(f"{who}: {label} must be a number")
        return
    if not lo <= f <= hi:
        errs.append(f"{who}: {label} must be between {lo} and {hi}")
    elif integer and f != int(f):
        errs.append(f"{who}: {label} must be a whole number")


def validate(board: dict, workers: dict | None = None, paid=lambda m: False):
    """Return {"errors": [...], "warnings": [...]}. Errors block Play."""
    errs, warns = [], []
    if not isinstance(board, dict):
        return {"errors": ["board must be an object"], "warnings": []}
    agents = board.get("agents") or []
    edges = board.get("edges") or []
    depts = board.get("departments") or []
    ids = [a.get("id") for a in agents]
    if not agents:
        errs.append("Add at least one agent (click the whiteboard).")
    for i in ids:
        if not isinstance(i, str) or not ID_RE.match(i):
            errs.append(f"invalid agent id {i!r}")
    if len(set(ids)) != len(ids):
        errs.append("duplicate agent ids")
    dids = {d.get("id") for d in depts}
    amap = {a["id"]: a for a in agents if isinstance(a.get("id"), str)}
    names = [str(a.get("name", "")).strip() for a in agents]
    for a in agents:
        who = f"agent '{a.get('name') or a.get('id')}'"
        if not str(a.get("name", "")).strip():
            errs.append(f"{who}: name is required")
        if names.count(str(a.get("name", "")).strip()) > 1 and str(a.get("name", "")).strip():
            warns.append(f"{who}: duplicate name (ids still distinguish them)")
        m = a.get("model")
        if not m:
            errs.append(f"{who}: choose a model")
        elif workers is not None and m not in workers:
            errs.append(f"{who}: model {m!r} is not a connected worker")
        elif paid(m) and not a.get("paused"):
            warns.append(f"{who}: {m} is a paid worker; Play creates the task but an operator must approve each run on the Floor")
        lim = a.get("limits") or {}
        _num(lim.get("token_budget", 0), 0, 1e9, "token budget", errs, who, True)
        _num(lim.get("spend_cap_usd", 0), 0, 1e6, "spending cap", errs, who)
        _num(lim.get("max_seconds", 0), 1, 600, "execution time (s)", errs, who, True)
        _num(lim.get("concurrency", 1), 1, 64, "concurrency", errs, who, True)
        sub = a.get("subagents") or {}
        if sub.get("enabled"):
            _num(sub.get("max", 0), 1, 32, "max subagents", errs, who, True)
            sm = sub.get("model") or ""
            if sm and workers is not None and sm not in workers: errs.append(f"{who}: subagent model {sm!r} is not a connected worker")
            elif sm and paid(sm) and not L.effective(board, a)["license"].get("paid_allowed"): errs.append(f"{who}: subagent model {sm} is paid; enable 'paid execution' on its License Board")
            sl = sub.get("limits") or {}
            _num(sl.get("token_budget", 0), 0, 1e9, "subagent token budget", errs, who, True)
            if float(sl.get("token_budget") or 0) > float(lim.get("token_budget") or 0) > 0:
                errs.append(f"{who}: a subagent budget cannot exceed its parent's budget")
        mem = a.get("memory") or {}
        if mem.get("mode", "read") not in MEM_MODES:
            errs.append(f"{who}: memory mode must be one of {MEM_MODES}")
        if a.get("dept") is not None and a["dept"] not in dids:
            errs.append(f"{who}: unknown department {a['dept']!r}")
    eids = set()
    pairs = set()
    for e in edges:
        who = f"connection {e.get('from')}→{e.get('to')}"
        if e.get("id") in eids:
            errs.append(f"{who}: duplicate connection id")
        eids.add(e.get("id"))
        if e.get("from") not in amap or e.get("to") not in amap:
            errs.append(f"{who}: connects to a missing agent")
            continue
        if e["from"] == e["to"]:
            errs.append(f"{who}: an agent cannot connect to itself")
        if e.get("kind", "delegate") not in EDGE_KINDS:
            errs.append(f"{who}: kind must be one of {EDGE_KINDS}")
        if e.get("memory", "none") not in MEM_MODES:
            errs.append(f"{who}: memory permission must be one of {MEM_MODES}")
        _num(e.get("max_messages", 1), 1, 1000, "message limit", errs, who, True)
        key = (e["from"], e["to"])
        if key in pairs:
            warns.append(f"{who}: duplicate connection")
        pairs.add(key)
    for d in depts:
        who = f"department '{d.get('name')}'"
        lim = d.get("limits") or {}
        for k, lo, hi in (("token_budget", 0, 1e10), ("spend_cap_usd", 0, 1e7), ("max_seconds", 0, 86400), ("concurrency", 0, 256)):
            _num(lim.get(k, 0), lo, hi, k, errs, who)
        members = [a for a in agents if a.get("dept") == d.get("id")]
        cap = float(lim.get("token_budget") or 0)
        if cap and sum(float((m.get("limits") or {}).get("token_budget") or 0) for m in members) > cap:
            warns.append(f"{who}: members' token budgets exceed the department cap; the cap is enforced collectively at run time")
    # ---- license, connection permissions, gambits, department policy
    try:
        eff = effective_of(board)
        for a in agents:
            e1, w1 = L.validate_license(board, a, workers, paid); errs += e1; warns += w1
            e2, w2 = G.validate_rules(board, a, eff); errs += e2; warns += w2
        for e in edges:
            if e.get("from") not in amap or e.get("to") not in amap or e["from"] == e["to"]: continue
            A, B = eff(e["from"]), eff(e["to"]); who = f"connection {A['name']}→{B['name']}"; k = e.get("kind", "delegate")
            if k in ("delegate", "both"):
                if not A["license"]["comms"].get("delegate"): errs.append(f"{who}: {A['name']} may not delegate (License Board)")
                if not B["license"]["comms"].get("receive"): errs.append(f"{who}: {B['name']} may not receive delegated work (License Board)")
            if k in ("report", "both") and not A["license"]["comms"].get("report"): errs.append(f"{who}: {A['name']} may not report (License Board)")
            mem = e.get("memory", "none")
            need = {"read": "mem:read", "readwrite": "mem:write"}.get(mem)
            if need and not (need in L.granted(A) and need in L.granted(B)): errs.append(f"{who}: shared memory '{mem}' needs {need} on both agents")
        for d in depts:
            pol = d.get("policy") or {}
            if pol.get("max_autonomy") not in (None, *L.AUTONOMY): errs.append(f"department '{d.get('name')}': invalid max autonomy")
    except (KeyError, TypeError, ValueError, AttributeError) as ex:
        errs.append(f"configuration is malformed: {type(ex).__name__}: {ex}")
    if not errs:
        order, cyc = dependency_order(board)
        if cyc:
            errs.append("delegation cycle: " + " → ".join(amap[i]["name"] for i in cyc))
    if agents and not edges and len(agents) > 1:
        warns.append("agents are not connected; each will run independently")
    return {"errors": errs, "warnings": warns}


def dependency_graph(board):
    """child depends on parent for delegate/both edges; for report edges the receiver depends on the sender."""
    deps = {a["id"]: set() for a in board.get("agents", [])}
    for e in board.get("edges", []):
        s, t = e.get("from"), e.get("to")
        if s not in deps or t not in deps or s == t:
            continue
        k = e.get("kind", "delegate")
        if k in ("delegate", "both"):
            deps[t].add(s)
        # "report" edges are messaging only: a worker reporting back to its delegator must not create a cycle.
    return deps


def dependency_order(board):
    """Kahn topological order. Returns (order, cycle_ids_or_None)."""
    deps = {k: set(v) for k, v in dependency_graph(board).items()}
    order = []
    ready = sorted(k for k, v in deps.items() if not v)
    while ready:
        n = ready.pop(0)
        order.append(n)
        for k, v in deps.items():
            if n in v:
                v.discard(n)
                if not v and k not in order and k not in ready:
                    ready.append(k)
        ready.sort()
    if len(order) == len(deps):
        return order, None
    rest = [k for k in deps if k not in order]
    return order, rest


def _agent_prompt(a, board, mission):
    amap = {x["id"]: x for x in board["agents"]}
    up = [amap[e["from"]]["name"] for e in board["edges"] if e["to"] == a["id"] and e["from"] in amap and e.get("kind", "delegate") in ("delegate", "both")]
    down = [amap[e["to"]]["name"] for e in board["edges"] if e["from"] == a["id"] and e["to"] in amap and e.get("kind", "delegate") in ("delegate", "both")]
    reports = [amap[e["to"]]["name"] for e in board["edges"] if e["from"] == a["id"] and e["to"] in amap and e.get("kind") == "report"]
    mem = a.get("memory") or {}
    parts = [f"You are {a['name']}."]
    if a.get("soul"): parts.append(f"SOUL: {a['soul']}")
    if a.get("instructions"): parts.append(f"INSTRUCTIONS: {a['instructions']}")
    parts.append(f"MISSION: {mission}")
    if up: parts.append("Receives work from: " + ", ".join(up))
    if down: parts.append("Delegates to: " + ", ".join(down))
    if reports: parts.append("Reports to: " + ", ".join(reports))
    parts.append(f"Memory: {'private' if mem.get('private', True) else 'no private'}; shared namespaces {mem.get('shared') or []} ({mem.get('mode', 'read')}).")
    lim = a.get("limits") or {}
    parts.append(f"Limits: {lim.get('token_budget')} tokens, ${lim.get('spend_cap_usd')} cap, {lim.get('max_seconds')}s, concurrency {lim.get('concurrency')}.")
    sub = a.get("subagents") or {}
    if (a.get("license") or {}).get("skills"): parts.append("Skills: " + ", ".join(a["license"]["skills"]))
    if sub.get("enabled"): parts.append(f"May spawn up to {sub.get('max')} subagents within their own limits.")
    return "\n".join(parts)


ACCOUNT_TOOLS = ("shell", "browser", "file_write", "code_exec", "http_api")

def account_grant(eff):
    """What a connected-account agent may do, from the EFFECTIVE config: tool names for the Claude allow-list, sandbox mode for Codex.
    read-only agents lose every write-capable tool. API-provider accounts run a bounded tool loop (files in one folder, web, granted MCP) when the provider supports tools."""
    ts = [t for t in (eff.get("tools") or []) if t in ACCOUNT_TOOLS]
    write = (eff.get("permissions") or "read-only") != "read-only"
    if not write: ts = [t for t in ts if t not in ("shell", "file_write", "code_exec")]
    return {"tools": ts, "sandbox": "workspace-write" if write and "file_write" in ts else "read-only", "mcp": [m for m in (eff.get("mcp") or []) if isinstance(m, str)][:12]}

CONTRACT_HOOKS = []      # callables (eff, contract, model) -> None, run in registration order

def task_contract(eff, scope, criteria=None, draft=False):
    """Task contract for a task owned by this (effective) agent. Shared by Play, Hunt claims and Gambit actions."""
    lim = eff.get("limits") or {}
    c = {"scope": scope, "allowed_tools": list(eff.get("tools") or []) + [f"mcp:{m}" for m in eff.get("mcp") or []],
         "timeout_s": int(float(lim.get("max_seconds") or 300)), "risk": "low"}
    m = eff.get("model") or DEFAULT_MODEL
    if m == "det.01": c.update(operation="manifest", verification="manifest", auto_accept=True)   # zero-cost, independently verified
    else:
        v = str(criteria or eff.get("verification") or "").strip()
        if v: c["verification"] = v
    for hook in CONTRACT_HOOKS:                                    # plugins/extensions add runtime-specific keys (see ordivyr.plugins)
        hook(eff, c, m)
    if m.startswith("acct."):
        c["account"] = {**account_grant(eff), "room": str(eff.get("_board_id") or "")[:60], "token_budget": int((eff.get("limits") or {}).get("token_budget") or 0)}
        c.setdefault("verification", "file:result.md")             # evidence = the runner-written, non-empty result file
    if draft: c["draft"] = True
    return c


def compile_board(board: dict, mission: str, run_id: str):
    """Compile to task specs in dependency order. Paused agents are skipped (dependents drop that link)."""
    order, cyc = dependency_order(board)
    if cyc:
        raise ValueError("delegation cycle")
    amap = {a["id"]: a for a in board["agents"]}
    eff = effective_of(board)
    deps = dependency_graph(board)
    gated = {e["to"] for e in board.get("edges", []) if e.get("approval") and e.get("kind", "delegate") != "report"
             and e.get("from") in amap and not amap[e["from"]].get("paused")}
    specs = []
    for i in order:
        a = amap[i]
        if a.get("paused"):
            continue
        e = eff(i)
        specs.append({
            "agent_id": a["id"], "title": f"[{board.get('name', 'room')}] {a['name']}",
            "description": _agent_prompt(e, board, mission), "owner": e.get("model") or DEFAULT_MODEL,
            "depends_on_agents": sorted(d for d in deps[i] if not amap[d].get("paused")),
            "contract": task_contract(e, f"{SCOPE_PREFIX}:{run_id}:{a['id']}", draft=i in gated), "request_id": f"{REQUEST_PREFIX}:{run_id}:{a['id']}",
        })
    return specs


def reachable_downstream(board, agent_ids):
    """All agents transitively reachable via edges leaving the given ids (for 'stop department')."""
    seen, stack = set(), list(agent_ids)
    while stack:
        n = stack.pop()
        for e in board.get("edges", []):
            if e.get("from") == n and e.get("to") not in seen and e.get("kind", "delegate") != "report":
                seen.add(e["to"]); stack.append(e["to"])
    return seen


# ---------------------------------------------------------------- templates / import-export
def export_board(board, agent_ids=None, name=None):
    """Portable JSON for the board or a subset (e.g. one department)."""
    b = copy.deepcopy(board)
    if agent_ids is not None:
        keep = set(agent_ids)
        b["agents"] = [a for a in b["agents"] if a["id"] in keep]
        b["edges"] = [e for e in b["edges"] if e["from"] in keep and e["to"] in keep]
        used = {a.get("dept") for a in b["agents"]}
        b["departments"] = [d for d in b["departments"] if d["id"] in used]
    if name: b["name"] = name
    b["schema"] = SCHEMA
    return b


def import_board(doc, workers=None):
    """Parse untrusted JSON into a sanitized board (unknown keys dropped, models coerced to a connected worker)."""
    if isinstance(doc, str):
        doc = json.loads(doc)
    if not isinstance(doc, dict) or not isinstance(doc.get("agents", []), list):
        raise ValueError("not an ORDIVYR export")
    if int(doc.get("schema", SCHEMA)) > SCHEMA:
        raise ValueError("export is from a newer ORDIVYR")
    board = new_board(str(doc.get("name") or "Imported room")[:80])
    for a in doc.get("agents", []):
        base = new_agent(0, 0)
        for k in base:
            if k in a: base[k] = a[k]
        base["id"] = str(a.get("id") or base["id"])
        if workers is not None and base["model"] not in workers: base["model"] = DEFAULT_MODEL
        board["agents"].append(base)
    for e in doc.get("edges", []):
        base = new_edge(None, None)
        for k in base:
            if k in e: base[k] = e[k]
        board["edges"].append(base)
    for k in ("stickers", "doodles", "notes"): board[k] = doc.get(k) if isinstance(doc.get(k), list) else []
    for d in doc.get("departments", []):
        base = new_department()
        for k in base:
            if k in d: base[k] = d[k]
        board["departments"].append(base)
    return board


def instantiate(doc, dx=0, dy=0, suffix=""):
    """Clone a board/subset with fresh ids (duplicate department, apply template) offset by (dx, dy)."""
    b = copy.deepcopy(doc)
    amap = {a["id"]: new_id("a") for a in b["agents"]}
    dmap = {d["id"]: new_id("d") for d in b["departments"]}
    for a in b["agents"]:
        a["id"] = amap[a["id"]]; a["x"] += dx; a["y"] += dy
        if suffix: a["name"] += suffix
        a["dept"] = dmap.get(a.get("dept"))
        a["paused"] = False
    for d in b["departments"]:
        d["id"] = dmap[d["id"]]; d["x"] += dx; d["y"] += dy
        if suffix: d["name"] += suffix
    for e in b["edges"]:
        e["id"] = new_id("e"); e["from"] = amap[e["from"]]; e["to"] = amap[e["to"]]
    for a in b["agents"]:                       # gambits reference agents by id: remap them with the clone
        for r in a.get("gambits") or []:
            r["id"] = new_id("g")
            t = r.get("then") or {}; c = r.get("if") or {}
            if t.get("target") in amap: t["target"] = amap[t["target"]]
            if c.get("agent") in amap: c["agent"] = amap[c["agent"]]
    normalize(b); sanitize_gambits(b)
    return b


def sanitize_gambits(board):
    """Disable (never delete) rules that cannot validate in this board, e.g. a copied department whose manager was not copied."""
    eff = effective_of(board); n = 0
    for a in board.get("agents", []):
        for r in a.get("gambits") or []:
            if not r.get("enabled", True): continue
            probe = {**a, "gambits": [r]}
            errs, _ = G.validate_rules(board, probe, eff)
            if errs: r["enabled"] = False; r["note"] = "disabled on copy: " + errs[0].split(": ", 1)[-1][:120]; n += 1
    return n


def _team(name, lead, workers, model=DEFAULT_MODEL, cx=0, cy=0):
    """Department with a lead and worker agents laid out in a row beneath it."""
    d = new_department(name, cx - 60, cy - 40, 160 + 190 * max(len(workers), 1), 330)
    boss = new_agent(cx + 40 + 95 * max(len(workers) - 1, 0), cy + 20, lead[0], instructions=lead[1], soul=lead[2] if len(lead) > 2 else "", model=model, dept=d["id"])
    agents, edges = [boss], []
    for i, (nm, ins) in enumerate(workers):
        w = new_agent(cx + 20 + 190 * i, cy + 190, nm, instructions=ins, model=model, dept=d["id"])
        agents.append(w)
        edges.append(new_edge(boss["id"], w["id"], report=True, kind="both"))
    return d, agents, edges


def builtin_templates():
    T = {}

    def assemble(key, title, desc, teams, god=None):
        b = new_board(title)
        gx = 80
        for (nm, lead, workers) in teams:
            d, ags, eds = _team(nm, lead, workers, cx=gx, cy=260)
            b["departments"].append(d); b["agents"] += ags; b["edges"] += eds
            gx += d["w"] + 40
        if god or len(teams) > 1:
            g = new_agent(max(gx // 2 - 90, 0), 20, god[0] if god else "Director", instructions=god[1] if god else "Split the mission across departments and consolidate their reports.", soul="Calm, decisive, accountable.")
            leads = [a for a in b["agents"] if a["dept"] and a["x"] is not None and any(a["id"] == e["from"] for e in b["edges"]) and not any(a["id"] == e["to"] for e in b["edges"])]
            b["agents"].insert(0, g)
            for l in leads: b["edges"].append(new_edge(g["id"], l["id"], kind="both", report=True))
        T[key] = {"key": key, "title": title, "description": desc, "board": b}

    assemble("personal-assistant", "Personal assistant", "One assistant with research and scheduling helpers.",
             [("Assistant team", ("Assistant", "Take requests, delegate, and summarise outcomes."), [("Researcher", "Find and cite facts."), ("Scheduler", "Plan time and reminders.")])],
             god=("You", "Owner of the request."))
    assemble("sales-team", "Sales team", "Outreach lead with five specialised workers.",
             [("Outreach", ("Outreach lead", "Plan campaigns; require approval before anything is sent."), [("Prospector", "Build target lists."), ("Researcher", "Profile each prospect."), ("Copywriter", "Draft messages."), ("Reviewer", "Check tone and claims."), ("Follow-up", "Prepare follow-up cadence.")])],
             god=("GOD", "Own the revenue goal; approve outreach batches."))
    assemble("software-factory", "Software development factory", "Engineering department: coding, testing, deployment.",
             [("Engineering", ("Engineering lead", "Break work into tasks and integrate results."), [("Coder", "Implement changes."), ("Tester", "Write and run tests."), ("Deployer", "Prepare a deployment plan; never deploy without approval.")])],
             god=("GOD", "Own delivery."))
    assemble("research-department", "Research department", "Lead analyst with collectors and a fact checker.",
             [("Research", ("Lead analyst", "Frame the question and synthesise a brief."), [("Collector A", "Gather primary sources."), ("Collector B", "Gather secondary sources."), ("Fact checker", "Verify every claim.")])],
             god=("Editor", "Commission the brief."))
    assemble("content-team", "Content production team", "Editor with writer, designer and SEO reviewer.",
             [("Content", ("Editor", "Own the content calendar and quality bar."), [("Writer", "Draft."), ("Designer", "Specify visuals."), ("SEO reviewer", "Check keywords and structure.")])],
             god=("Publisher", "Approve final content."))
    assemble("full-organization", "Full organization (GOD)", "GOD agent over Outreach, Engineering and Media.",
             [("Outreach", ("Outreach lead", "Run outreach."), [("Worker 1", "Outreach worker."), ("Worker 2", "Outreach worker."), ("Worker 3", "Outreach worker."), ("Worker 4", "Outreach worker."), ("Worker 5", "Outreach worker.")]),
              ("Engineering", ("Engineering lead", "Run engineering."), [("Coding", "Implement."), ("Testing", "Verify."), ("Deployment", "Plan releases.")]),
              ("Media", ("Media lead", "Run media."), [("Scripts", "Write scripts."), ("Production", "Produce assets.")])],
             god=("GOD", "Own the organization's mission."))
    from .examples import five_agent_board
    T["five-agent-example"] = {"key": "five-agent-example", "title": "GOD + Research / Coding / QA / Outreach (with Gambits)",
                               "description": "Reference org: licenses, department policy, gambit routing, QA hand-off and escalation.", "board": five_agent_board()}
    return T
