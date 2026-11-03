"""Agent Team Templates: portable, framework-independent JSON ("ordivyr-template/1") that expands into a normal ORDIVYR board.

A template names agents by `key` (never by generated id) and carries everything a team needs: roles, instructions, suggested models
(provider + model, BYOK - keys are never part of a template), subagents, bridges (edges), gambits, License-tree permissions,
private/shared memory and limits. build() maps it onto the existing board model, so every template is edited, validated and run
by exactly the same code as a hand-drawn room. Nothing here imports Hermes or any other runtime.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from .roles import ROLES
from . import core, gambits as G, license as L

SCHEMA = "ordivyr-template/1"
LEGACY_SCHEMAS = ()      # a host product may add older schema names it must keep importing (rewritten to SCHEMA)
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
AGENT_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
BUILTIN_DIR = Path(__file__).with_name("team_templates")
MAX_BYTES = 300_000
MAX_AGENTS = 24
SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY|xox[abp]-[A-Za-z0-9-]{10,}|ghp_[A-Za-z0-9]{20,})")
TIERS = ("strong", "balanced", "fast", "free")


class TemplateError(ValueError): pass


def _s(v, n): return str(v if v is not None else "")[:n]


def _hw_req(h):
    h = h if isinstance(h, dict) else {}
    return {"min_vram_mb": max(0, min(10**6, int(h.get("min_vram_mb") or 0))), "min_gpus": max(0, min(16, int(h.get("min_gpus") or 0))), "local_only": bool(h.get("local_only")),
            "needs_roles": [r for r in (h.get("needs_roles") or []) if r in ROLES][:8]}


def clean(doc):
    """Validate + normalise an untrusted template document -> a new dict (unknown keys dropped). Raises TemplateError with a plain message."""
    if isinstance(doc, (str, bytes)):
        if len(doc) > MAX_BYTES: raise TemplateError("template file is too large")
        try: doc = json.loads(doc)
        except ValueError: raise TemplateError("that file is not valid JSON")
    if not isinstance(doc, dict) or doc.get("schema") not in (SCHEMA, *LEGACY_SCHEMAS): raise TemplateError(f"not an ORDIVYR team template (expected schema {SCHEMA!r})")
    if SECRET_RE.search(json.dumps(doc)): raise TemplateError("this template appears to contain an API key or secret; templates never carry keys - remove it")
    key = _s(doc.get("key"), 64)
    if not KEY_RE.match(key): raise TemplateError("template key must be lowercase letters, digits and dashes")
    agents_in = doc.get("agents")
    if not isinstance(agents_in, list) or not agents_in: raise TemplateError("a template needs at least one agent")
    if len(agents_in) > MAX_AGENTS: raise TemplateError(f"at most {MAX_AGENTS} agents per template")
    out = {"schema": SCHEMA, "key": key, "title": _s(doc.get("title"), 80) or key, "tagline": _s(doc.get("tagline"), 120), "description": _s(doc.get("description"), 600),
           "tags": [_s(t, 24) for t in (doc.get("tags") or []) if isinstance(t, str)][:8], "mission_hint": _s(doc.get("mission_hint"), 400),
           "hardware": _hw_req(doc.get("hardware")), "settings": {k: v for k, v in (doc.get("settings") or {}).items() if k in ("max_depth", "max_actions", "max_drex_calls") and isinstance(v, int)},
           "events": [_s(e, 60) for e in (doc.get("events") or []) if isinstance(e, str)][:20], "shared_memory": [_s(m, 60) for m in (doc.get("shared_memory") or []) if isinstance(m, str)][:20],
           "departments": [], "agents": [], "bridges": []}
    dkeys = set()
    for d in doc.get("departments") or []:
        if not isinstance(d, dict) or not AGENT_KEY_RE.match(str(d.get("key", ""))): raise TemplateError("each department needs a simple key")
        dkeys.add(d["key"]); pol = d.get("policy") if isinstance(d.get("policy"), dict) else {}
        out["departments"].append({"key": d["key"], "name": _s(d.get("name"), 60) or d["key"], **{k: int(d.get(k) or 0) for k in ("x", "y")}, "w": int(d.get("w") or 320), "h": int(d.get("h") or 220), "policy": pol})
    akeys = set()
    for a in agents_in:
        if not isinstance(a, dict) or not AGENT_KEY_RE.match(str(a.get("key", ""))): raise TemplateError("each agent needs a simple key (letters, digits, - _)")
        if a["key"] in akeys: raise TemplateError(f"duplicate agent key {a['key']!r}")
        akeys.add(a["key"])
        m = a.get("model") if isinstance(a.get("model"), dict) else {}
        sug = [{"provider": _s(s.get("provider"), 30), "model": _s(s.get("model"), 80)} for s in (m.get("suggest") or []) if isinstance(s, dict) and s.get("provider")][:6]
        out["agents"].append({"key": a["key"], "name": _s(a.get("name"), 40) or a["key"], "role": _s(a.get("role"), 80), "x": int(a.get("x") or 0), "y": int(a.get("y") or 0), "dept": a.get("dept") if a.get("dept") in dkeys else None,
            "soul": _s(a.get("soul"), 400), "instructions": _s(a.get("instructions"), 2000), "tools": [t for t in (a.get("tools") or []) if t in L.DEFAULT_TOOLS],
            "mcp": [_s(x, 40) for x in (a.get("mcp") or []) if isinstance(x, str)][:12], "permissions": "workspace-write" if a.get("permissions") == "workspace-write" else "read-only",
            "model": {"tier": m.get("tier") if m.get("tier") in TIERS else "balanced", "suggest": sug, "role": m.get("role") if m.get("role") in ROLES else ""},
            "limits": {k: (float(v) if k == "spend_cap_usd" else int(v)) for k, v in (a.get("limits") or {}).items() if k in core.LIMIT_KEYS and isinstance(v, (int, float))},
            "subagents": a.get("subagents") if isinstance(a.get("subagents"), dict) else {"enabled": False, "max": 0},
            "memory": {"private": bool((a.get("memory") or {}).get("private", True)), "shared": [_s(n, 60) for n in ((a.get("memory") or {}).get("shared") or []) if isinstance(n, str)][:10],
                       "mode": (a.get("memory") or {}).get("mode") if (a.get("memory") or {}).get("mode") in core.MEM_MODES else "read"},
            "license": {k: v for k, v in (a.get("license") or {}).items() if k in ("skills", "comms", "paid_allowed", "gpu", "autonomy", "fallbacks")},
            "gambits": [g for g in (a.get("gambits") or []) if isinstance(g, dict) and isinstance(g.get("if"), dict) and isinstance(g.get("then"), dict)][:20]})
        out["agents"][-1]["license"].setdefault("skills", [])
    for b in doc.get("bridges") or []:
        if not isinstance(b, dict) or b.get("from") not in akeys or b.get("to") not in akeys or b["from"] == b["to"]: raise TemplateError("a bridge connects two agents in this template")
        out["bridges"].append({"from": b["from"], "to": b["to"], "kind": b.get("kind") if b.get("kind") in core.EDGE_KINDS else "delegate", "note": _s(b.get("note"), 80),
                               "color": b.get("color") if b.get("color") in core.PENS else "", "memory": b.get("memory") if b.get("memory") in core.MEM_MODES else "none",
                               "approval": bool(b.get("approval")), "handoff": bool(b.get("handoff", True)), "report": bool(b.get("report")), "two_way": bool(b.get("two_way")),
                               "max_messages": max(1, min(200, int(b.get("max_messages") or 20)))})
    return out


def builtin():
    """key -> cleaned template, in a stable display order."""
    order = ["saas-dev-team", "research-department", "youtube-production-team", "business-operations-team", "crypto-research-team"]
    docs = {}
    for p in sorted(BUILTIN_DIR.glob("*.json")):
        t = clean(p.read_text("utf-8")); docs[t["key"]] = t
    return {k: docs[k] for k in order + sorted(set(docs) - set(order)) if k in docs}


def user_dir(home): return Path(home) / "team-templates"


def user_templates(home):
    out = {}
    d = user_dir(home)
    if d.is_dir():
        for p in sorted(d.glob("*.json")):
            try: t = clean(p.read_text("utf-8")); t["user"] = True; out[t["key"]] = t
            except (TemplateError, OSError): continue
    return out


def save_user(home, doc):
    t = clean(doc); d = user_dir(home); d.mkdir(parents=True, exist_ok=True)
    if t["key"] in builtin(): t["key"] = "my-" + t["key"][:60]
    (d / f"{t['key']}.json").write_text(json.dumps(t, indent=2) + "\n"); return t


def delete_user(home, key):
    p = user_dir(home) / f"{key}.json"
    if not KEY_RE.match(key) or not p.is_file(): raise TemplateError("unknown template")
    p.unlink()


def catalog(home):
    return {**builtin(), **user_templates(home)}


def summary(t):
    """What a card / preview needs: no instructions, but enough to draw the team and say what it needs."""
    return {"key": t["key"], "title": t["title"], "tagline": t["tagline"], "description": t["description"], "tags": t["tags"], "mission_hint": t["mission_hint"], "user": bool(t.get("user")),
            "agents": [{"key": a["key"], "name": a["name"], "role": a["role"], "x": a["x"], "y": a["y"], "dept": a["dept"], "tier": a["model"]["tier"], "suggest": a["model"]["suggest"][:2],
                        "tools": a["tools"], "subagents": a["subagents"].get("max", 0) if a["subagents"].get("enabled") else 0, "gambits": len(a["gambits"]), "writes": a["permissions"] != "read-only",
                        "approval": a["license"].get("autonomy") == "manual", "shared": a["memory"]["shared"], "mode": a["memory"]["mode"]} for a in t["agents"]],
            "departments": [{"key": d["key"], "name": d["name"], "x": d["x"], "y": d["y"], "w": d["w"], "h": d["h"]} for d in t["departments"]],
            "bridges": [{"from": b["from"], "to": b["to"], "kind": b["kind"], "color": b["color"], "note": b["note"], "memory": b["memory"], "approval": b["approval"]} for b in t["bridges"]],
            "shared_memory": t["shared_memory"], "tiers": sorted({a["model"]["tier"] for a in t["agents"]})}


# ------------------------------------------------------------------ template -> board
def pick_model(suggest, accounts, workers):
    """Best CONNECTED account that matches a suggestion (provider and, if given, model), else the free default. Never invents a worker."""
    for s in suggest:
        for acc in accounts:
            if acc.get("provider") != s["provider"] or not (acc.get("enabled") and acc.get("connected")): continue
            if s.get("model") and acc.get("model") and s["model"] != acc["model"]: continue
            wid = "acct." + acc["id"]
            if wid in workers: return wid
    return core.DEFAULT_MODEL


def build(t, accounts=(), workers=None, name=None, role_plan=None):
    """-> (board, needs). `needs` lists agents still on the free default model with what to connect (BYOK), for the post-create checklist."""
    t = clean(t) if not t.get("schema") == SCHEMA or "agents" not in t else t
    workers = workers if workers is not None else {core.DEFAULT_MODEL: {}}
    b = core.new_board(_s(name, 80) or t["title"]); b["settings"].update(t["settings"]); b["events"] = list(t["events"]); amap = {}; dmap = {}; needs = []
    for d in t["departments"]:
        nd = core.new_department(d["name"], d["x"], d["y"], d["w"], d["h"])
        for k, v in d["policy"].items():
            if k in nd["policy"]: nd["policy"][k] = v
        dmap[d["key"]] = nd["id"]; b["departments"].append(nd)
    for a in t["agents"]:
        na = core.new_agent(a["x"], a["y"], a["name"], soul=a["soul"], instructions=a["instructions"], tools=list(a["tools"]), mcp=list(a["mcp"]), permissions=a["permissions"],
                            dept=dmap.get(a["dept"]), memory=dict(a["memory"]))
        na["limits"] = core.default_limits(**a["limits"])
        sa = a["subagents"]; na["subagents"] = {"enabled": bool(sa.get("enabled")), "max": max(0, min(10, int(sa.get("max") or 0))), "limits": core.default_limits(**{**{"token_budget": 10000, "max_seconds": 120}, **(sa.get("limits") or {})})}
        na["license"]["skills"] = list(a["license"].get("skills") or [])
        for k in ("paid_allowed", "gpu", "autonomy", "fallbacks"):
            if k in a["license"]: na["license"][k] = a["license"][k]
        if isinstance(a["license"].get("comms"), dict): na["license"]["comms"].update({c: bool(v) for c, v in a["license"]["comms"].items() if c in L.COMMS})
        na["model"] = pick_model(a["model"]["suggest"], accounts, workers)
        rp = (role_plan or {}).get(a["model"].get("role") or "", {})
        if rp.get("model") and na["model"] == core.DEFAULT_MODEL: na["model"] = "role:" + a["model"]["role"]       # hardware-aware: a local model fills this role
        if (workers.get(na["model"]) or {}).get("paid"):             # a connected PAID account: allowed unless the department forbids it; every paid run is still held for your approval
            d = next((x for x in b["departments"] if x["id"] == na["dept"]), None)
            if d and d["policy"].get("paid_allowed") is False: na["model"] = core.DEFAULT_MODEL
            else: na["license"]["paid_allowed"] = True
        if na["model"] == core.DEFAULT_MODEL and a["model"]["suggest"] and not rp.get("model"): needs.append({"agent": na["name"], "id": na["id"], "tier": a["model"]["tier"], "suggest": a["model"]["suggest"][:3]})
        if a["role"]: na["soul"] = (na["soul"] + " " if na["soul"] else "") + f"Role: {a['role']}."
        amap[a["key"]] = na["id"]; b["agents"].append(na)
    for e in t["bridges"]:
        b["edges"].append(core.new_edge(amap[e["from"]], amap[e["to"]], kind=e["kind"], note=e["note"], color=e["color"], memory=e["memory"], approval=e["approval"], handoff=e["handoff"],
                                        report=e["report"] or e["kind"] in ("report", "both"), two_way=e["two_way"], max_messages=e["max_messages"]))
    for a, na in zip(t["agents"], b["agents"]):
        rules = []
        for g in a["gambits"]:
            r = G.new_rule(g["if"].get("kind", "task_type"), g["then"].get("kind", "notify"), name=_s(g.get("name"), 80)); r["if"] = dict(g["if"]); r["then"] = dict(g["then"])
            tg = str(r["then"].get("target") or "")
            if tg.startswith("@"):
                if tg[1:] not in amap: raise TemplateError(f"gambit in {a['name']} targets unknown agent {tg!r}")
                r["then"]["target"] = amap[tg[1:]]
            rules.append(r)
        na["gambits"] = rules
    return core.normalize(b), needs


# ------------------------------------------------------------------ board -> template (so customers can save + share their own)
def from_board(board, title, description="", key=None):
    keymap = {}; used = set()
    for a in board.get("agents", []):
        base = re.sub(r"[^a-z0-9]+", "-", a["name"].lower()).strip("-")[:30] or "agent"; k = base; i = 2
        while k in used: k = f"{base}-{i}"; i += 1
        used.add(k); keymap[a["id"]] = k
    dkey = {d["id"]: f"dept-{i}" for i, d in enumerate(board.get("departments", []), 1)}
    ags = []
    for a in board.get("agents", []):
        gam = []
        for r in a.get("gambits") or []:
            tg = (r.get("then") or {}).get("target")
            gam.append({"name": r.get("name", ""), "if": r["if"], "then": {**r["then"], "target": "@" + keymap[tg] if tg in keymap else tg or ""}})
        ags.append({"key": keymap[a["id"]], "name": a["name"], "role": "", "x": int(a.get("x") or 0), "y": int(a.get("y") or 0), "dept": dkey.get(a.get("dept")), "soul": a.get("soul", ""), "instructions": a.get("instructions", ""),
                    "tools": a.get("tools", []), "mcp": a.get("mcp", []), "permissions": a.get("permissions", "read-only"), "model": {"tier": "balanced", "suggest": []},
                    "limits": a.get("limits", {}), "subagents": {k: v for k, v in (a.get("subagents") or {}).items()}, "memory": a.get("memory", {}),
                    "license": {k: v for k, v in (a.get("license") or {}).items() if k != "fallbacks"}, "gambits": gam})
    doc = {"schema": SCHEMA, "key": key or ("my-" + (re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40] or "team")), "title": title, "tagline": "", "description": description, "tags": [], "mission_hint": "",
           "settings": {k: board.get("settings", {}).get(k) for k in ("max_depth", "max_actions", "max_drex_calls") if isinstance(board.get("settings", {}).get(k), int)}, "events": board.get("events", []),
           "shared_memory": sorted({n for a in ags for n in (a["memory"].get("shared") or [])}),
           "departments": [{"key": dkey[d["id"]], "name": d["name"], "x": d["x"], "y": d["y"], "w": d["w"], "h": d["h"], "policy": d.get("policy", {})} for d in board.get("departments", [])], "agents": ags,
           "bridges": [{"from": keymap[e["from"]], "to": keymap[e["to"]], "kind": e.get("kind", "delegate"), "note": e.get("note", ""), "color": e.get("color", ""), "memory": e.get("memory", "none"), "approval": bool(e.get("approval")),
                        "handoff": bool(e.get("handoff", True)), "report": bool(e.get("report")), "two_way": bool(e.get("two_way")), "max_messages": e.get("max_messages", 20)} for e in board.get("edges", []) if e["from"] in keymap and e["to"] in keymap]}
    return clean(doc)
