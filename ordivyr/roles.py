"""Specialised model roles: which model plays planner, coder, reviewer, router, embedder, vision, summarizer.

A role says what it needs (tags, minimum size, whether it must be local); `assign()` scores the models you actually have (local inventory
+ BYOK provider models) against each role and the detected hardware, and explains every choice. Agents refer to a role as `role:<name>`
and the runner resolves it. User overrides always win. Nothing here calls a model.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

ROLES = {
    "router":     {"label": "Router", "about": "cheap, fast triage: classify a task and pick who handles it", "prefer": ["small", "fast"], "min_b": 0, "max_b": 9, "need": []},
    "planner":    {"label": "Planner", "about": "decomposes a mission into steps; benefits from reasoning models", "prefer": ["reason", "large"], "min_b": 7, "need": []},
    "coder":      {"label": "Coder", "about": "writes and edits code", "prefer": ["coder", "large"], "min_b": 7, "need": []},
    "reviewer":   {"label": "Reviewer", "about": "checks others' work; should differ from the model that produced it", "prefer": ["reason", "large"], "min_b": 7, "need": [], "distinct_from": "coder"},
    "summarizer": {"label": "Summarizer", "about": "condenses long text and memory", "prefer": ["small", "fast", "longctx"], "min_b": 0, "need": []},
    "embedder":   {"label": "Embedder", "about": "text embeddings for memory search", "prefer": ["embed"], "min_b": 0, "need": ["embed"]},
    "vision":     {"label": "Vision", "about": "reads screenshots and images", "prefer": ["vision"], "min_b": 0, "need": ["vision"]},
}


def tags_for(name):
    n = (name or "").lower(); t = set()
    if re.search(r"coder|code|starcoder|codestral|devstral|deepseek-coder", n): t.add("coder")
    if re.search(r"embed|bge-|nomic|minilm|e5-|gte-", n): t.add("embed")
    if re.search(r"llava|vision|-vl|vl-|moondream|minicpm-v|pixtral|gemma3|qwen2\.5vl", n): t.add("vision")
    if re.search(r"r1|reason|think|qwq|o1|o3|magistral|-thinking", n): t.add("reason")
    if re.search(r"instruct|chat|-it\b", n) or not t: t.add("chat")
    return t


@dataclass
class Candidate:
    name: str; backend: str; params_b: float | None = None; tags: set = field(default_factory=set); local: bool = True; paid: bool = False; fits: bool = True; note: str = ""
    def ref(self): return f"{self.backend}:{self.name}"


def candidates_from(models, hardware=None, paid_models=()):
    """models: llm.Model list -> Candidates (marks those that cannot fit this machine); paid_models: [(provider, name)] BYOK API models."""
    out = []
    for m in models:
        c = Candidate(m.name, m.backend, m.params_b, tags_for(m.name))
        if hardware is not None and not m.loaded:
            from . import hw as HW
            need = m.need_mb()
            if need and HW.fits(hardware, need)["where"] is None: c.fits = False; c.note = f"needs ~{need} MB, does not fit"
        out.append(c)
    for prov, name in paid_models:
        pb = None; c = Candidate(name, prov, pb, tags_for(name), local=False, paid=True); out.append(c)
    return out


def _score(role, c, local_only):
    spec = ROLES[role]
    if any(n not in c.tags for n in spec["need"]): return None
    if "embed" in c.tags and role != "embedder": return None
    if "vision" in c.tags and role not in ("vision",) and "chat" not in c.tags and role != "summarizer": pass
    if not c.fits: return None
    if local_only and not c.local: return None
    s = 0.0; p = c.params_b
    if p is not None:
        if spec.get("min_b") and p < spec["min_b"]: s -= 40
        if spec.get("max_b") and p > spec["max_b"]: s -= 10 + (p - spec["max_b"])
    for pref in spec["prefer"]:
        if pref == "coder" and "coder" in c.tags: s += 40
        elif pref == "reason" and "reason" in c.tags: s += 30
        elif pref == "vision" and "vision" in c.tags: s += 40
        elif pref == "embed" and "embed" in c.tags: s += 40
        elif pref == "large" and p: s += min(p, 40) * 0.6
        elif pref in ("small", "fast") and p: s += max(0, 12 - p) * 1.2
    if c.paid: s -= 5            # prefer free local models on ties; paid is opt-in
    return s


def assign(candidates, local_only=True, overrides=None, roles=None):
    """-> {role: {'model': ref|None, 'why': str, 'alternatives': [ref]}}. Reviewer avoids the coder's model when another good one exists."""
    out = {}; overrides = overrides or {}
    for role in (roles or list(ROLES)):
        if role in overrides: out[role] = {"model": overrides[role], "why": "set by you", "alternatives": []}; continue
        scored = [(s, c) for c in candidates if (s := _score(role, c, local_only)) is not None]
        dist = ROLES[role].get("distinct_from")
        if dist and dist in out and out[dist]["model"]:
            alt = [(s, c) for s, c in scored if c.ref() != out[dist]["model"]]
            if alt: scored = alt
        scored.sort(key=lambda t: (-t[0], t[1].name))
        if not scored:
            why = "no suitable " + ("local " if local_only else "") + "model" + (f" tagged {ROLES[role]['need']}" if ROLES[role]["need"] else "") + " is installed that fits this machine"
            out[role] = {"model": None, "why": why, "alternatives": []}; continue
        s, c = scored[0]
        out[role] = {"model": c.ref(), "why": f"{ROLES[role]['about']}; picked for tags {sorted(c.tags)}" + (f", {c.params_b:g}B" if c.params_b else ""), "alternatives": [x.ref() for _, x in scored[1:4]]}
    return out
