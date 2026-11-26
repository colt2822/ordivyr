"""Typed node-to-node handoff: a downstream agent gets a compact, validated {summary, changed_files, artifacts, open_risks} instead of a raw 2,500-char dump.
An upstream agent may end its output with a fenced ```handoff JSON block; otherwise the fields are derived (first paragraphs, file-like paths, RISK/TODO lines)."""
import json, re

ASK = "\nEnd with a fenced ```handoff JSON block: {\"summary\": str, \"changed_files\": [paths], \"artifacts\": [str], \"open_risks\": [str]} for the agents that build on your work."
CAPS = {"summary": 2500, "changed_files": 20, "artifacts": 10, "open_risks": 8, "item": 160}
_BLOCK = re.compile(r"```handoff\s*(\{.*?\})\s*```", re.S)
_PATH = re.compile(r"(?<![\w/])((?:[\w.-]+/)+[\w.-]+\.[A-Za-z0-9]{1,6})(?![\w/])")
_RISK = re.compile(r"^\s*(?:[-*]\s*)?(?:risk|todo|open question|caveat|blocker)s?\s*[:\-]\s*(.+)$", re.I | re.M)


def _strs(x, n):
    return [str(i).strip()[:CAPS["item"]] for i in (x if isinstance(x, list) else []) if str(i).strip()][:n]


def validate(h):
    """-> a clean handoff dict (unknown keys dropped, types and sizes forced)."""
    h = h if isinstance(h, dict) else {}
    return {"summary": str(h.get("summary") or "").strip()[:CAPS["summary"]], "changed_files": _strs(h.get("changed_files"), CAPS["changed_files"]),
            "artifacts": _strs(h.get("artifacts"), CAPS["artifacts"]), "open_risks": _strs(h.get("open_risks"), CAPS["open_risks"])}


def extract(text):
    text = text or ""; m = _BLOCK.search(text)
    if m:
        try:
            h = validate(json.loads(m.group(1)))
            if not h["summary"]: h["summary"] = _BLOCK.sub("", text).strip()[:CAPS["summary"]]
            return h
        except ValueError: pass
    body = _BLOCK.sub("", text).strip()
    return validate({"summary": body, "changed_files": list(dict.fromkeys(_PATH.findall(body))), "open_risks": _RISK.findall(body)})


def render(name, h):
    out = [f"HANDOFF FROM {name}:", h["summary"]]
    for label, k in (("Changed files", "changed_files"), ("Artifacts", "artifacts"), ("Open risks", "open_risks")):
        if h[k]: out.append(f"{label}: " + "; ".join(h[k]))
    return "\n".join(out)
