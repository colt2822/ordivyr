"""Tell the human when the room needs them. Pure event detection (testable) + two quiet senders: desktop (notify-send) and a webhook.
Payloads carry names and short status text only - never prompts, results or secrets. Each event fires once (remembered per run/agent/task)."""
from __future__ import annotations
import json, shutil, subprocess, urllib.request
from urllib.parse import urlparse

LOOP = ("127.0.0.1", "localhost", "::1")


def events(snap, board, seen: set):
    """New (kind, agent name, text) events in this snapshot. Marks them seen."""
    out = []; run = snap.get("run") or {}; rid = run.get("run_id")
    if not rid: return out
    names = {a["id"]: a["name"] for a in board["agents"]}
    def fire(key, kind, who, text):
        if key in seen: return
        seen.add(key); out.append({"kind": kind, "agent": who, "text": text, "room": board["name"]})
    for aid, ag in (snap.get("agents") or {}).items():
        n = names.get(aid, aid); k = (rid, aid, ag.get("task_id"))
        if ag.get("question"): fire(k + ("q",), "question", n, f"{n} has a question for you")
        elif ag.get("column") == "HUMAN_APPROVAL": fire(k + ("a",), "approval", n, f"{n} is waiting for your approval to run")
        elif ag.get("status") == "error": fire(k + ("e",), "error", n, f"{n} failed")
        elif ag.get("column") == "REVIEW": fire(k + ("r",), "review", n, f"{n} finished - review the result")
    if run.get("status") in ("DONE", "ATTENTION"): fire((rid, "run", run["status"]), "run_" + run["status"].lower(), "", f"Room finished ({run['status'].lower()})")
    return out


def deliver(cfg, ev, which=shutil.which, run=subprocess.run, urlopen=urllib.request.urlopen):
    """cfg: {'desktop': bool, 'webhook': str}. Returns the channels that were used. Never raises."""
    used = []
    if cfg.get("desktop") and which("notify-send"):
        try: run(["notify-send", "-a", "ORDIVYR", ev["room"], ev["text"]], timeout=5, capture_output=True); used.append("desktop")
        except Exception: pass
    u = urlparse(cfg.get("webhook") or "")
    if u.scheme in ("https", "http") and u.hostname and (u.scheme == "https" or u.hostname in LOOP):
        try:
            req = urllib.request.Request(cfg["webhook"], json.dumps({"text": f"{ev['room']}: {ev['text']}", **ev, "source": "ordivyr"}).encode(), {"Content-Type": "application/json"})
            urlopen(req, timeout=5).read(); used.append("webhook")
        except Exception: pass
    return used


def check_webhook(url):
    u = urlparse(url or "")
    if not url: return ""
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password: raise ValueError("webhook must be an http(s) URL without credentials")
    if u.scheme == "http" and u.hostname not in LOOP: raise ValueError("use https for a webhook that isn't on this machine")
    return url.strip()
