"""Per-account usage ledger: one JSON line per call in <home>/usage.jsonl (tokens as reported by the provider; no prices, so no dollar figures)."""
from __future__ import annotations
import json, time
from pathlib import Path

MAX_BYTES = 2_000_000


def log(home, account, tokens=0, ok=True, limited=False, err="", source="run"):
    p = Path(home) / "usage.jsonl"
    try:
        if p.exists() and p.stat().st_size > MAX_BYTES: p.write_text("".join(p.read_text().splitlines(True)[-3000:]))   # keep the recent tail
        with open(p, "a") as f: f.write(json.dumps({"ts": time.time(), "account": account, "tokens": int(tokens or 0), "ok": bool(ok), "limited": bool(limited), "err": str(err)[:160], "source": source}) + "\n")
    except OSError: pass


def summary(home, account, cooldowns=None, now=None):
    now = now or time.time(); day = now - 86400; week = now - 7 * 86400
    out = {"today_tokens": 0, "week_tokens": 0, "runs_today": 0, "errors_today": 0, "last_error": "", "cooldown_s": 0}
    try: lines = (Path(home) / "usage.jsonl").read_text().splitlines()[-5000:]
    except OSError: lines = []
    for ln in lines:
        try: r = json.loads(ln)
        except ValueError: continue
        if r.get("account") != account: continue
        if r["ts"] >= week: out["week_tokens"] += r.get("tokens", 0)
        if r["ts"] >= day:
            out["today_tokens"] += r.get("tokens", 0); out["runs_today"] += 1
            if not r.get("ok"): out["errors_today"] += 1; out["last_error"] = r.get("err", "")
    cd = (cooldowns or {}).get(account, 0)
    out["cooldown_s"] = max(0, int(cd - now))
    return out
