"""Schedules and webhook triggers for a room.

A schedule says "play this mission every N minutes/hours" or "daily at HH:MM"; a trigger is a secret URL an outside service can POST to.
Both only ever call the same Play path as the button, so paid agents are still held for your approval and every limit still applies.
State lives in settings.json under rooms[<board>] (never in the shareable board document); the trigger token is stored only as a hash.
"""
from __future__ import annotations
import datetime as dt, hashlib, re, secrets, time

MIN_EVERY_MIN = 5
DEFAULT_MAX_PER_DAY = 6
HARD_MAX_PER_DAY = 48
HOOK_COOLDOWN_S = 10


def parse(text: str):
    """'every 30 minutes' | 'every 2 hours' | 'every hour' | 'every day at 9:30' | 'daily at 18:00' | 'every day at 9am' -> {'every_min': n} or {'daily': 'HH:MM'}."""
    t = re.sub(r"\s+", " ", str(text or "").strip().lower())
    m = re.fullmatch(r"(?:run )?every (?:(\d+) ?)?(min(?:ute)?s?|m|hours?|h|days?)", t)
    if m:
        n = int(m.group(1) or 1); unit = m.group(2)
        if unit.startswith("d"): return {"daily": "09:00"} if n == 1 else {"every_min": n * 1440}
        every = n * (60 if unit.startswith("h") else 1)
        if every < MIN_EVERY_MIN: raise ValueError(f"the shortest repeat is every {MIN_EVERY_MIN} minutes")
        return {"every_min": min(every, 60 * 24 * 30)}
    m = re.fullmatch(r"(?:run )?(?:every day|daily|each day) at (\d{1,2})(?::(\d{2}))? ?(am|pm)?", t)
    if m:
        hh, mm, ap = int(m.group(1)), int(m.group(2) or 0), m.group(3)
        if ap == "pm" and hh < 12: hh += 12
        if ap == "am" and hh == 12: hh = 0
        if not (0 <= hh <= 23 and 0 <= mm <= 59): raise ValueError("that is not a valid time of day")
        return {"daily": f"{hh:02d}:{mm:02d}"}
    raise ValueError("say it like: every 30 minutes, every 2 hours, every day at 9:00")


def describe(s: dict) -> str:
    if "daily" in s: return f"every day at {s['daily']}"
    n = int(s.get("every_min") or 0)
    return "every hour" if n == 60 else f"every {n // 60} hours" if n % 60 == 0 and n >= 120 else f"every {n} minutes"


def clean(s: dict) -> dict:
    out = {"enabled": bool(s.get("enabled")), "mission": str(s.get("mission") or "").strip()[:500], "max_per_day": max(1, min(HARD_MAX_PER_DAY, int(s.get("max_per_day") or DEFAULT_MAX_PER_DAY)))}
    if "daily" in s and re.fullmatch(r"\d\d:\d\d", str(s["daily"])): out["daily"] = s["daily"]
    else: out["every_min"] = max(MIN_EVERY_MIN, min(60 * 24 * 30, int(s.get("every_min") or 60)))
    for k in ("last_run", "day", "runs_today", "last_error"):
        if k in s: out[k] = s[k]
    return out


def due(s: dict, now: float | None = None) -> bool:
    """Is a run owed right now? A missed window (machine was off) is caught up with ONE run, never a burst. The first check after enabling only starts the clock."""
    now = now or time.time(); s = clean(s) | {k: v for k, v in s.items() if k in ("last_run", "day", "runs_today")}
    if not s["enabled"] or not s["mission"]: return False
    today = dt.date.fromtimestamp(now).isoformat()
    if s.get("day") == today and int(s.get("runs_today") or 0) >= s["max_per_day"]: return False
    last = s.get("last_run")
    if last is None: return False
    if "daily" in s:
        hh, mm = map(int, s["daily"].split(":")); slot = dt.datetime.combine(dt.date.fromtimestamp(now), dt.time(hh, mm)).timestamp()
        return now >= slot and last < slot
    return now - last >= s["every_min"] * 60


def mark_run(s: dict, now: float | None = None):
    now = now or time.time(); today = dt.date.fromtimestamp(now).isoformat()
    s["runs_today"] = (int(s.get("runs_today") or 0) + 1) if s.get("day") == today else 1; s["day"] = today; s["last_run"] = now; s.pop("last_error", None)


def next_run(s: dict, now: float | None = None):
    now = now or time.time(); s = clean(s) | {k: v for k, v in s.items() if k in ("last_run",)}
    if not s["enabled"]: return None
    if "daily" in s:
        hh, mm = map(int, s["daily"].split(":")); d = dt.date.fromtimestamp(now); slot = dt.datetime.combine(d, dt.time(hh, mm)).timestamp()
        return slot if slot > now else slot + 86400
    return (s.get("last_run") or now) + s["every_min"] * 60


# ---------------------------------------------------------------- webhook token (stored hashed; shown once)
def new_token() -> tuple[str, str]:
    t = secrets.token_urlsafe(24); return t, hash_token(t)


def hash_token(t: str) -> str: return hashlib.sha256(str(t).encode()).hexdigest()


def check_token(hook: dict | None, token: str) -> bool:
    return bool(hook and hook.get("hash")) and secrets.compare_digest(hook["hash"], hash_token(token))
