"""Scorecards from recorded run transcripts (<home>/runs/*.json): completion rate, failures, tokens and wall time per board, and per gambit actions that fired.
Pure reads; $0."""
import json
from collections import defaultdict
from pathlib import Path


def collect(runs_dir):
    rows = []
    for p in sorted(Path(runs_dir).glob("*.json")):
        try: t = json.loads(p.read_text())
        except (OSError, ValueError): continue
        if isinstance(t, dict) and isinstance(t.get("agents"), dict): rows.append(t)
    return rows


def scorecard(rows):
    boards = defaultdict(lambda: {"runs": 0, "done": 0, "failed_agents": 0, "agents": 0, "tokens": 0, "seconds": 0.0, "gambit_actions": defaultdict(int)})
    for t in rows:
        b = boards[t.get("board_id") or t.get("board_name") or "unknown"]; b["runs"] += 1; b["done"] += t.get("status") == "done"; b["seconds"] += float(t.get("seconds") or 0)
        for a in t["agents"].values(): b["agents"] += 1; b["failed_agents"] += a.get("status") in ("failed", "blocked"); b["tokens"] += int(a.get("tokens") or 0)
        for x in t.get("actions") or []: b["gambit_actions"][str((x or {}).get("action") or (x or {}).get("kind") or "action")] += 1
    return {k: {"runs": v["runs"], "completion_rate": round(v["done"] / v["runs"], 3), "agent_failure_rate": round(v["failed_agents"] / max(1, v["agents"]), 3),
                "tokens_per_run": round(v["tokens"] / v["runs"]), "seconds_per_run": round(v["seconds"] / v["runs"], 3), "gambit_actions": dict(v["gambit_actions"])} for k, v in boards.items()}
