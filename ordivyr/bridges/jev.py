"""JEV Fleet Command bridge (JEV is Apache-2.0): show ORDIVYR agents and runs in a JEV dashboard and read its human approvals.

Uses JEV's own storage API (`jev_fleet.db.FleetDB`) - no scraping, no second schema. Idempotent: a run/agent pair maps to one JEV task (idem_key).
JEV is an observer/register, not a worker: this bridge writes records and reads approval decisions; it does not make JEV execute anything.
JEV is imported lazily; pass `src=` (a checkout containing jev_fleet/) if it is not pip-installed. Pass an explicit `db_path` - the bridge never guesses a default database.
"""
from __future__ import annotations
import importlib, sys

STATUS = {"queued": "QUEUED", "running": "RUNNING", "done": "SUCCEEDED", "failed": "FAILED", "waiting": "QUEUED"}


class JevUnavailable(RuntimeError): pass


class JevBridge:
    name = "jev"
    def __init__(self, db_path, src=None, now=None):
        if src and str(src) not in sys.path: sys.path.insert(0, str(src))
        try: dbmod = importlib.import_module("jev_fleet.db")
        except ImportError as e: raise JevUnavailable("jev_fleet is not installed; pip install jev-fleet-command or pass src=<checkout>") from e
        self.db = dbmod.FleetDB(db_path, **({"now": now} if now else {}))
    def sync_agents(self, board):
        n = 0
        for a in board.get("agents", []):
            self.db.upsert_agent({"agent_id": f"ordivyr.{board.get('board_id', 'board')}.{a['id']}", "name": a.get("name", a["id"]), "provider": "ORDIVYR",
                                  "runtime": str(a.get("model") or "det.01"), "status": "IDLE" if not a.get("paused") else "PAUSED",
                                  "capabilities": {"tools": a.get("tools", []), "skills": (a.get("license") or {}).get("skills", [])}}); n += 1
        return n
    def record(self, run_id, board_id, agent, title, status, result=None, error=None):
        aid = f"ordivyr.{board_id}.{agent}"
        tid, created = self.db.enqueue_task(aid, "ordivyr-run", title[:160], f"{run_id}:{agent}", {"run_id": run_id})
        js = STATUS.get(status, "QUEUED")
        if js != "QUEUED": self.db.update_task_status(tid, js, result=result, error=error)
        return tid
    def request_approval(self, task_id, agent_id, action, note=""): return self.db.request_approval(task_id, agent_id, action, note)
    def approvals(self, status="PENDING"): return self.db.get_approvals(status)
    def is_approved(self, approval_id):
        """Reads JEV's recorded decision only. JEV 1.0.x has no approve/reject control, so this is True only if a human edited the register."""
        return any(a["approval_id"] == approval_id and a["status"] in ("APPROVED", "GRANTED") for a in self.db.get_approvals())
