"""ORDIVYR adapter: drives the REAL `python -m ordivyr run` CLI -> Runner -> durable Store -> tool loop -> model. No direct agentloop calls."""
from __future__ import annotations
import json, sqlite3, subprocess
from .. import suite
from pathlib import Path
from .base import Adapter, Invocation, write_json

SRC = Path(__file__).resolve().parents[3]                    # directory that contains the `ordivyr` package


class OrdivyrAdapter(Adapter):
    name = "ordivyr"
    capabilities = {"native_resume": True, "delegation": True}
    resume_mechanism = "same --run-id/--durable DB: durable store re-claims the interrupted agent task after its lease expires; finished agents are not re-run"

    def available(self): return (SRC / "ordivyr" / "cli.py").exists(), "ordivyr source not found"
    def version(self):
        try:
            v = subprocess.run(["git", "-C", str(SRC), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=10).stdout.strip()
            import importlib; m = importlib.import_module("ordivyr"); return f"{m.__version__}+{v}"
        except Exception: return "unknown"

    def _board(self, task, model):
        from .. import suite
        from ... import core
        tag = "openai:" + model["name"]; b = core.new_board("arena")
        if task.get("category") == "delegation":
            owners = task["meta"]["owners"]; lead = core.new_agent(0, 0, "Lead", id="lead", model=tag, tools=[], permissions="read-only", instructions="You coordinate. Reply with one sentence that assigns each module to a worker.")
            b["agents"].append(lead)
            for i, (mod, fn) in enumerate(owners.items()):
                w = core.new_agent(0, 0, f"Worker {mod}", id=f"w{i}", model=tag, tools=["file_write"], permissions="read-write",
                                   instructions=f"You own ONLY the file `{fn}`: read spec.txt, then write `{fn}` with the complete implementation. Do not edit other files.")
                b["agents"].append(w); b["edges"].append({"id": f"e{i}", "from": "lead", "to": w["id"], "kind": "delegate"})
        else:
            b["agents"].append(core.new_agent(0, 0, "Engineer", id="eng", model=tag, tools=["file_write"], permissions="read-write", instructions=""))
        return b

    def prepare(self, lane, task, model, resume=False):
        home = lane.home / "ordivyr"; home.mkdir(parents=True, exist_ok=True)
        if not resume:
            write_json(home / "board.json", self._board(task, model)); (lane.home / "key").write_text(model["key"])
        argv = ["python3", "-m", "ordivyr", "run", "/arena-home/ordivyr/board.json", "--mission", suite.full_prompt(task), "--openai", model["base"], "--key-file", "/arena-home/key", "--workdir", "/lane/w",
                "--durable", "/arena-home/ordivyr/q.db", "--run-id", lane.run_id, "--max-steps", str(task["limits"]["max_steps"]), "--lease-ttl", str(model.get("lease_ttl", 6)), "--json"]
        return Invocation(argv=argv, env={"PYTHONPATH": "/arena-src", "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/arena-home", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, ro=[(str(SRC), "/arena-src")])

    def parse(self, lane, task, stdout):
        out = {"final_text": None, "steps": None, "tool_calls": None, "tool_errors": None, "tokens_reported": None, "protocol_errors": 0}
        try:
            j = json.loads(stdout[stdout.index("{"):]); ag = j.get("agents", {}); out["final_text"] = " | ".join((a.get("output") or "")[:200] for a in ag.values()); out["tokens_reported"] = sum(a.get("tokens", 0) for a in ag.values())
            out["status"] = j.get("status")
        except (ValueError, KeyError): out["protocol_errors"] += 1
        db = lane.home / "ordivyr" / "q.db"
        if db.exists():
            try:
                c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10); rows = c.execute("SELECT tool, output FROM outputs").fetchall()
                out["tool_calls"] = len(rows); out["tool_errors"] = sum(1 for _, o in rows if (o or "").startswith("ERROR")); out["steps"] = c.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
                out["durable_counts"] = dict(c.execute("SELECT state, COUNT(*) FROM tasks GROUP BY state").fetchall())
                out["attempts"] = [r[0] for r in c.execute("SELECT attempt FROM tasks")]
            except sqlite3.Error: pass
        return out
