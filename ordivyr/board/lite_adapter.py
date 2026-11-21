"""Personal Lite worker: lease and progress glue, never an agent loop.

Lite is an optional, separately installed distribution. Jobs are confined to a
personal worker and a locally configured model binding. Shared pool execution
and delegation are deliberately not advertised by this adapter.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .. import durable as D
from . import contract as C


def board_handler(ctx):
    try:
        from ordivyr_lite.board_adapter import execute
    except ImportError as exc:
        raise D.Fatal("runtime_unavailable: install ordivyr-lite in the worker environment") from exc
    cfg_path = os.environ.get("ORDIVYR_LITE_WORKER_CONFIG")
    if not cfg_path:
        raise D.NeedsApproval("needs_owner: configure ORDIVYR_LITE_WORKER_CONFIG")
    cfg = json.loads(Path(cfg_path).read_text())
    job = ctx.payload
    ctx.check()
    route = cfg["route"]
    if job.get("model_ref") != {"endpoint": "local", "model": cfg["model"]}:
        raise D.Fatal("invalid_job: model_ref differs from this worker's configured binding")
    # A fence-specific workspace prevents an expired worker and its replacement
    # mutating the same files. Interrupted attempts are held for review instead
    # of launching another agent over ambiguous side effects.
    approval = (ctx.checkpoint or {}).get('owner_approval') or {}
    approved = approval == {'attempt': ctx.task.get('attempt', 1) - 1, 'resolution': 'retry'}
    if ctx.task.get("attempt", 1) > 1 and not approved:
        raise D.NeedsApproval("needs_owner: interrupted Lite attempt retained; inspect its journal and artifacts before retry")
    wd = ctx.dir / "workspace"
    wd.mkdir(exist_ok=True)
    session_path = ctx.dir / "lite-session.jsonl"

    def cancelled():
        return ctx.cancel.is_set() or ctx.lost.is_set()

    last_delta = [0.0]
    def event(ev):
        ctx.check()
        if ev.get('type') == 'delta':
            now = time.monotonic()
            if now - last_delta[0] < 1.0:
                return
            last_delta[0] = now
        if ev.get("type") not in ('snapshot',):
            ctx.write({"op": "output", "tool": "lite." + str(ev.get("type", "event")),
                       "args": {}, "output": json.dumps(ev, default=str)[:4000]})

    result = execute(job, wd, route, session_path=session_path,
                     on_event=event, cancel_event=cancelled)
    ctx.check()
    if result["status"] == "cancelled":
        raise D.Cancelled()
    if result["status"] == "held":
        raise D.NeedsApproval((result.get("error") or {}).get("message", "Lite needs review"))
    if result["status"] != "completed":
        raise D.Fatal("Lite: " + str(result.get("error") or result["stop"])[:1000])
    return result, None
