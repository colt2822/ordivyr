"""`ordivyr up`: single-command self-hosted start. Embedded SQLite queue + loopback lease API + N local workers under the existing durable supervisor. Idle cost: a few processes, no polling storm (workers poll every 0.25s only while the process runs)."""
from __future__ import annotations
import json, signal, threading
from pathlib import Path
from . import modes


def main(home=None, workers=2, ttl=6.0):
    from .. import durable_sup as DS
    svc = modes.build(home=home); h = svc.home; cfg = {"db": str(h / "queue.db"), "ws": str(h / "ws"), "run": str(h / "run"), "tag": "ordivyr", "workers": workers, "ttl": ttl, "max_concurrency": max(1, workers), "token_file": str(h / "run" / "lease.token")}
    (h / "ws").mkdir(exist_ok=True); sup = DS.Supervisor(cfg).start(); done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set()); signal.signal(signal.SIGINT, lambda *_: done.set())
    print(json.dumps({"mode": svc.mode, "home": str(h), "lease_api_port": sup.coord.port, "workers": workers, "admin_token_file": str(h / "admin.token"), "stop": "Ctrl-C / SIGTERM (graceful: leases are released by expiry, nothing is lost)"}), flush=True)
    done.wait(); sup.shutdown(); return 0
