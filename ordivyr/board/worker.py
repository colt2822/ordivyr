"""A Board worker process: speaks only the lease API (BoardRemote) with its own worker token. The same program runs next to Board (platform pool) or on a customer's machine.

  python -m ordivyr.board.worker --url http://host:port --token-file F --name W --ws DIR --engine ordivyr [--slots 2]   (model endpoints: ORDIVYR_GATEWAY_HOME on THIS machine)
"""
from __future__ import annotations
import argparse, signal, threading
from pathlib import Path
from .. import durable_worker as W
from .coordinator import BoardRemote
from .runtime_adapter import board_handler


def run(url, token, name, ws, engine="ordivyr", slots=2, ttl=6.0, stop=None, longpoll=2.0, node=None, log=lambda *a: None, sandbox=False):
    from .sandbox import board_handler_sandboxed
    if engine == "lite":
        if sandbox:
            raise ValueError("Lite adapter supports personal workers only")
        from .lite_adapter import board_handler as lite_handler
        W.HANDLERS["board.lite"] = lite_handler
    else:
        W.HANDLERS[f"board.{engine}"] = board_handler_sandboxed if sandbox else board_handler
    store = BoardRemote(url, token, timeout=8.0)
    W.serve_pool(store, name, node or name, ws, slots=slots, ttl=ttl, kinds=[f"board.{engine}"], stop=stop or threading.Event(), longpoll=longpoll, log=log)


def main(argv=None):
    a = argparse.ArgumentParser(); a.add_argument("--url", required=True); a.add_argument("--token-file", required=True); a.add_argument("--name", required=True); a.add_argument("--ws", required=True)
    a.add_argument("--engine", default="ordivyr"); a.add_argument("--slots", type=int, default=2); a.add_argument("--ttl", type=float, default=6.0); a.add_argument("--sandbox", action="store_true", help="run every job in the namespace sandbox (required for shared pool workers)"); a = a.parse_args(argv)
    stop = threading.Event(); signal.signal(signal.SIGTERM, lambda *_: stop.set()); signal.signal(signal.SIGINT, lambda *_: stop.set())
    import faulthandler; faulthandler.register(signal.SIGUSR1, all_threads=True)      # `kill -USR1 <pid>` dumps every thread's stack to the worker log (diagnosing a stalled worker without a debugger)
    Path(a.ws).mkdir(parents=True, exist_ok=True)
    run(a.url, Path(a.token_file).read_text().strip(), a.name, a.ws, a.engine, a.slots, a.ttl, stop, log=lambda *x: print(*x, flush=True), sandbox=a.sandbox)


if __name__ == "__main__": main()
