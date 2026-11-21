"""Personal SQLite installation. Uses the existing registry and fenced workers.

No service installation, model request, or paid authorization happens here.
The first-run lock serializes bootstrap; partial runs retain recoverable keys.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path

from . import contract as C
from .service import Board

TOOLS = ["list_files", "read_file", "grep", "find_files", "edit_file", "write_file"]


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def initialize(home, model, base_url, slots=1, key_file=None, protocol="openai", engine="ordivyr", authorize=None):
    from urllib.parse import urlparse
    if engine not in ("ordivyr", "lite"):
        raise ValueError("engine must be 'ordivyr' (built in) or 'lite' (optional ordivyr-lite package)")
    if not model or not 1 <= slots <= 2:
        raise ValueError("model is required; personal free-plan slots must be 1 or 2")
    url = urlparse(base_url)
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
        raise ValueError("model URL must be http(s) without inline credentials")
    if url.hostname not in ("127.0.0.1", "localhost", "::1") and url.scheme != "https":
        raise ValueError("remote model URL requires HTTPS")
    home = Path(home).expanduser().resolve()
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    with open(home / ".init.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state_file = home / "selfhost.json"
        if state_file.exists():
            state = json.loads(state_file.read_text())
            requested_key = str(Path(key_file).expanduser().resolve()) if key_file else None
            if ((state["model"], state["base_url"], state["slots"], state['route'].get('protocol'), state['route'].get('api_key_file'), state.get("engine"))
                    != (model, base_url, slots, protocol, requested_key, engine)):
                raise ValueError("installation already configured; preserve selfhost.json and configure a separate home")
            for name in ('board.db', 'queue.db', 'admin.token', Path(state["worker_token_file"]).name, 'platform.token', 'master.key'):
                if not (home / name).is_file():
                    raise ValueError('incomplete installation: missing ' + name + '; restore the installation before continuing')
            return {**state, "created": False}
        if os.environ.get("BOARD_PG_DSN"):
            raise ValueError("personal bootstrap qualifies SQLite only; unset BOARD_PG_DSN")
        bd = Board(home)
        try:
            bd.init_platform()
            platform = bd.principal((home / "platform.token").read_text().strip())
            admin_file = home / "admin.token"
            if not admin_file.exists():
                if bd.db.c().execute("SELECT 1 FROM orgs WHERE id='local'").fetchone():
                    raise ValueError("partial bootstrap has no admin.token; recover operator credentials before continuing")
                org = bd.create_org(platform, "local", "My Board")
                private_write(admin_file, org["admin_key"])
            admin = bd.principal(admin_file.read_text().strip())
            if admin is None or admin.org != "local" or admin.role != "admin":
                raise ValueError("admin.token does not authorize this personal installation")
            if not bd.db.c().execute("SELECT 1 FROM projects WHERE org='local' AND id='main'").fetchone():
                bd.create_project(admin, "main")
            worker_file = home / ("lite-worker.token" if engine == "lite" else "worker.token")
            if not worker_file.exists():
                if engine == "lite":
                    caps = C.capabilities("lite", TOOLS, slots, ["cancel", "checkpoint", "validators"],
                                          "local", endpoints=["local"], isolation="process")
                else:
                    from . import runtime_adapter as RA
                    caps = RA.capabilities(slots, ["local"], validators=True, engine="ordivyr", isolation="process")
                worker = bd.register_worker(admin, engine, caps, project="main", node="personal-local")
                private_write(worker_file, worker["token"])
            if engine == "ordivyr":
                _configure_gateway(home / "gateway", base_url, key_file, protocol, authorize)
            route = {"provider": "custom", "model": model, "base_url": base_url,
                     "protocol": protocol, "context_window": 32768}
            if key_file:
                key = Path(key_file).expanduser().resolve()
                if not key.is_file():
                    raise ValueError("model key file does not exist")
                route["api_key_file"] = str(key)
            state = {"version": 1, "org": "local", "project": "main", "engine": engine, "gateway_home": str(home / "gateway"),
                     "model": model, "base_url": base_url, "slots": slots, "route": route,
                     "admin_token_file": str(admin_file), "worker_token_file": str(worker_file)}
            if not bd.db.c().execute("SELECT 1 FROM agents WHERE org='local' AND project='main' AND id='coder'").fetchone():
                bd.define_agent(admin, "main", "coder", {"name": "Coder", "engine": engine,
                    "tools": TOOLS, "permissions": {"write": True, "web": False, "terminal": "none"},
                    "model_ref": {"endpoint": "local", "model": model},
                    "limits": {"max_turns": 32, "max_tool_calls": 120, "max_seconds": 300}})
            private_write(state_file, json.dumps(state, indent=2) + "\n")
            return {**state, "created": True}
        finally:
            bd.db.close()
            bd.store._conn().close()


def _configure_gateway(gw_home, base_url, key_file, protocol, authorize):
    """The built-in engine reaches models through the Gateway. Loopback endpoints are free; a remote endpoint is paid and stays UNAUTHORIZED
    (jobs are refused) until the owner supplies explicit daily/total USD caps."""
    from urllib.parse import urlparse
    from ..selfhost.gateway import Gateway
    gw = Gateway(gw_home)
    if "local" in gw.cfg["endpoints"]:
        return
    key = Path(key_file).expanduser().resolve().read_text().strip() if key_file else None
    if urlparse(base_url).hostname in ("127.0.0.1", "localhost", "::1"):
        gw.add_local("local", base_url, key)
        return
    gw.add_endpoint("local", "custom", base_url, protocol, key)
    if authorize:
        gw.authorize("local", authorize[0], authorize[1])


def status(home, require_lite=False):
    """Read persistent state and configured capacity without executing a model."""
    import importlib.util
    import shutil
    import sqlite3
    home = Path(home).expanduser().resolve()
    state = json.loads((home / "selfhost.json").read_text())
    result = {"home": str(home), "backend": "sqlite", "model": state["model"],
              "slots": state["slots"], "lite_installed": importlib.util.find_spec("ordivyr_lite") is not None,
              "bwrap_available": bool(shutil.which("bwrap")), "databases": {}}
    try:
        result["lite_adapter_available"] = importlib.util.find_spec("ordivyr_lite.board_adapter") is not None
    except (ImportError, ValueError):
        result["lite_adapter_available"] = False
    for name in ("board.db", "queue.db"):
        try:
            with sqlite3.connect(f"file:{home / name}?mode=ro", uri=True) as db:
                result["databases"][name] = db.execute("PRAGMA quick_check").fetchone()[0]
        except sqlite3.Error as exc:
            result["databases"][name] = "error: " + str(exc)
    result["engine"] = state.get("engine", "lite")
    if result["engine"] == "ordivyr":
        try:
            from ..selfhost.gateway import Gateway
            ep = Gateway(home / "gateway").describe("local")
            result["endpoint"] = {"base": ep["base"], "paid": ep["paid"], "authorized": ep["authorized"]}
        except Exception as exc:
            result["endpoint"] = {"error": str(exc)}
    result["lite_required"] = require_lite
    result["ok"] = all(v == "ok" for v in result["databases"].values()) and (
        not require_lite or result["lite_adapter_available"])
    ep = result.get("endpoint")
    if ep and ("error" in ep or (ep["paid"] and not ep["authorized"])):
        result["ok"] = False
        result["notice"] = "model endpoint is missing or is a paid remote endpoint without spend authorization"
    return result
