"""python -m ordivyr.board up --home H [--port 8870] [--lease-port 8871] [--gateway-home G --local-worker]   |   org-create --home H --id acme [--plan team]"""
from __future__ import annotations
import argparse, json, os, shlex, signal, sys, threading
from pathlib import Path
from .service import Board
from .api import serve
from .coordinator import BoardCoordinator


def configure_from_env(board):
    """Operator wiring that must not live on a command line: BOARD_MAIL_DIR (write .eml files) or BOARD_SMTP_HOST/PORT/USER/PASSWORD_FILE/FROM/MODE(starttls|tls), BOARD_PUBLIC_URL."""
    e = os.environ
    if e.get("BOARD_PUBLIC_URL"): board.public_url = e["BOARD_PUBLIC_URL"]
    from . import mailer as M
    if e.get("BOARD_SMTP_HOST"):
        pw = Path(e["BOARD_SMTP_PASSWORD_FILE"]).read_text().strip() if e.get("BOARD_SMTP_PASSWORD_FILE") else None
        board.mailer = M.SMTPTransport(e["BOARD_SMTP_HOST"], int(e.get("BOARD_SMTP_PORT", "587")), e.get("BOARD_SMTP_USER"), pw, e.get("BOARD_SMTP_FROM", "board@localhost"), e.get("BOARD_SMTP_MODE", "starttls"))
    elif e.get("BOARD_MAIL_DIR"): board.mailer = M.FileTransport(e["BOARD_MAIL_DIR"], e.get("BOARD_SMTP_FROM", "board@localhost"))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ordivyr-board"); sub = ap.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("up"); up.add_argument("--home", required=True); up.add_argument("--host", default="127.0.0.1"); up.add_argument("--port", type=int, default=8870); up.add_argument("--lease-port", type=int, default=8871)
    up.add_argument("--pg-dsn", help="PostgreSQL DSN (prefer env BOARD_PG_DSN: command lines are visible in ps)"); up.add_argument("--allow-public-bind", action="store_true"); up.add_argument("--local-worker", action="store_true", help="also run a shared pool worker (engine ordivyr) next to Board"); up.add_argument("--gateway-home")
    up.add_argument("--unsafe-unsandboxed-pool", action="store_true", help="DEV ONLY: allow the shared pool worker to run tenant code without a sandbox")
    up.add_argument("--tls-cert"); up.add_argument("--tls-key"); up.add_argument("--access-log", help="JSON access log file (default: stderr)")
    up.add_argument("--lite-worker", action="store_true", help="run the configured personal Lite worker")
    init = sub.add_parser("init", help="configure a personal SQLite Board and model")
    init.add_argument("--home", required=True); init.add_argument("--model", required=True)
    init.add_argument("--base-url", required=True); init.add_argument("--slots", type=int, default=1)
    init.add_argument("--key-file"); init.add_argument("--protocol", choices=("openai", "anthropic"), default="openai")
    init.add_argument("--engine", choices=("ordivyr", "lite"), default="ordivyr", help="ordivyr = built-in engine (default); lite = optional ordivyr-lite package")
    init.add_argument("--authorize-daily-usd", type=float); init.add_argument("--authorize-total-usd", type=float, help="spend caps for a PAID remote model endpoint (both required; without them its jobs are refused)")
    doctor = sub.add_parser("doctor", help="check personal installation and configured capacity")
    doctor.add_argument("--home", required=True)
    doctor.add_argument("--lite-worker", action="store_true", help="also require the optional Lite dependency")
    bk = sub.add_parser("backup"); bk.add_argument("--home"); bk.add_argument("--pg-dsn"); bk.add_argument("--out", required=True); bk.add_argument("--include-personal", action="store_true", help="also save the personal-install credentials (owner/worker tokens, model config and API key); protect the backup like those secrets"); bk.add_argument("--pg-bin")
    rs = sub.add_parser("restore"); rs.add_argument("--from", dest="src", required=True); rs.add_argument("--home"); rs.add_argument("--pg-dsn"); rs.add_argument("--pg-bin")
    bv = sub.add_parser("backup-verify"); bv.add_argument("--from", dest="src", required=True)
    oc = sub.add_parser("org-create"); oc.add_argument("--home", required=True); oc.add_argument("--id", required=True); oc.add_argument("--plan", default="free"); oc.add_argument("--pg-dsn")
    a = ap.parse_args(argv)
    if a.cmd in ("init", "doctor"):
        from . import bootstrap
        try:
            if a.cmd == "init":
                auth = (a.authorize_daily_usd, a.authorize_total_usd) if a.authorize_daily_usd and a.authorize_total_usd else None
                state = bootstrap.initialize(a.home, a.model, a.base_url, a.slots, a.key_file, a.protocol, a.engine, auth)
                print(json.dumps({k: state[k] for k in ("created", "org", "project", "engine", "model", "slots", "admin_token_file")}, indent=2))
                print(f"next: ordivyr-board up --home {shlex.quote(str(Path(a.home).expanduser()))}", file=sys.stderr)
                return 0
            report = bootstrap.status(a.home, require_lite=a.lite_worker)
            print(json.dumps(report, indent=2)); return 0 if report["ok"] else 2
        except (ValueError, OSError, KeyError) as exc:
            print(f"error: {exc}", file=sys.stderr); return 2
    personal = None
    if a.cmd == "up" and not a.lite_worker and not a.local_worker and (Path(a.home).expanduser() / "selfhost.json").is_file():
        st = json.loads((Path(a.home).expanduser() / "selfhost.json").read_text())
        if st.get("engine") == "ordivyr": personal = st                 # a personal install made by `init`: run its built-in worker with it
    if a.cmd == "up" and a.lite_worker:
        if a.local_worker:
            raise SystemExit("choose --lite-worker or --local-worker")
        state_path = Path(a.home).expanduser().resolve() / "selfhost.json"
        state = json.loads(state_path.read_text())
        try:
            import ordivyr_lite.board_adapter
        except ImportError:
            raise SystemExit("install ordivyr-lite in this environment before --lite-worker")
        os.environ["ORDIVYR_LITE_WORKER_CONFIG"] = str(state_path)
    if a.cmd in ("backup", "restore", "backup-verify"):
        from . import backup as BK
        try:
            if a.cmd == "backup": print(json.dumps(BK.backup(a.home, a.out, a.pg_dsn or os.environ.get("BOARD_PG_DSN"), a.pg_bin, a.include_personal), indent=1))
            elif a.cmd == "restore": print(json.dumps(BK.restore(a.src, a.home, a.pg_dsn or os.environ.get("BOARD_PG_DSN"), a.pg_bin), indent=1))
            else: print(json.dumps(BK.verify_backup(a.src), indent=1))
        except BK.BackupError as e: print(f"error: {e}", file=sys.stderr); return 2
        return 0
    board = Board(a.home, dsn=a.pg_dsn); first = board.init_platform(); configure_from_env(board)
    plat = board.principal((Path(a.home) / "platform.token").read_text().strip())
    if a.cmd == "org-create": print(json.dumps(board.create_org(plat, a.id, a.id, a.plan))); return 0
    if bool(a.tls_cert) != bool(a.tls_key): raise SystemExit("--tls-cert and --tls-key go together")
    tls = (a.tls_cert, a.tls_key) if a.tls_cert else None; scheme = "https" if tls else "http"
    if a.host not in ("127.0.0.1", "::1", "localhost") and not tls: print("WARNING: serving a non-loopback address without TLS: put a TLS terminator in front (docs/board/OPERATIONS.md)", file=sys.stderr)
    logf = open(a.access_log, "a", buffering=1) if a.access_log else sys.stderr
    coord = BoardCoordinator(board, host=a.host, port=a.lease_port, tls=tls).start(); srv = serve(board, a.host, a.port, a.allow_public_bind, tls=tls, access_log=lambda r: print(json.dumps(r), file=logf, flush=True))
    board.lease_url = f"{scheme}://{'localhost' if tls else a.host}:{coord.port}"; board.start_loop(1.0); stop = threading.Event()
    if a.lite_worker:
        from . import worker as BW
        threading.Thread(target=BW.run, args=(board.lease_url,
            (Path(a.home) / "lite-worker.token").read_text().strip(), "personal-local",
            str(Path(a.home) / "ws"), "lite", state["slots"], 6.0, stop), daemon=True).start()
    if personal:
        from . import worker as BW
        os.environ["ORDIVYR_GATEWAY_HOME"] = str(Path(a.home).expanduser().resolve() / "gateway")      # relative to the home, so a restored install works at a new path
        ws = Path(a.home).expanduser() / "ws"; ws.mkdir(exist_ok=True)
        threading.Thread(target=BW.run, args=(board.lease_url, (Path(a.home).expanduser() / Path(personal["worker_token_file"]).name).read_text().strip(), "personal-local", str(ws), "ordivyr", personal["slots"], 6.0, stop), daemon=True).start()
    if a.local_worker:
        from . import runtime_adapter as RA, worker as BW
        if a.gateway_home: os.environ["ORDIVYR_GATEWAY_HOME"] = a.gateway_home
        from . import sandbox as SB
        sbx = SB.available() and not a.unsafe_unsandboxed_pool
        if not sbx and not a.unsafe_unsandboxed_pool: raise SystemExit("refusing to start a shared pool worker: no sandbox available (bwrap). Install bubblewrap or pass --unsafe-unsandboxed-pool for development.")
        board.allow_unsandboxed_pool = a.unsafe_unsandboxed_pool
        r = board.register_worker(plat, "ordivyr", RA.capabilities(4, (), validators=True, isolation=SB.ISOLATION if sbx else "process"), platform=True, node="board-local")
        ws = Path(a.home) / "ws"; ws.mkdir(exist_ok=True); threading.Thread(target=BW.run, args=(board.lease_url, r["token"], "board-local", str(ws), "ordivyr", 4, 6.0, stop), kwargs={"sandbox": sbx}, daemon=True).start()
    admin_key = Path(a.home).expanduser() / "admin.token"
    if admin_key.is_file(): print(f"Board is ready. Open {scheme}://{a.host}:{srv.server_address[1]} and sign in with 'Or paste an API key' using the key in {admin_key}", file=sys.stderr, flush=True)
    print(json.dumps({"api": f"{scheme}://{a.host}:{srv.server_address[1]}", "lease_api": f"{scheme}://{a.host}:{coord.port}", "platform_token_file": str(Path(a.home) / "platform.token"), "first_start": bool(first)}), flush=True)
    signal.signal(signal.SIGTERM, lambda *_: stop.set()); signal.signal(signal.SIGINT, lambda *_: stop.set()); stop.wait(); board.stop_loop(); board.fleet_shutdown(); srv.shutdown(); coord.stop(); return 0


if __name__ == "__main__": sys.exit(main())
