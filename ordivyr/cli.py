"""ordivyr command line. Read-only unless a command says otherwise; nothing is downloaded, loaded onto a GPU, or sent anywhere by default.

  ordivyr version | doctor
  ordivyr hw                                   detected GPUs/CPU/RAM and notes
  ordivyr models   [--ollama URL] [--openai URL]
  ordivyr roles    [--ollama URL] [--openai URL] [--allow-cloud]
  ordivyr plan MODEL [MODEL...] [--ollama URL]     where each model would fit (arithmetic only)
  ordivyr templates [--ollama URL]             which templates this machine can run
  ordivyr new TEMPLATE [-o board.json] [--ollama URL]
  ordivyr validate board.json
  ordivyr run board.json --mission TEXT [--ollama URL] [--openai URL --key-file F] [--workdir DIR] [--durable DB --run-id ID] [--max-steps N] [--memory DB] [--jev-db PATH --jev-src DIR] [--json]
  ordivyr durable status|audit|reap DB | worker ARGS.. | supervise CONFIG.json     crash-safe task queue (leases, fencing, checkpoints)
  ordivyr up [--home DIR] [--workers N]      one command: embedded queue + coordinator + workers (self-hosted); ordivyr platform info|doctor shows the assembled mode
  ordivyr arena run|compare|results|regressions ...                                  competitive benchmark arena (see docs/arena/README.md)
  ordivyr nova DB add|search|pack|get|verify|reject|correct|delete|export|import|stats|purge ...   NOVA Memory (local file)
  ordivyr init [--provider ollama|openai --url URL --key-file F --check] | diagnose [--fix] | history | memory search|add|get|verify|export|backup|... (config-driven)
  ordivyr plugins [--plugins DIR]
  ordivyr plugin list|inspect ID|discover|install PATH|import KIND PATH|grant ID PERM..|revoke ID [PERM..]|enable ID|disable ID|trust ID HASH|verify ID|uninstall ID|tools ID|call ID TOOL JSON|audit|catalog LOC [--search Q|--install ID]
  ordivyr drex status|route ...                configured via ORDIVYR_DREX_URL / ORDIVYR_DREX_KEY(_FILE)
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from . import __version__, CODENAME, core, hw as HW, llm as LLM, roles as R, hwtemplates as HT, teams as T, runner as RUN, memory as M, plugins as PL
from .bridges import drex as DX


def _mgr(a, hardware=None):
    bs = []
    if getattr(a, "ollama", None): bs.append(LLM.OllamaBackend(a.ollama))
    if getattr(a, "openai", None):
        kf = getattr(a, "key_file", None) or os.environ.get("ORDIVYR_OPENAI_KEY_FILE"); key = open(kf).read().strip() if kf else os.environ.get("ORDIVYR_OPENAI_KEY", "")
        bs.append(LLM.OpenAIBackend(a.openai, key=key))
    if not bs and not getattr(a, "no_default", False):
        d = LLM.OllamaBackend()
        if d.reachable(): bs.append(d)
    return LLM.Manager(bs, hardware or HW.detect())


def _plan(a):
    hw = HW.detect(); m = _mgr(a, hw); inv, errs = m.inventory()
    return hw, m, inv, errs, R.assign(R.candidates_from(inv, hw), local_only=not getattr(a, "allow_cloud", False))


def out(o): print(json.dumps(o, indent=2, default=str))


def _home(a):
    from pathlib import Path
    return Path(a.home or os.environ.get("ORDIVYR_HOME") or Path.home() / ".local/state/ordivyr")


def plugin_cmd(a):
    from .ecosystem import store as ST, host as HO, importers as IM, discover as DI, manifest as MF
    st = ST.PluginStore(_home(a)); x = a.args; act = a.action
    def need(n, usage):
        if len(x) < n: raise ValueError("usage: ordivyr plugin " + usage)
    if act == "list": out(st.list())
    elif act == "inspect":
        need(1, "inspect ID"); m = st.get(x[0]); out({**m, "state": st.state(x[0]), "verified": st.verify(x[0]), "tree_hash": MF.tree_hash(st.path(x[0]))})
    elif act == "discover": out(DI.scan_local(extra_dirs=a.scan_dir))
    elif act == "install":
        need(1, "install PATH [--sha256 H] [--force]"); m = st.install(x[0], force=a.force, sha256=a.sha256); out({"installed": m["id"], "runtime": m["runtime"], "requested_permissions": m["permissions"], "next": f"review, then: ordivyr plugin grant {m['id']} <perm>... ; ordivyr plugin enable {m['id']}"})
    elif act == "import":
        need(2, "import skills|opencode|mcp|agents|n8n PATH [--origin hermes|openclaw] [--base-url URL] [--id ID]"); kind, path = x[0], x[1]; res = []
        if kind == "skills": res = [IM.skills_dir(path, a.origin, a.id)]
        elif kind == "opencode": res = IM.opencode_config(path)
        elif kind == "mcp": res = IM.mcp_servers(path)
        elif kind == "agents": res = [IM.agents_dir(path, plugin_id=a.id)]
        elif kind == "n8n": res = [IM.n8n_workflow(path, a.base_url, a.id)]
        else: raise ValueError("kind must be skills, opencode, mcp, agents or n8n")
        rep = []
        for doc, files, notes in res:
            if doc is None: rep.append({"skipped": notes}); continue
            m = st.install_manifest(doc, files, force=a.force, note=f"import:{kind}"); rep.append({"installed": m["id"], "runtime": m["runtime"], "requested_permissions": m["permissions"], "advisory": m["advisory_permissions"], "notes": notes})
        out(rep)
    elif act == "grant": need(2, "grant ID PERM..."); st.grant(x[0], x[1:]); out(st.state(x[0]))
    elif act == "revoke": need(1, "revoke ID [PERM...]"); st.revoke(x[0], x[1:] or None); out(st.state(x[0]))
    elif act == "enable": need(1, "enable ID"); st.enable(x[0]); print(f"enabled {x[0]}")
    elif act == "disable": need(1, "disable ID"); st.disable(x[0]); print(f"disabled {x[0]}")
    elif act == "trust": need(2, "trust ID TREE_HASH"); st.trust_native(x[0], x[1]); print(f"trusted {x[0]} at {x[1][:12]}")
    elif act == "verify": need(1, "verify ID"); ok = st.verify(x[0]); print("verified" if ok else "MODIFIED"); return 0 if ok else 1
    elif act == "uninstall": need(1, "uninstall ID"); st.uninstall(x[0]); print(f"removed {x[0]}")
    elif act == "audit": out(st.read_audit())
    elif act in ("tools", "call"):
        need(1 if act == "tools" else 2, "tools ID | call ID TOOL [JSON]"); h = HO.Host(st)
        try:
            h.adapter(x[0])
            if act == "tools": out(list(h.specs[x[0]].values()))
            else: print(h.call(x[0], x[1], json.loads(x[2]) if len(x) > 2 else {}))
        finally: h.close()
    elif act == "catalog":
        need(1, "catalog LOCATION [--search Q | --install ID]"); c = DI.Catalog.load(x[0])
        if a.install: out({"installed": c.install(st, a.install)["id"]})
        else: out(c.search(a.search or ""))
    else: raise ValueError("unknown plugin action")
    return 0


def NOVA_BACKEND(a):
    from .nova_memory import NovaMemory, NovaBackend
    return NovaBackend(NovaMemory(a.memory), a.tenant, a.project)


def main(argv=None):
    p = argparse.ArgumentParser(prog="ordivyr", description=f"ORDIVYR {__version__} ({CODENAME}) - open multi-agent orchestration core")
    sub = p.add_subparsers(dest="cmd", required=True)
    def srv(sp):
        sp.add_argument("--ollama", help="Ollama base URL (default http://127.0.0.1:11434 when reachable)"); sp.add_argument("--openai", help="OpenAI-compatible base URL, e.g. http://127.0.0.1:8080/v1"); sp.add_argument("--key-file", help="file holding the bearer key for --openai (or ORDIVYR_OPENAI_KEY_FILE / ORDIVYR_OPENAI_KEY)")
    sub.add_parser("version"); sub.add_parser("doctor"); sub.add_parser("hw")
    for n in ("models", "roles", "templates"):
        s = sub.add_parser(n); srv(s)
        if n == "roles": s.add_argument("--allow-cloud", action="store_true")
    s = sub.add_parser("plan"); srv(s); s.add_argument("models", nargs="+")
    s = sub.add_parser("new"); srv(s); s.add_argument("template"); s.add_argument("-o", "--out")
    s = sub.add_parser("validate"); s.add_argument("board")
    s = sub.add_parser("run"); srv(s); s.add_argument("--home"); s.add_argument("board"); s.add_argument("--mission", required=True); s.add_argument("--memory"); s.add_argument("--memory-backend", choices=["sqlite", "nova"], default="sqlite"); s.add_argument("--tenant", default="local"); s.add_argument("--project", default="default"); s.add_argument("--jev-db"); s.add_argument("--jev-src"); s.add_argument("--json", action="store_true"); s.add_argument("--log", help="write the run transcript to this path (default: <home>/runs/<run_id>.json, --log none to disable)")
    s.add_argument("--workdir", help="folder the agents' file tools are confined to"); s.add_argument("--durable", help="durable task DB: each agent is a fenced, resumable task"); s.add_argument("--run-id"); s.add_argument("--max-steps", type=int); s.add_argument("--lease-ttl", type=float, default=10.0)
    s = sub.add_parser("durable"); s.add_argument("action", choices=["status", "audit", "reap", "worker", "supervise"]); s.add_argument("args", nargs=argparse.REMAINDER)
    s = sub.add_parser("up"); s.add_argument("--home"); s.add_argument("--workers", type=int, default=2); s.add_argument("--ttl", type=float, default=6.0)
    s = sub.add_parser("platform"); s.add_argument("action", choices=["info", "doctor"]); s.add_argument("--home")
    s = sub.add_parser("arena"); s.add_argument("args", nargs=argparse.REMAINDER)
    s = sub.add_parser("init"); s.add_argument("--home"); s.add_argument("--provider", choices=["none", "ollama", "openai"], default="none"); s.add_argument("--url"); s.add_argument("--key-file"); s.add_argument("--model")
    s.add_argument("--no-nova", action="store_true"); s.add_argument("--check", action="store_true"); s.add_argument("--force", action="store_true"); s.add_argument("--tenant", default="local"); s.add_argument("--project", default="default")
    s = sub.add_parser("diagnose"); s.add_argument("--home"); s.add_argument("--fix", action="store_true")
    s = sub.add_parser("history"); s.add_argument("--home"); s.add_argument("--limit", type=int, default=20)
    s = sub.add_parser("memory"); s.add_argument("--home"); s.add_argument("args", nargs=argparse.REMAINDER)
    s = sub.add_parser("nova"); s.add_argument("args", nargs=argparse.REMAINDER)
    s = sub.add_parser("plugins"); s.add_argument("--plugins", action="append", default=[])
    s = sub.add_parser("drex"); s.add_argument("action", choices=["status", "route"]); s.add_argument("--state", default=""); s.add_argument("--option", action="append", default=[], help="key=description")
    s = sub.add_parser("plugin"); s.add_argument("action"); s.add_argument("args", nargs="*"); s.add_argument("--home"); s.add_argument("--origin", default="hermes"); s.add_argument("--base-url", default="http://127.0.0.1:5678")
    s.add_argument("--sha256"); s.add_argument("--force", action="store_true"); s.add_argument("--search"); s.add_argument("--install"); s.add_argument("--id"); s.add_argument("--scan-dir", action="append", default=[])
    a = p.parse_args(argv)
    try:
        if a.cmd == "version": print(f"ordivyr {__version__} ({CODENAME})")
        elif a.cmd == "hw": out(HW.detect().to_dict())
        elif a.cmd == "doctor":
            hw = HW.detect(); res = {"version": __version__, "python": sys.version.split()[0], "tier": hw.tier, "gpus": len(hw.gpus), "ollama_reachable": LLM.OllamaBackend().reachable(),
                                     "drex": DX.DrexBridge().status(), "notes": [n for g in hw.gpus for n in g.notes]}
            out(res)
        elif a.cmd == "models":
            m = _mgr(a); inv, errs = m.inventory(); out({"models": [x.to_dict() for x in inv], "backend_errors": errs})
        elif a.cmd == "roles":
            hw, m, inv, errs, plan = _plan(a); out({"hardware_tier": hw.tier, "roles": plan, "backend_errors": errs})
        elif a.cmd == "plan":
            m = _mgr(a); out(m.plan(a.models))
        elif a.cmd == "templates":
            hw, m, inv, errs, plan = _plan(a); out(HT.recommend(hw, plan))
        elif a.cmd == "new":
            hw, m, inv, errs, plan = _plan(a); board, needs = HT.instantiate(a.template, plan)
            if a.out: open(a.out, "w").write(json.dumps(board, indent=2)); print(f"wrote {a.out}")
            else: out(board)
            if needs: print(f"note: {len(needs)} agent(s) still on the free deterministic model", file=sys.stderr)
        elif a.cmd == "validate":
            r = core.validate(json.load(open(a.board))); out(r); return 1 if r["errors"] else 0
        elif a.cmd == "run":
            from . import firstrun as FR
            FR.apply_defaults(a, FR.load_config(getattr(a, "home", None)))
            board = json.load(open(a.board)); hw = HW.detect(); mgr = _mgr(a, hw); inv, _ = mgr.inventory(); plan = R.assign(R.candidates_from(inv, hw))
            jev = None
            if a.jev_db:
                from .bridges.jev import JevBridge; jev = JevBridge(a.jev_db, src=a.jev_src)
            store = None
            if a.durable:
                from . import durable as DU; store = DU.Store(a.durable)
            res = RUN.Runner(board, a.mission, llm=mgr, role_plan=plan, memory=(None if not a.memory else NOVA_BACKEND(a) if a.memory_backend == "nova" else M.SqliteMemory(a.memory)), drex=DX.DrexBridge(), jev=jev,
                             workdir=a.workdir, store=store, run_id=a.run_id, max_steps=a.max_steps, lease_ttl=a.lease_ttl).run()
            log_path = None
            if getattr(a, "log", None) != "none":
                dest = Path(a.log) if getattr(a, "log", None) else _home(a) / "runs" / f"{res['run_id']}.json"
                dest.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)          # transcripts hold prompts and model output: owner-only
                with os.fdopen(fd, "w") as fh: fh.write(json.dumps(res, indent=2))
                os.chmod(dest, 0o600)
                log_path = str(dest)
            if a.json: out({**res, "log_path": log_path})
            else:
                print(f"run {res['run_id']}: {res['status']}")
                if log_path: print(f"transcript: {log_path}")
                for k, v in res["agents"].items(): print(f"  {k:14} {v['status']:8} {v['model']:30} {v['output'][:90]!r}")
            return 0 if res["status"] == "done" else 2
        elif a.cmd == "durable":
            from . import durable as DU
            if a.action == "worker":
                from . import durable_worker as DW; DW.main(a.args)
            elif a.action == "supervise":
                from . import durable_sup as DS; DS.main(a.args)
            else:
                if not a.args: raise ValueError("usage: ordivyr durable status|audit|reap DB")
                st = DU.Store(a.args[0])
                if a.action == "status": out({"counts": st.counts(), "violations": st.audit()})
                elif a.action == "audit": v = st.audit(); out({"violations": v}); return 1 if v else 0
                else: out({"reaped": st.reap()})
        elif a.cmd == "platform":
            from .hosting import modes as HM
            svc = HM.build(home=a.home); out(svc.describe())
        elif a.cmd == "up":
            from .hosting import up as HU; return HU.main(a.home, a.workers, a.ttl)
        elif a.cmd == "arena":
            from .arena import cli as AC; return AC.main(a.args)
        elif a.cmd == "init":
            from . import firstrun as FR
            try: out(FR.init(a.home, a.provider, a.url, a.key_file, a.model, not a.no_nova, a.check, a.force, a.tenant, a.project))
            except (FileExistsError, ValueError) as e: print(f"error: {e}", file=sys.stderr); return 2
        elif a.cmd == "diagnose":
            from . import firstrun as FR
            r = FR.diagnose(a.home, a.fix); out(r); return 0 if r["ok"] else 1
        elif a.cmd == "history":
            from . import firstrun as FR
            out(FR.history(a.home, a.limit))
        elif a.cmd == "memory":
            from . import firstrun as FR
            from .nova_memory import cli as NC
            cfg = FR.load_config(a.home)
            if not cfg or cfg["memory"]["backend"] != "nova": print("error: NOVA Memory is not enabled; run `ordivyr init` first", file=sys.stderr); return 2
            m = cfg["memory"]; return NC.main([m["db"], *a.args[:1], *a.args[1:], "--tenant", m["tenant"], "--project", m["project"]])
        elif a.cmd == "nova":
            from .nova_memory import cli as NC; return NC.main(a.args)
        elif a.cmd == "plugins":
            pm = PL.PluginManager()
            for d in a.plugins + [x for x in os.environ.get("ORDIVYR_PLUGINS", "").split(os.pathsep) if x]: pm.load_dir(d)
            out({**pm.summary(), "installed_entry_points": pm.discover_entry_points()})
        elif a.cmd == "plugin": return plugin_cmd(a)
        elif a.cmd == "drex":
            b = DX.DrexBridge()
            if a.action == "status": out(b.status())
            else:
                opts = dict(o.split("=", 1) for o in a.option if "=" in o)
                out({"choice": b.route(a.state, opts), "status": b.status()})
    except (LLM.LLMError, RUN.RunError, T.TemplateError, OSError, ValueError, KeyError, RuntimeError) as e:
        print(f"ordivyr: {e}", file=sys.stderr); return 1
    return 0


if __name__ == "__main__": sys.exit(main())
