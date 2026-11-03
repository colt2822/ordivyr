"""ordivyr command line. Read-only unless a command says otherwise; nothing is downloaded, loaded onto a GPU, or sent anywhere by default.

  ordivyr version | doctor
  ordivyr hw                                   detected GPUs/CPU/RAM and notes
  ordivyr models   [--ollama URL] [--openai URL]
  ordivyr roles    [--ollama URL] [--openai URL] [--allow-cloud]
  ordivyr plan MODEL [MODEL...] [--ollama URL]     where each model would fit (arithmetic only)
  ordivyr templates [--ollama URL]             which templates this machine can run
  ordivyr new TEMPLATE [-o board.json] [--ollama URL]
  ordivyr validate board.json
  ordivyr run board.json --mission TEXT [--ollama URL] [--memory DB] [--jev-db PATH --jev-src DIR] [--json]
  ordivyr plugins [--plugins DIR]
  ordivyr plugin list|inspect ID|discover|install PATH|import KIND PATH|grant ID PERM..|revoke ID [PERM..]|enable ID|disable ID|trust ID HASH|verify ID|uninstall ID|tools ID|call ID TOOL JSON|audit|catalog LOC [--search Q|--install ID]
  ordivyr drex status|route ...                configured via ORDIVYR_DREX_URL / ORDIVYR_DREX_KEY(_FILE)
"""
from __future__ import annotations
import argparse, json, os, sys
from . import __version__, CODENAME, core, hw as HW, llm as LLM, roles as R, hwtemplates as HT, teams as T, runner as RUN, memory as M, plugins as PL
from .bridges import drex as DX


def _mgr(a, hardware=None):
    bs = []
    if getattr(a, "ollama", None): bs.append(LLM.OllamaBackend(a.ollama))
    if getattr(a, "openai", None): bs.append(LLM.OpenAIBackend(a.openai))
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


def main(argv=None):
    p = argparse.ArgumentParser(prog="ordivyr", description=f"ORDIVYR {__version__} ({CODENAME}) - open multi-agent orchestration core")
    sub = p.add_subparsers(dest="cmd", required=True)
    def srv(sp):
        sp.add_argument("--ollama", help="Ollama base URL (default http://127.0.0.1:11434 when reachable)"); sp.add_argument("--openai", help="OpenAI-compatible base URL, e.g. http://127.0.0.1:8080/v1")
    sub.add_parser("version"); sub.add_parser("doctor"); sub.add_parser("hw")
    for n in ("models", "roles", "templates"):
        s = sub.add_parser(n); srv(s)
        if n == "roles": s.add_argument("--allow-cloud", action="store_true")
    s = sub.add_parser("plan"); srv(s); s.add_argument("models", nargs="+")
    s = sub.add_parser("new"); srv(s); s.add_argument("template"); s.add_argument("-o", "--out")
    s = sub.add_parser("validate"); s.add_argument("board")
    s = sub.add_parser("run"); srv(s); s.add_argument("board"); s.add_argument("--mission", required=True); s.add_argument("--memory"); s.add_argument("--jev-db"); s.add_argument("--jev-src"); s.add_argument("--json", action="store_true")
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
            board = json.load(open(a.board)); hw = HW.detect(); mgr = _mgr(a, hw); inv, _ = mgr.inventory(); plan = R.assign(R.candidates_from(inv, hw))
            jev = None
            if a.jev_db:
                from .bridges.jev import JevBridge; jev = JevBridge(a.jev_db, src=a.jev_src)
            res = RUN.Runner(board, a.mission, llm=mgr, role_plan=plan, memory=M.SqliteMemory(a.memory) if a.memory else None, drex=DX.DrexBridge(), jev=jev).run()
            if a.json: out(res)
            else:
                print(f"run {res['run_id']}: {res['status']}")
                for k, v in res["agents"].items(): print(f"  {k:14} {v['status']:8} {v['model']:30} {v['output'][:90]!r}")
            return 0 if res["status"] == "done" else 2
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
