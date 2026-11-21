"""Self-hosting control-center backend: ONE facade over Hub, Engine Manager, Gateway, Agents, Boards. Pure JSON in / JSON out; the HTTP binding lives in the commercial engine server
(GET /api/selfhost/... read-only, mutations as `selfhost_*` actions on the existing CSRF-protected /api/action). Disabled unless ORDIVYR_SELFHOST=1 (or settings selfhost=true).
Nothing here returns an API key, an engine key file's content, or a launch credential. Frontend contracts: docs/selfhost/CODEX_FRONTEND_CONTRACTS.md."""
from __future__ import annotations
import json, os, re, subprocess, threading, time
from pathlib import Path
from .. import hw as HW, durable as D
from .hub import Hub, HubError
from .engines import Manager, EngineError
from .gateway import Gateway, GatewayError
from .agents import AgentStore, History
from . import agents as AG
from .boards import BoardRunner, BoardError

VERSION = "selfhost-1"
def enabled(settings=None): return os.environ.get("ORDIVYR_SELFHOST") == "1" or bool(settings and getattr(settings, "data", {}).get("selfhost"))

def gpu_policy(settings=None):
    """GPU deny/allow lists from ORDIVYR_SELFHOST_DENY_GPUS / _ALLOW_GPUS (comma-separated GPU UUIDs - preferred, they survive nvidia-smi reordering - or indexes) or settings selfhost_deny_gpus / selfhost_allow_gpus."""
    def parse(env, key):
        raw = os.environ.get(env) or ",".join(map(str, (getattr(settings, "data", {}) or {}).get(key, []) or []))
        out = {int(x) if x.strip().isdigit() else x.strip() for x in raw.split(",") if x.strip()}; return out
    allow = parse("ORDIVYR_SELFHOST_ALLOW_GPUS", "selfhost_allow_gpus")
    return {"deny_gpus": parse("ORDIVYR_SELFHOST_DENY_GPUS", "selfhost_deny_gpus"), "allow_gpus": allow or None}

class ApiError(ValueError):
    def __init__(self, code, msg, status=400): super().__init__(msg); self.code, self.status = code, status

class SelfHost:
    def __init__(self, home=None, allow_gpus=None, deny_gpus=(), external_model_dirs=(), hub_kw=None, engine_kw=None):
        self.home = Path(home or os.environ.get("ORDIVYR_SELFHOST_HOME") or Path.home() / ".local/share/ordivyr"); self.home.mkdir(parents=True, exist_ok=True)
        self.hub = Hub(self.home / "models", external_dirs=external_model_dirs, **(hub_kw or {})); self.engines = Manager(self.home / "engines", allow_gpus=allow_gpus, deny_gpus=deny_gpus, **(engine_kw or {}))
        self.gw = Gateway(self.home / "gateway"); self.agents = AgentStore(self.home / "gateway"); self.hist = History(self.home / "gateway"); self.store = D.Store(self.home / "tasks.db")
        AG.DEFAULT_GATEWAY_HOME = str(self.home / "gateway"); self.worker_stop = threading.Event(); self.worker = None; self.workers = int(os.environ.get("ORDIVYR_SELFHOST_WORKERS", "2"))
        self.board_runs = {}; self._lock = threading.Lock(); self.errors = []; self.links = {}            # engine instance id -> gateway endpoint id (credentials move backend-side only)

    def _ensure_worker(self):
        """The shipped server consumes its own `gw_agent` tasks: one bounded worker pool (default 2 slots) on this store. Lazy: nothing runs until a board is submitted."""
        with self._lock:
            if self.worker and self.worker.is_alive(): return
            from .. import durable_worker as W
            ws = self.home / "ws"; ws.mkdir(exist_ok=True)
            self.worker = threading.Thread(target=W.serve_pool, args=(self.store, "selfhost-w", "main", str(ws), self.workers, 30.0, ["gw_agent"], self.worker_stop), daemon=True, name="selfhost-worker"); self.worker.start()
    def close(self):
        self.worker_stop.set()
        try: self.engines.shutdown()
        except Exception as e: self.errors.append({"ts": time.time(), "where": "close", "error": str(e)})

    # ---------------------------------------------------------------- reads
    def capabilities(self):
        e = self.engines.engines()
        return {"enabled": True, "version": VERSION, "features": {"hub": True, "engines": True, "gateway": True, "agents": True, "boards": True, "terminals": "via ORDIVYR broker"},
                "engines": {k: {"installed": v["installed"], "launch": v["launch"]} for k, v in e.items()}, "providers": ["local", "openai", "anthropic", "google", "openrouter", "deepseek", "custom"],
                "limits": {"vllm_sglang_start": False, "hf_token": bool(self.hub.token)}}
    def hardware(self):
        h = HW.detect(disk_path=str(self.home)); d = h.to_dict(); d["vram_ledger"] = self.engines.vram(); d["live"] = self._live(); d["policy"] = {"deny_gpus": sorted(self.engines.deny_gpus), "allow_gpus": sorted(self.engines.allow_gpus) if self.engines.allow_gpus is not None else None}
        d["compatibility"] = {g.name: {"llama.cpp": self._compat(g)} for g in h.gpus}; return d
    def _compat(self, g):
        from .engines import compat, cuda_runtime_of
        return compat("llama.cpp", g, "gguf", cuda_runtime_of(Path(self.engines.bin).parent) if self.engines.bin else None)
    @staticmethod
    def _live():
        out = {"gpus": [], "ram_available_mb": 0, "load1": os.getloadavg()[0]}
        try:
            for ln in subprocess.run(["nvidia-smi", "--query-gpu=index,utilization.gpu,temperature.gpu,power.draw,memory.used", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=5).stdout.strip().splitlines():
                p = [x.strip() for x in ln.split(",")]; out["gpus"].append({"index": int(p[0]), "util_pct": float(p[1]), "temp_c": float(p[2]), "power_w": float(p[3]), "mem_used_mb": float(p[4])})
        except (OSError, subprocess.SubprocessError, ValueError, IndexError): pass
        try: out["ram_available_mb"] = int(re.search(r"MemAvailable:\s+(\d+)", open("/proc/meminfo").read()).group(1)) // 1024
        except (OSError, AttributeError): pass
        return out
    def models_installed(self): return {"models": self.hub.installed()}
    def models_search(self, q, limit=20): return {"results": self.hub.search(q, int(limit))}
    def models_files(self, repo): i = self.hub.files(repo); return {**{k: i[k] for k in ("id", "rev", "license", "gated", "vision")}, "variants": self.hub.variants(i), "projector": self.hub.projector_for(i)}
    def models_recommend(self, repo, ctx=4096):
        i = self.hub.files(repo); return self.hub.recommend(i, HW.detect(disk_path=str(self.home / "models")), int(ctx), allowed_gpus=self.engines.allow_gpus if self.engines.allow_gpus is not None else {g.index for g in self.engines.usable_gpus()})
    def downloads(self): return {"downloads": [self.hub.job(j) for j in self.hub.jobs]}
    def instances(self): return {"engines": self.engines.engines(), "instances": self.engines.list(), "vram": self.engines.vram(), "events": [{"ts": t, "instance": i, "event": e, "detail": d} for t, i, e, d in self.engines.events[-50:]]}
    def endpoints(self): return {"endpoints": self.gw.endpoints(), 'model_prices': self.gw.prices}
    def usage(self, since_s=None, by="endpoint"): return {"by": by, "rows": self.gw.usage(int(since_s) if since_s else None, by), "limits": [{"endpoint": e["id"], "paid": e["paid"], "authorized": e["authorized"], "caps": e["caps"], "spent_today_usd": e["spent_today_usd"], "spent_total_usd": e["spent_total_usd"]} for e in self.gw.endpoints()]}
    def agents_list(self): return {"agents": self.agents.list()}
    def runs(self, agent=None, board=None): return {"runs": self.hist.runs(agent, board)}
    def run_steps(self, rid): return {"steps": self.hist.steps(rid)}
    def board_run_report(self, rid):
        r = self.board_runs.get(rid)
        if not r: raise ApiError("not_found", "unknown board run", 404)
        return r
    def health(self):
        inst = self.engines.list(); bad = [i for i in inst if i["state"] in ("failed", "restarting")]
        return {"ok": not bad and not self.errors[-1:], "instances": [{"id": i["id"], "state": i["state"], "restarts": i["restarts"], "healthy": self.engines.health(i["id"]) if i["state"] == "running" else False, "last_error": i["last_error"]} for i in inst],
                "recovery": [{"instance": i, "event": e} for _, i, e, _ in self.engines.events[-20:]], "errors": self.errors[-20:], "tasks": self.store.counts()}

    def get(self, parts, q):
        r = {("capabilities",): lambda: self.capabilities(), ("hardware",): lambda: self.hardware(), ("models", "installed"): lambda: self.models_installed(), ("models", "search"): lambda: self.models_search(q.get("q", ""), q.get("limit", 20)),
             ("models", "files"): lambda: self.models_files(q["repo"]), ("models", "recommend"): lambda: self.models_recommend(q["repo"], q.get("ctx", 4096)), ("downloads",): lambda: self.downloads(), ("instances",): lambda: self.instances(),
             ("endpoints",): lambda: self.endpoints(), ("usage",): lambda: self.usage(q.get("since"), q.get("by", "endpoint")), ("agents",): lambda: self.agents_list(), ("runs",): lambda: self.runs(q.get("agent"), q.get("board")), ("health",): lambda: self.health()}
        key = tuple(parts)
        if key in r: return self._wrap(r[key])
        if parts[:1] == ["runs"] and len(parts) == 2: return self._wrap(lambda: self.run_steps(parts[1]))
        if parts[:1] == ["board-runs"] and len(parts) == 2: return self._wrap(lambda: self.board_run_report(parts[1]))
        if parts[:1] == ["downloads"] and len(parts) == 2: return self._wrap(lambda: self.hub.job(parts[1]))
        return 404, {"error": {"code": "not_found", "message": "unknown selfhost route"}}
    def _wrap(self, fn):
        try: return 200, fn()
        except HubError as e: return (403 if e.code == "gated" else 404 if e.code == "not_found" else 400), {"error": {"code": e.code, "message": str(e)}}
        except EngineError as e: return 409, {"error": e.to_dict() | {"code": e.code}}
        except GatewayError as e: return 402 if e.code in ("paid_not_authorized", "cap_exceeded") else 400, e.to_dict()
        except ApiError as e: return e.status, {"error": {"code": e.code, "message": str(e)}}
        except (KeyError, BoardError, ValueError) as e: return 400, {"error": {"code": "bad_request", "message": f"{type(e).__name__}: {e}"}}

    # ---------------------------------------------------------------- mutations (called from the CSRF-protected /api/action)
    def act(self, action, b):
        a = action.removeprefix("selfhost_")
        def inst_model():
            if b.get("model_id"): return self.hub.path_of(b["model_id"])
            raise ApiError("bad_request", "model_id (an installed hub model) is required; arbitrary paths are not accepted")
        T = {"download_start": lambda: {"job": self.hub.start(b["repo"], b["variant"], b.get("rev", "main"), b.get("with_projector", True))},
             "download_cancel": lambda: (self.hub.cancel(b["job"]), {"cancelled": True})[1], "model_remove": lambda: self._remove_model(b["model_id"]),
             "instance_start": lambda: (lambda p: self._linked(self.engines.start(p["weights"], gpu=b.get("gpu"), ctx=int(b.get("ctx", 4096)), parallel=int(b.get("parallel", 1)), mmproj=p["mmproj"], max_rss_mb=b.get("max_rss_mb")), b.get("endpoint_id"), b, p["mmproj"] is not None))(inst_model()),
             "instance_stop": lambda: self.engines.stop(b["instance"]),
             "instance_restart": lambda: self._linked(self.engines.restart(b["instance"]), self.links.get(b["instance"]), b),
             "instance_switch": lambda: (lambda p: self._linked(self.engines.switch(b["instance"], p["weights"], mmproj=p["mmproj"]), self.links.get(b["instance"]), b, p["mmproj"] is not None))(inst_model()),
             "endpoint_add_local": lambda: self.gw.add_local(b["id"], b["base_url"], b.get("key"), b.get("vision", False), b.get("tools", True)),
             "endpoint_add_cloud": lambda: self.gw.add_endpoint(b["id"], b["provider"], b.get("base"), None, b.get("key"), b.get("models"), b.get("capabilities")),
             "endpoint_authorize": lambda: self.gw.authorize(b["id"], float(b["daily_usd"]), float(b["total_usd"]), b.get("per_request_usd")), "endpoint_revoke": lambda: self.gw.revoke(b["id"]),
             "price_set": lambda: (self.gw.set_price(b["model"], float(b["in_per_mtok"]), float(b["out_per_mtok"]), b.get('cache_read_per_mtok'), b.get('cache_write_per_mtok')), {"ok": True})[1],
             "agent_create": lambda: self.agents.create(b["name"], b["endpoint"], b["model"], b.get("system", "You are a careful assistant. Use tools when they help."), b.get("tools"), b.get("permissions"), b.get("memory_ns"), int(b.get("max_steps", 8)), b.get("budget_usd")),
             "agent_update": lambda: self.agents.update(b["id"], **b["values"]), "agent_switch": lambda: self.agents.switch_provider(b["id"], b["endpoint"], b["model"], self.gw), "agent_delete": lambda: (self.agents.remove(b["id"]), {"deleted": True})[1],
             "board_run": lambda: self._board_run(b)}
        if a not in T: raise ApiError("unknown_action", f"unknown selfhost action {action}")
        code, out = self._wrap(T[a])
        if code != 200: raise ApiError(out["error"]["code"], out["error"]["message"], code)
        return out
    def _remove_model(self, mid):
        p = self.hub.path_of(mid)
        for i in self.engines.inst.values():
            if i["state"] not in ("stopped", "failed") and i["model"] in (p["weights"],) or (i["state"] not in ("stopped", "failed") and i.get("mmproj") and i["mmproj"] == p["mmproj"]):
                raise ApiError("in_use", f"{mid} is being served by running instance {i['id']}; stop or switch it first", 409)
        return self.hub.remove(mid)
    def _linked(self, iid, eid, b, vision=False):
        """Optionally (re)register this instance as a gateway endpoint. The engine's key goes engine-file -> gateway secrets file inside this process; it is never returned."""
        if b.get("wait", True): self.engines.wait_ready(iid, b.get("timeout"))
        if eid:
            c = self.engines.credentials(iid); self.gw.add_local(eid, c["base_url"], c["key"], vision=vision or bool(self.gw.cfg["endpoints"].get(eid, {}).get("capabilities", {}).get("vision") and False)); self.links[iid] = eid
        return {"instance": iid, "endpoint": eid, "state": self.engines.inst[iid]["state"]}
    def _board_run(self, b):
        self._ensure_worker(); rid = b.get("run_id") or "run-" + os.urandom(4).hex(); board = b["board"]; self.board_runs[rid] = {"run_id": rid, "state": "running", "board": board["id"]}
        def go():
            try: rep = BoardRunner(self.store, self.agents, self.gw).run(board, rid, timeout=float(b.get("timeout", 900))); self.board_runs[rid] = {**rep, "state": "done" if rep["ok"] else "failed"}
            except Exception as e: self.errors.append({"ts": time.time(), "where": "board_run", "error": f"{type(e).__name__}: {e}"}); self.board_runs[rid] = {"run_id": rid, "state": "error", "error": str(e)}
        threading.Thread(target=go, daemon=True).start(); return {"run_id": rid}
