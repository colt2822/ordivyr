"""The built-in ORDIVYR runtime, expressed as a contract implementation: `board_handler(ctx)` runs one Board job through the EXISTING agent loop (selfhost.agents.run_agent
-> gateway -> sandboxed ToolBox). It is an adapter, not a second engine: Lite can replace it by speaking the same lease API (see docs/architecture/ORDIVYR_RUNTIME_CONTRACT.md).

Credentials: model_ref is resolved by the worker's OWN gateway home (ORDIVYR_GATEWAY_HOME). Nothing secret ever arrives in a job.
Delegation / child results / memory are exposed to the model as tools that call Board through the job's fenced lease (`ctx.store.board_*`).
"""
from __future__ import annotations
import os, time
from pathlib import Path
from .. import durable as D, durable_worker as W
from . import contract as C

ENGINE_TOOLS = ["list_files", "read_file", "grep", "find_files", "edit_file", "write_file", "fetch_url", "delegate", "child_results", "memory_get", "memory_list", "memory_put"]
FEATURES = ["cancel", "checkpoint", "validators", "delegate"]
_SPECS = {
    "delegate": ("Hand a sub-task to another agent in this project. Returns the child job id; use child_results to collect it.", {"agent": ("string", "agent id from your delegation list"), "prompt": ("string", "the sub-task"), "engine": ("string", "optional engine"), "key": ("string", "optional dedupe key")}, ["agent", "prompt"]),
    "child_results": ("Status and answers of the jobs you delegated. wait_s (max 60) waits for all of them.", {"wait_s": ("number", "seconds to wait, default 0")}, []),
    "memory_get": ("Read a value from shared project memory (ns 'project') or your private memory (ns 'agent').", {"ns": ("string", "project|agent"), "key": ("string", "key")}, ["key"]),
    "memory_list": ("List keys in a memory namespace.", {"ns": ("string", "project|agent")}, []),
    "memory_put": ("Write a JSON value to memory.", {"ns": ("string", "project|agent"), "key": ("string", "key"), "value": ("string", "value (any JSON)")}, ["key", "value"]),
}


def capabilities(max_concurrency=2, endpoints=(), validators=True, engine="ordivyr", isolation="process"):
    """`validators=False` for shared/pool workers: submitter-supplied validator commands then never reach them."""
    return C.capabilities(engine, ENGINE_TOOLS, max_concurrency, [f for f in FEATURES if validators or f != "validators"], "gateway", endpoints=endpoints, isolation=isolation)


class BoardTools:
    """mcp-shaped client for ToolBox: every call re-checks the contract permission (belt and braces: the tool is also simply not offered when not granted)."""
    def __init__(self, ctx, job): self.ctx, self.job = ctx, job
    def table(self):
        t = {}
        for name, (desc, props, req) in _SPECS.items():
            if C.tool_allowed(self.job, name):
                t[name] = (self, {"name": name, "description": desc, "inputSchema": {"type": "object", "properties": {k: {"type": ty, "description": d} for k, (ty, d) in props.items()}, "required": req}})
        return t
    def call(self, name, args):
        ctx = self.ctx; ctx.check()
        if not C.tool_allowed(self.job, name): return "ERROR: tool_not_granted"
        try:
            if name == "delegate": r = ctx.store.board_delegate(ctx.tid, ctx.fence, {k: args.get(k) for k in ("agent", "prompt", "engine", "key") if args.get(k)})
            elif name == "child_results":
                end = time.time() + max(0.0, min(float(args.get("wait_s") or 0), 60.0))
                while True:
                    r = ctx.store.board_children(ctx.tid, ctx.fence)
                    if r["all_done"] or time.time() >= end: break
                    ctx.check(); time.sleep(0.4)
            elif name == "memory_get": r = ctx.store.board_memory(ctx.tid, ctx.fence, "get", args.get("ns") or "project", args.get("key"))
            elif name == "memory_list": r = ctx.store.board_memory(ctx.tid, ctx.fence, "list", args.get("ns") or "project")
            else: r = ctx.store.board_memory(ctx.tid, ctx.fence, "put", args.get("ns") or "project", args.get("key"), args.get("value"))
        except PermissionError as e: return f"ERROR: {e}"
        import json; return json.dumps(r)[:8000]


def _fatal(code, msg): return D.Fatal(f"{code}: {msg}")


def check_job(job):
    """Host-side admission of a job (version, shape, model_ref). Raises D.Fatal; returns model_ref."""
    if not C.version_ok(job.get("contract_version")): raise _fatal("unsupported_version", f"job contract {job.get('contract_version')!r}, runtime speaks {C.CONTRACT_VERSION}")
    bad = C.validate_job(job)
    if bad: raise _fatal("invalid_job", "; ".join(bad)[:600])
    if not job.get("model_ref"): raise _fatal("invalid_job", "the ordivyr engine needs model_ref")
    return job["model_ref"]


def execute_job(job, wd, gateway, on_step, tools_client, run_validator, record_evidence=lambda *a: None, started=None):
    """The execution core shared by the in-process handler and the sandboxed job runner. Pure w.r.t. the host: everything it touches arrives as an argument.
    gateway.chat(...) and tools_client.call(...) may be local objects or RPC proxies; run_validator(v) -> (rc, out)."""
    from ..selfhost.agents import run_agent
    t0 = started or time.time(); mr = job["model_ref"]; ag = job["agent"]; perms = ag.get("permissions") or {}; lim = job.get("limits") or {}
    agent = {"id": f"{job['org']}.{job['project']}.{ag['id']}", "name": ag.get("name") or ag["id"], "system": ag.get("system") or "You are a careful assistant. Use tools when they help.", "endpoint": mr["endpoint"], "model": mr["model"],
             "tools": ag.get("tools"), "permissions": {"write": bool(perms.get("write")), "web": bool(perms.get("web")), "terminal": "none"},
             "max_steps": lim.get("max_turns"), "max_tool_calls": lim.get("max_tool_calls"), "max_seconds": lim.get("max_seconds"), "budget_usd": lim.get("budget_usd"), "max_output_tokens": lim.get("max_output_tokens")}
    wrote = [False]
    def step(name, args, out):
        if name in C.WRITE_TOOLS and not str(out).startswith("ERROR"): wrote[0] = True
        on_step(name, args, out)
    res = run_agent(agent, job["prompt"], wd, gateway, None, on_step=step, task_id=job["job_id"], board=job["job_id"], mcp=tools_client.table() if tools_client else None)
    tests = None; evid = []
    for v in job.get("validators") or []:
        rc, out = run_validator(v); ok = rc == 0; record_evidence(v["name"], ok, out[-2000:]); evid.append({"name": v["name"], "ok": ok, "detail": out[-300:]}); tests = ok if tests is None else (tests and ok)
    u = {"prompt_tokens": res["tokens_in"], "completion_tokens": res["tokens_out"], "cache_read_tokens": res.get("cache_read_tokens", 0), "cache_write_tokens": res.get("cache_write_tokens", 0),
         "turns": res["steps"], "tool_calls": res["tool_calls"], "cost_usd": res["cost_usd"], "wall_seconds": round(time.time() - t0, 3)}
    comp = C.completion(model_said_done=res["stop"] == "done", code_written=(wrote[0] if perms.get("write") else None), tests_passed=tests)
    return C.make_result(job["job_id"], "completed", res["stop"], res["text"], u, evidence=evid, comp=comp, runtime={"name": "ordivyr", "version": "builtin", "endpoint": res["endpoint"], "model": res["model"]}), tests


def map_gateway_error(code, msg, retryable):
    """gateway/runtime error -> the durable-queue exception that produces the right contract outcome."""
    from ..selfhost.agents import NEEDS_OWNER
    if code in NEEDS_OWNER: return D.NeedsApproval(f"{'cap_exceeded' if code in ('cap_exceeded', 'paid_not_authorized') else 'needs_owner'}: {msg}")
    if retryable: return D.Transient(f"model_unavailable: {msg}")
    return _fatal("provider_error", str(msg)[:600])


def board_handler(ctx):
    """IN-PROCESS execution (no sandbox): for a customer's own worker or development. Shared pool workers must use the sandboxed handler (sandbox.board_handler_sandboxed)."""
    from ..selfhost.gateway import Gateway, GatewayError
    job = ctx.payload; t0 = time.time(); ctx.check(); check_job(job)
    home = os.environ.get("ORDIVYR_GATEWAY_HOME")
    if not home: raise D.NeedsApproval("needs_owner: this worker has no ORDIVYR_GATEWAY_HOME (no model endpoints configured)")
    wsn = (job.get("workspace") or {}).get("name"); wd = (ctx.ws / "board" / job["org"] / job["project"] / wsn) if wsn else ctx.dir
    wd.mkdir(parents=True, exist_ok=True)
    def on_step(name, args, out): ctx.check(); ctx.write({"op": "output", "tool": name, "args": args, "output": str(out)[:2000]})
    def validate(v):
        ctx.check(); return W._run(ctx, W._argv(v["cmd"]), wd, v.get("timeout", 60), W._env())
    try: r, tests = execute_job(job, wd, Gateway(home), on_step, BoardTools(ctx, job), validate, lambda n, ok, d: ctx.store.add_evidence(ctx.tid, ctx.fence, n, ok, d), t0)
    except GatewayError as e: raise map_gateway_error(e.code, e, e.retryable)
    ctx.check(); ctx.write({"op": "checkpoint", "phase": "generated", "data": {"stop": r["stop"], "turns": r["usage"]["turns"]}}, {"op": "begin", "phase": "validating"})
    if tests is False: raise W.ValidationFailed("validation_failed: " + "; ".join(e["name"] for e in r["evidence"] if not e["ok"]))
    return r, None
