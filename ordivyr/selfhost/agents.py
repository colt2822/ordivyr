"""Provider-independent agents: an agent is DATA (prompt, tools, permissions, budget, and a logical model reference `endpoint/model`). It never holds a key or a base URL.

  AgentStore      create / update / switch_provider / remove  (JSON, atomic)
  run_agent       the tool loop: every model call goes through the Gateway (caps, authorisation, capability gates, accounting); tools are ORDIVYR's sandboxed ToolBox
                  (+ terminal tools only when the agent's permission says so AND the engine broker authorises each call)
  History         per-run record: status, steps (tool, args, output preview), tokens, cost, endpoint/model actually used, error
  h_gw_agent      durable-task handler ("gw_agent"): the SAME task protocol (leases, fencing, retries, validators, idempotent commit) for local, cloud and hybrid agents
Gateway location for a worker: ORDIVYR_GATEWAY_HOME (a path - never a key). Endpoint ids are logical per machine, so a task for endpoint "local" resolves to whatever "local" is ON THAT NODE.
"""
from __future__ import annotations
import json, os, secrets, sqlite3, threading, time
from pathlib import Path
from .. import agentloop as AL
from .. import durable as D
from .gateway import Gateway, GatewayError

DEFAULT_GATEWAY_HOME = None          # set by SelfHost in the server process (a PATH, never a key); a standalone worker uses ORDIVYR_GATEWAY_HOME
NEEDS_OWNER = {"paid_not_authorized", "cap_exceeded", "unpriced_model", "unknown_endpoint"}      # not retryable by the worker: a human must act
DEFAULT_PERMS = {"write": False, "web": False, "terminal": "none"}

class AgentStore:
    def __init__(self, home): self.path = Path(home) / "agents.json"; self.path.parent.mkdir(parents=True, exist_ok=True); self._lock = threading.Lock()
    def _load(self):
        try: return json.loads(self.path.read_text())
        except (OSError, ValueError): return {}
    def _save(self, d): t = self.path.with_suffix(".tmp"); t.write_text(json.dumps(d, indent=1)); os.replace(t, self.path)
    def create(self, name, endpoint, model, system="You are a careful assistant. Use tools when they help.", tools=None, permissions=None, memory_ns=None, max_steps=AL.MAX_STEPS, budget_usd=None, skills=()):
        a = {"id": "ag-" + secrets.token_hex(4), "name": name, "system": system, "endpoint": endpoint, "model": model, "tools": tools, "permissions": {**DEFAULT_PERMS, **(permissions or {})},
             "memory_ns": memory_ns or "", "max_steps": max_steps, "budget_usd": budget_usd, "skills": list(skills), "created": time.time()}
        with self._lock: d = self._load(); d[a["id"]] = a; self._save(d)
        return a
    def get(self, aid):
        a = self._load().get(aid)
        if not a: raise KeyError(f"unknown agent {aid}")
        return a
    def list(self): return list(self._load().values())
    def update(self, aid, **kw):
        with self._lock:
            d = self._load(); a = d[aid]; bad = set(kw) - {"name", "system", "tools", "permissions", "memory_ns", "max_steps", "budget_usd", "skills"}
            if bad: raise ValueError(f"not updatable here: {sorted(bad)} (use switch_provider for the model)")
            a.update(kw); self._save(d); return a
    def switch_provider(self, aid, endpoint, model, gateway=None):
        """Same agent, different model/provider. Validates against the gateway when given (endpoint exists; tools supported if the agent uses them)."""
        if gateway is not None:
            e = gateway.describe(endpoint); a = self.get(aid)
            if (a["tools"] is None or a["tools"]) and not e["capabilities"].get("tools"): raise GatewayError("capability_unsupported", f"{endpoint} does not support tools but agent {a['name']} uses them", endpoint)
        with self._lock: d = self._load(); d[aid].update(endpoint=endpoint, model=model); self._save(d); return d[aid]
    def remove(self, aid):
        with self._lock: d = self._load(); d.pop(aid, None); self._save(d)

class History:
    def __init__(self, home):
        self.db = sqlite3.connect(str(Path(home) / "agent-history.db"), check_same_thread=False, isolation_level=None)
        self.db.executescript("CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, agent TEXT, task TEXT, board TEXT, started REAL, finished REAL, status TEXT, steps INT, tin INT, tout INT, usd REAL, endpoint TEXT, model TEXT, error TEXT, result TEXT);"
                              "CREATE TABLE IF NOT EXISTS steps(run TEXT, n INT, ts REAL, tool TEXT, args TEXT, out TEXT);")
    def begin(self, agent, task=None, board=None): rid = "run-" + secrets.token_hex(5); self.db.execute("INSERT INTO runs(id,agent,task,board,started,status) VALUES(?,?,?,?,?,'running')", (rid, agent, task, board, time.time())); return rid
    def step(self, rid, n, tool, args, out): self.db.execute("INSERT INTO steps VALUES(?,?,?,?,?,?)", (rid, n, time.time(), tool, json.dumps(args)[:500], str(out)[:500]))
    def end(self, rid, status, steps, tin, tout, usd, endpoint, model, error=None, result=None):
        self.db.execute("UPDATE runs SET finished=?,status=?,steps=?,tin=?,tout=?,usd=?,endpoint=?,model=?,error=?,result=? WHERE id=?", (time.time(), status, steps, tin, tout, usd, endpoint, model, error, (result or "")[:4000], rid))
    def runs(self, agent=None, board=None, limit=50):
        q = "SELECT id,agent,task,board,started,finished,status,steps,tin,tout,usd,endpoint,model,error FROM runs WHERE 1=1" + (" AND agent=?" if agent else "") + (" AND board=?" if board else "") + " ORDER BY started DESC LIMIT ?"
        cols = ("id", "agent", "task", "board", "started", "finished", "status", "steps", "tokens_in", "tokens_out", "usd", "endpoint", "model", "error"); a = [x for x in (agent, board) if x] + [limit]
        return [dict(zip(cols, r)) for r in self.db.execute(q, a)]
    def steps(self, rid): return [{"n": r[0], "tool": r[1], "args": r[2], "out": r[3]} for r in self.db.execute("SELECT n,tool,args,out FROM steps WHERE run=? ORDER BY n", (rid,))]

class TerminalDenied(ValueError): pass

class BrokerTerminal:
    """Minimal client for the engine's terminal broker (same wire as the commercial engine's remote terminal port, re-implemented so the open-source core has no dependency on it).
    The credential is passed in by the worker's environment; every call is authorised, bound to the task's process tree and audited by the ENGINE, not here."""
    def __init__(self, url, task, cred, timeout=60): self.url, self.task, self.cred, self.timeout = url.rstrip("/") + "/api/agent/terminal", str(task), str(cred), timeout
    def _call(self, **body):
        import urllib.request, urllib.error
        req = urllib.request.Request(self.url, json.dumps(body).encode(), {"Content-Type": "application/json", "Authorization": "Bearer " + self.cred, "X-Task-Id": self.task})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r: return json.load(r)
        except urllib.error.HTTPError as e:
            try: msg = json.load(e).get("error", "")
            except Exception: msg = ""
            raise TerminalDenied(msg or f"HTTP {e.code}")
        except (urllib.error.URLError, OSError) as e: raise TerminalDenied(f"terminal service unreachable: {e}")
    def list(self):
        try: return self._call(verb="list")["terminals"]
        except TerminalDenied: return []
    def read(self, name, lines=120): return self._call(verb="read", terminal=name, lines=lines)
    def run(self, name, command, timeout=60): return self._call(verb="run", terminal=name, command=command, timeout=timeout)

def _specs(box, allow):
    return [{"type": "function", "function": {"name": d["name"], "description": d["description"], "parameters": d["schema"]}} for d in box.defs if allow is None or d["name"] in allow]

def run_agent(agent, prompt, workdir, gateway, history=None, terminals=None, on_step=None, task_id=None, board=None, endpoint=None, model=None, timeout=120, max_tokens=None, clock=None, mcp=None, spend_scope=None, spend_limit_usd=None, endpoint_binding=None, check=None, gate=None):
    """-> dict(text, steps, tool_calls, tokens_in, tokens_out, cost_usd, endpoint, model, stop, ...). `steps` counts MODEL TURNS (one request to the model, however many tools it
    called); tool executions are counted separately in `tool_calls`. Explicit limits: turns (agent max_steps), tool calls (max_tool_calls), wall clock (max_seconds) and spend
    (budget_usd). `endpoint`/`model` override the agent's reference for this run only (provider switch without editing the agent). A malformed or output-truncated tool call is
    NEVER executed: it gets a structured error back, with a bounded number of corrections (stop 'malformed')."""
    import time as _t
    now = clock or _t.time; t0 = now()
    ep, md = endpoint or agent["endpoint"], model or agent["model"]; perms = agent.get("permissions") or DEFAULT_PERMS; hist_id = history.begin(agent["id"], task_id, board) if history else None
    box = AL.ToolBox(Path(workdir), write=bool(perms.get("write")), web=bool(perms.get("web")), ask=False, terminals=terminals if perms.get("terminal", "none") != "none" else None, mcp=mcp); box.gate = gate
    allow = None if agent.get("tools") is None else set(agent["tools"])
    if allow is not None and not agent.get('strict_tools'):                 # legacy saved allowlists inherit refinements; compiled drawings have explicit tool grants
        if "write_file" in allow: allow.add("edit_file")
        if "read_file" in allow: allow |= {"grep", "find_files"}
    tools = _specs(box, allow) or None
    out_limit = AL.output_limit(md, max_tokens or agent.get("max_output_tokens"))
    max_turns = int(agent.get("max_steps") or AL.MAX_STEPS); max_calls = int(agent.get("max_tool_calls") or AL.MAX_TOOL_CALLS); max_s = float(agent.get("max_seconds") or AL.MAX_SECONDS)
    msgs = [{"role": "system", "content": agent["system"]}, {"role": "user", "content": prompt}]; tin = tout = cache_r = cache_w = 0; cost = 0.0; turns = 0; ncalls = 0; stop = "done"; text = ""
    bad_turns = 0; bad_seen = {}; truncated_turns = malformed = 0
    token_budget = int(agent.get('token_budget') or 0)
    try:
        while True:
            if check: check()
            remaining_s = max_s - (now() - t0)
            if remaining_s <= 0: stop = 'time'; break
            if agent.get('budget_usd') and cost >= agent['budget_usd']: stop = 'budget'; break
            request_output = out_limit
            if token_budget:
                input_bound = len(json.dumps(msgs, ensure_ascii=True).encode()) + len(json.dumps(tools, ensure_ascii=True).encode()) + 256
                request_output = min(out_limit, token_budget - tin - tout - input_bound)
                if request_output <= 0: stop = 'tokens'; break
            if endpoint_binding is not None:
                from .placement import binding
                try:
                    current_cfg = json.loads(gateway.cfg_path.read_text())
                    current = binding(current_cfg['endpoints'][ep], current_cfg.get('prices', {}).get(md))
                except (OSError, ValueError, KeyError, TypeError):
                    raise GatewayError('endpoint_changed', 'Endpoint configuration is unavailable; inspect before continuing', ep)
                if current != endpoint_binding:
                    raise GatewayError('endpoint_changed', 'Endpoint or model rates changed after setup; inspect before continuing', ep)
            spending = {} if spend_scope is None else {'spend_scope': spend_scope, 'spend_limit_usd': spend_limit_usd}
            r = gateway.chat(agent["id"], ep, md, msgs, tools=tools, max_tokens=int(request_output), timeout=min(timeout, remaining_s), **spending)
            turns += 1; tin += r.usage["prompt_tokens"]; tout += r.usage["completion_tokens"]; cache_r += r.usage.get("cache_read_tokens", 0); cache_w += r.usage.get("cache_write_tokens", 0); cost += r.cost_usd; text = r.text
            if check: check()
            if now() - t0 > max_s: stop = 'time'; break
            if token_budget and tin + tout > token_budget: stop = 'tokens'; break
            if agent.get('budget_usd') and cost > agent['budget_usd']: stop = 'budget'; break
            if not r.tool_calls:
                if getattr(r, 'finish', '') in ('length', 'max_tokens'): stop = 'truncated'
                break
            cut = r.finish in ("length", "max_tokens")
            parsed = []                       # (call, args | None, refusal | None)
            for c in r.tool_calls:
                raw = c["arguments"] or "{}"; args = err = None
                try:
                    args = json.loads(raw)
                    if not isinstance(args, dict): args, err = None, "arguments must be a JSON object"
                except (ValueError, TypeError) as e: err = f"malformed JSON arguments ({str(e)[:80]})"
                if cut: err = AL._truncation_note(out_limit)[len("ERROR: not executed - "):]
                elif err is None and allow is not None and c["name"] not in allow: err = None          # permission refusal is reported by the existing branch below
                if err is None and args is not None:
                    why = box.validate(c["name"], args)
                    if why: err = why
                parsed.append((c, args, err))
            # replay only valid JSON in the history (the Anthropic adapter json.loads it): a malformed string becomes a short marker
            msgs.append({"role": "assistant", "content": r.text or None, "tool_calls": [{"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": c["arguments"] if err is None else json.dumps({"_malformed_arguments": str(c["arguments"])[:200]})}} for c, a, err in parsed]})
            ran = 0
            for c, args, err in parsed:
                if err is not None:
                    malformed += 1; out = AL._bad_note(c["name"], err, c["arguments"]) if not cut else AL._truncation_note(out_limit)
                    if history: history.step(hist_id, ncalls + 1, c["name"], {"_refused": err[:120]}, out)
                    msgs.append({"role": "tool", "tool_call_id": c["id"], "content": out}); continue
                if ncalls >= max_calls: out = "ERROR: not executed - the tool-call limit for this run was reached"
                else:
                    ncalls += 1; ran += 1
                    if allow is not None and c["name"] not in allow: out = "not allowed: this agent may not use " + c["name"]
                    else:
                        if check: check()
                        out = box.call(c["name"], args)
                    if history: history.step(hist_id, ncalls, c["name"], args, out)
                    if on_step: on_step(c["name"], args, out)
                msgs.append({"role": "tool", "tool_call_id": c["id"], "content": str(out)})
            if cut: truncated_turns += 1
            if ran == 0:                      # every call refused: bounded correction, and the byte-identical malformed call twice is a loop
                bad_turns += 1
                for c, a, e in parsed: k = (c["name"], str(c["arguments"])[:200]); bad_seen[k] = bad_seen.get(k, 0) + 1
                if bad_turns >= AL.MAX_BAD_TURNS or max(bad_seen.values()) > AL.MAX_SAME_BAD: stop = "malformed"; break
            else: bad_turns = 0
            if ncalls >= max_calls: stop = "tool_calls"; break
            if turns >= max_turns: stop = "steps"; break
            if now() - t0 >= max_s: stop = "time"; break
            if agent.get("budget_usd") and cost >= agent["budget_usd"]: stop = "budget"; break
    except GatewayError as e:
        if history: history.end(hist_id, "error:" + e.code, turns, tin, tout, cost, ep, md, str(e))
        raise
    except (D.Cancelled, D.StaleLease) as e:
        if history: history.end(hist_id, 'interrupted', turns, tin, tout, cost, ep, md, type(e).__name__)
        raise
    if history: history.end(hist_id, "ok" if stop == "done" else stop, turns, tin, tout, cost, ep, md, None, text)
    return {"text": text, "steps": turns, "tool_calls": ncalls, "tokens_in": tin, "tokens_out": tout, "cost_usd": cost, "endpoint": ep, "model": md, "stop": stop, "run": hist_id,
            "malformed_calls": malformed, "truncated_turns": truncated_turns, "output_limit": out_limit, "cache_read_tokens": cache_r, "cache_write_tokens": cache_w}

def h_gw_agent(ctx):
    """Durable handler for kind 'gw_agent'. payload: agent (snapshot), prompt, validators?, board?, endpoint?/model? (per-task override), shared_dir?"""
    from .. import durable as D, durable_worker as W
    p = ctx.payload; home = os.environ.get("ORDIVYR_GATEWAY_HOME") or DEFAULT_GATEWAY_HOME
    if not home: raise D.NeedsApproval("this worker has no ORDIVYR_GATEWAY_HOME: it cannot reach any model endpoint")
    gw = Gateway(home); hist = History(home); wd = Path(p["shared_dir"]) if p.get("shared_dir") else ctx.dir; wd.mkdir(parents=True, exist_ok=True)
    ctx.check()
    def on_step(name, args, out): ctx.check(); ctx.write({"op": "output", "tool": name, "args": args, "output": str(out)[:2000]})
    term = None
    if p.get("terminal"):
        t = p["terminal"]; term = BrokerTerminal(t["url"], t["task"], os.environ.get("ORDIVYR_TERM_CRED", ""), timeout=60)          # credential comes from the worker's environment, never from the task payload
    try: res = run_agent(p["agent"], p["prompt"], wd, gw, hist, terminals=term, on_step=on_step, task_id=str(ctx.tid), board=p.get("board"), endpoint=p.get("endpoint"), model=p.get("model"), spend_scope=p.get('spend_scope'), spend_limit_usd=p.get('spend_limit_usd'), endpoint_binding=p.get('endpoint_binding'), check=ctx.check)
    except GatewayError as e:
        if e.code in NEEDS_OWNER or e.code == 'endpoint_changed': raise D.NeedsApproval(f"{e.code}: {e}")
        if p.get("hold_uncertain") and e.retryable:
            raise D.NeedsApproval(f"{e.code}: provider outcome requires inspection; automatic replay refused: {e}")
        if e.retryable: raise D.Transient(f"{e.code}: {e}")
        raise W.ValidationFailed(f"{e.code}: {e}")
    if p.get("hold_uncertain") and res.get("stop") != "done":
        raise W.ValidationFailed(f"agent stopped incomplete: {res.get('stop')}")
    ctx.check(); ctx.write({"op": "checkpoint", "phase": "generated", "data": {"text": res["text"][:2000], "cost_usd": res["cost_usd"], "endpoint": res["endpoint"], "model": res["model"]}}, {"op": "begin", "phase": "validating"})
    bad = []
    for v in p.get("validators", []):
        ctx.check(); rc, out = W._run(ctx, W._argv(v["cmd"]), wd, v.get("timeout", 60), W._env()); ctx.store.add_evidence(ctx.tid, ctx.fence, v["name"], rc == 0, out[-2000:])
        if rc != 0: bad.append(f"{v['name']}: rc={rc}")
    if bad: raise W.ValidationFailed("validation failed: " + "; ".join(bad))
    return {k: res[k] for k in ("text", "steps", "tool_calls", "tokens_in", "tokens_out", "cost_usd", "endpoint", "model", "stop")} | {"agent": p["agent"]["id"], "board": p.get("board")}, None
