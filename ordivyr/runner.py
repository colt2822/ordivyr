"""In-process orchestrator: run a board end to end with no external runtime.

Order = dependency order of the board. For each agent: effective config (department policy applied) -> License gate (paid, tools, autonomy) ->
memory recall -> model call -> memory write -> Gambits (first matching rule; delegate/send_to/escalate re-checked against connections and License).
Models an agent can use (its `model` field):
  det.01                   deterministic, free, no model: records what the agent would do (always completes)
  role:<role>              resolved through ordivyr.roles to the best local model for that role
  <backend>:<model>        a model on a local backend (e.g. ollama:qwen3-coder:30b); free, runs on this machine
  acct.<id>                one of YOUR BYOK API accounts (accounts={id: {protocol, base, key, model}}); PAID unless its base URL is loopback
Paid runs need ALL of: run(allow_paid=True), the agent's License paid_allowed, and approve(agent, reason) returning True. Default is deny.
Everything that touches the network is injectable (`llm`, `http`), so the whole run is testable offline.
"""
from __future__ import annotations
import tempfile, threading, time, uuid
from . import durable as D
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from . import core, gambits as G, license as L, memory as M, providers as PV

TERMINAL = ("done", "failed", "skipped", "blocked")


class RunError(ValueError): pass


class Runner:
    def __init__(self, board, mission, llm=None, accounts=None, memory=None, drex=None, jev=None, role_plan=None, allow_paid=False, approve=None,
                 http=None, workdir=None, events=(), clock=time.time, run_id=None, plugins=None, parallel=None, store=None, lease_ttl=10.0, max_steps=None, terminals=None, scheduler="event"):
        if not isinstance(board, dict) or not board.get("agents"): raise RunError("board has no agents")
        self.board, self.mission = board, mission; self.llm, self.accounts = llm, dict(accounts or {}); self.mem = memory or M.NullMemory()
        self.drex, self.jev, self.roles = drex, jev, role_plan or {}; self.allow_paid, self.approve = allow_paid, approve or (lambda agent, why: False)
        self.http, self.workdir, self.events = http, workdir, tuple(events); self.clock = clock; self.plugins = plugins
        self.parallel = max(1, int(parallel if parallel is not None else (board.get("settings") or {}).get("parallel", 1))); self._alock = threading.Lock()   # parallel=1 (default) = the original strictly sequential order
        self.run_id = run_id or "run-" + uuid.uuid4().hex[:8]; board.setdefault("board_id", "board")
        self.eff = core.effective_of(board); self.state = {a["id"]: {"status": "pending", "output": "", "tokens": 0, "failures": 0, "model": a.get("model") or core.DEFAULT_MODEL, "notes": []} for a in board["agents"]}
        self.store, self.lease_ttl, self.max_steps = store, float(lease_ttl), max_steps                                  # store = durable.Store: every agent execution becomes a fenced, resumable task
        self.scheduler = scheduler; self.cancelled = threading.Event(); self.terminals = terminals     # callable(agent_id) -> port | None, supplied by the host; the model never names an identity
        self.actions = []; self.log = []; self.paid_stopped = False; self.queue = []; self.max_actions = int((board.get("settings") or {}).get("max_actions", 40))

    # ------------------------------------------------------------ helpers
    def _note(self, aid, msg): self.state[aid]["notes"].append(msg); self.log.append({"t": self.clock(), "agent": aid, "msg": msg})
    def _port(self, aid):
        try: return self.terminals(aid) if self.terminals else None
        except Exception: return None
    def _agent(self, aid): return next(a for a in self.board["agents"] if a["id"] == aid)

    def resolve(self, model):
        """-> (kind, backend/provider, model, paid). kind: det | local | account."""
        if model in (None, "", "det.01"): return ("det", "", "det.01", False)
        if model.startswith("role:"):
            ref = (self.roles.get(model[5:]) or {}).get("model")
            if not ref: raise RunError(f"role {model[5:]!r} has no model assigned on this machine")
            if ref.startswith("acct."): model = ref
            else: b, _, m = ref.partition(":"); return ("local", b, m, False)
        if model.startswith("acct."):
            acc = self.accounts.get(model[5:])
            if not acc: raise RunError(f"account {model[5:]!r} is not configured")
            return ("account", model[5:], acc.get("model", ""), not PV.is_local(acc["base"]))
        if ":" in model and not model.startswith("acct."):
            b, _, m = model.partition(":"); return ("local", b, m, False)
        raise RunError(f"unknown model {model!r}: use det.01, role:<role>, <backend>:<model> or acct.<id>")

    def _prompt(self, aid):
        e = self.eff(aid); up = [x for x in G.managers_of(self.board, aid)]
        ctx = "\n\n".join(f"OUTPUT FROM {self._agent(u)['name']}:\n{self.state[u]['output'][:2500]}" for u in up if self.state[u]["status"] == "done" and self.state[u]["output"])
        mem = M.context_for(self.mem, e, e["name"], self.mission, self.board.get("board_id"))
        return core._agent_prompt(e, self.board, self.mission), "\n\n".join(x for x in (mem, ctx, "Do your part of the mission now. Be concise and concrete.") if x)

    # ------------------------------------------------------------ one agent
    def _execute(self, aid):
        a, e, st = self._agent(aid), self.eff(aid), self.state[aid]
        kind, who, model, paid = self.resolve(a.get("model"))
        system, prompt = self._prompt(aid)
        lim = e.get("limits") or {}; budget = int(float(lim.get("token_budget") or 0)); maxtok = min(2048, budget) if budget else 1024
        if kind == "det":
            return f"[det.01] {e['name']} acknowledged the mission and would act within: tools={e.get('tools') or []}, skills={(e.get('license') or {}).get('skills') or []}.", 0, "det.01"
        if paid:
            if not (self.allow_paid and e["license"].get("paid_allowed") and not self.paid_stopped): raise RunError("paid execution is not allowed (needs allow_paid, the agent's License paid_allowed, and no stop_paid)")
            with self._alock: approved = self.approve(a, f"paid run on {model}")      # approval prompts are never shown concurrently
            if not approved: raise RunError("paid run was not approved")
        pids = self.plugins.licensed(e) if self.plugins else []
        if pids and kind in ("local", "account"):                      # plugin tools: only those the agent's License grants, through the guarded host
            tm = self.plugins.toolmap(pids)
            if tm:
                from . import agentloop as AL
                if kind == "local":
                    be = self.llm.backends[who]; proto, base, key = "openai", be.base + ("/v1" if be.kind == "ollama" else ""), ""
                else: acc = self.accounts[who]; proto, base, key = acc["protocol"], acc["base"], acc.get("key", "")
                if proto in ("openai", "anthropic"):
                    sk = self.plugins.skills_prompt(pids); tl = e.get("tools") or []; box = AL.ToolBox(Path(self.workdir or tempfile.mkdtemp(prefix="ordivyr-run-")), write="file_write" in tl and (e.get("permissions") or "read-only") != "read-only", web="http_api" in tl, ask=False, mcp=tm, terminals=self._port(aid))
                    text, tk, used, _, _ = AL.run(proto, base, key, model, system + ("\n\n" + sk if sk else ""), prompt, box, http=self.http, token_budget=budget)
                    return text, tk, used
        if kind == "local":
            if not self.llm: raise RunError("no local LLM manager configured")
            be = (getattr(self.llm, "backends", None) or {}).get(who)          # a manager without a backend map (or an unknown backend) falls through to llm.chat
            if self.workdir and getattr(be, "kind", "") == "openai":                    # local OpenAI-compatible server + a working folder: the same guarded file-tool loop accounts get
                from . import agentloop as AL
                tl = e.get("tools") or []; box = AL.ToolBox(Path(self.workdir), write="file_write" in tl and (e.get("permissions") or "read-only") != "read-only", web=False, ask=False, terminals=self._port(aid))
                text, tk, used, _, _ = AL.run("openai", be.base, getattr(be, "key", ""), model, system, prompt, box, http=self.http, token_budget=budget, max_steps=self.max_steps or AL.MAX_STEPS, on_step=self._step_hook, free_endpoint=True)
                return text, tk, used
            text, tk, used = self.llm.chat(who, model, system, [{"role": "user", "text": prompt}], max_tokens=maxtok)
            return text, tk, used
        acc = self.accounts[who]; tools = [t for t in (e.get("tools") or [])]
        if self.workdir and acc.get("protocol") in ("openai", "anthropic"):          # a working folder always gets the guarded loop (reads at least); writes/web stay gated by file_write/http_api below
            from . import agentloop as AL
            box = AL.ToolBox(Path(self.workdir), write="file_write" in tools and (e.get("permissions") or "read-only") != "read-only", web="http_api" in tools, ask=False, terminals=self._port(aid))
            text, tk, used, _, _ = AL.run(acc["protocol"], acc["base"], acc.get("key", ""), model, system, prompt, box, http=self.http, token_budget=budget, max_steps=self.max_steps or AL.MAX_STEPS, on_step=self._step_hook)
            return text, tk, used
        text, tk, used = PV.chat(acc["protocol"], acc["base"], acc.get("key", ""), model, system, [{"role": "user", "text": prompt}], http=self.http, max_tokens=maxtok)
        return text, tk, used

    # ------------------------------------------------------------ durable execution (P0.1 store wired into the Runner)
    _tl = threading.local()
    def _step_hook(self, name, args, out):
        ctx = getattr(self._tl, "ctx", None)
        if ctx is None: return
        st, tid, fence = ctx; st.apply(tid, fence, [{"op": "output", "tool": name, "args": args, "output": out}, {"op": "checkpoint", "phase": "tool", "data": {"tool": name}}])      # one fenced transaction = one fsync, not two
        ctx_lost = getattr(self._tl, "lost", None)
        if ctx_lost is not None and ctx_lost.is_set(): raise D.StaleLease(f"task {tid}: lease lost")

    def _durable_execute(self, aid):
        """One agent = one durable task (idempotent key run_id:agent). A finished agent is never re-executed on resume; an interrupted one is re-claimed after its lease expires."""
        st = self.store; kind = f"runner:{self.run_id}"; key = f"{self.run_id}:{aid}"
        tid = st.submit(kind, {"run": self.run_id, "agent": aid}, idem_key=key, max_attempts=3)
        deadline = time.time() + self.lease_ttl + 30
        while True:
            t = st.get(tid)
            if t["state"] == "completed": r = t["result"]; self._note(aid, "resumed from durable store"); return r["text"], r["tokens"], r["model"]
            if t["state"] in ("failed", "cancelled"): raise RunError(f"durable task {tid} is {t['state']}: {t['failure']}")
            st.reap(); t = st.claim(f"runner-{self.run_id}", "main", self.lease_ttl, [kind])
            if t: break
            if time.time() > deadline: raise RunError(f"durable task {tid} is held by another worker")
            time.sleep(0.25)
        fence = t["fence"]; stop = threading.Event(); lost = threading.Event()
        def beat():
            while not stop.wait(self.lease_ttl / 3):
                try:
                    if st.heartbeat(tid, fence, self.lease_ttl) == "cancel": lost.set()
                except D.StaleLease: lost.set(); return
        threading.Thread(target=beat, daemon=True).start()
        self._tl.ctx = (st, tid, fence); self._tl.lost = lost
        try:
            st.begin(tid, fence, "running"); text, tk, used = self._execute(aid)
            if lost.is_set(): raise D.StaleLease(f"task {tid}: lease lost")
            st.begin(tid, fence, "validating"); st.complete(tid, fence, {"text": text, "tokens": tk, "model": used}); return text, tk, used
        except D.StaleLease as ex: raise RunError(str(ex))
        except BaseException as ex:
            try: st.fail(tid, fence, f"{type(ex).__name__}: {str(ex)[:500]}", retry=False)
            except D.StaleLease: pass
            raise
        finally: stop.set(); self._tl.ctx = None

    def _gctx(self, aid, phase):
        a, e = self._agent(aid), self.eff(aid); st = self.state[aid]
        return {"phase": phase, "agent_id": aid, "task_type": G.classify(self.mission), "failures": st["failures"], "tokens_used": st["tokens"],
                "token_budget": int((e.get("limits") or {}).get("token_budget") or 0), "statuses": {k: v["status"] for k, v in self.state.items()},
                "now": G.ctx_now(self.clock()), "events": self.events, "no_worker": False}

    def _gambits(self, aid, phase):
        if len(self.actions) >= self.max_actions: return
        e = self.eff(aid); rule = G.evaluate(e.get("gambits") or [], self._gctx(aid, phase))
        if not rule: return
        kind = rule["then"]["kind"]; rec = {"agent": aid, "rule": rule.get("id"), "action": kind, "phase": phase}
        if kind in G.TARGET_ACTIONS:
            tgt = G.resolve_target(self.board, e, rule, G.classify(self.mission), effective_of=self.eff)
            ok, why = G.authorise(self.board, e, kind, tgt, self.eff) if tgt else (False, "no target")
            rec.update(target=tgt, allowed=ok, reason=why)
            if ok and kind in ("delegate", "send_to") and self.state[tgt]["status"] == "pending" and tgt not in self.queue: self.queue.append(tgt)
            elif ok and kind == "escalate": self._note(aid, f"escalated to {tgt}")
        elif kind == "stop_paid": self.paid_stopped = True
        elif kind == "pause_self": self._agent(aid)["paused"] = True; self.state[aid]["status"] = "done" if phase == "done" else self.state[aid]["status"]
        elif kind == "notify": self._note(aid, f"gambit notice ({phase})")
        elif kind == "ask_drex":
            opts = {t: self._agent(t)["name"] for t in G.delegate_targets(self.board, aid) if self.state[t]["status"] == "pending"}
            if len(opts) < 2: rec.update(result="skipped", reason="needs two or more candidate agents")
            elif not self.drex: rec.update(result="skipped", reason="DREX bridge not configured")
            else:
                pick = self.drex.route(f"Mission: {self.mission}\nLast output: {self.state[aid]['output'][:600]}", opts)
                rec.update(result="routed" if pick else "no-confident-answer", target=pick)
                if pick: self.queue.append(pick)
        else: rec.update(result="unsupported-in-core")
        self.actions.append(rec)

    def _paid(self, aid):
        """Paid (or unresolvable) agents never share a wave: a stop_paid gambit from one must be able to stop the next one's spend."""
        try: return bool(self.resolve(self._agent(aid).get("model"))[3])
        except Exception: return True

    def _ready(self, aid):
        st = self.state[aid]
        if st["status"] != "pending" or self._agent(aid).get("paused") or self._paid(aid): return False
        return all(self.state[d]["status"] in ("done", "skipped") for d in core.dependency_graph(self.board)[aid] if not self._agent(d).get("paused"))

    def _run_batch(self, batch):
        def one(aid):
            try: return self._durable_execute(aid) if self.store else self._execute(aid)
            except Exception as ex: return ex
        if len(batch) == 1: return [one(batch[0])]
        with ThreadPoolExecutor(len(batch)) as ex: return list(ex.map(one, batch))

    def _finish(self, aid, outcome):
        st, a = self.state[aid], self._agent(aid)
        try:
            if isinstance(outcome, Exception): raise outcome
            text, tk, used = outcome
            st.update(status="done", output=text, tokens=tk, model=used)
            e = self.eff(aid)
            if M.scopes(e, self.board.get("board_id"))["write"]:
                ns = M.scopes(e, self.board.get("board_id"))["write"][-1]
                self.mem.remember(e["name"], ns, f"{self.mission[:60]}", text[:1500])
            self._gambits(aid, "done")
        except Exception as ex:                                                # any single-agent failure is contained and recorded
            st["failures"] += 1; st.update(status="failed", output=f"{type(ex).__name__}: {str(ex)[:300]}"); self._note(aid, f"failed: {type(ex).__name__}: {str(ex)[:120]}"); self._gambits(aid, "failed")
        if self.jev:
            try: self.jev.record(self.run_id, self.board["board_id"], aid, f"{a['name']}: {self.mission[:80]}", {"done": "done", "failed": "failed"}.get(st["status"], "queued"), {"tokens": st["tokens"]}, st["output"] if st["status"] == "failed" else None)
            except Exception as ex: self._note(aid, f"jev record failed: {ex}")

    # ------------------------------------------------------------ run
    def cancel(self):
        """Cooperative cancellation: nothing new starts; agents already executing finish their current call (a model call cannot be interrupted safely); the rest are skipped."""
        self.cancelled.set()

    def _admit(self, aid):
        """-> 'run' | 'defer' (a dependency is still pending/running) | 'drop' (decided: skipped or blocked)."""
        st = self.state[aid]; a = self._agent(aid)
        if a.get("paused"): st["status"] = "skipped"; self._note(aid, "paused"); return "drop"
        deps = [d for d in core.dependency_graph(self.board)[aid] if not self._agent(d).get("paused")]
        if any(self.state[d]["status"] in ("failed", "blocked") for d in deps): st["status"] = "blocked"; self._note(aid, "a dependency failed"); return "drop"
        if any(self.state[d]["status"] in ("pending", "running") for d in deps): return "defer"
        return "run"

    def _run_events(self):
        """Event-driven scheduling: an agent starts the moment ITS dependencies finish (no wave barrier), at most `parallel` at a time. Paid agents stay exclusive (nothing runs
        beside them, and while one is waiting nothing new starts, so it cannot starve) so a stop_paid gambit can still stop the next spend. Bookkeeping runs on this thread in
        dependency order among simultaneous completions."""
        from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
        def one(aid):
            try: return self._durable_execute(aid) if self.store else self._execute(aid)
            except Exception as ex: return ex
        running = {}
        with ThreadPoolExecutor(self.parallel) as ex:
            while self.queue or running:
                if self.cancelled.is_set():
                    for aid in list(self.queue):
                        if self.state[aid]["status"] == "pending": self.state[aid]["status"] = "skipped"; self._note(aid, "run cancelled"); self._cancel_skipped = True
                    self.queue.clear()
                else:
                    paid_running = any(self._paid(x) for x in running.values())
                    for aid in list(self.queue):
                        if self.state[aid]["status"] != "pending": self.queue.remove(aid); continue
                        v = self._admit(aid)
                        if v == "drop": self.queue.remove(aid); continue
                        if v == "defer": continue
                        paid = self._paid(aid)
                        if paid_running or len(running) >= self.parallel or (paid and running): break
                        self.queue.remove(aid); self.state[aid]["status"] = "running"; running[ex.submit(one, aid)] = aid
                        if paid: break
                if not running:
                    for aid in list(self.queue): self.state[aid]["status"] = "blocked"; self._note(aid, "dependency never ran")      # nothing can ever make these ready
                    self.queue.clear(); break
                done, _ = wait(list(running), return_when=FIRST_COMPLETED)
                for fut in sorted(done, key=lambda f: self._rank.get(running[f], 0)): self._finish(running.pop(fut), fut.result())

    def _run_waves(self):
        """The original strictly ordered / wave-batched loop (parallel=1 default: byte-identical transcript to earlier releases)."""
        started = self.clock()
        while self.queue:
            aid = self.queue.pop(0); st = self.state[aid]
            if st["status"] != "pending": continue
            a = self._agent(aid)
            if a.get("paused"): st["status"] = "skipped"; self._note(aid, "paused"); continue
            deps = [d for d in core.dependency_graph(self.board)[aid] if not self._agent(d).get("paused")]
            if any(self.state[d]["status"] in ("failed", "blocked") for d in deps): st["status"] = "blocked"; self._note(aid, "a dependency failed"); continue
            if any(self.state[d]["status"] == "pending" for d in deps):       # a dependency has not run yet: retry after it (bounded)
                st["retries"] = st.get("retries", 0) + 1
                if st["retries"] > len(self.state) + 2: st["status"] = "blocked"; self._note(aid, "dependency never ran")
                else: self.queue.append(aid)
                continue
            st["status"] = "running"; batch = [aid]
            if self.parallel > 1 and not self._paid(aid):                      # independent agents whose dependencies are all finished run side by side
                for nxt in list(self.queue):
                    if len(batch) >= self.parallel: break
                    if self._ready(nxt): self.queue.remove(nxt); self.state[nxt]["status"] = "running"; batch.append(nxt)
            for b_aid, outcome in zip(batch, self._run_batch(batch)): self._finish(b_aid, outcome)      # bookkeeping always in queue order -> same transcript as a sequential run

    def run(self):
        order, cyc = core.dependency_order(self.board)
        if cyc: raise RunError(f"delegation cycle among: {', '.join(cyc)}")
        errs = core.validate(self.board).get("errors", [])
        errs = [x for x in errs if "connected worker" not in x]
        if errs: raise RunError("; ".join(errs[:3]))
        if self.jev: self.jev.sync_agents(self.board)
        if self.store: self.store.reap()                                                  # resume: dead leases from a crashed earlier process go back to the queue
        self.queue = list(order); started = self.clock(); self._rank = {x: i for i, x in enumerate(order)}
        if self.parallel > 1 and self.scheduler == "event": self._run_events()
        else: self._run_waves()
        stat = [s["status"] for s in self.state.values()]
        status = "cancelled" if getattr(self, "_cancel_skipped", False) else "done" if all(s in ("done", "skipped") for s in stat) else "failed" if all(s in ("failed", "blocked", "skipped") for s in stat) else "partial"
        return {"run_id": self.run_id, "status": status, "seconds": round(self.clock() - started, 3), "agents": self.state, "actions": self.actions, "log": self.log}
