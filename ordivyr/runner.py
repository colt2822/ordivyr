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
import tempfile, time, uuid
from pathlib import Path
from . import core, gambits as G, license as L, memory as M, providers as PV

TERMINAL = ("done", "failed", "skipped", "blocked")


class RunError(ValueError): pass


class Runner:
    def __init__(self, board, mission, llm=None, accounts=None, memory=None, drex=None, jev=None, role_plan=None, allow_paid=False, approve=None,
                 http=None, workdir=None, events=(), clock=time.time, run_id=None, plugins=None):
        if not isinstance(board, dict) or not board.get("agents"): raise RunError("board has no agents")
        self.board, self.mission = board, mission; self.llm, self.accounts = llm, dict(accounts or {}); self.mem = memory or M.NullMemory()
        self.drex, self.jev, self.roles = drex, jev, role_plan or {}; self.allow_paid, self.approve = allow_paid, approve or (lambda agent, why: False)
        self.http, self.workdir, self.events = http, workdir, tuple(events); self.clock = clock; self.plugins = plugins
        self.run_id = run_id or "run-" + uuid.uuid4().hex[:8]; board.setdefault("board_id", "board")
        self.eff = core.effective_of(board); self.state = {a["id"]: {"status": "pending", "output": "", "tokens": 0, "failures": 0, "model": a.get("model") or core.DEFAULT_MODEL, "notes": []} for a in board["agents"]}
        self.actions = []; self.log = []; self.paid_stopped = False; self.queue = []; self.max_actions = int((board.get("settings") or {}).get("max_actions", 40))

    # ------------------------------------------------------------ helpers
    def _note(self, aid, msg): self.state[aid]["notes"].append(msg); self.log.append({"t": self.clock(), "agent": aid, "msg": msg})
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
            if not self.approve(a, f"paid run on {model}"): raise RunError("paid run was not approved")
        pids = self.plugins.licensed(e) if self.plugins else []
        if pids and kind in ("local", "account"):                      # plugin tools: only those the agent's License grants, through the guarded host
            tm = self.plugins.toolmap(pids)
            if tm:
                from . import agentloop as AL
                if kind == "local":
                    be = self.llm.backends[who]; proto, base, key = "openai", be.base + ("/v1" if be.kind == "ollama" else ""), ""
                else: acc = self.accounts[who]; proto, base, key = acc["protocol"], acc["base"], acc.get("key", "")
                if proto in ("openai", "anthropic"):
                    sk = self.plugins.skills_prompt(pids); tl = e.get("tools") or []; box = AL.ToolBox(Path(self.workdir or tempfile.mkdtemp(prefix="ordivyr-run-")), write="file_write" in tl and (e.get("permissions") or "read-only") != "read-only", web="http_api" in tl, ask=False, mcp=tm)
                    text, tk, used, _, _ = AL.run(proto, base, key, model, system + ("\n\n" + sk if sk else ""), prompt, box, http=self.http, token_budget=budget)
                    return text, tk, used
        if kind == "local":
            if not self.llm: raise RunError("no local LLM manager configured")
            text, tk, used = self.llm.chat(who, model, system, [{"role": "user", "text": prompt}], max_tokens=maxtok)
            return text, tk, used
        acc = self.accounts[who]; tools = [t for t in (e.get("tools") or [])]
        if self.workdir and acc.get("protocol") in ("openai", "anthropic") and any(t in ("file_write", "http_api") for t in tools):
            from . import agentloop as AL
            box = AL.ToolBox(Path(self.workdir), write="file_write" in tools and (e.get("permissions") or "read-only") != "read-only", web="http_api" in tools, ask=False)
            text, tk, used, _, _ = AL.run(acc["protocol"], acc["base"], acc.get("key", ""), model, system, prompt, box, http=self.http, token_budget=budget)
            return text, tk, used
        text, tk, used = PV.chat(acc["protocol"], acc["base"], acc.get("key", ""), model, system, [{"role": "user", "text": prompt}], http=self.http, max_tokens=maxtok)
        return text, tk, used

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

    # ------------------------------------------------------------ run
    def run(self):
        order, cyc = core.dependency_order(self.board)
        if cyc: raise RunError(f"delegation cycle among: {', '.join(cyc)}")
        errs = core.validate(self.board).get("errors", [])
        errs = [x for x in errs if "connected worker" not in x]
        if errs: raise RunError("; ".join(errs[:3]))
        if self.jev: self.jev.sync_agents(self.board)
        self.queue = list(order); started = self.clock()
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
            st["status"] = "running"
            try:
                text, tk, used = self._execute(aid)
                st.update(status="done", output=text, tokens=tk, model=used)
                e = self.eff(aid)
                if M.scopes(e, self.board.get("board_id"))["write"]:
                    ns = M.scopes(e, self.board.get("board_id"))["write"][-1]
                    self.mem.remember(e["name"], ns, f"{self.mission[:60]}", text[:1500])
                self._gambits(aid, "done")
            except Exception as ex:                                            # any single-agent failure is contained and recorded
                st["failures"] += 1; st.update(status="failed", output=f"{type(ex).__name__}: {str(ex)[:300]}"); self._gambits(aid, "failed")
            if self.jev:
                try: self.jev.record(self.run_id, self.board["board_id"], aid, f"{a['name']}: {self.mission[:80]}", {"done": "done", "failed": "failed"}.get(st["status"], "queued"), {"tokens": st["tokens"]}, st["output"] if st["status"] == "failed" else None)
                except Exception as ex: self._note(aid, f"jev record failed: {ex}")
        stat = [s["status"] for s in self.state.values()]
        status = "done" if all(s in ("done", "skipped") for s in stat) else "failed" if all(s in ("failed", "blocked", "skipped") for s in stat) else "partial"
        return {"run_id": self.run_id, "status": status, "seconds": round(self.clock() - started, 3), "agents": self.state, "actions": self.actions, "log": self.log}
