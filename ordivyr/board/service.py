"""BoardService: the orchestration layer. Composes the existing durable queue (`ordivyr.durable.Store`) with the Board registry (`db.py`).

Mapping: org + project -> store tenant "org:project" (':' is illegal in ids), so the queue's existing fairness, quotas, idempotency scoping and tenant-bound claiming
are the isolation primitives. Board adds the registry, authorisation, agents, delegation, memory, schedules, metering, audit and operational controls on top.
It never executes a job; a runtime does, through the contract (`contract.py`).
"""
from __future__ import annotations
import hashlib, json, os, re, secrets, time
from dataclasses import dataclass
from pathlib import Path
from .. import durable as D, schedule as SCH
from . import contract as C
from .db import DB, h as _h
from .vault import Vault
from .accounts import AccountsMixin
from .spending import SpendingMixin
from .ops import OpsMixin
from .mailer import MailMixin
from .reliability import ReliabilityMixin

class _Strict:
    """A compiled pattern whose fullmatch() is False (not TypeError) for non-strings: identifiers arrive from JSON, where a number, list or object is a caller mistake, not a server error."""
    def __init__(self, rx): self.rx = re.compile(rx)
    def fullmatch(self, s): return self.rx.fullmatch(s) if isinstance(s, str) else None
    def __getattr__(self, n): return getattr(self.rx, n)


ID = _Strict(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
ACTIVE_STATES = ("claimed", "running", "validating")
PLANS = {   # quota profiles (not prices): nothing here charges anyone. `max_active/max_queued` are PER PROJECT (queue tenant); the rest are per org.
    "free": {"max_active": 2, "max_queued": 50, "max_projects": 3, "monthly_jobs": 200, "max_depth": 2, "max_fanout": 3, "max_descendants": 10, "max_workers": 1},
    "team": {"max_active": 16, "max_queued": 2000, "max_projects": 25, "monthly_jobs": 20000, "max_depth": 3, "max_fanout": 8, "max_descendants": 100, "max_workers": 20},
    "scale": {"max_active": 128, "max_queued": 20000, "max_projects": 250, "monthly_jobs": 500000, "max_depth": 4, "max_fanout": 16, "max_descendants": 1000, "max_workers": 200},
}
AGENT_KEYS = {"name", "system", "tools", "permissions", "model_ref", "limits", "engine", "description"}
PERM_KEYS = {"write", "web", "terminal", "delegate", "memory", "secrets", "approve"}
MEM_MAX_VALUE, MEM_MAX_ENTRIES = 16_384, 5000
_TASK_UNSET = object()


from .errors import BoardError, NotFound, Forbidden, Invalid, Conflict, QuotaError, Unavailable


@dataclass(frozen=True)
class P:
    role: str; org: str | None; project: str | None; kid: str; user: str | None = None
    @property
    def actor(self): return f"{self.role}:{self.kid}"


def tenant_of(org, project): return f"{org}:{project}"
def _j(x): return json.dumps(x, sort_keys=True, default=str)


def _month_start(now):
    import calendar; t = time.gmtime(now); return calendar.timegm((t.tm_year, t.tm_mon, 1, 0, 0, 0))


DEFAULT_JOB_SECONDS, MAX_JOB_SECONDS = 1800.0, 3600.0


class Board(AccountsMixin, SpendingMixin, OpsMixin, MailMixin, ReliabilityMixin):
    def __init__(self, home, store=None, clock=time.time, dsn=None):
        self.home = Path(home); self.home.mkdir(parents=True, exist_ok=True); self.clock = clock; dsn = dsn or os.environ.get("BOARD_PG_DSN") or None
        if dsn and store is None:
            from ..hosting.pgstore import PgStore
            store = PgStore(dsn)
        self.db = DB(None if dsn else self.home / "board.db", clock, dsn=dsn); self.vault = Vault(self.home / "master.key"); self.store = store or D.Store(self.home / "queue.db"); self._gates = [self._spending_gate]; self.allow_unsandboxed_pool = False      # dev only: lets a shared pool worker run tenant code without a sandbox

    # ------------------------------------------------------------------ identity
    def init_platform(self):
        """First start: mint the platform operator token into <home>/platform.token (0600). Never regenerated, never logged."""
        f = self.home / "platform.token"
        if f.exists(): return None
        tok, kid = self.db.issue_key("platform", None, None, "platform operator", actor="init"); f.write_text(tok); f.chmod(0o600); return tok

    def principal(self, token):
        if str(token).startswith("ords_"): return self._session_principal(token)
        r = self.db.key_of(token)
        if r is None: return None
        self._touch_key(r)
        if r["org"]:
            o = self.db.c().execute("SELECT status FROM orgs WHERE id=?", (r["org"],)).fetchone()
            if o is None or o["status"] != "active": return None
        return P(r["role"], r["org"], r["project"], r["kid"])

    @property
    def killed(self): return self.db.meta("killed") == "1"

    # ------------------------------------------------------------------ platform / org administration
    def _need(self, p, *roles):
        if p.role not in roles: raise Forbidden(f"requires role {'/'.join(roles)}")

    def create_org(self, p, org, name="", plan="free", admin_label="owner"):
        self._need(p, "platform")
        if not ID.fullmatch(org or ""): raise Invalid("org id must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
        if plan not in PLANS: raise Invalid(f"plan must be one of {sorted(PLANS)}")
        with self.db.tx() as c:
            if c.execute("SELECT 1 FROM orgs WHERE id=?", (org,)).fetchone(): raise Conflict("org exists")
            c.execute("INSERT INTO orgs(id,name,plan,created) VALUES(?,?,?,?)", (org, name[:120], plan, self.clock()))
            self.db.audit(p.actor, "org.create", org, None, {"plan": plan}, c)
            tok, kid = self.db.issue_key("admin", org, None, admin_label, actor=p.actor, c=c)
        return {"org": org, "plan": plan, "admin_key": tok, "kid": kid}

    def set_plan(self, p, org, plan):
        self._need(p, "platform")
        if plan not in PLANS: raise Invalid("unknown plan")
        with self.db.tx() as c:
            if not c.execute("UPDATE orgs SET plan=? WHERE id=?", (plan, org)).rowcount: raise NotFound("org")
            self.db.audit(p.actor, "org.plan", org, None, {"plan": plan}, c)
        for r in self.db.c().execute("SELECT id,status FROM projects WHERE org=?", (org,)).fetchall(): self._apply_limits(org, r["id"], r["status"] == "paused")
        return {"org": org, "plan": plan}

    def set_org_status(self, p, org, status):
        self._need(p, "platform")
        if status not in ("active", "suspended"): raise Invalid("status")
        with self.db.tx() as c:
            if not c.execute("UPDATE orgs SET status=? WHERE id=?", (status, org)).rowcount: raise NotFound("org")
            self.db.audit(p.actor, "org." + status, org, None, {}, c)
        if status == "suspended":
            for r in self.db.c().execute("SELECT tid FROM jobs WHERE org=? AND tid IS NOT NULL", (org,)).fetchall(): self.store.cancel(r["tid"])
        return {"org": org, "status": status}

    def _org(self, org):
        r = self.db.c().execute("SELECT * FROM orgs WHERE id=?", (org,)).fetchone()
        if r is None or r["status"] != "active": raise NotFound("org")
        return r

    def plan_of(self, org): return PLANS[self._org(org)["plan"]]

    def _apply_limits(self, org, project, paused=False):
        pl = PLANS[self.db.c().execute("SELECT plan FROM orgs WHERE id=?", (org,)).fetchone()["plan"]]
        self.store.tenant_set(tenant_of(org, project), 1.0, 0 if paused else pl["max_active"], pl["max_queued"])

    def create_project(self, p, project, budget_usd=None):
        self._need(p, "admin")
        if not ID.fullmatch(project or ""): raise Invalid("project id invalid")
        if p.project: raise Forbidden("project-scoped keys cannot create projects")
        pl = self.plan_of(p.org)
        with self.db.xlock("org:" + p.org), self.db.tx() as c:
            if c.execute("SELECT 1 FROM projects WHERE org=? AND id=?", (p.org, project)).fetchone(): raise Conflict("project exists")
            if c.execute("SELECT COUNT(*) FROM projects WHERE org=? AND status!='deleted'", (p.org,)).fetchone()[0] >= pl["max_projects"]: raise QuotaError("project limit for this plan reached")
            c.execute("INSERT INTO projects(org,id,budget_usd,created) VALUES(?,?,?,?)", (p.org, project, budget_usd, self.clock())); self.db.audit(p.actor, "project.create", p.org, project, {"budget_usd": budget_usd}, c)
        self._apply_limits(p.org, project); return {"org": p.org, "project": project}

    def projects(self, p):
        self._need(p, "admin", "member", "viewer")
        q = "SELECT id,status,budget_usd,created FROM projects WHERE org=? AND status!='deleted'" + (" AND id=?" if p.project else "")
        return [dict(r) for r in self.db.c().execute(q + " ORDER BY id", (p.org, p.project) if p.project else (p.org,))]

    def _scope(self, p, project, need="read"):
        """Authorise `p` for `project`; returns the project row. need: read | write | admin. Out-of-scope == not found (never reveals that another tenant's object exists)."""
        if p.role == "platform": raise Forbidden("platform keys administer orgs; they do not read customer data")
        if p.role == "worker" or not p.org: raise Forbidden("this key cannot use the Board API")
        if p.project and p.project != project: raise NotFound("project")
        r = self.db.c().execute("SELECT * FROM projects WHERE org=? AND id=? AND status!='deleted'", (p.org, project)).fetchone()
        if r is None: raise NotFound("project")
        ok = {"admin": ("admin",), "write": ("admin", "member"), "read": ("admin", "member", "viewer")}[need]
        if p.role not in ok: raise Forbidden(f"role {p.role} cannot {need}")
        return r

    def issue_key(self, p, role, project=None, label="", ttl_s=None):
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot issue keys")
        if role not in ("admin", "member", "viewer"): raise Invalid("role must be admin|member|viewer (worker keys come from register_worker)")
        if project is not None: self._scope(p, project, "admin")
        if role == "admin" and project is not None: raise Invalid("admin keys are org-wide")
        tok, kid = self.db.issue_key(role, p.org, project, label, ttl_s, actor=p.actor); return {"key": tok, "kid": kid, "role": role, "project": project}

    def revoke_key(self, p, kid):
        self._need(p, "admin")
        if not self.db.revoke_key(kid, p.actor, org=p.org): raise NotFound("key")
        return {"revoked": kid}

    # ------------------------------------------------------------------ agents and teams (agents are DATA: no keys, no URLs)
    def _clean_agent(self, spec):
        if not isinstance(spec, dict): raise Invalid("agent spec must be an object")
        bad = set(spec) - AGENT_KEYS
        if bad: raise Invalid(f"unknown agent fields {sorted(bad)}")
        a = {k: spec[k] for k in AGENT_KEYS if k in spec}
        for k, t in (("limits", dict), ("model_ref", dict), ("system", str)):                    # JSON types are the caller's input: a number where an object belongs is a 422, not a crash
            if a.get(k) is not None and not isinstance(a[k], t): raise Invalid(f"agent {k} must be {'an object' if t is dict else 'a string'}")
        if a.get("tools") is not None and not (isinstance(a["tools"], list) and all(isinstance(x, str) for x in a["tools"])): raise Invalid("agent tools must be a list of tool names")
        perms = a.get("permissions") or {}
        if not isinstance(perms, dict) or set(perms) - PERM_KEYS: raise Invalid(f"permissions may only use {sorted(PERM_KEYS)}")
        if perms.get("memory", "none") not in ("none", "read", "write"): raise Invalid("permissions.memory is none|read|write")
        d = perms.get("delegate", False)
        if not (isinstance(d, bool) or (isinstance(d, list) and all(isinstance(x, str) for x in d))): raise Invalid("permissions.delegate is bool or a list of agent ids")
        sc = perms.get("secrets", [])
        if not (isinstance(sc, list) and len(sc) <= 20 and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", x) for x in sc)): raise Invalid("permissions.secrets is a list of up to 20 secret NAMES")
        ap = perms.get("approve", [])
        from . import gate as G
        if not (isinstance(ap, list) and all(isinstance(x, str) and x in G.GATEABLE for x in ap)): raise Invalid(f"permissions.approve is a list drawn from {sorted(G.GATEABLE)}")
        a["permissions"] = perms; a.setdefault("engine", "ordivyr")
        if ap and a["engine"] != "ordivyr": raise Invalid("permissions.approve is only enforced by the ordivyr engine")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,31}", str(a["engine"])): raise Invalid("engine id invalid")
        probe = {"contract_version": C.CONTRACT_VERSION, "job_id": "probe", "org": "probe", "project": "probe", "prompt": "x", "agent": {"id": "probe", **{k: a[k] for k in ("system", "tools", "permissions") if k in a}},
                 "model_ref": a.get("model_ref"), "limits": a.get("limits") or {}}
        if a.get("model_ref") is None: probe.pop("model_ref")
        bad = C.validate_job(probe)
        if bad: raise Invalid("; ".join(bad))
        return a

    def define_agent(self, p, project, agent_id, spec):
        self._scope(p, project, "admin")          # an agent definition is a grant of capability (write/shell/delegate): org admins only; members merely submit jobs to it
        if not ID.fullmatch(agent_id or ""): raise Invalid("agent id invalid")
        a = self._clean_agent(spec); now = self.clock()
        with self.db.tx() as c:
            r = c.execute("SELECT version FROM agents WHERE org=? AND project=? AND id=?", (p.org, project, agent_id)).fetchone()
            if r: c.execute("UPDATE agents SET spec=?, version=version+1, updated=? WHERE org=? AND project=? AND id=?", (_j(a), now, p.org, project, agent_id)); v = r["version"] + 1
            else: c.execute("INSERT INTO agents(org,project,id,spec,created,updated) VALUES(?,?,?,?,?,?)", (p.org, project, agent_id, _j(a), now, now)); v = 1
            self.db.audit(p.actor, "agent.define", p.org, project, {"agent": agent_id, "version": v, "permissions": a["permissions"], "tools": a.get("tools")}, c)
        return {"id": agent_id, "version": v}

    def agent(self, org, project, agent_id):
        r = self.db.c().execute("SELECT * FROM agents WHERE org=? AND project=? AND id=?", (org, project, agent_id)).fetchone()
        if r is None: raise NotFound("agent")
        return {"id": r["id"], "version": r["version"], **json.loads(r["spec"])}

    def agents(self, p, project):
        self._scope(p, project, "read")
        return [{"id": r["id"], "version": r["version"], **json.loads(r["spec"])} for r in self.db.c().execute("SELECT * FROM agents WHERE org=? AND project=? ORDER BY id", (p.org, project))]

    def define_team(self, p, project, team_id, lead, members):
        """A team = a lead agent + the agents it may delegate to. Defining it sets the lead's `permissions.delegate` allow-list to the members (explicit authority, audited)."""
        self._scope(p, project, "admin")
        if not ID.fullmatch(team_id or ""): raise Invalid("team id invalid")
        if not isinstance(lead, str) or not (members is None or isinstance(members, list)) or not all(isinstance(m, str) for m in (members or [])):
            raise Invalid("lead must be an agent id and members a list of agent ids")
        members = list(dict.fromkeys(members or []))
        for m in [lead, *members]: self.agent(p.org, project, m)
        if lead in members: raise Invalid("lead cannot be its own member")
        with self.db.tx() as c:
            c.execute("INSERT INTO teams(org,project,id,spec,created) VALUES(?,?,?,?,?) ON CONFLICT(org,project,id) DO UPDATE SET spec=excluded.spec", (p.org, project, team_id, _j({"lead": lead, "members": members}), self.clock()))
            r = c.execute("SELECT spec FROM agents WHERE org=? AND project=? AND id=?", (p.org, project, lead)).fetchone(); a = json.loads(r["spec"]); a["permissions"] = {**a.get("permissions", {}), "delegate": members}
            c.execute("UPDATE agents SET spec=?, version=version+1, updated=? WHERE org=? AND project=? AND id=?", (_j(a), self.clock(), p.org, project, lead))
            self.db.audit(p.actor, "team.define", p.org, project, {"team": team_id, "lead": lead, "members": members}, c)
        return {"team": team_id, "lead": lead, "members": members}

    def teams(self, p, project):
        self._scope(p, project, "read")
        return [{"id": r["id"], **json.loads(r["spec"])} for r in self.db.c().execute("SELECT * FROM teams WHERE org=? AND project=?", (p.org, project))]

    # ------------------------------------------------------------------ workers (local and remote runtimes)
    def register_worker(self, p, engine, caps, project=None, node=None, platform=False):
        """Customer: org admin registers a worker bound to ITS org (optionally one project). Platform operator (`platform=True`) registers a shared pool worker (org=None)."""
        if platform: self._need(p, "platform"); org = None; project = None
        else:
            self._need(p, "admin")
            if p.project: raise Forbidden("project-scoped keys cannot register workers")
            org = p.org
            if project is not None: self._scope(p, project, "admin")
            self.plan_of(org)
        caps = dict(caps or {}); caps.setdefault("engine", engine)
        bad = C.validate_capabilities(caps)
        if platform and caps.get("isolation", "process") == "process" and not self.allow_unsandboxed_pool: raise Forbidden("shared pool workers must declare a sandbox isolation level (namespace|container|microvm): tenant code may not run unsandboxed on shared infrastructure")
        if bad or caps["engine"] != engine: raise Invalid("; ".join(bad) or "capabilities.engine must equal engine")
        wid = "w-" + secrets.token_hex(5)
        with self.db.xlock("org:" + (org or "~pool~")), self.db.tx() as c:
            if org and c.execute("SELECT COUNT(*) FROM workers WHERE org=? AND revoked IS NULL", (org,)).fetchone()[0] >= self.plan_of(org)["max_workers"]: raise QuotaError("worker limit for this plan reached")
            tok, kid = self.db.issue_key("worker", org, project, f"worker {wid}", actor=p.actor, c=c)
            c.execute("INSERT INTO workers(id,org,project,engine,caps,kid,node,registered) VALUES(?,?,?,?,?,?,?,?)", (wid, org, project, engine, _j(caps), kid, node, self.clock()))
            self.db.audit(p.actor, "worker.register", org, project, {"worker": wid, "engine": engine, "node": node, "pool": platform}, c)
        return {"worker": wid, "token": tok, "engine": engine, "kinds": [f"board.{engine}"]}

    def claim_kinds(self, pr):
        """Queue kinds this worker may claim, from what it REGISTERED (never from what it asks for)."""
        from . import gate as G
        r = self._worker_row(pr["wid"]); kinds = [f"board.{pr['engine']}"]
        if r is not None and pr["engine"] == "ordivyr" and G.FEATURE in (json.loads(r["caps"]).get("features") or ()): kinds.append(f"board.{pr['engine']}.gated")
        return kinds

    def _worker_row(self, wid): return self.db.c().execute("SELECT * FROM workers WHERE id=?", (wid,)).fetchone()

    def workers(self, p):
        self._need(p, "admin", "member", "viewer")
        out = []
        for r in self.db.c().execute("SELECT * FROM workers WHERE org=? ORDER BY registered", (p.org,)):
            out.append({"id": r["id"], "engine": r["engine"], "project": r["project"], "node": r["node"], "last_seen": r["last_seen"], "drained": bool(r["drained"]), "revoked": bool(r["revoked"]), "caps": json.loads(r["caps"])})
        return out

    def _worker_admin(self, p, wid):
        self._need(p, "admin", "platform")
        r = self._worker_row(wid)
        if r is None or (p.role == "admin" and r["org"] != p.org): raise NotFound("worker")
        return r

    def drain_worker(self, p, wid, on=True):
        r = self._worker_admin(p, wid)
        with self.db.tx() as c: c.execute("UPDATE workers SET drained=? WHERE id=?", (1 if on else 0, wid)); self.db.audit(p.actor, "worker.drain" if on else "worker.undrain", r["org"], r["project"], {"worker": wid}, c)
        return {"worker": wid, "drained": on}

    def revoke_worker(self, p, wid):
        r = self._worker_admin(p, wid)
        with self.db.tx() as c:
            c.execute("UPDATE workers SET revoked=? WHERE id=?", (self.clock(), wid)); c.execute("UPDATE keys SET revoked=? WHERE kid=? AND revoked IS NULL", (self.clock(), r["kid"]))
            self.db.audit(p.actor, "worker.revoke", r["org"], r["project"], {"worker": wid}, c)
        return {"worker": wid, "revoked": True}

    def worker_principal(self, token):
        """For the lease API: -> dict for a live worker key or None. Looked up on every RPC (revocation, org suspension and drain take effect immediately)."""
        k = self.db.key_of(token)
        if k is None or k["role"] != "worker": return None
        if k["org"]:
            o = self.db.c().execute("SELECT status FROM orgs WHERE id=?", (k["org"],)).fetchone()
            if o is None or o["status"] != "active": return None
        w = self.db.c().execute("SELECT * FROM workers WHERE kid=? AND revoked IS NULL", (k["kid"],)).fetchone()
        return None if w is None else {"role": "worker", "wid": w["id"], "org": w["org"], "project": w["project"], "engine": w["engine"], "drained": bool(w["drained"]), "kid": k["kid"]}

    def tenants_for(self, wp):
        """Tenants a worker may serve. None = unrestricted (platform pool worker). [] is returned as a poison tenant: the queue treats an empty filter as 'all'."""
        if wp["org"] is None: return None
        if wp["project"]: ts = [tenant_of(wp["org"], wp["project"])]
        else: ts = [tenant_of(wp["org"], r["id"]) for r in self.db.c().execute("SELECT id FROM projects WHERE org=? AND status!='deleted'", (wp["org"],))]
        return ts or ["~no-projects~"]

    def note_worker_alive(self, wid, every=5.0):
        """Throttled liveness stamp for non-claim lease calls (one write per worker per `every` seconds)."""
        now = time.monotonic(); seen = self.__dict__.setdefault("_alive_at", {})
        if now - seen.get(wid, -1e9) >= every: seen[wid] = now; self.touch_worker(wid)

    def touch_worker(self, wid):
        with self.db.tx() as c: c.execute("UPDATE workers SET last_seen=? WHERE id=?", (self.clock(), wid))

    def _eligible(self, org, project, spec):
        """Is there a registered, non-revoked, non-drained worker that may run this job (engine, tools, endpoint)?"""
        for w in self.db.c().execute("SELECT * FROM workers WHERE engine=? AND revoked IS NULL AND drained=0 AND (org IS NULL OR org=?) AND (project IS NULL OR project=?)", (spec["engine"], org, project)):
            caps = json.loads(w["caps"])
            if w["org"] is None and caps.get("isolation", "process") == "process" and not self.allow_unsandboxed_pool: continue      # never place tenant work on an unsandboxed shared worker
            if not C.requirements_met(spec, caps): continue
            eps = caps.get("endpoints") or []
            if eps and spec.get("model_ref") and spec["model_ref"]["endpoint"] not in eps: continue
            return True
        return False

    # ------------------------------------------------------------------ jobs
    def _reserved(self, c, org, project=None):
        """(compute_s, cost_usd) held by admitted-but-unmetered jobs: the worst case of work already in flight."""
        q = "SELECT COALESCE(SUM(compute_s),0) AS cs, COALESCE(SUM(cost_usd),0) AS cu FROM reservations WHERE org=? AND released IS NULL"; a = [org]
        if project is not None: q += " AND project=?"; a.append(project)
        r = c.execute(q, a).fetchone(); return float(r["cs"]), float(r["cu"])

    def _admit(self, c, org, project, pl, pr, reserve=(0.0, 0.0)):
        """THE choke point for new work (user submit, delegation, schedule fire and webhook all pass through _submit). Runs inside the org lock + transaction.
        `reserve` = (compute_s, cost_usd) worst case of THIS job. Limits are enforced against metered usage + everything already reserved + this job, so concurrent in-flight work cannot overshoot a cap."""
        ms = _month_start(self.clock())
        if c.execute("SELECT COUNT(*) FROM jobs WHERE org=? AND created>=?", (org, ms)).fetchone()[0] >= pl["monthly_jobs"]: raise QuotaError("monthly job limit for this plan reached")
        if pr["budget_usd"] is not None:
            spent = c.execute("SELECT COALESCE(SUM(qty),0) FROM meter WHERE org=? AND project=? AND kind='cost_usd' AND ts>=?", (org, project, ms)).fetchone()[0]
            if spent + self._reserved(c, org, project)[1] + reserve[1] > pr["budget_usd"] + 1e-9: raise QuotaError("project monthly budget exhausted (including spend reserved by jobs in flight)")
        for g in getattr(self, "_gates", []): g(c, org, project, reserve)           # spending-limit gates register here (external policy can append more)

    def _month_jobs(self, org): return self.db.c().execute("SELECT COUNT(*) FROM jobs WHERE org=? AND created>=?", (org, _month_start(self.clock()))).fetchone()[0]

    def _month_cost(self, org, project):
        r = self.db.c().execute("SELECT COALESCE(SUM(qty),0) FROM meter WHERE org=? AND project=? AND kind='cost_usd' AND ts>=?", (org, project, _month_start(self.clock()))).fetchone(); return r[0]

    def submit_job(self, p, project, prompt, agent_id=None, agent=None, engine=None, limits=None, model_ref=None, idem_key=None, workspace=None, validators=None, priority=0):
        self._scope(p, project, "write")
        if validators and p.role != "admin": raise Forbidden("validators run commands on the worker host: org admins only")
        if agent is not None and p.role != "admin": raise Forbidden("inline agents grant capability: org admins only (members submit to a defined agent)")
        if (agent_id is None) == (agent is None): raise Invalid("give exactly one of agent_id or an inline agent")
        a = self.agent(p.org, project, agent_id) if agent_id else {"id": "inline", **self._clean_agent(agent)}
        return self._submit(p.org, project, a, prompt, engine, limits, model_ref, idem_key, p.actor, "user", None, workspace, validators, priority)

    def _submit(self, org, project, a, prompt, engine, limits, model_ref, idem, actor, origin, parent, workspace=None, validators=None, priority=0):
        if self.killed: raise Unavailable("Board is stopped by the operator kill switch")
        o = self._org(org)
        pr = self.db.c().execute("SELECT * FROM projects WHERE org=? AND id=?", (org, project)).fetchone()
        if pr is None or pr["status"] == "deleted": raise NotFound("project")
        if pr["status"] == "paused": raise Conflict("project is paused")
        pl = PLANS[o["plan"]]; tenant = tenant_of(org, project)
        jid = "j-" + (hashlib.sha256(f"{tenant}\x1f{idem}".encode()).hexdigest()[:16] if idem else secrets.token_hex(8))
        ex = self.db.c().execute("SELECT * FROM jobs WHERE job_id=? AND org=? AND project=?", (jid, org, project)).fetchone()
        if ex: return self._redrive(ex) or self.job_view(ex)
        engine = engine or a.get("engine") or "ordivyr"
        lim = {**(a.get("limits") or {}), **(limits or {})}
        lim.pop("tenant_budget_usd", None)                                                        # this authority is derived from Board state, never caller input
        lim["max_seconds"] = min(float(lim.get("max_seconds") or DEFAULT_JOB_SECONDS), MAX_JOB_SECONDS)       # every job has a finite, platform-capped runtime: that is what makes the reservation a real bound
        spec = {"contract_version": C.CONTRACT_VERSION, "job_id": jid, "org": org, "project": project, "engine": engine,
                "agent": {"id": a["id"], "version": a.get("version"), "name": a.get("name", a["id"]), "system": a.get("system", ""), "tools": a.get("tools"), "permissions": a.get("permissions") or {}},
                "prompt": str(prompt or ""), "limits": lim, "labels": {"origin": origin}}
        if model_ref or a.get("model_ref"): spec["model_ref"] = model_ref or a["model_ref"]
        if workspace: spec["workspace"] = {"name": str(workspace)}
        if validators: spec["validators"] = validators
        if parent: spec["parent"] = {"job_id": parent["job_id"], "depth": parent["depth"] + 1}
        bad = C.validate_job(spec)
        if bad: raise Invalid("; ".join(bad))
        if "workspace" in spec and not ID.fullmatch(spec["workspace"]["name"]): raise Invalid("workspace name invalid")
        if not self._eligible(org, project, spec): raise Unavailable(f"no registered runtime can run engine {engine!r} with these tools/endpoint", engine=engine)
        root = parent["root"] if parent else jid; depth = parent["depth"] + 1 if parent else 0
        trace = (self.db.c().execute("SELECT trace FROM jobs WHERE job_id=?", (parent["job_id"],)).fetchone() or {"trace": None})["trace"] if parent else None
        trace = trace or self.current_trace() or self.new_trace(); spec["labels"]["trace_id"] = trace
        with self.db.xlock("org:" + org), self.db.tx() as c:                      # the Board row exists BEFORE the task; quota/budget/spend gates run under the org lock so concurrent processes cannot both pass them
            ex = c.execute("SELECT 1 FROM jobs WHERE job_id=?", (jid,)).fetchone()
            if not ex:
                provider_limit = c.execute("SELECT gateway_budget_usd FROM spend_limits WHERE org=?", (org,)).fetchone()
                tenant_caps = [float(pr["budget_usd"])] if pr["budget_usd"] is not None else []
                budget_left = []
                if pr["budget_usd"] is not None:
                    left = float(pr["budget_usd"]) - self._month_cost(org, project) - self._reserved(c, org, project)[1]
                    if left <= 1e-9: raise QuotaError("project monthly budget exhausted (including spend reserved by jobs in flight)")
                    budget_left.append(left)
                if provider_limit and provider_limit["gateway_budget_usd"] is not None:
                    cap = float(provider_limit["gateway_budget_usd"]); tenant_caps.append(cap)
                    month = _month_start(self.clock())
                    actual = c.execute("SELECT COALESCE(SUM(qty),0) FROM meter WHERE org=? AND kind='cost_usd' AND ts>=?", (org, month)).fetchone()[0]
                    left = cap - actual - self._reserved(c, org)[1]
                    if left <= 1e-9: raise QuotaError("tenant gateway budget exhausted (including spend reserved by jobs in flight)")
                    budget_left.append(left)
                if budget_left:
                    left = min(budget_left)
                    if lim.get("budget_usd") is None: lim["budget_usd"] = round(left, 6)
                    elif lim["budget_usd"] > left + 1e-9: raise QuotaError(f"tenant/project budget has ${left:.2f} unreserved; this job asks for ${lim['budget_usd']:.2f}")
                if tenant_caps: lim["tenant_budget_usd"] = min(tenant_caps)
                spec["limits"] = lim
                reserve = (float(lim["max_seconds"]), float(lim.get("budget_usd") or 0.0)); self._admit(c, org, project, pl, pr, reserve)
                c.execute("INSERT OR IGNORE INTO reservations(job_id,org,project,compute_s,cost_usd,created) VALUES(?,?,?,?,?,?)", (jid, org, project, reserve[0], reserve[1], self.clock()))
            c.execute("INSERT OR IGNORE INTO jobs(job_id,org,project,spec,prio,parent,root,depth,engine,agent_id,budget,origin,created,trace) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (jid, org, project, _j(spec), priority, parent["job_id"] if parent else None, root, depth, engine, a["id"], lim.get("budget_usd"), origin, self.clock(), trace))
            self.db.audit(actor, "job.submit", org, project, {"job": jid, "agent": a["id"], "engine": engine, "origin": origin, "parent": parent["job_id"] if parent else None}, c)
        row = self.db.c().execute("SELECT * FROM jobs WHERE job_id=?", (jid,)).fetchone()
        try: self._redrive(row, strict=True)
        except D.QuotaExceeded as e:
            with self.db.tx() as c: c.execute("DELETE FROM jobs WHERE job_id=? AND tid IS NULL", (jid,)); c.execute("DELETE FROM reservations WHERE job_id=?", (jid,))
            raise QuotaError(str(e))
        return self.job_view(self.db.c().execute("SELECT * FROM jobs WHERE job_id=?", (jid,)).fetchone())

    def _redrive(self, row, strict=False):
        """Make sure the Board row has its queue task (idempotent: the queue dedups on job_id within the tenant)."""
        if row["tid"] is not None: return None
        spec = json.loads(row["spec"])
        from . import gate as G
        try: tid = self.store.submit(G.queue_kind(row["engine"], spec), spec, idem_key=row["job_id"], max_attempts=3, priority=row["prio"], tenant=tenant_of(row["org"], row["project"]))
        except D.QuotaExceeded:
            if strict: raise
            return None
        with self.db.tx() as c: c.execute("UPDATE jobs SET tid=? WHERE job_id=? AND tid IS NULL", (tid, row["job_id"]))
        return self.job_view(self.db.c().execute("SELECT * FROM jobs WHERE job_id=?", (row["job_id"],)).fetchone())

    def _row(self, org, project, job_id):
        r = self.db.c().execute("SELECT * FROM jobs WHERE job_id=? AND org=? AND project=?", (str(job_id), org, project)).fetchone()
        if r is None: raise NotFound("job")
        return r

    def job_view(self, r, full=False, task=_TASK_UNSET):
        t = (self.store.get(r["tid"]) if r["tid"] is not None else None) if task is _TASK_UNSET else task
        st = {"queued": "queued", "claimed": "running", "running": "running", "validating": "running", "completed": "completed", "failed": "failed", "cancelled": "cancelled", "needs_approval": "held"}.get(t["state"] if t else "", "queued")
        v = {"job_id": r["job_id"], "trace": r["trace"], "project": r["project"], "status": st, "engine": r["engine"], "agent": r["agent_id"], "parent": r["parent"], "root": r["root"], "depth": r["depth"], "origin": r["origin"], "created": r["created"],
             "attempt": t["attempt"] if t else 0, "cancel_requested": bool(t and t["cancel_requested"]), "phase": t["phase"] if t else None}
        if t and st in ("failed", "held"): v["error"] = t["failure"]
        if t and st == "completed":
            v["result"] = t["result"]; res = t["result"] if isinstance(t["result"], dict) else {}
            v["ok"] = res.get("stop") == "done" and (res.get("completion") or {}).get("tests_passed") is not False      # `completed` = the runtime finished; `ok` = it finished the job, not merely hit a limit
        if full: v["spec"] = json.loads(r["spec"]); v["children"] = [x["job_id"] for x in self.db.c().execute("SELECT job_id FROM jobs WHERE parent=? ORDER BY created", (r["job_id"],))]
        return v

    def get_job(self, p, project, job_id):
        self._scope(p, project, "read"); return self.job_view(self._row(p.org, project, job_id), full=True)

    def list_jobs(self, p, project, status=None, limit=100):
        self._scope(p, project, "read")
        rows = self.db.c().execute("SELECT * FROM jobs WHERE org=? AND project=? ORDER BY created DESC, rowid DESC LIMIT ?", (p.org, project, max(1, min(int(limit), 500)))).fetchall()
        tasks = self.store.get_many(r["tid"] for r in rows if r["tid"] is not None)
        out = [self.job_view(r, task=tasks.get(r["tid"])) for r in rows]; return [j for j in out if not status or j["status"] == status]

    def job_events(self, p, project, job_id):
        self._scope(p, project, "read"); r = self._row(p.org, project, job_id)
        return [{"ts": e["ts"], "kind": e["kind"], "worker": e["worker"], "node": e["node"], "detail": json.loads(e["detail"]) if e["detail"] else None} for e in self.store.history(r["tid"])] if r["tid"] else []

    def job_stream(self, p, project, job_id, emit, alive=lambda: True, poll=0.5, max_s=300.0, after=0):
        """Live telemetry for one job: calls emit(event, data) for every new lifecycle event and tool/step output as it lands (polled from the durable store, so it works
        across processes), then a final `end` with the job view. Authorisation happens once, up front; the stream stops on a terminal status, a dead client or max_s."""
        self._scope(p, project, "read"); r = self._row(p.org, project, job_id); seen_ev = 0; t0 = time.monotonic(); last = None
        while alive() and time.monotonic() - t0 < max_s:
            r = self._row(p.org, project, job_id)                     # re-read: a job not yet dispatched has no task id when the stream opens
            v = self.job_view(r)                                      # status BEFORE events: whatever finished the job is then already readable below
            if r["tid"] is not None:
                ev = self.job_events(p, project, job_id)
                for e in ev[seen_ev:]: emit("event", e)
                seen_ev = len(ev)
                while True:                                           # drain fully, so the `end` event never cuts off a backlog
                    batch = self.store.task_outputs(r["tid"], after, 200)
                    for o in batch: after = max(after, o["id"]); emit("step", o)
                    if len(batch) < 200 or not alive(): break
            if v["status"] != last: last = v["status"]; emit("status", {"status": v["status"], "phase": v.get("phase"), "attempt": v.get("attempt")})
            if v["status"] in ("completed", "failed", "cancelled"): emit("end", v); return v
            time.sleep(poll)
        emit("end", {"status": last, "truncated": True}); return None

    def job_timings(self, p, project, job_id, cap=100):
        """Phase timeline for this job's whole delegation tree (same root), at most `cap` jobs. One history query per job, on demand only (never inside job_view/list_jobs)."""
        from . import timings as TM
        self._scope(p, project, "read"); r = self._row(p.org, project, job_id); now = self.clock()
        rows = self.db.c().execute("SELECT * FROM jobs WHERE org=? AND project=? AND root=? ORDER BY created, rowid LIMIT ?", (p.org, project, r["root"], cap)).fetchall()
        tasks = self.store.get_many(x["tid"] for x in rows if x["tid"] is not None); out = []
        for x in rows:
            v = self.job_view(x, task=tasks.get(x["tid"])); seg = TM.segments(x["created"], [{"ts": e["ts"], "kind": e["kind"], "detail": json.loads(e["detail"]) if e["detail"] else None} for e in self.store.history(x["tid"])] if x["tid"] is not None else [], now)
            ots = getattr(self.store, "task_output_ts", None); ticks = ([] if x["tid"] is None else ots(x["tid"], 200) if ots else [o["ts"] for o in self.store.task_outputs(x["tid"], 0, 200)])
            out.append({"job_id": x["job_id"], "parent": x["parent"], "depth": x["depth"], "agent": x["agent_id"], "status": v["status"], "created": x["created"], "ticks": ticks, **seg})
        return {"root": r["root"], "jobs": out, "truncated": len(rows) >= cap and self.db.c().execute("SELECT COUNT(*) FROM jobs WHERE org=? AND project=? AND root=?", (p.org, project, r["root"])).fetchone()[0] > cap}

    def job_outputs(self, p, project, job_id, after=0, limit=100):
        self._scope(p, project, "read")
        row = self._row(p.org, project, job_id)
        return self.store.task_outputs(row["tid"], after, limit) if row["tid"] else []

    def cancel_job(self, p, project, job_id):
        self._scope(p, project, "write"); r = self._row(p.org, project, job_id); n = self._cancel_tree(r["job_id"]); self.db.audit(p.actor, "job.cancel", p.org, project, {"job": job_id, "cancelled": n}); return {"job_id": job_id, "cancelled": n}

    def approve_job(self, p, project, job_id, resolution="retry"):
        """A `held` job (needs_owner / cap_exceeded / ambiguous side effect) waits for a human. Org admins resolve it; the decision is audited."""
        self._scope(p, project, "admin"); r = self._row(p.org, project, job_id)
        if resolution not in ("retry", "skip"): raise Invalid("resolution is retry|skip")
        if not self.store.approve(r["tid"], resolution): raise Conflict("job is not held")
        self.db.audit(p.actor, "job.approve", p.org, project, {"job": job_id, "resolution": resolution}); return {"job_id": job_id, "approved": True}

    def _cancel_tree(self, job_id):
        n, todo = 0, [job_id]
        while todo:
            j = todo.pop()
            r = self.db.c().execute("SELECT tid FROM jobs WHERE job_id=?", (j,)).fetchone()
            if r and r["tid"] is not None and self.store.cancel(r["tid"]) in ("cancelled", "cancelling"): n += 1
            elif r and r["tid"] is None:
                with self.db.tx() as c:
                    deleted = c.execute("DELETE FROM jobs WHERE job_id=? AND tid IS NULL", (j,)).rowcount
                    if deleted: c.execute("UPDATE reservations SET released=? WHERE job_id=? AND released IS NULL", (self.clock(), j))
            todo += [x["job_id"] for x in self.db.c().execute("SELECT job_id FROM jobs WHERE parent=?", (j,))]
        return n

    # ------------------------------------------------------------------ worker-side (fenced) operations: delegation, children, memory
    def _lease(self, tid, fence):
        t = self.store.get(tid)
        if t is None or t["fence"] != fence or t["state"] not in ACTIVE_STATES: raise D.StaleLease(f"task {tid}: fence {fence} no longer holds the lease")
        r = self.db.c().execute("SELECT * FROM jobs WHERE tid=?", (tid,)).fetchone()
        if r is None: raise PermissionError("task is not a Board job")
        return r, json.loads(r["spec"])

    def w_gateway_spend(self, tid, fence, op, request_id="", amount_usd=0.0, usage=None):
        """Fenced, durable spend reservation for trusted gateway calls. Uncertain provider outcomes keep their reservation and hold job completion."""
        row, spec = self._lease(tid, fence)
        if op not in ("reserve", "settle", "uncertain", "failed", "summary"): raise Invalid("gateway spend operation")
        if op != "summary" and (not isinstance(request_id, str) or not request_id or len(request_id) > 96): raise Invalid("gateway request id")
        if not isinstance(amount_usd, (int, float)) or isinstance(amount_usd, bool) or not 0 <= amount_usd < float("inf"): raise Invalid("gateway amount must be finite non-negative dollars")
        u = usage or {}
        vals = {}
        for k in ("prompt_tokens", "completion_tokens", "cache_read_tokens", "cache_write_tokens"):
            v = u.get(k, 0)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0: raise Invalid(f"invalid gateway usage: {k}")
            vals[k] = v
        budget = (spec.get("limits") or {}).get("budget_usd")
        with self.db.xlock("org:" + row["org"]), self.db.tx() as c:
            if op == "summary":
                r = c.execute("SELECT COALESCE(SUM(CASE WHEN status='settled' THEN actual_usd ELSE 0 END),0) AS cost, COALESCE(SUM(CASE WHEN status IN ('reserved','uncertain') THEN reserved_usd ELSE 0 END),0) AS uncertain, COALESCE(SUM(prompt_tokens),0) AS prompt, COALESCE(SUM(completion_tokens),0) AS completion, COALESCE(SUM(cache_read_tokens),0) AS cache_read, COALESCE(SUM(cache_write_tokens),0) AS cache_write FROM gateway_calls WHERE job_id=?", (row["job_id"],)).fetchone()
                return {"cost_usd": float(r["cost"]), "uncertain_usd": float(r["uncertain"]), "prompt_tokens": int(r["prompt"]), "completion_tokens": int(r["completion"]), "cache_read_tokens": int(r["cache_read"]), "cache_write_tokens": int(r["cache_write"])}
            old = c.execute("SELECT * FROM gateway_calls WHERE job_id=? AND request_id=?", (row["job_id"], request_id)).fetchone()
            if op == "reserve":
                if old is not None: return {"status": old["status"], "reserved_usd": old["reserved_usd"]}
                if budget is None: raise QuotaError("paid gateway calls require an explicit or tenant-inherited job budget", billing="gateway_budget")
                used = c.execute("SELECT COALESCE(SUM(CASE WHEN status='settled' THEN actual_usd WHEN status IN ('reserved','uncertain') THEN reserved_usd ELSE 0 END),0) FROM gateway_calls WHERE job_id=?", (row["job_id"],)).fetchone()[0]
                if used + amount_usd > budget + 1e-12: raise QuotaError("job gateway budget is exhausted", billing="gateway_budget")
                now = self.clock()
                c.execute("INSERT INTO gateway_calls(job_id,request_id,org,project,reserved_usd,actual_usd,status,created,updated) VALUES(?,?,?,?,?,0,'reserved',?,?)", (row["job_id"], request_id, row["org"], row["project"], amount_usd, now, now))
                return {"status": "reserved", "reserved_usd": amount_usd}
            if old is None: raise NotFound("gateway reservation")
            if old["status"] in ("settled", "failed", "uncertain"): return {"status": old["status"], "replayed": True}
            now = self.clock()
            if op == "settle":
                c.execute("UPDATE gateway_calls SET actual_usd=?, status='settled', prompt_tokens=?, completion_tokens=?, cache_read_tokens=?, cache_write_tokens=?, updated=? WHERE job_id=? AND request_id=? AND status='reserved'", (amount_usd, vals["prompt_tokens"], vals["completion_tokens"], vals["cache_read_tokens"], vals["cache_write_tokens"], now, row["job_id"], request_id))
            elif op == "uncertain": c.execute("UPDATE gateway_calls SET status='uncertain', updated=? WHERE job_id=? AND request_id=? AND status='reserved'", (now, row["job_id"], request_id))
            else: c.execute("UPDATE gateway_calls SET reserved_usd=0, status='failed', updated=? WHERE job_id=? AND request_id=? AND status='reserved'", (now, row["job_id"], request_id))
            return {"status": op}

    @staticmethod
    def _escalates(parent_perms, child_perms):
        rank = {"none": 0, "read": 1, "write": 2}
        from . import gate as G
        if not G.gated({"agent": {"permissions": parent_perms}}) <= G.gated({"agent": {"permissions": child_perms}}): return True          # dropping an approval gate is gaining capability
        if child_perms.get("write") and not parent_perms.get("write"): return True
        if child_perms.get("web") and not parent_perms.get("web"): return True
        if child_perms.get("terminal", "none") not in ("none", None, False, "") and parent_perms.get("terminal", "none") in ("none", None, False, ""): return True
        if rank[child_perms.get("memory", "none")] > rank[parent_perms.get("memory", "none")]: return True
        if child_perms.get("delegate") and not parent_perms.get("delegate"): return True
        if not set(child_perms.get("secrets") or []).issubset(parent_perms.get("secrets") or []): return True
        return False

    def w_delegate(self, tid, fence, req):
        row, spec = self._lease(tid, fence)
        with self.db.xlock("root:" + row["root"]): return self._w_delegate(row, spec, req)

    def _w_delegate(self, row, spec, req):
        perms = spec["agent"].get("permissions") or {}; d = perms.get("delegate")
        if not d: raise PermissionError("tool_not_granted: delegate")
        org, project = row["org"], row["project"]          # ALWAYS the parent's: a runtime cannot choose another org or project
        pl = self.plan_of(org); target = str((req or {}).get("agent") or "")
        if isinstance(d, list) and target not in d: raise PermissionError(f"permission_denied: agent {target!r} is not in this agent's delegation list")
        prompt = str((req or {}).get("prompt") or "")
        fallback_key = hashlib.sha256((target + "\x1f" + prompt).encode()).hexdigest()[:16]          # computed outside the f-string: a backslash inside {} is a SyntaxError before Python 3.12
        idem = f"{row['job_id']}\x1e{(req or {}).get('key') or fallback_key}"
        jid = "j-" + hashlib.sha256(f"{tenant_of(org, project)}\x1f{idem}".encode()).hexdigest()[:16]
        ex = self.db.c().execute("SELECT * FROM jobs WHERE job_id=? AND org=? AND project=?", (jid, org, project)).fetchone()
        if ex: v = self.job_view(ex); return {"job_id": v["job_id"], "engine": v["engine"], "status": v["status"]}      # a retried delegate (e.g. after a crash) returns the SAME child, before any limit is re-checked
        if row["depth"] + 1 > pl["max_depth"]: raise QuotaError(f"delegation depth limit {pl['max_depth']} reached")
        c0 = self.db.c()
        if c0.execute("SELECT COUNT(*) FROM jobs WHERE parent=?", (row["job_id"],)).fetchone()[0] >= pl["max_fanout"]: raise QuotaError(f"fan-out limit {pl['max_fanout']} reached")
        if c0.execute("SELECT COUNT(*) FROM jobs WHERE root=? AND job_id!=?", (row["root"], row["root"])).fetchone()[0] >= pl["max_descendants"]: raise QuotaError(f"descendant limit {pl['max_descendants']} reached")
        a = self.agent(org, project, target)
        if d is True and self._escalates(perms, a.get("permissions") or {}): raise PermissionError("permission_denied: delegation may not escalate permissions (use an explicit team delegation list)")
        lim = dict((req or {}).get("limits") or {}); pb = row["budget"]
        if pb is not None:
            rem = pb - (c0.execute("SELECT COALESCE(SUM(budget),0) FROM jobs WHERE parent=?", (row["job_id"],)).fetchone()[0] or 0)
            slots = max(1, pl["max_fanout"] - c0.execute("SELECT COUNT(*) FROM jobs WHERE parent=?", (row["job_id"],)).fetchone()[0])
            want = lim.get("budget_usd", rem / slots)                      # unspecified = an equal share of what is left across the remaining fan-out slots, so one child cannot starve its siblings
            if rem <= 0 or want > rem + 1e-12: raise QuotaError(f"child budget exceeds the parent's remaining budget (${max(rem, 0):.4f})")
            lim["budget_usd"] = want
        eng = (req or {}).get("engine") or a.get("engine") or spec["engine"]
        parent = {"job_id": row["job_id"], "depth": row["depth"], "root": row["root"]}
        v = self._submit(org, project, a, prompt, eng, lim, None, idem, f"job:{row['job_id']}", "delegate", parent, spec.get("workspace", {}).get("name"))
        return {"job_id": v["job_id"], "engine": v["engine"], "status": v["status"]}

    def w_children(self, tid, fence):
        row, spec = self._lease(tid, fence)
        if not (spec["agent"].get("permissions") or {}).get("delegate"): raise PermissionError("tool_not_granted: child_results")
        kids = [self.job_view(r) for r in self.db.c().execute("SELECT * FROM jobs WHERE parent=? ORDER BY created, rowid", (row["job_id"],))]
        return {"children": [{"job_id": k["job_id"], "status": k["status"], "agent": k["agent"], "text": ((k.get("result") or {}).get("text") or "")[:4000], "error": k.get("error"),
                              "usage": (k.get("result") or {}).get("usage")} for k in kids], "all_done": all(k["status"] in ("completed", "failed", "cancelled") for k in kids)}

    def _mem_ns(self, spec, ns):
        ns = str(ns or "project")
        if ns == "project": return "project"
        if ns == "agent": return f"agent:{spec['agent']['id']}"                    # private: derived from the lease, never from the caller
        raise PermissionError("permission_denied: namespace must be 'project' or 'agent'")

    def w_memory(self, tid, fence, op, ns, key=None, value=None):
        row, spec = self._lease(tid, fence); mp = (spec["agent"].get("permissions") or {}).get("memory", "none"); ns = self._mem_ns(spec, ns)
        need = {"get": "read", "list": "read", "put": "write"}.get(op)
        if need is None: raise Invalid("op")
        if mp not in ("read", "write") or (need == "write" and mp != "write"): raise PermissionError(f"tool_not_granted: memory_{op}")
        return self._mem(row["org"], row["project"], op, ns, key, value, f"job:{row['job_id']}")

    def _mem(self, org, project, op, ns, key, value, by):
        c = self.db.c()
        if op == "list": return {"keys": [r["k"] for r in c.execute("SELECT k FROM memory WHERE org=? AND project=? AND ns=? ORDER BY k LIMIT 500", (org, project, ns))]}
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", str(key or "")): raise Invalid("memory key invalid")
        if op == "get":
            r = c.execute("SELECT v,ts,by FROM memory WHERE org=? AND project=? AND ns=? AND k=?", (org, project, ns, key)).fetchone()
            return {"found": r is not None, "value": json.loads(r["v"]) if r else None}
        v = _j(value)
        if len(v) > MEM_MAX_VALUE: raise Invalid(f"memory value over {MEM_MAX_VALUE} bytes")
        with self.db.tx() as cc:
            if not cc.execute("SELECT 1 FROM memory WHERE org=? AND project=? AND ns=? AND k=?", (org, project, ns, key)).fetchone() and cc.execute("SELECT COUNT(*) FROM memory WHERE org=? AND project=?", (org, project)).fetchone()[0] >= MEM_MAX_ENTRIES:
                raise QuotaError("project memory entry limit reached")
            cc.execute("INSERT INTO memory(org,project,ns,k,v,by,ts) VALUES(?,?,?,?,?,?,?) ON CONFLICT(org,project,ns,k) DO UPDATE SET v=excluded.v, by=excluded.by, ts=excluded.ts", (org, project, ns, key, v, by, self.clock()))
        return {"ok": True}

    def memory(self, p, project, op, ns, key=None, value=None):
        self._scope(p, project, "read" if op in ("get", "list") else "write")
        if not re.fullmatch(r"project|agent:[A-Za-z0-9_.-]{1,64}", str(ns)): raise Invalid("namespace must be 'project' or 'agent:<id>'")
        return self._mem(p.org, project, op, ns, key, value, p.actor)

    # ------------------------------------------------------------------ schedules and triggers
    def create_schedule(self, p, project, name, prompt, agent_id, every=None, max_per_day=6, webhook=False, engine=None, limits=None):
        self._scope(p, project, "write"); self.agent(p.org, project, agent_id)
        if not prompt: raise Invalid("prompt required")
        spec = {"enabled": True, "mission": (name or prompt)[:500], "max_per_day": max_per_day}
        if webhook:
            if every: raise Invalid("a webhook trigger has no repeat interval")
            spec["kind"] = "webhook"
        else:
            try: spec.update(SCH.parse(every))
            except ValueError as e: raise Invalid(str(e))
            spec = SCH.clean(spec) | {"kind": "timer", "last_run": self.clock()}          # the clock starts now; a missed window later is caught up with ONE run
        sid = "s-" + secrets.token_hex(5); tok = hh = None
        if webhook: tok, hh = SCH.new_token()
        with self.db.tx() as c:
            c.execute("INSERT INTO schedules(id,org,project,name,spec,job,hook_hash,created) VALUES(?,?,?,?,?,?,?,?)", (sid, p.org, project, name[:120], _j(spec), _j({"agent": agent_id, "prompt": prompt, "engine": engine, "limits": limits or {}}), hh, self.clock()))
            self.db.audit(p.actor, "schedule.create", p.org, project, {"schedule": sid, "every": every, "webhook": webhook, "agent": agent_id}, c)
        out = {"id": sid, "kind": spec["kind"]}
        if webhook: out["hook_path"] = f"/v1/hooks/{sid}/{tok}"; out["note"] = "shown once"
        else: out["describe"] = SCH.describe(spec)
        return out

    def schedules(self, p, project):
        self._scope(p, project, "read")
        return [{"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]), "runs": r["runs"], **{k: v for k, v in json.loads(r["spec"]).items() if k in ("kind", "every_min", "daily", "last_run", "max_per_day")}} for r in self.db.c().execute("SELECT * FROM schedules WHERE org=? AND project=?", (p.org, project))]

    def set_schedule(self, p, project, sid, enabled):
        self._scope(p, project, "write")
        with self.db.tx() as c:
            if not c.execute("UPDATE schedules SET enabled=? WHERE id=? AND org=? AND project=?", (1 if enabled else 0, sid, p.org, project)).rowcount: raise NotFound("schedule")
            self.db.audit(p.actor, "schedule.enable" if enabled else "schedule.disable", p.org, project, {"schedule": sid}, c)
        return {"id": sid, "enabled": enabled}

    def _fire(self, r, idem, actor, now):
        job = json.loads(r["job"]); a = self.agent(r["org"], r["project"], job["agent"])
        return self._submit(r["org"], r["project"], a, job["prompt"], job.get("engine"), job.get("limits"), None, f"sched:{r['id']}:{idem}", actor, "schedule", None)

    def tick(self, now=None):
        """Fire every due timer. Restart-safe and double-fire-safe: the queue task is submitted with idempotency key sched:<id>:<run#> BEFORE the schedule row advances, so a crash
        between the two re-submits the same key (a no-op) instead of firing twice. -> list of fired schedule ids."""
        now = now or self.clock(); fired = []
        if self.killed: return fired
        for r in self.db.c().execute("SELECT s.* FROM schedules s JOIN orgs o ON o.id=s.org AND o.status='active' JOIN projects pr ON pr.org=s.org AND pr.id=s.project AND pr.status='active' WHERE s.enabled=1").fetchall():
            spec = json.loads(r["spec"])
            if spec.get("kind") != "timer" or not SCH.due(spec, now): continue
            try: self._fire(r, r["runs"] + 1, f"schedule:{r['id']}", now)
            except BoardError as e:
                spec["last_error"] = str(e)[:200]; SCH.mark_run(spec, now)           # a refused fire (quota, no runtime) still consumes the slot: no hot retry loop
                with self.db.tx() as c: c.execute("UPDATE schedules SET spec=?, runs=runs+1 WHERE id=?", (_j(spec), r["id"])); self.db.audit(f"schedule:{r['id']}", "schedule.refused", r["org"], r["project"], {"schedule": r["id"], "why": str(e)[:200]}, c)
                continue
            SCH.mark_run(spec, now)
            with self.db.tx() as c: c.execute("UPDATE schedules SET spec=?, runs=runs+1 WHERE id=? AND runs=?", (_j(spec), r["id"], r["runs"])); self.db.audit(f"schedule:{r['id']}", "schedule.fire", r["org"], r["project"], {"schedule": r["id"], "run": r["runs"] + 1}, c)
            fired.append(r["id"])
        return fired

    def fire_hook(self, sid, token, idem=None, now=None):
        """Public webhook entry. The token is the only credential; a wrong token and an unknown id are indistinguishable (404)."""
        now = now or self.clock(); r = self.db.c().execute("SELECT * FROM schedules WHERE id=?", (str(sid),)).fetchone()
        if r is None or not SCH.check_token({"hash": r["hook_hash"]}, str(token)) or not r["enabled"]: raise NotFound("hook")
        with self.db.xlock("hook:" + r["id"]): return self._fire_hook(r["id"], idem, now)

    def _fire_hook(self, sid, idem, now):
        r = self.db.c().execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()                                  # re-read INSIDE the lock: the cooldown and daily counters live in this row
        spec = json.loads(r["spec"])
        if spec.get("kind") != "webhook": raise NotFound("hook")
        if spec.get("last_run") and now - spec["last_run"] < SCH.HOOK_COOLDOWN_S and not idem: raise QuotaError(f"hook cooldown {SCH.HOOK_COOLDOWN_S}s")
        if spec.get("day") == time.strftime("%Y-%m-%d", time.localtime(now)) and int(spec.get("runs_today") or 0) >= int(spec.get("max_per_day") or 6): raise QuotaError("hook daily limit reached")
        v = self._fire(r, idem or f"hook-{int(now * 1000)}", f"hook:{r['id']}", now)
        SCH.mark_run(spec, now)
        with self.db.tx() as c: c.execute("UPDATE schedules SET spec=?, runs=runs+1 WHERE id=?", (_j(spec), r["id"])); self.db.audit(f"hook:{r['id']}", "hook.fire", r["org"], r["project"], {"schedule": r["id"], "job": v["job_id"]}, c)
        return {"job_id": v["job_id"]}

    # ------------------------------------------------------------------ metering and background reconciliation
    def reconcile(self):
        """Idempotent housekeeping: re-drive half-submitted jobs, propagate cancellation to children, meter finished jobs exactly once, record queue reaping. Safe to call from any process."""
        out = {"redriven": 0, "metered": 0, "cancelled_children": 0}
        for r in self.db.c().execute("SELECT * FROM jobs WHERE tid IS NULL AND created<?", (self.clock() - 3,)).fetchall():
            if self._redrive(r): out["redriven"] += 1
        for r in self.db.c().execute("SELECT c.job_id, c.tid FROM jobs c JOIN jobs p ON p.job_id=c.parent WHERE c.tid IS NOT NULL").fetchall():
            pt = self.db.c().execute("SELECT tid FROM jobs WHERE job_id=(SELECT parent FROM jobs WHERE job_id=?)", (r["job_id"],)).fetchone()
            if pt and pt["tid"] is not None:
                ps = self.store.get(pt["tid"])["state"]
                if ps == "cancelled" and self.store.get(r["tid"])["state"] not in ("completed", "failed", "cancelled") and self.store.cancel(r["tid"]) in ("cancelled", "cancelling"): out["cancelled_children"] += 1
        for r in self.db.c().execute("SELECT * FROM jobs WHERE metered=0 AND tid IS NOT NULL").fetchall():
            t = self.store.get(r["tid"])
            if t is None or t["state"] not in ("completed", "failed", "cancelled"): continue
            q = {f"jobs_{t['state']}": 1.0}
            if t["state"] == "completed" and isinstance(t["result"], dict) and isinstance(t["result"].get("usage"), dict):
                u = t["result"]["usage"]; q.update({k: float(u.get(k) or 0) for k in C.USAGE_KEYS})
            with self.db.tx() as c:
                for k, v in q.items(): c.execute("INSERT OR IGNORE INTO meter(ts,org,project,job_id,kind,qty) VALUES(?,?,?,?,?,?)", (self.clock(), r["org"], r["project"], r["job_id"], k, v))
                c.execute("UPDATE jobs SET metered=1 WHERE job_id=?", (r["job_id"],)); c.execute("UPDATE reservations SET released=? WHERE job_id=? AND released IS NULL", (self.clock(), r["job_id"]))      # meter row and reservation swap atomically: never counted twice, never neither
            out["metered"] += 1
        return out

    def usage(self, p, project=None, since=0.0):
        self._need(p, "admin", "member", "viewer")
        if project: self._scope(p, project, "read")
        elif p.project: project = p.project
        q = "SELECT project, kind, SUM(qty) q FROM meter WHERE org=? AND ts>=?" + (" AND project=?" if project else "") + " GROUP BY project, kind"
        rows = self.db.c().execute(q, (p.org, since, *( [project] if project else [])))
        by = {}
        for r in rows: by.setdefault(r["project"], {})[r["kind"]] = r["q"]
        tot = {}
        for d in by.values():
            for k, v in d.items(): tot[k] = tot.get(k, 0) + v
        pl = PLANS[self._org(p.org)["plan"]]; return {"org": p.org, "plan": self._org(p.org)["plan"], "total": tot, "by_project": by, "limits": pl, "jobs_this_month": self._month_jobs(p.org)}

    # ------------------------------------------------------------------ operational controls and audit
    def pause_project(self, p, project, on=True):
        self._scope(p, project, "admin")
        with self.db.tx() as c: c.execute("UPDATE projects SET status=? WHERE org=? AND id=?", ("paused" if on else "active", p.org, project)); self.db.audit(p.actor, "project.pause" if on else "project.resume", p.org, project, {}, c)
        self._apply_limits(p.org, project, paused=on); return {"project": project, "status": "paused" if on else "active"}

    def kill(self, p, on=True):
        """Platform kill switch: refuse all submits/claims/fires; on=True also cancels every non-finished job. Reversible."""
        self._need(p, "platform"); self.db.meta("killed", "1" if on else "0"); n = 0
        if on:
            for r in self.db.c().execute("SELECT tid FROM jobs WHERE tid IS NOT NULL").fetchall():
                if self.store.cancel(r["tid"]) in ("cancelled", "cancelling"): n += 1
        self.db.audit(p.actor, "kill" if on else "unkill", None, None, {"cancelled": n}); return {"killed": on, "cancelled": n}

    def audit_export(self, p, after=0, limit=1000):
        self._need(p, "admin", "platform")
        rows = self.db.audit_rows(org=None if p.role == "platform" else p.org, after=after, limit=limit)
        ok, bad = self.db.verify_audit(); return {"chain_ok": ok, "first_bad": bad, "rows": rows}

    def start_loop(self, interval=1.0):
        """Background maintenance: fire due schedules, reap dead leases, reconcile (re-drive, cancel propagation, metering). Each step is idempotent, so several Board processes may run it."""
        import threading
        self._stop = threading.Event()
        def run():
            while not self._stop.wait(interval):
                for fn in (self.store.reap, self.tick, self.reconcile, self.billing_tick, self.fleet_tick, self.mail_tick, self.retention_tick):
                    try: fn()
                    except Exception as e: self.db.meta("last_loop_error", f"{fn.__name__}: {type(e).__name__}: {e}"[:300])
        self._loop = threading.Thread(target=run, daemon=True, name="board-loop"); self._loop.start(); return self

    def stop_loop(self):
        if getattr(self, "_stop", None): self._stop.set(); self._loop.join(5)
        try: self.reconcile()                  # final pass: a job that finished within the last tick is metered now, not left for the next start
        except Exception as e: self.errors.append(f"final reconcile: {type(e).__name__}") if hasattr(self, "errors") else None

    def health(self):
        return {"ok": True, "allow_unsandboxed_pool": self.allow_unsandboxed_pool, "killed": self.killed, "queue": self.store.counts(), "audit_chain_ok": self.db.verify_audit()[0]}
