"""Operations layer for Board: per-org secrets (AES-GCM, tenant-bound AAD), hosted worker lifecycle (provision -> supervise -> health -> recover -> deprovision), health reports, manual retry, Prometheus metrics.

Hosted worker = a dedicated, org-bound, SANDBOXED worker process that Board supervises on its own host. Customer code runs inside bwrap (see sandbox.py); the worker process (trusted) holds the org's model keys,
which are materialised from the vault into a private gateway home at spawn time and never enter the sandbox. Supervision is lease-based so several Board processes can run it and a dead supervisor is replaced.
"""
from __future__ import annotations
import ipaddress, json, os, re, secrets, shutil, signal, socket, subprocess, sys, time
from pathlib import Path
from urllib.parse import urlparse
from .errors import Invalid, NotFound, Forbidden, Conflict, QuotaError, Unavailable
from .vault import VaultError

NAME = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
MAX_SECRET_BYTES, MAX_SECRETS = 8192, 200
ONLINE_S, STARTUP_GRACE_S, LEASE_S = 30.0, 20.0, 15.0
RESTART_WINDOW_S, RESTART_MAX = 600.0, 5


def _pdeathsig():
    try:
        import ctypes; ctypes.CDLL("libc.so.6").prctl(1, signal.SIGKILL)                  # PR_SET_PDEATHSIG: if the supervising Board process dies (even kill -9) its workers die with it
    except Exception: pass
    os.setsid()


def _public_host(host):
    """SSRF guard for customer-supplied model endpoints: every address the name resolves to must be globally routable."""
    try: infos = socket.getaddrinfo(host, None)
    except OSError: raise Invalid("endpoint host does not resolve")
    for i in infos:
        ip = ipaddress.ip_address(i[4][0].split("%")[0])
        if not ip.is_global: raise Invalid("endpoint resolves to a non-public address (private, loopback, link-local or reserved): refused")


class OpsMixin:
    allow_local_endpoints = os.environ.get("BOARD_ALLOW_LOCAL_ENDPOINTS") == "1"        # DEV/DEMO ONLY: lets hosted workers use loopback model endpoints (a customer endpoint must be a public https host)
    isolation_strict = os.environ.get("BOARD_ISOLATION_STRICT") == "1"      # workers refuse to run tenant code unless seccomp + cgroups are really applied
    worker_launcher = json.loads(os.environ["BOARD_WORKER_LAUNCHER"]) if os.environ.get("BOARD_WORKER_LAUNCHER") else None   # command prefix list (root deployments: per-tenant OS uid)
    lease_url = None                                   # set by `up` once the lease API is listening
    online_s, startup_grace_s, fleet_lease_s = ONLINE_S, STARTUP_GRACE_S, LEASE_S

    # ------------------------------------------------------------------ secrets
    @staticmethod
    def _saad(org, project, name): return f"secret|{org}|{project or ''}|{name}"

    def put_secret(self, p, name, value, project=None):
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot manage secrets")
        if not NAME.fullmatch(str(name or "")): raise Invalid("secret name must match [A-Za-z0-9_.:-]{1,64}")
        if not isinstance(value, str) or not value or len(value.encode()) > MAX_SECRET_BYTES: raise Invalid(f"secret value must be a non-empty string up to {MAX_SECRET_BYTES} bytes")
        if project is not None: self._scope(p, project, "admin")
        blob = self.vault.seal(value, self._saad(p.org, project, name)); now = self.clock()
        with self.db.xlock("secrets:" + p.org), self.db.tx() as c:
            ex = c.execute("SELECT version FROM secrets WHERE org=? AND project=? AND name=?", (p.org, project or "", name)).fetchone()
            if ex is None and c.execute("SELECT COUNT(*) FROM secrets WHERE org=?", (p.org,)).fetchone()[0] >= MAX_SECRETS: raise QuotaError("secret limit reached")
            if ex: c.execute("UPDATE secrets SET blob=?, version=version+1, updated=?, made_by=? WHERE org=? AND project=? AND name=?", (blob, now, p.actor, p.org, project or "", name))
            else: c.execute("INSERT INTO secrets(org,project,name,blob,version,created,updated,made_by) VALUES(?,?,?,?,?,?,?,?)", (p.org, project or "", name, blob, 1, now, now, p.actor))
            self.db.audit(p.actor, "secret.put", p.org, project, {"name": name, "version": (ex["version"] + 1) if ex else 1}, c)       # the VALUE is never logged
        return {"name": name, "project": project, "version": (ex["version"] + 1) if ex else 1}

    def secrets_list(self, p):
        self._need(p, "admin")
        return [dict(name=r["name"], project=r["project"] or None, version=r["version"], updated=r["updated"], by=r["made_by"]) for r in self.db.c().execute("SELECT * FROM secrets WHERE org=? ORDER BY project,name", (p.org,)).fetchall()]

    def delete_secret(self, p, name, project=None):
        self._need(p, "admin")
        with self.db.tx() as c:
            if not c.execute("DELETE FROM secrets WHERE org=? AND project=? AND name=?", (p.org, project or "", str(name))).rowcount: raise NotFound("secret")
            self.db.audit(p.actor, "secret.delete", p.org, project, {"name": name}, c)
        return {"deleted": name}

    def _secret_value(self, org, project, name):
        for pr in ([project] if project else []) + [""]:
            r = self.db.c().execute("SELECT blob FROM secrets WHERE org=? AND project=? AND name=?", (org, pr, name)).fetchone()
            if r:
                try: return self.vault.open(r["blob"], self._saad(org, pr or None, name)).decode()
                except VaultError: raise Unavailable("secret cannot be decrypted with the configured master key")
        return None

    def w_secret(self, tid, fence, name):
        """Fenced lease call for TRUSTED runtimes. The job's own agent spec must list the name in permissions.secrets: a shared worker can never fetch another org's (or an unlisted) secret."""
        row, spec = self._lease(tid, fence); allow = (spec["agent"].get("permissions") or {}).get("secrets") or []
        if name not in allow: raise PermissionError(f"tool_not_granted: secret {name!r} is not in this agent's permissions.secrets")
        v = self._secret_value(row["org"], row["project"], name)
        if v is None: raise NotFound("secret")
        with self.db.tx() as c: self.db.audit(f"job:{row['job_id']}", "secret.read", row["org"], row["project"], {"name": name}, c)
        return {"value": v}

    def rotate_master_key(self, p):
        """Platform operator: add a new master key and re-encrypt every sealed value (secrets, MFA seeds, hosted tokens) under it."""
        self._need(p, "platform"); kid = self.vault.rotate(); n = 0
        with self.db.tx() as c:
            for r in c.execute("SELECT * FROM secrets").fetchall(): c.execute("UPDATE secrets SET blob=? WHERE org=? AND project=? AND name=?", (self.vault.rewrap(r["blob"], self._saad(r["org"], r["project"] or None, r["name"])), r["org"], r["project"], r["name"])); n += 1
            for r in c.execute("SELECT id,mfa_secret FROM users WHERE mfa_secret IS NOT NULL").fetchall(): c.execute("UPDATE users SET mfa_secret=? WHERE id=?", (self.vault.rewrap(r["mfa_secret"], f"mfa|{r['id']}"), r["id"])); n += 1
            for r in c.execute("SELECT id,body FROM outbox WHERE body IS NOT NULL AND status IN ('queued','sending')").fetchall(): c.execute("UPDATE outbox SET body=? WHERE id=?", (self.vault.rewrap(r["body"], f"mail|{r['id']}"), r["id"])); n += 1
            for r in c.execute("SELECT id,token_blob FROM hosted WHERE token_blob IS NOT NULL").fetchall(): c.execute("UPDATE hosted SET token_blob=? WHERE id=?", (self.vault.rewrap(r["token_blob"], f"hosted|{r['id']}"), r["id"])); n += 1
            self.db.audit(p.actor, "vault.rotate", None, None, {"key": kid, "rewrapped": n}, c)
        return {"key": kid, "rewrapped": n}

    # ------------------------------------------------------------------ hosted workers: provision / control
    def _check_endpoint(self, cfg):
        base = str(cfg.get("base") or ""); u = urlparse(base)
        if self.allow_local_endpoints and u.hostname in ("127.0.0.1", "localhost", "::1"): return
        if u.scheme != "https" or not u.hostname or u.username or u.password: raise Invalid("model endpoints must be https URLs without embedded credentials")
        _public_host(u.hostname)

    def provision_worker(self, p, name, slots=2, project=None, endpoints=()):
        self._need(p, "admin")
        if p.project: raise Forbidden("project-scoped keys cannot provision workers")
        from . import sandbox as SB, runtime_adapter as RA
        if not SB.available(): raise Unavailable("hosted workers require a sandbox (bwrap) on this host")
        slots = int(slots)
        if not (1 <= slots <= 16): raise Invalid("slots must be 1..16")
        endpoints = [str(e) for e in endpoints or ()]
        for e in endpoints:
            if not NAME.fullmatch(e): raise Invalid("endpoint id invalid")
            raw = self._secret_value(p.org, project, "endpoint:" + e)
            if raw is None: raise Invalid(f"store a secret named 'endpoint:{e}' (JSON with base/key/provider/models) first")
            try: self._check_endpoint(json.loads(raw))
            except ValueError: raise Invalid(f"secret endpoint:{e} is not valid JSON")
        hid = "h-" + secrets.token_hex(5)
        reg = self.register_worker(p, "ordivyr", RA.capabilities(slots, tuple(endpoints), validators=True, isolation=SB.ISOLATION), project=project, node=f"hosted-{hid}")
        now = self.clock()
        with self.db.tx() as c:
            c.execute("INSERT INTO hosted(id,org,project,name,slots,endpoints,worker_id,token_blob,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (hid, p.org, project, str(name)[:60], slots, json.dumps(endpoints), reg["worker"], self.vault.seal(reg["token"], f"hosted|{hid}"), now, now))
            self.db.audit(p.actor, "hosted.provision", p.org, project, {"hosted": hid, "worker": reg["worker"], "slots": slots, "endpoints": endpoints}, c)
        return {"id": hid, "worker": reg["worker"], "state": "pending"}

    def _hosted(self, p, hid):
        self._need(p, "admin"); r = self.db.c().execute("SELECT * FROM hosted WHERE id=? AND org=? AND desired!='deleted'", (hid, p.org)).fetchone()
        if r is None: raise NotFound("hosted worker")
        return r

    def hosted_list(self, p):
        self._need(p, "admin", "member", "viewer"); now = self.clock(); out = []
        for r in self.db.c().execute("SELECT h.*, w.last_seen, w.drained FROM hosted h LEFT JOIN workers w ON w.id=h.worker_id WHERE h.org=? AND h.desired!='deleted' ORDER BY h.created", (p.org,)).fetchall():
            out.append(dict(id=r["id"], name=r["name"], project=r["project"], slots=r["slots"], endpoints=json.loads(r["endpoints"]), desired=r["desired"], state=r["state"], worker=r["worker_id"], restarts=r["restarts"],
                            last_exit=r["last_exit"], last_error=r["last_error"], last_start=r["last_start"], online=bool(r["last_seen"] and now - r["last_seen"] < self.online_s), drained=bool(r["drained"])))
        return out

    def _set_desired(self, p, hid, desired, extra="", audit=""):
        r = self._hosted(p, hid)
        with self.db.tx() as c:
            c.execute(f"UPDATE hosted SET desired=?, updated=?{extra} WHERE id=?", (desired, self.clock(), hid)); self.db.audit(p.actor, audit or f"hosted.{desired}", p.org, r["project"], {"hosted": hid}, c)
        return {"id": hid, "desired": desired}

    def stop_hosted(self, p, hid): return self._set_desired(p, hid, "stopped", "", "hosted.stop")
    def start_hosted(self, p, hid): return self._set_desired(p, hid, "running", ", state='pending', window_restarts=0, window_start=NULL, next_start=NULL, last_error=NULL", "hosted.start")

    def scale_hosted(self, p, hid, slots):
        r = self._hosted(p, hid); slots = int(slots)
        if not (1 <= slots <= 16): raise Invalid("slots must be 1..16")
        w = self._worker_row(r["worker_id"]); caps = json.loads(w["caps"]); caps["max_concurrency"] = slots
        with self.db.tx() as c:
            c.execute("UPDATE workers SET caps=? WHERE id=?", (json.dumps(caps, sort_keys=True), r["worker_id"])); c.execute("UPDATE hosted SET slots=?, updated=? WHERE id=?", (slots, self.clock(), hid)); self.db.audit(p.actor, "hosted.scale", p.org, r["project"], {"hosted": hid, "slots": slots}, c)
        self._kill(hid, "scale")                                                                                        # supervisor restarts it with the new slot count
        return {"id": hid, "slots": slots}

    def deprovision_hosted(self, p, hid):
        r = self._hosted(p, hid)
        with self.db.tx() as c:                                                                                         # the token dies NOW; the supervisor then stops the process and purges the workspace
            c.execute("UPDATE workers SET revoked=? WHERE id=?", (self.clock(), r["worker_id"])); c.execute("UPDATE keys SET revoked=? WHERE kid=(SELECT kid FROM workers WHERE id=?) AND revoked IS NULL", (self.clock(), r["worker_id"]))
            c.execute("UPDATE hosted SET desired='deleted', updated=? WHERE id=?", (self.clock(), hid)); self.db.audit(p.actor, "hosted.deprovision", p.org, r["project"], {"hosted": hid, "worker": r["worker_id"]}, c)
        self._fleet_converge(hid); return {"id": hid, "deleted": True}

    # ------------------------------------------------------------------ the supervisor (lease-based; any number of Board processes may run fleet_tick)
    def _fleet_dir(self, hid): return self.home / "fleet" / hid
    def _procs_map(self):
        if not hasattr(self, "_procs"): self._procs = {}
        return self._procs

    def _kill(self, hid, why):
        pr = self._procs_map().pop(hid, None)
        if pr is not None and pr.poll() is None:
            try: os.killpg(pr.pid, signal.SIGTERM)
            except OSError: pass
            try: pr.wait(8)
            except subprocess.TimeoutExpired:
                try: os.killpg(pr.pid, signal.SIGKILL)
                except OSError: pass
                pr.wait(5)
        return pr.returncode if pr is not None else None

    def _spawn(self, r):
        hid = r["id"]; d = self._fleet_dir(hid); (d / "ws").mkdir(parents=True, exist_ok=True); (d / "home").mkdir(exist_ok=True); gwd = d / "gw"
        shutil.rmtree(gwd, ignore_errors=True); gwd.mkdir(mode=0o700)
        from ..selfhost.gateway import Gateway
        gw = Gateway(gwd)
        for e in json.loads(r["endpoints"]):
            raw = self._secret_value(r["org"], r["project"], "endpoint:" + e)
            if raw is None: raise Unavailable(f"secret endpoint:{e} is missing")
            cfg = json.loads(raw); self._check_endpoint(cfg)
            gw.add_endpoint(e, provider=cfg.get("provider", "custom"), base=cfg["base"], protocol=cfg.get("protocol", "openai"), key=cfg.get("key"), models=cfg.get("models"), local=bool(self.allow_local_endpoints and cfg.get("local")))
            gw.authorize(e, float(cfg.get("daily_usd", 5)), float(cfg.get("total_usd", 50)))
        tf = d / "token"; fd = os.open(tf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, self.vault.open(r["token_blob"], f"hosted|{hid}")); os.close(fd)
        root = str(Path(__file__).resolve().parents[2]); env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "HOME": str(d / "home"), "ORDIVYR_GATEWAY_HOME": str(gwd), "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")}
        log = open(d / "worker.log", "ab")                                                                              # NOT inherited: Board's DSN, master key and tokens never reach the worker's environment
        argv = [sys.executable, "-m", "ordivyr.board.worker", "--url", self.lease_url, "--token-file", str(tf), "--name", hid, "--ws", str(d / "ws"), "--ttl", str(int(os.environ.get("BOARD_WORKER_TTL", "20"))), "--slots", str(r["slots"]), "--sandbox"]
        if self.isolation_strict: env["ORDIVYR_ISOLATION_STRICT"] = "1"
        pre = [_pdeathsig]; launcher = self.worker_launcher
        if launcher: argv = list(launcher) + argv                                                                       # root deployments: sudo -n systemd-run -p DynamicUser=yes ... (distinct OS uid per worker)
        else:
            from . import isolate as I
            cg = self._cgroups()
            if cg.ok:                                                                                                   # the whole worker tree (and every sandbox it spawns) lives under these limits
                I.Cgroups.destroy(os.path.join(cg.base, f"hosted-{hid}"))                                               # a previous incarnation's leftovers die first
                path = cg.make(f"hosted-{hid}", mem_mb=int(r["slots"]) * 1536 + 512, tasks=int(r["slots"]) * 192 + 64); pre.append(I.Cgroups.enter(cg.leaf(path)))
            elif self.isolation_strict: raise Unavailable(f"hosted workers need cgroup v2 limits in strict isolation mode ({cg.why})")
        return subprocess.Popen(argv, env=env, cwd=root, stdout=log, stderr=log, stdin=subprocess.DEVNULL, preexec_fn=lambda: [f() for f in pre])

    def _cgroups(self):
        if getattr(self, "_cg", None) is None:
            from . import isolate as I
            self._cg = I.Cgroups()
        return self._cg

    def _fleet_converge(self, hid):
        r = self.db.c().execute("SELECT * FROM hosted WHERE id=?", (hid,)).fetchone()
        if r is None: return
        now = self.clock(); procs = self._procs_map(); pr = procs.get(hid)
        def upd(**kw):
            sets = ", ".join(f"{k}=?" for k in kw); 
            with self.db.tx() as c: c.execute(f"UPDATE hosted SET {sets}, updated=? WHERE id=?", (*kw.values(), now, hid))
        if r["desired"] == "deleted":
            self._kill(hid, "deleted")
            with self.db.tx() as c: c.execute("DELETE FROM hosted WHERE id=?", (hid,)); self.db.audit("fleet", "hosted.purged", r["org"], r["project"], {"hosted": hid}, c)
            shutil.rmtree(self._fleet_dir(hid), ignore_errors=True); return
        if r["desired"] == "stopped":
            if pr is not None: self._kill(hid, "stopped")
            if r["state"] != "stopped": upd(state="stopped", pid=None)
            return
        if pr is not None and pr.poll() is None:                                                                         # alive: check it is actually serving
            w = self._worker_row(r["worker_id"]); seen = (w["last_seen"] or 0) if w else 0
            if now - (r["last_start"] or now) > self.startup_grace_s and now - seen > self.online_s:
                self._kill(hid, "unhealthy"); self._alert(r["org"], "hosted_unhealthy", {"hosted": hid, "silent_s": round(now - seen)}); upd(state="backoff", last_exit="killed: unresponsive", pid=None, next_start=now + 2)
            elif r["state"] != "running" and seen >= (r["last_start"] or 0): upd(state="running", pid=pr.pid)
            return
        if pr is not None:                                                                                              # it died: count it against the restart window
            procs.pop(hid, None); ws = r["window_start"]; wr = r["window_restarts"]
            if not ws or now - ws > RESTART_WINDOW_S: ws, wr = now, 0
            wr += 1
            if wr > RESTART_MAX:
                upd(state="failed", pid=None, restarts=r["restarts"] + 1, last_exit=f"exit {pr.returncode}", window_start=ws, window_restarts=wr, last_error="restart limit reached: fix the cause, then start it again"); self._alert(r["org"], "hosted_failed", {"hosted": hid}); return
            upd(state="backoff", pid=None, restarts=r["restarts"] + 1, last_exit=f"exit {pr.returncode}", window_start=ws, window_restarts=wr, next_start=now + min(60, 2 ** wr)); return
        if r["state"] == "failed" or (r["next_start"] and now < r["next_start"]): return
        ws, wr = r["window_start"], r["window_restarts"]
        try:
            procs[hid] = np_ = self._spawn(r)
            upd(state="starting", pid=np_.pid, host=socket.gethostname(), last_start=now, last_error=None, next_start=None)
        except Exception as e:
            if not ws or now - ws > RESTART_WINDOW_S: ws, wr = now, 0
            wr += 1; bad = wr > RESTART_MAX
            err = f"{type(e).__name__}: {e}"
            if bad: self._alert(r["org"], "hosted_failed", {"hosted": hid, "error": err[:120]}); err = "restart limit reached (" + err[:120] + "): fix the cause, then start it again"
            upd(state="failed" if bad else "backoff", last_error=err[:240], window_start=ws, window_restarts=wr, next_start=now + min(60, 2 ** wr))

    def _alert(self, org, kind, detail):
        with self.db.tx() as c: c.execute("INSERT INTO alerts(ts,org,kind,detail) VALUES(?,?,?,?)", (self.clock(), org, kind, json.dumps(detail)))

    def fleet_tick(self):
        if not self.lease_url: return {}
        owner = getattr(self, "_fleet_owner", None) or f"{socket.gethostname()}:{os.getpid()}:{id(self)}"; self._fleet_owner = owner; now = self.clock(); n = 0
        for r in self.db.c().execute("SELECT id FROM hosted WHERE lease_owner IS NULL OR lease_owner=? OR lease_until<?", (owner, now)).fetchall():
            with self.db.tx() as c: got = c.execute("UPDATE hosted SET lease_owner=?, lease_until=? WHERE id=? AND (lease_owner IS NULL OR lease_owner=? OR lease_until<?)", (owner, now + self.fleet_lease_s, r["id"], owner, now)).rowcount
            if got: self._fleet_converge(r["id"]); n += 1
        return {"supervised": n}

    def fleet_shutdown(self):
        for hid in list(self._procs_map()): self._kill(hid, "shutdown")
        with self.db.tx() as c: c.execute("UPDATE hosted SET lease_owner=NULL, lease_until=NULL WHERE lease_owner=?", (getattr(self, "_fleet_owner", ""),))

    # ------------------------------------------------------------------ health, retry, metrics
    def health_of(self, p):
        self._need(p, "admin", "member", "viewer"); now = self.clock(); c = self.db.c()
        workers = [dict(id=r["id"], node=r["node"], project=r["project"], online=bool(r["last_seen"] and now - r["last_seen"] < self.online_s), last_seen=r["last_seen"], drained=bool(r["drained"]), revoked=bool(r["revoked"]))
                   for r in c.execute("SELECT * FROM workers WHERE org=? AND revoked IS NULL", (p.org,)).fetchall()]
        queue = {}
        for r in c.execute("SELECT id FROM projects WHERE org=? AND status!='deleted'", (p.org,)).fetchall():
            from .service import tenant_of
            cn = self.store.counts_for(tenant_of(p.org, r["id"])); queue[r["id"]] = {"queued": cn.get("queued", 0), "running": sum(cn.get(s, 0) for s in ("claimed", "running", "validating")), "failed": cn.get("failed", 0), "needs_approval": cn.get("needs_approval", 0)}
        online = sum(w["online"] for w in workers); backlog = sum(q["queued"] for q in queue.values())
        status = "ok" if online or not backlog else "degraded: work is queued but no worker is online"
        return {"status": status, "workers": workers, "hosted": self.hosted_list(p), "queue": queue, "alerts": [a for a in self.alerts_of(p) if not a["acked"]][:20]}

    def retry_job(self, p, project, job_id):
        self._scope(p, project, "write"); r = self._row(p.org, project, job_id); v = self.job_view(r)
        if v["status"] not in ("failed", "cancelled"): raise Conflict("only failed or cancelled jobs can be retried")
        spec = json.loads(r["spec"]); a = self.agent(p.org, project, spec["agent"]["id"]) if spec["agent"]["id"] != "inline" else {"id": "inline", "name": spec["agent"].get("name"), "system": spec["agent"].get("system", ""), "tools": spec["agent"].get("tools"), "permissions": spec["agent"].get("permissions") or {}}
        if spec["agent"]["id"] == "inline" and p.role != "admin": raise Forbidden("retrying an inline-agent job needs an org admin")
        return self._submit(p.org, project, a, spec["prompt"], r["engine"], spec.get("limits"), spec.get("model_ref"), f"retry:{job_id}:{secrets.token_hex(4)}", p.actor, "retry", None, (spec.get("workspace") or {}).get("name"), spec.get("validators") if p.role == "admin" else None)

    def metrics_text(self):
        """Prometheus exposition. Aggregates only: no org names, no ids, no tenant data."""
        now = self.clock(); c = self.db.c(); L = []
        def g(name, help_, rows):
            L.append(f"# HELP {name} {help_}"); L.append(f"# TYPE {name} gauge")
            for lab, v in rows: L.append(f"{name}{lab} {v}")
        g("board_up", "1 if the Board process is serving", [("", 1)]); g("board_killed", "1 if the operator kill switch is on", [("", 1 if self.killed else 0)])
        g("board_queue_tasks", "tasks by state across all tenants", [(f'{{state="{k}"}}', v) for k, v in sorted(self.store.counts().items())])
        g("board_workers_online", "workers seen in the last 30s", [("", c.execute("SELECT COUNT(*) FROM workers WHERE revoked IS NULL AND last_seen>?", (now - self.online_s,)).fetchone()[0])])
        g("board_workers_registered", "non-revoked workers", [("", c.execute("SELECT COUNT(*) FROM workers WHERE revoked IS NULL").fetchone()[0])])
        g("board_hosted_workers", "hosted workers by state", [(f'{{state="{r[0]}"}}', r[1]) for r in c.execute("SELECT state, COUNT(*) FROM hosted GROUP BY state").fetchall()] or [('{state="none"}', 0)])
        g("board_orgs", "orgs by status", [(f'{{status="{r[0]}"}}', r[1]) for r in c.execute("SELECT status, COUNT(*) FROM orgs GROUP BY status").fetchall()] or [('{status="none"}', 0)])
        g("board_audit_rows", "audit chain length", [("", c.execute("SELECT COUNT(*) FROM audit").fetchone()[0])]); g("board_schema_version", "applied schema version", [("", self.db.schema_version())])
        g("board_db_backend", "database backend", [(f'{{backend="{self.db.backend}"}}', 1)])
        g("board_http_requests_total", "API requests by status class", [(f'{{class="{k}"}}', v) for k, v in sorted(getattr(self, "http_counts", {}).items())] or [('{class="none"}', 0)])
        g("board_outbox", "email outbox by status", [(f'{{status="{r[0]}"}}', r[1]) for r in c.execute("SELECT status, COUNT(*) FROM outbox GROUP BY status").fetchall()] or [('{status="none"}', 0)])
        g("board_reservations_open", "open spend/compute reservations (jobs in flight)", [("", c.execute("SELECT COUNT(*) FROM reservations WHERE released IS NULL").fetchone()[0])])
        g("board_hosted_restarts_total", "supervisor restarts of hosted workers (sum)", [("", c.execute("SELECT COALESCE(SUM(restarts),0) FROM hosted").fetchone()[0])])
        g("board_oldest_queued_seconds", "age of the oldest queued task (0 if none)", [("", round(max(0.0, now - (self.store.oldest_queued() or now)), 1))])
        g("board_accounts_throttled", "account/network throttle rows currently blocking", [("", c.execute("SELECT COUNT(*) FROM auth_throttle WHERE locked_until>?", (now,)).fetchone()[0])])
        g("board_loop_error", "1 if the background loop recorded an error", [("", 1 if self.db.meta("last_loop_error") else 0)])
        return "\n".join(L) + "\n"
