"""Reliability and data lifecycle: request->job tracing, retention policies, tenant erasure, graceful stop.

Tracing: every API request carries a trace id (client `X-Trace-Id` if well-formed, else generated); jobs created under it store it (children inherit their parent's), so one id walks
request -> job -> delegated children -> queue events. Views are org-scoped: a trace id from another tenant resolves to nothing.
Retention (defaults, per-org override for jobs): finished jobs 90 d (task rows, events, outputs go with them); sessions/invites/mail 30 d after they stop mattering; acked alerts 90 d;
billing webhook ids 400 d (replay protection outlives any signature window). NEVER deleted: meter rows, invoices, refunds, subscriptions (financial record) and the hash-chained audit log.
"""
from __future__ import annotations
import json, re, secrets, threading
from .errors import Invalid, NotFound, Conflict

TRACE_RX = re.compile(r"[A-Za-z0-9_\-]{8,64}")
DEFAULT_JOB_DAYS, DAY = 90, 86400.0


class ReliabilityMixin:
    # ------------------------------------------------------------------ tracing
    def _trace_tl(self):
        tl = self.__dict__.get("_ttl")
        if tl is None: tl = self.__dict__.setdefault("_ttl", threading.local())
        return tl

    def set_trace(self, tid): self._trace_tl().t = tid if tid and TRACE_RX.fullmatch(tid) else None
    def current_trace(self): return getattr(self._trace_tl(), "t", None)
    @staticmethod
    def new_trace(): return "tr-" + secrets.token_hex(8)

    def trace_view(self, p, trace_id):
        self._need(p, "admin", "member", "viewer")
        if not TRACE_RX.fullmatch(str(trace_id or "")): raise NotFound("trace")
        q = "SELECT * FROM jobs WHERE trace=? AND org=?"; a = [trace_id, p.org]
        if p.project: q += " AND project=?"; a.append(p.project)
        rows = self.db.c().execute(q + " ORDER BY created", a).fetchall()
        if not rows: raise NotFound("trace")
        out = []
        for r in rows:
            t = self.store.get(r["tid"]) if r["tid"] is not None else None
            ev = [dict(ts=e["ts"], kind=e["kind"], worker=e.get("worker") if isinstance(e, dict) else e["worker"]) for e in (self.store.history(r["tid"]) if r["tid"] is not None else [])][:50]
            out.append({"job_id": r["job_id"], "project": r["project"], "parent": r["parent"], "depth": r["depth"], "agent": r["agent_id"], "origin": r["origin"], "created": r["created"], "state": t["state"] if t else "pending", "events": ev})
        return {"trace_id": trace_id, "jobs": out, "span_s": round(max([o["created"] for o in out] + [e["ts"] for o in out for e in o["events"]]) - out[0]["created"], 3)}

    # ------------------------------------------------------------------ retention
    def set_retention(self, p, job_days):
        self._need(p, "admin")
        if p.project: from .errors import Forbidden; raise Forbidden("project-scoped keys cannot change retention")
        if job_days is not None and (not isinstance(job_days, int) or isinstance(job_days, bool) or not 1 <= job_days <= 3650): raise Invalid("job_days must be an integer 1..3650 (or null for the default)")
        with self.db.tx() as c:
            c.execute("DELETE FROM retention WHERE org=?", (p.org,))
            if job_days is not None: c.execute("INSERT INTO retention(org, job_days) VALUES(?,?)", (p.org, job_days))
            self.db.audit(p.actor, "retention.set", p.org, None, {"job_days": job_days}, c)
        return {"job_days": job_days or DEFAULT_JOB_DAYS, "default": job_days is None}

    def retention_tick(self, now=None, batch=200):
        """Idempotent; any process. -> counts of what was removed."""
        now = now or self.clock(); out = {"jobs": 0, "sessions": 0, "invites": 0, "mail": 0, "alerts": 0, "billing_events": 0, "throttle": 0, "reservations": 0}
        with self.db.xlock("retention"):
            c0 = self.db.c()
            for o in c0.execute("SELECT id FROM orgs").fetchall():
                r = c0.execute("SELECT job_days FROM retention WHERE org=?", (o["id"],)).fetchone(); days = r["job_days"] if r else DEFAULT_JOB_DAYS
                rows = c0.execute("SELECT job_id, tid FROM jobs WHERE org=? AND metered=1 AND created<? ORDER BY created LIMIT ?", (o["id"], now - days * DAY, batch)).fetchall()
                for j in rows:
                    t = self.store.get(j["tid"]) if j["tid"] is not None else None
                    if t is not None and t["state"] not in ("completed", "failed", "cancelled"): continue                   # never delete live work
                    if t is not None and not self.store.purge([j["tid"]]): continue
                    with self.db.tx() as c: c.execute("DELETE FROM jobs WHERE job_id=?", (j["job_id"],)); c.execute("DELETE FROM reservations WHERE job_id=? AND released IS NOT NULL", (j["job_id"],)); out["jobs"] += 1
            with self.db.tx() as c:
                def d(sql, a, k): out[k] += c.execute(sql, a).rowcount or 0
                d("DELETE FROM sessions WHERE (revoked IS NOT NULL AND revoked<?) OR expires<?", (now - 30 * DAY, now - 30 * DAY), "sessions")
                d("DELETE FROM invites WHERE (used IS NOT NULL AND used<?) OR expires<?", (now - 30 * DAY, now - 30 * DAY), "invites")
                d("DELETE FROM outbox WHERE status IN ('sent','failed') AND created<?", (now - 30 * DAY,), "mail")
                d("DELETE FROM alerts WHERE acked IS NOT NULL AND acked<?", (now - 90 * DAY,), "alerts")
                d("DELETE FROM billing_events WHERE received<?", (now - 400 * DAY,), "billing_events")
                d("DELETE FROM auth_throttle WHERE COALESCE(last_ok,0)<? AND COALESCE(last_fail,0)<? AND (locked_until IS NULL OR locked_until<?)", (now - 30 * DAY, now - DAY, now), "throttle")
                d("DELETE FROM reservations WHERE released IS NOT NULL AND released<?", (now - 30 * DAY,), "reservations")
        return out

    # ------------------------------------------------------------------ erasure (customer deletion request)
    def erase_org(self, p, org, confirm):
        """Platform operator, irreversible. Removes every piece of customer content and access; keeps the financial record (meter, invoices, refunds, subscription) and the tamper-evident audit chain."""
        self._need(p, "platform")
        if confirm != org: raise Invalid("confirm must equal the org id")
        o = self.db.c().execute("SELECT * FROM orgs WHERE id=?", (org,)).fetchone()
        if o is None: raise NotFound("org")
        from .service import P
        counts = {}
        with self.db.xlock("org:" + org):
            with self.db.tx() as c: c.execute("UPDATE orgs SET status='deleted' WHERE id=?", (org,)); c.execute("UPDATE sessions SET revoked=COALESCE(revoked,?) WHERE org=?", (self.clock(), org)); c.execute("UPDATE keys SET revoked=COALESCE(revoked,?) WHERE org=?", (self.clock(), org)) if self._has_col("keys", "revoked") else None
            for h in self.db.c().execute("SELECT id FROM hosted WHERE org=?", (org,)).fetchall():
                try: self.deprovision_hosted(P("admin", org, None, "erase", "platform"), h["id"])
                except Exception: pass
            tids = []
            for j in self.db.c().execute("SELECT tid FROM jobs WHERE org=? AND tid IS NOT NULL", (org,)).fetchall():
                t = self.store.get(j["tid"])
                if t and t["state"] not in ("completed", "failed", "cancelled"): self.store.cancel(j["tid"]); t = self.store.get(j["tid"])
                if t and t["state"] in ("completed", "failed", "cancelled"): tids.append(j["tid"])
            counts["tasks"] = self.store.purge(tids)
            with self.db.tx() as c:
                uids = [r["user_id"] for r in c.execute("SELECT user_id FROM memberships WHERE org=?", (org,)).fetchall()]
                for t in ("jobs", "reservations", "agents", "teams", "schedules", "memory", "secrets", "hosted", "workers", "projects", "invites", "outbox", "sso_providers", "sso_nonces", "retention"):
                    try: counts[t] = c.execute(f"DELETE FROM {t} WHERE org=?" if t != "projects" else "DELETE FROM projects WHERE org=?", (org,)).rowcount
                    except Exception: pass
                c.execute("DELETE FROM memberships WHERE org=?", (org,))
                for uid in uids:
                    if not c.execute("SELECT 1 FROM memberships WHERE user_id=?", (uid,)).fetchone():                 # nowhere else to belong: anonymise the account itself
                        c.execute("UPDATE users SET status='deleted', email=?, pw_hash=NULL, mfa_secret=NULL, mfa_enabled=0, recovery=NULL WHERE id=?", (f"deleted-{uid}@invalid.local", uid)); c.execute("UPDATE sessions SET revoked=COALESCE(revoked,?) WHERE user_id=?", (self.clock(), uid)); c.execute("DELETE FROM auth_throttle WHERE user_id=?", (uid,))
                self.db.audit(p.actor, "org.erase", org, None, {"counts": counts}, c)
        return {"org": org, "erased": counts, "kept": ["meter", "invoices", "refunds", "subscription", "audit chain"]}

    def _has_col(self, table, col):
        try: self.db.c().execute(f"SELECT {col} FROM {table} LIMIT 1"); return True
        except Exception: return False
