"""BYO-key spending controls: a tenant gateway budget (USD) enforced at the single admission choke point (`Board._admit`), plus alerts.

No subscriptions, invoices, payment processing or entitlement checks exist here. Money is only ever *your own provider keys' cost*, tracked from the
`meter` table (kind='cost_usd', exactly-once rows) plus in-flight reservations, so a budget cannot be overshot by concurrent work.
"""
from __future__ import annotations
import calendar, json, time
from .errors import Invalid, QuotaError


def period_of(now):
    """Calendar-month UTC period [start, end) used for budget accounting."""
    t = time.gmtime(now); s = calendar.timegm((t.tm_year, t.tm_mon, 1, 0, 0, 0)); y, m = (t.tm_year + (t.tm_mon == 12), 1 if t.tm_mon == 12 else t.tm_mon + 1)
    return s, calendar.timegm((y, m, 1, 0, 0, 0))


class SpendingMixin:
    def _usage_in(self, c, org, start, end):
        r = c.execute("SELECT COALESCE(SUM(qty),0) FROM meter WHERE org=? AND kind IN ('jobs_completed','jobs_failed') AND ts>=? AND ts<?", (org, start, end)).fetchone()[0]
        s = c.execute("SELECT COALESCE(SUM(qty),0) FROM meter WHERE org=? AND kind='wall_seconds' AND ts>=? AND ts<?", (org, start, end)).fetchone()[0]
        return int(r), float(s)

    def set_spend_limit(self, p, gateway_budget_usd=None):
        self._need(p, "admin")
        if gateway_budget_usd is not None and (not isinstance(gateway_budget_usd, (int, float)) or isinstance(gateway_budget_usd, bool) or not 0 <= gateway_budget_usd < float("inf") or gateway_budget_usd > 100000):
            raise Invalid("gateway_budget_usd must be finite non-negative dollars")
        with self.db.tx() as c:
            c.execute("DELETE FROM spend_limits WHERE org=?", (p.org,))
            c.execute("INSERT INTO spend_limits(org,soft_cents,hard_cents,gateway_budget_usd) VALUES(?,?,?,?)", (p.org, None, None, gateway_budget_usd))
            self.db.audit(p.actor, "spending.limit", p.org, None, {"gateway_budget_usd": gateway_budget_usd}, c)
        return {"gateway_budget_usd": gateway_budget_usd}

    def _spending_gate(self, c, org, project, reserve=(0.0, 0.0)):
        """Registered in Board._gates: refuse NEW work when metered cost + in-flight reservations + this job's reservation would exceed the tenant budget."""
        lim = c.execute("SELECT gateway_budget_usd FROM spend_limits WHERE org=?", (org,)).fetchone()
        if not lim or lim["gateway_budget_usd"] is None: return
        ps, _ = period_of(self.clock())
        actual = c.execute("SELECT COALESCE(SUM(qty),0) FROM meter WHERE org=? AND kind='cost_usd' AND ts>=?", (org, ps)).fetchone()[0]
        if actual + self._reserved(c, org)[1] + reserve[1] > lim["gateway_budget_usd"] + 1e-9:
            raise QuotaError("tenant gateway spending budget exhausted", billing="gateway_budget")

    def spending_state(self, p):
        self._need(p, "admin", "member", "viewer"); ps, pe = period_of(self.clock()); c = self.db.c()
        lim = c.execute("SELECT gateway_budget_usd FROM spend_limits WHERE org=?", (p.org,)).fetchone()
        jobs, cs = self._usage_in(c, p.org, ps, pe)
        cost = c.execute("SELECT COALESCE(SUM(qty),0) FROM meter WHERE org=? AND kind='cost_usd' AND ts>=?", (p.org, ps)).fetchone()[0]
        return {"period": {"start": ps, "end": pe}, "usage": {"jobs": jobs, "compute_min": round(cs / 60, 2), "provider_cost_usd": round(float(cost), 6)},
                "limits": {"gateway_budget_usd": lim["gateway_budget_usd"] if lim else None}}

    def alerts_of(self, p):
        self._need(p, "admin", "member", "viewer")
        return [dict(id=r["id"], ts=r["ts"], kind=r["kind"], detail=json.loads(r["detail"] or "{}"), acked=r["acked"]) for r in self.db.c().execute("SELECT * FROM alerts WHERE org=? ORDER BY id DESC LIMIT 100", (p.org,)).fetchall()]

    def billing_tick(self, now=None): return {}      # retained no-op hook name: background loops call every *_tick
