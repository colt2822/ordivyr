"""Per-job phase timeline (the data behind the dashboard waterfall), derived from the durable event log. Pure: no I/O.
Phases: queued (waiting for a worker, a retry, or an approval to be granted), running ("model + tools": there are no per-model-call timestamps, so this is NOT split further),
validating, held (waiting for a human). Segments are contiguous and ordered; a live job's last segment is open and ends at `now`."""
TERMINAL = ("commit", "failed", "cancelled")
REQUEUE = ("attempt_failed", "released", "lease_expired")


def segments(created, events, now):
    """-> {"segments": [{"phase","start","end","attempt","open"}], "purged": bool}. events = [{"ts","kind","detail"}] oldest first (detail already decoded or None)."""
    if not events: return {"segments": [], "purged": True}
    segs = []; cur = {"phase": "queued", "start": float(created), "attempt": 1, "spec": False}
    def close(ts):
        nonlocal cur
        if cur is None: return
        end = max(float(ts), cur["start"])
        if not (cur["spec"] and end - cur["start"] < 0.005): segs.append({"phase": cur["phase"], "start": cur["start"], "end": end, "attempt": cur["attempt"], "open": False})
        cur = None
    def open_(phase, ts, attempt, spec=False):
        nonlocal cur
        cur = {"phase": phase, "start": float(ts), "attempt": attempt, "spec": spec}
    for e in events:
        k, ts, d = e["kind"], e["ts"], e.get("detail") or {}
        if cur is None: break
        att = cur["attempt"]
        if k == "claimed": close(ts); open_("running", ts, int(d.get("attempt") or att))
        elif k == "state":
            ph = d.get("state")
            if ph == "validating" and cur["phase"] != "validating": close(ts); open_("validating", ts, att)
            elif ph == "running" and cur["phase"] not in ("running",): close(ts); open_("running", ts, att)
        elif k == "needs_approval": close(ts); open_("held", ts, att)
        elif k == "approved": close(ts); open_("queued", ts, att)
        elif k in REQUEUE: close(ts); open_("queued", ts, att + 1, spec=True)
        elif k in TERMINAL: close(ts)
    if cur is not None: segs.append({"phase": cur["phase"], "start": cur["start"], "end": max(float(now), cur["start"]), "attempt": cur["attempt"], "open": True})
    return {"segments": segs, "purged": False}
