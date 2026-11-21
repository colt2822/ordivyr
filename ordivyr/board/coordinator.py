"""Board's lease API: the existing Coordinator + Board-aware auth/scoping, and a facade over the queue that adds the fenced `board_*` operations.

What the facade adds on top of the plain lease API (all enforced SERVER-SIDE, so a customer-run worker cannot opt out):
  * auth against the live key table on every RPC (revoke / drain / org suspension are immediate);
  * claims are forced to the worker's engine kind (`board.<engine>`) and to the org/project it is bound to; an org with no projects gets a poison filter (the queue treats [] as 'all');
  * kill switch and drained workers receive no new work, but keep heartbeating what they hold;
  * `complete` is validated against the runtime contract; a non-conforming result is converted into a non-retryable failure instead of being stored as success;
  * `board_delegate / board_children / board_memory` (fenced; org + project come from the parent job, never from the request).
"""
from __future__ import annotations
import hashlib, inspect, secrets
from .. import durable as D
from ..durable_net import Coordinator, RemoteStore, WORKER_METHODS, FENCED, METHODS
from . import contract as C

BOARD_METHODS = frozenset({"board_delegate", "board_children", "board_memory", "board_secret", "board_gateway_spend"})
CLAIM_SIG = {"claim": ("worker", "node", "ttl", "kinds", "tenants"), "claim_many": ("worker", "node", "ttl", "kinds", "limit", "tenants"),
             "claim_many_wait": ("worker", "node", "ttl", "kinds", "limit", "tenants", "wait_s")}
LEASE_METHODS = (WORKER_METHODS | BOARD_METHODS) - {"get", "evidence", "node_report", "cap"}      # get/evidence expose whole task rows; node_report would let a customer worker zero the platform node's capacity


class Facade:
    def __init__(self, board): self.board, self.store = board, board.store
    def __getattr__(self, name):
        if name.startswith("_") or name not in METHODS: raise AttributeError(name)
        return getattr(self.store, name)

    def _claim(self, m, w, **k):
        bd = self.board; bd.touch_worker(w)
        wp = bd._worker_row(w)
        if bd.killed or (wp is not None and wp["drained"]): return None if m == "claim" else []
        return getattr(self.store, m)(**k)
    def claim(self, _w=None, **k): return self._claim("claim", _w, **k)
    def claim_many(self, _w=None, **k): return self._claim("claim_many", _w, **k)
    def claim_many_wait(self, _w=None, **k): return self._claim("claim_many_wait", _w, **k)

    def complete(self, tid, fence, result, promote=None):
        probs = C.validate_result(result) if isinstance(result, dict) else ["result must be an object"]
        if not probs and result.get("status") != "completed": probs = [f"complete() requires status 'completed', got {result.get('status')!r}"]
        jid = (self.store.get(tid) or {}).get("payload", {}).get("job_id")
        if not probs and result.get("job_id") != jid: probs = ["result.job_id does not match the job"]
        if probs:
            self.store.fail(tid, fence, "invalid_result: " + "; ".join(probs)[:1500], retry=False); raise D.StaleLease("result rejected: " + "; ".join(probs)[:300])
        return self.store.complete(tid, fence, result)

    @staticmethod
    def _wrap(fn, *a):
        from .service import BoardError
        try: return fn(*a)
        except BoardError as e: raise PermissionError(f"{e.code}: {e}")      # surfaces to the runtime as a refusal (HTTP 403 -> tool error), never as 'coordinator unreachable'
    def board_delegate(self, tid, fence, req): return self._wrap(self.board.w_delegate, tid, fence, req)
    def board_children(self, tid, fence): return self._wrap(self.board.w_children, tid, fence)
    def board_memory(self, tid, fence, op, ns="project", key=None, value=None): return self._wrap(self.board.w_memory, tid, fence, op, ns, key, value)
    def board_secret(self, tid, fence, name): return self._wrap(self.board.w_secret, tid, fence, name)
    def board_gateway_spend(self, tid, fence, op, request_id="", amount_usd=0.0, usage=None): return self._wrap(self.board.w_gateway_spend, tid, fence, op, request_id, amount_usd, usage)


class BoardCoordinator(Coordinator):
    def __init__(self, board, host="127.0.0.1", port=0, reap_every=2.0, tls=None):
        self.board = board
        super().__init__(Facade(board), secrets.token_urlsafe(32), host, port, principals=None, reap_every=reap_every, tls=tls)      # the built-in admin token is random and unshared: only worker keys exist

    def auth(self, header):
        if not header.startswith("Bearer "): return None
        return self.board.worker_principal(header[7:])

    def scope(self, pr, m, a, k):
        if pr.get("role") != "worker": raise PermissionError("no role")
        if m not in LEASE_METHODS: raise PermissionError(f"workers cannot call {m!r}")
        ts = self.board.tenants_for(pr)
        if m in CLAIM_SIG:
            d = dict(zip(CLAIM_SIG[m], a)); d.update(k); d["kinds"] = [f"board.{pr['engine']}"]; d["tenants"] = ts; d["_w"] = pr["wid"]
            if m != "claim_many_wait": d.pop("wait_s", None)
            return m, [], d
        try: bound = inspect.signature(getattr(self.store, m)).bind(*a, **k)           # bind positional AND keyword calls to the real signature: the tenant check below cannot be skipped by how the call is spelled
        except (TypeError, AttributeError) as e: raise PermissionError(f"malformed call to {m!r}: {e}")
        args = dict(bound.arguments)
        if "promote" in args: raise PermissionError("promote is not callable remotely")
        if "tid" in args: tids = [args["tid"]]
        elif "leases" in args:
            try: tids = [x[0] for x in args["leases"]]
            except (TypeError, IndexError, KeyError): raise PermissionError("malformed leases")
        else: raise PermissionError(f"{m!r} names no task: refused")                      # every non-claim lease call must identify the task it acts on
        for tid in tids:
            if not isinstance(tid, int) or isinstance(tid, bool): raise PermissionError("task id must be an integer")
            tn = self.board.store.tenant_of(tid)
            if tn is None or (ts is not None and tn not in ts): raise PermissionError("task belongs to a tenant this worker does not serve")
        self.board.note_worker_alive(pr["wid"])                                          # a worker whose slots are all busy never claims: any authorised lease call (heartbeat, checkpoint...) proves it is alive
        return m, [], args


class BoardRemote(RemoteStore):
    """RemoteStore that also exposes the fenced board_* calls."""
    def __getattr__(self, name):
        if name in BOARD_METHODS: return lambda *a, **k: self._rpc(name, list(a), k)
        return super().__getattr__(name)
