"""Contract conformance harness: `check_runtime(run_job)` drives ANY runtime callable through the mandatory behaviours and returns [(check, ok, detail)].

`run_job(job, ctl)` -> result dict.  `ctl` is a minimal control surface the harness provides: `ctl.cancelled()` (poll) and `ctl.tool_attempts` (list the runtime must append
(name, executed:bool) to when the model asks for a tool). Stdlib + contract.py only, so Lite can run it against itself.
"""
from __future__ import annotations
from . import contract as C


class Ctl:
    def __init__(self, cancel_after=None): self.tool_attempts = []; self._n = 0; self._after = cancel_after
    def cancelled(self):
        self._n += 1; return self._after is not None and self._n > self._after


def base_job(**kw):
    j = {"contract_version": C.CONTRACT_VERSION, "job_id": "conf-1", "org": "conf", "project": "p", "engine": "x",
         "agent": {"id": "ag", "tools": ["read_file"], "permissions": {"write": False}}, "prompt": "say hi", "model_ref": {"endpoint": "stub", "model": "m"}}
    j.update(kw); return j


def check_runtime(run_job):
    out = []
    def rec(name, ok, detail=""): out.append((name, bool(ok), detail))
    j = base_job(); assert not C.validate_job(j)
    r = run_job(j, Ctl()); pr = C.validate_result(r); rec("result_valid", not pr, "; ".join(pr)); rec("result_job_id", r.get("job_id") == j["job_id"])
    rec("usage_keys", all(k in (r.get("usage") or {}) for k in C.USAGE_KEYS))
    ctl = Ctl(); j2 = base_job(job_id="conf-2", prompt="please call write_file"); r2 = run_job(j2, ctl)
    rec("ungranted_tool_never_executed", not any(ex for n, ex in ctl.tool_attempts if n == "write_file"), str(ctl.tool_attempts))
    rec("ungranted_tool_result_valid", not C.validate_result(r2))
    r3 = run_job(base_job(job_id="conf-3", prompt="work for a long time"), Ctl(cancel_after=1))
    rec("cancel_honoured", r3.get("status") == "cancelled" and r3.get("stop") == "cancelled", str(r3.get("status")))
    r4 = run_job(base_job(job_id="conf-4", contract_version="9.0"), Ctl())
    rec("unsupported_version_refused", r4.get("status") == "failed" and (r4.get("error") or {}).get("code") == "unsupported_version", str(r4.get("error")))
    return out
