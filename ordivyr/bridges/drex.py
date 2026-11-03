"""DREX bridge: a model-powered decision role for BOUNDED questions.

DREX answers three kinds of question about a state you describe: `choice` (pick one option, with probabilities), `noul` (yes/no probability)
and `score` (a level). It never executes or approves anything; every answer is advice that ORDIVYR's deterministic guards may still reject.
Safety properties, all covered by tests:
  * OFF unless an endpoint AND a key are configured (nothing is shipped; the endpoint is yours to supply). No call is made otherwise.
  * Key from ORDIVYR_DREX_KEY or a 0600 key file (ORDIVYR_DREX_KEY_FILE); it is only ever sent as the Authorization header to YOUR endpoint (https, or loopback).
  * State text is redacted (keys, tokens, emails, IPs, home paths) before it leaves the process.
  * A hard per-bridge call cap; any failure, bad reply, or a reply from a different model than the pinned one returns WAIT/HUMAN_REVIEW - never a substitute answer.
Live status: the wire contract is tested with an injected transport. It has NOT been verified against a live DREX service in this release.
"""
from __future__ import annotations
import json, math, os, re, time, urllib.error, urllib.request, uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

MODEL = "drex-max"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_REDACT = [(re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "[REDACTED_KEY]"), (re.compile(r"\b[a-z]{2,6}_sk_[A-Za-z0-9_-]{16,}"), "[REDACTED_KEY]"),
           (re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}"), "[REDACTED_TOKEN]"),
           (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "[REDACTED_JWT]"),
           (re.compile(r"(?i)\b(bearer|authorization|api[_-]?key|password|secret|token)\b\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
           (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
           (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"), (re.compile(r"/home/[^/\s]+"), "~")]


def sanitize(text, limit=6000):
    t = str(text)
    for p, r in _REDACT: t = p.sub(r, t)
    return t[:limit]


def choice(instructions, options):
    if not 2 <= len(options) <= 255: raise ValueError("choice needs 2..255 options")
    return {"type": "choice", "instructions": instructions, "criteria": dict(options)}
def binary(instructions): return {"type": "noul", "instructions": instructions}
def score(instructions, levels):
    if not 1 <= len(levels) <= 255: raise ValueError("score needs 1..255 levels")
    return {"type": "score", "instructions": instructions, "criteria": list(levels)}


@dataclass
class Decision:
    ok: bool; disposition: str; call_id: str; answers: dict = field(default_factory=dict); error_kind: str | None = None; error: str | None = None
    latency_ms: float | None = None
    def choice(self, qid, min_confidence=0.75):
        a = self.answers.get(qid) if self.ok else None
        if not a or a.get("type") != "choice": return None
        return a["choice"] if (a.get("probabilities") or {}).get(a.get("choice"), 0.0) >= min_confidence else None
    def noul(self, qid):
        a = self.answers.get(qid) if self.ok else None
        return a.get("noul") if a and a.get("type") == "noul" else None
    def score(self, qid):
        a = self.answers.get(qid) if self.ok else None
        return a.get("score") if a and a.get("type") == "score" else None


class BridgeError(Exception):
    def __init__(self, kind, msg): super().__init__(msg); self.kind = kind


def validate_answers(questions, body):
    if not isinstance(body, dict): raise BridgeError("BAD_RESPONSE", "response is not an object")
    if body.get("model") != MODEL: raise BridgeError("MODEL_MISMATCH", f"provider answered with model {body.get('model')!r}, required {MODEL!r}")
    ans = body.get("answers")
    if not isinstance(ans, dict) or set(ans) != set(questions): raise BridgeError("BAD_RESPONSE", "answers do not match the questions asked")
    for qid, q in questions.items():
        a = ans[qid]
        if not isinstance(a, dict) or a.get("type") != q["type"]: raise BridgeError("BAD_RESPONSE", f"answer {qid} has wrong type")
        if q["type"] == "noul":
            v = a.get("noul")
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not 0.0 <= v <= 1.0: raise BridgeError("BAD_RESPONSE", f"noul {qid} out of range")
        elif q["type"] == "choice":
            pr = a.get("probabilities") or {}
            if a.get("choice") not in q["criteria"] or set(pr) != set(q["criteria"]): raise BridgeError("BAD_RESPONSE", f"choice {qid} outside the offered options")
            if not math.isclose(sum(pr.values()), 1.0, abs_tol=0.02): raise BridgeError("BAD_RESPONSE", f"choice {qid} probabilities do not sum to 1")
        elif q["type"] == "score":
            v = a.get("score")
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not 0 <= v <= len(q["criteria"]) - 1: raise BridgeError("BAD_RESPONSE", f"score {qid} outside levels")
    return ans


def _transport(url, body, headers, timeout):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return r.status, r.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e: return e.code, e.read(65536)
    except (urllib.error.URLError, TimeoutError, OSError) as e: raise BridgeError("NETWORK", f"cannot reach the DREX endpoint: {getattr(e, 'reason', e)}")


class DrexBridge:
    name = "drex"
    def __init__(self, endpoint=None, key=None, key_file=None, transport=None, max_calls=20, timeout=60):
        self.endpoint = endpoint if endpoint is not None else os.environ.get("ORDIVYR_DREX_URL", "")
        self._key = key; self.key_file = key_file or os.environ.get("ORDIVYR_DREX_KEY_FILE")
        self.transport = transport or _transport; self.max_calls = max_calls; self.timeout = timeout; self.calls = 0; self.log = []
    def _get_key(self):
        k = self._key or os.environ.get("ORDIVYR_DREX_KEY", "").strip()
        if k: return k
        if self.key_file:
            p = Path(self.key_file)
            try:
                if p.is_file() and p.stat().st_mode & 0o077 == 0: return p.read_text("utf-8").strip()
            except OSError: pass
        return ""
    def _endpoint_ok(self):
        u = urlparse(self.endpoint or "")
        return bool(u.hostname) and (u.scheme == "https" or (u.scheme == "http" and u.hostname in LOOPBACK)) and not (u.username or u.password)
    def status(self):
        return {"configured": self._endpoint_ok() and bool(self._get_key()), "endpoint_set": bool(self.endpoint), "key_found": bool(self._get_key()),
                "calls_used": self.calls, "max_calls": self.max_calls, "live_verified": False}
    def decide(self, state, questions, purpose="decision"):
        cid = uuid.uuid4().hex[:12]
        if not self._endpoint_ok(): return Decision(False, "WAIT", cid, error_kind="NO_ENDPOINT", error="DREX endpoint is not configured (https URL, or loopback http)")
        key = self._get_key()
        if not key: return Decision(False, "WAIT", cid, error_kind="NO_CREDENTIAL", error="DREX key is not configured")
        if self.calls >= self.max_calls: return Decision(False, "WAIT", cid, error_kind="BUDGET", error=f"call cap of {self.max_calls} reached")
        if not questions or len(questions) > 16: return Decision(False, "WAIT", cid, error_kind="INVALID_REQUEST", error="1..16 questions required")
        body = json.dumps({"model": MODEL, "state": sanitize(state), "questions": questions}).encode()
        headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json", "X-Trace-Id": cid}
        key = ""; self.calls += 1; t0 = time.perf_counter()
        try:
            st, raw = self.transport(self.endpoint, body, headers, self.timeout)
            try: j = json.loads(raw or b"{}")
            except ValueError: j = {}
            if st >= 400: raise BridgeError({401: "AUTH", 403: "AUTH", 402: "CREDIT", 429: "RATE_LIMIT"}.get(st, "PROVIDER_ERROR" if st >= 500 else "INVALID_REQUEST"), f"HTTP {st}")
            answers = validate_answers(questions, j)
        except BridgeError as e:
            d = Decision(False, "HUMAN_REVIEW" if e.kind in ("MODEL_MISMATCH", "BAD_RESPONSE") else "WAIT", cid, error_kind=e.kind, error=str(e)[:200], latency_ms=(time.perf_counter() - t0) * 1000)
            self.log.append({"call_id": cid, "purpose": purpose, "ok": False, "kind": e.kind}); return d
        self.log.append({"call_id": cid, "purpose": purpose, "ok": True})
        return Decision(True, "DECIDED", cid, answers, latency_ms=(time.perf_counter() - t0) * 1000)
    def route(self, state, options, min_confidence=0.75):
        """Pick one of {option: description}; None when not configured, not confident, or invalid (the caller falls back / asks a human)."""
        d = self.decide(state, {"route": choice("Which option should handle this?", options)}, "route")
        return d.choice("route", min_confidence)
    def judge(self, state, instructions):
        d = self.decide(state, {"judge": binary(instructions)}, "judge"); return d.noul("judge")
