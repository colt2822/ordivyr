"""Outbound signed webhooks: POST a JSON event with `X-Ordivyr-Timestamp` and `X-Ordivyr-Signature: sha256=HMAC(secret, "<ts>.<body>")`. Receivers verify with verify()
(constant-time, 5-minute replay window). Delivery is best-effort with bounded retries and never raises into the run."""
import hashlib, hmac, json, threading, time, urllib.request
from urllib.parse import urlparse

EVENTS = ("completed", "failed", "awaiting_approval", "cancelled")


def sign(secret, body: bytes, ts=None):
    ts = str(int(ts if ts is not None else time.time())); mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"X-Ordivyr-Timestamp": ts, "X-Ordivyr-Signature": "sha256=" + mac}


def verify(secret, body: bytes, headers, tolerance=300, now=None):
    try: ts = int(headers.get("X-Ordivyr-Timestamp", "")); sig = headers.get("X-Ordivyr-Signature", "")
    except ValueError: return False
    if abs((now if now is not None else time.time()) - ts) > tolerance: return False
    return hmac.compare_digest(sig, sign(secret, body, ts)["X-Ordivyr-Signature"])


def _post(url, body, headers, timeout): 
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "ordivyr-webhook", **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r: return r.status


class Emitter:
    """Emitter(url, secret, events=EVENTS)(event, payload). post is injectable for tests; background=False delivers inline."""
    def __init__(self, url, secret, events=EVENTS, post=_post, retries=3, background=True, sleep=time.sleep):
        u = urlparse(url)
        if u.scheme not in ("http", "https") or not u.hostname: raise ValueError("webhook url must be http(s)")
        if u.scheme == "http" and u.hostname not in ("127.0.0.1", "localhost", "::1"): raise ValueError("plain http webhooks are loopback-only; use https")
        if not secret: raise ValueError("a webhook secret is required")
        self.url, self.secret, self.events, self.post, self.retries, self.background, self.sleep = url, secret, set(events), post, retries, background, sleep; self.delivered = 0; self.failed = 0; self._threads = []
    def __call__(self, event, payload):
        if event not in self.events: return False
        body = json.dumps({"event": event, "ts": time.time(), **payload}, default=str, sort_keys=True).encode()
        if self.background:
            t = threading.Thread(target=self._deliver, args=(body,), daemon=True); self._threads = [x for x in self._threads if x.is_alive()] + [t]; t.start()
        else: self._deliver(body)
        return True
    def flush(self, timeout=60.0):
        """Wait (bounded) for in-flight deliveries; call before the process exits."""
        end = time.monotonic() + timeout
        for t in list(self._threads): t.join(max(0.0, end - time.monotonic()))
        return not any(t.is_alive() for t in self._threads)
    def _deliver(self, body):
        for i in range(self.retries):
            try:
                if 200 <= self.post(self.url, body, sign(self.secret, body), 10) < 300: self.delivered += 1; return
            except Exception: pass
            self.sleep(min(30, 2 ** i))
        self.failed += 1
