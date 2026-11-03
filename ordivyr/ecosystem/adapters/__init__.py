"""Adapters turn a plugin into tools. Every adapter exposes: tools() -> [{name, description, inputSchema, readOnly}], call(name, args) -> str, close().
HTTP adapters never touch the network except through `Net.request`, which checks the granted host allowlist first."""
from __future__ import annotations
import json, urllib.error, urllib.request

MAX_BODY = 2 * 1024 * 1024


class AdapterError(RuntimeError): pass


def _urlopen(method, url, headers, body, timeout):
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(MAX_BODY)
    except urllib.error.HTTPError as e: return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(65536)
    except (urllib.error.URLError, TimeoutError, OSError) as e: raise AdapterError(f"cannot reach {url[:80]}: {getattr(e, 'reason', e)}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None          # a redirect could leave the granted host list; refuse instead of following


def default_http(method, url, headers, body, timeout):
    op = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with op.open(req, timeout=timeout) as r: return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(MAX_BODY)
    except urllib.error.HTTPError as e: return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(65536)
    except (urllib.error.URLError, TimeoutError, OSError) as e: raise AdapterError(f"cannot reach {url[:80]}: {getattr(e, 'reason', e)}")


class Net:
    """Policy-checked HTTP. `http` is injectable: (method, url, headers, body, timeout) -> (status, headers, bytes)."""
    def __init__(self, policy, http=None, timeout=30): self.policy, self.http, self.timeout = policy, http or default_http, timeout
    def request(self, method, url, payload=None, headers=None):
        self.policy.check_url(url)
        h = {"User-Agent": "ordivyr", "Accept": "application/json", **(headers or {})}
        body = None
        if payload is not None: body = json.dumps(payload).encode(); h.setdefault("Content-Type", "application/json")
        return self.http(method, url, h, body, self.timeout)
    def json(self, method, url, payload=None, headers=None):
        st, hd, raw = self.request(method, url, payload, headers)
        try: j = json.loads(raw or b"{}")
        except ValueError: j = {"_raw": raw[:2000].decode("utf-8", "replace")}
        if st >= 400: raise AdapterError(f"HTTP {st} from {url[:80]}: {str(j)[:200]}")
        return j, hd
