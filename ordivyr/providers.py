"""Model providers: one small stdlib HTTP client for the three wire protocols that cover every mainstream provider.

  openai     POST {base}/chat/completions   OpenAI, OpenRouter, Groq, DeepSeek, Mistral, xAI, Together, Ollama, LM Studio, vLLM, any compatible server
  anthropic  POST {base}/v1/messages        Anthropic API
  gemini     POST {base}/models/{m}:generateContent   Google Gemini

API keys are used for exactly one thing - the Authorization header of a request to that account's own base_url - and are refused
over plain http unless the host is loopback. Providers here are TEXT-ONLY (no tool loop); Claude/Codex logins are the tool-capable ones.
Everything takes an injectable `http` callable so tests never touch the network.
"""
from __future__ import annotations
import http.client, json, re, socket, threading, urllib.error, urllib.request
from urllib.parse import urlparse

# key: label, protocol, base url, needs a key, suggested models (free text is always allowed)
PRESETS = {
    "anthropic": {"label": "Anthropic API", "protocol": "anthropic", "base": "https://api.anthropic.com", "key": True, "models": ["claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5"]},
    "openai": {"label": "OpenAI API", "protocol": "openai", "base": "https://api.openai.com/v1", "key": True, "models": []},
    "gemini": {"label": "Google Gemini", "protocol": "gemini", "base": "https://generativelanguage.googleapis.com/v1beta", "key": True, "models": []},
    "openrouter": {"label": "OpenRouter", "protocol": "openai", "base": "https://openrouter.ai/api/v1", "key": True, "models": []},
    "groq": {"label": "Groq", "protocol": "openai", "base": "https://api.groq.com/openai/v1", "key": True, "models": []},
    "deepseek": {"label": "DeepSeek", "protocol": "openai", "base": "https://api.deepseek.com/v1", "key": True, "models": []},
    "mistral": {"label": "Mistral", "protocol": "openai", "base": "https://api.mistral.ai/v1", "key": True, "models": []},
    "xai": {"label": "xAI", "protocol": "openai", "base": "https://api.x.ai/v1", "key": True, "models": []},
    "together": {"label": "Together AI", "protocol": "openai", "base": "https://api.together.xyz/v1", "key": True, "models": []},
    "ollama": {"label": "Ollama (local)", "protocol": "openai", "base": "http://127.0.0.1:11434/v1", "key": False, "models": []},
    "lmstudio": {"label": "LM Studio (local)", "protocol": "openai", "base": "http://127.0.0.1:1234/v1", "key": False, "models": []},
    "custom": {"label": "Custom endpoint", "protocol": "openai", "base": "", "key": False, "models": []},
}
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class ProviderError(ValueError): pass
class LimitError(ProviderError): """Rate limit / quota: the pool may fail over to the next account."""


def is_local(base_url: str) -> bool:
    return (urlparse(base_url).hostname or "") in LOOPBACK


def check_base(base_url: str) -> str:
    u = urlparse(str(base_url or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname: raise ProviderError("base URL must start with http:// or https://")
    if u.scheme == "http" and u.hostname not in LOOPBACK: raise ProviderError("plain http is only allowed for local servers; use https")
    if u.username or u.password: raise ProviderError("do not put credentials in the URL")
    return base_url.strip().rstrip("/")


_TL = threading.local()          # one keep-alive connection per (thread, scheme, host, port): no TCP/TLS handshake on every step of a tool loop


def _slow_path(method, url, headers, body, timeout):
    """urllib: proxies, redirects, anything the pooled client does not handle."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e: raise ProviderError(f"cannot reach the provider: {getattr(e, 'reason', e)}")


def _urlopen(method, url, headers, body, timeout):
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname: return _slow_path(method, url, headers, body, timeout)
    try:
        if urllib.request.getproxies().get(u.scheme) and not urllib.request.proxy_bypass(u.hostname): return _slow_path(method, url, headers, body, timeout)
    except Exception: return _slow_path(method, url, headers, body, timeout)
    pool = _TL.__dict__.setdefault("pool", {}); key = (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)); path = (u.path or "/") + ("?" + u.query if u.query else "")
    hdr = dict(headers); hdr.setdefault("Accept-Encoding", "identity")
    for attempt in (0, 1):
        c = pool.get(key); fresh = c is None
        if fresh:
            c = (http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection)(key[1], key[2], timeout=timeout); pool[key] = c
        else:
            try: c.timeout = timeout; c.sock and c.sock.settimeout(timeout)
            except OSError: c.close(); pool.pop(key, None); c = (http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection)(key[1], key[2], timeout=timeout); pool[key] = c; fresh = True   # idle socket already dead
        try:
            if fresh: c.connect(); c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.request(method, path, body=body, headers=hdr); r = c.getresponse(); data = r.read(); st = r.status
        except (http.client.RemoteDisconnected, http.client.CannotSendRequest, http.client.NotConnected, ConnectionResetError, BrokenPipeError) as e:
            c.close(); pool.pop(key, None)
            if fresh or attempt: raise ProviderError(f"cannot reach the provider: {e}")
            continue                                                  # a reused connection the server had already closed: retry once on a new one
        except (TimeoutError, OSError) as e:
            c.close(); pool.pop(key, None); raise ProviderError(f"cannot reach the provider: {e}")
        if r.will_close: c.close(); pool.pop(key, None)
        if 300 <= st < 400: return _slow_path(method, url, headers, body, timeout)   # the pooled client does not follow redirects
        return st, data


def _call(http, method, url, headers, payload, timeout):
    st, raw = (http or _urlopen)(method, url, headers, None if payload is None else json.dumps(payload).encode(), timeout)
    try: j = json.loads(raw or b"{}")
    except ValueError: j = {}
    if st in (401, 403): raise ProviderError("the provider rejected the API key")
    if st == 429 or (isinstance(j, dict) and re.search(r"rate.?limit|quota|insufficient_quota|overloaded", json.dumps(j.get("error", ""))[:400], re.I)):
        raise LimitError("provider rate limit or quota reached")
    if st >= 400: raise ProviderError(f"provider error {st}: {json.dumps(j.get('error', j))[:200]}")
    return j


def _headers(protocol, key):
    h = {"Content-Type": "application/json", "User-Agent": "ordivyr"}
    if protocol == "anthropic": h["anthropic-version"] = "2023-06-01"; key and h.__setitem__("x-api-key", key)
    elif protocol == "gemini": key and h.__setitem__("x-goog-api-key", key)
    elif key: h["Authorization"] = "Bearer " + key
    return h


def list_models(protocol, base, key, http=None, timeout=20):
    """Token-free: lists the models the key can use. Doubles as the 'Test connection' check."""
    base = check_base(base); h = _headers(protocol, key)
    url = base + ("/v1/models" if protocol == "anthropic" else "/models")
    j = _call(http, "GET", url, h, None, timeout)
    items = j.get("data") if protocol != "gemini" else j.get("models")
    names = [(m.get("id") or m.get("name") or "").removeprefix("models/") for m in (items or []) if isinstance(m, dict)]
    return sorted(n for n in names if n)[:300]


def chat(protocol, base, key, model, system, messages, http=None, timeout=90, max_tokens=2048):
    """-> (text, total_tokens, model). messages: [{'role': 'user'|'assistant', 'text': str}]"""
    base = check_base(base); h = _headers(protocol, key)
    if not model: raise ProviderError("pick a model for this account first")
    if protocol == "anthropic":
        j = _call(http, "POST", base + "/v1/messages", h, {"model": model, "max_tokens": max_tokens, "system": system,
                  "messages": [{"role": m["role"], "content": m["text"]} for m in messages]}, timeout)
        text = "".join(b.get("text", "") for b in j.get("content", []) if b.get("type") == "text"); u = j.get("usage") or {}
        return text, int(u.get("input_tokens") or 0) + int(u.get("output_tokens") or 0), j.get("model") or model
    if protocol == "gemini":
        j = _call(http, "POST", f"{base}/models/{model}:generateContent", h, {"systemInstruction": {"parts": [{"text": system}]},
                  "contents": [{"role": "user" if m["role"] == "user" else "model", "parts": [{"text": m["text"]}]} for m in messages],
                  "generationConfig": {"maxOutputTokens": max_tokens}}, timeout)
        parts = (((j.get("candidates") or [{}])[0]).get("content") or {}).get("parts") or []
        return "".join(p.get("text", "") for p in parts), int((j.get("usageMetadata") or {}).get("totalTokenCount") or 0), model
    j = _call(http, "POST", base + "/chat/completions", h, {"model": model, "max_tokens": max_tokens,
              "messages": [{"role": "system", "content": system}] + [{"role": m["role"], "content": m["text"]} for m in messages]}, timeout)
    text = (((j.get("choices") or [{}])[0]).get("message") or {}).get("content") or ""
    return text, int((j.get("usage") or {}).get("total_tokens") or 0), j.get("model") or model
