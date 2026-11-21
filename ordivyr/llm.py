"""Local LLM / GPU manager.

Backends (all plain HTTP, stdlib, injectable `http` so tests never need a model):
  OllamaBackend  - /api/tags (installed), /api/ps (loaded), load/unload via keep_alive, chat via /api/chat
  OpenAIBackend  - any OpenAI-compatible server (llama.cpp server, LM Studio, vLLM): /v1/models, /v1/chat/completions
Nothing is loaded or unloaded unless you call `load` / `unload` / `apply_plan(..., execute=True)`; planning is read-only.
`plan()` assigns models to GPUs with `hw.fits`, never evicting a pinned model, and reports what would not fit and why.
"""
from __future__ import annotations
import json, urllib.error, urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse
from . import hw as HW

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class LLMError(RuntimeError): pass


@dataclass
class Model:
    name: str; backend: str; size_mb: int = 0; params_b: float | None = None; quant: str | None = None; loaded: bool = False
    vram_mb: int = 0; ctx: int = 0; tags: list = field(default_factory=list)
    def need_mb(self, ctx=None):
        if self.vram_mb: return self.vram_mb
        if self.params_b: return HW.model_vram_mb(self.params_b, self.quant or "q4_k_m", ctx or self.ctx or 8192)
        return int(self.size_mb * 1.15) + 600 if self.size_mb else 0
    def to_dict(self): return {"name": self.name, "backend": self.backend, "size_mb": self.size_mb, "params_b": self.params_b, "quant": self.quant, "loaded": self.loaded, "need_mb": self.need_mb()}


def _urlopen(method, url, body, timeout, key=""):
    req = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": "application/json", "User-Agent": "ordivyr", **({"Authorization": "Bearer " + key} if key else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e: raise LLMError(f"cannot reach {url}: {getattr(e, 'reason', e)}")


def _check(base):
    u = urlparse(base)
    if u.scheme not in ("http", "https") or not u.hostname: raise LLMError("base URL must start with http:// or https://")
    if u.scheme == "http" and u.hostname not in LOOPBACK: raise LLMError("plain http is only allowed for local servers on this machine")
    return base.rstrip("/")


class _Base:
    def __init__(self, base, http=None, timeout=60, name=None, key=""):
        self.base = _check(base); self.key = key or ""; self._http = http or ((lambda m, u, b, t: _urlopen(m, u, b, t, self.key)) if self.key else _urlopen); self.timeout = timeout; self.name = name or self.kind
    def _j(self, method, path, payload=None, timeout=None):
        st, raw = self._http(method, self.base + path, None if payload is None else json.dumps(payload).encode(), timeout or self.timeout)
        try: j = json.loads(raw or b"{}")
        except ValueError: j = {}
        if st >= 400: raise LLMError(f"{self.name} {path}: HTTP {st} {str(j.get('error', ''))[:160]}")
        return j
    def reachable(self):
        try: self.models(); return True
        except LLMError: return False


class OllamaBackend(_Base):
    kind = "ollama"; manageable = True
    def __init__(self, base="http://127.0.0.1:11434", **kw): super().__init__(base, **kw)
    def models(self):
        ps = {m["name"]: m for m in self._j("GET", "/api/ps").get("models", [])}
        out = []
        for m in self._j("GET", "/api/tags").get("models", []):
            d = m.get("details") or {}; pb, q = HW.params_from_name(m["name"])
            try: ps_b = float(str(d.get("parameter_size", "")).lower().rstrip("b")); pb = ps_b or pb
            except ValueError: pass
            q = (d.get("quantization_level") or q or "").lower() or None
            live = ps.get(m["name"])
            out.append(Model(m["name"], self.name, int(m.get("size", 0)) // 2**20, pb, q, live is not None, int((live or {}).get("size_vram", 0)) // 2**20))
        return out
    def load(self, name, keep_alive="10m", ctx=None):
        o = {"num_ctx": ctx} if ctx else {}
        self._j("POST", "/api/generate", {"model": name, "prompt": "", "keep_alive": keep_alive, "stream": False, **({"options": o} if o else {})}, timeout=300)
    def unload(self, name): self._j("POST", "/api/generate", {"model": name, "prompt": "", "keep_alive": 0, "stream": False})
    def chat(self, model, system, messages, max_tokens=1024, **kw):
        j = self._j("POST", "/api/chat", {"model": model, "stream": False, "options": {"num_predict": max_tokens},
                    "messages": ([{"role": "system", "content": system}] if system else []) + [{"role": m["role"], "content": m["text"]} for m in messages]}, timeout=300)
        return (j.get("message") or {}).get("content", ""), int(j.get("prompt_eval_count") or 0) + int(j.get("eval_count") or 0), model


class OpenAIBackend(_Base):
    """llama.cpp server / LM Studio / vLLM. These load their model at start-up, so load/unload are not offered (manageable = False)."""
    kind = "openai"; manageable = False
    def __init__(self, base="http://127.0.0.1:8080/v1", **kw): super().__init__(base, **kw)
    def models(self):
        out = []
        for m in self._j("GET", "/models").get("data", []):
            pb, q = HW.params_from_name(m.get("id", "")); out.append(Model(m["id"], self.name, 0, pb, q, True, 0, int(m.get("meta", {}).get("n_ctx_train", 0) or 0)))
        return out
    def chat(self, model, system, messages, max_tokens=1024, **kw):
        j = self._j("POST", "/chat/completions", {"model": model, "max_tokens": max_tokens, "stream": False,
                    "messages": ([{"role": "system", "content": system}] if system else []) + [{"role": m["role"], "content": m["text"]} for m in messages]}, timeout=300)
        return (((j.get("choices") or [{}])[0]).get("message") or {}).get("content") or "", int((j.get("usage") or {}).get("total_tokens") or 0), j.get("model") or model


class Manager:
    """Facade over several backends + the detected hardware."""
    def __init__(self, backends, hardware=None, pinned=()):
        self.backends = {b.name: b for b in backends}; self.hw = hardware or HW.detect(); self.pinned = set(pinned)
    def inventory(self):
        out = []; errs = {}
        for n, b in self.backends.items():
            try: out += b.models()
            except LLMError as e: errs[n] = str(e)
        return out, errs
    def plan(self, wanted, ctx=8192):
        """wanted: model names in priority order -> {'placements': [{model, where, split, need_mb}], 'unplaceable': [{model, reason}]}. Pure arithmetic over free VRAM."""
        inv, _ = self.inventory(); byname = {m.name: m for m in inv}
        free = {g.index: g.free_mb for g in self.hw.gpus}
        # already-loaded models keep their VRAM; plan only adds
        sim = HW.Hardware([HW.GPU(g.index, g.name, g.vram_mb, g.vram_mb - free[g.index], g.compute_cap) for g in self.hw.gpus], self.hw.cpu_threads, self.hw.ram_mb)
        placements, bad = [], []
        for name in wanted:
            m = byname.get(name)
            if not m: bad.append({"model": name, "reason": "not installed on any connected backend"}); continue
            if m.loaded: placements.append({"model": name, "where": "already-loaded", "split": False, "need_mb": m.vram_mb or m.need_mb(ctx)}); continue
            need = m.need_mb(ctx)
            if not need: bad.append({"model": name, "reason": "size unknown; cannot plan"}); continue
            f = HW.fits(sim, need)
            if f["where"] is None: bad.append({"model": name, "reason": f"needs ~{need} MB; largest free GPU has {max((g.free_mb for g in sim.gpus), default=0)} MB"}); continue
            if f["where"] == "cpu": placements.append({"model": name, "where": "cpu", "split": False, "need_mb": need}); continue
            share = need // len(f["where"]) if f["split"] else need
            for gi in f["where"]:
                g = next(x for x in sim.gpus if x.index == gi); g.used_mb += share
            placements.append({"model": name, "where": f["where"], "split": f["split"], "need_mb": need})
        return {"placements": placements, "unplaceable": bad}
    def load(self, model):
        b = self.backends.get(model.backend)
        if not b or not getattr(b, "manageable", False): raise LLMError(f"{model.backend} cannot load models on demand")
        b.load(model.name)
    def unload(self, model):
        if model.name in self.pinned: raise LLMError(f"{model.name} is pinned; unpin it first")
        b = self.backends.get(model.backend)
        if not b or not getattr(b, "manageable", False): raise LLMError(f"{model.backend} cannot unload models")
        b.unload(model.name)
    def chat(self, backend, model, system, messages, **kw): return self.backends[backend].chat(model, system, messages, **kw)
