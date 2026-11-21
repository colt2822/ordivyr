"""Deployment-mode assembly. One set of contracts, three profiles:

  self_hosted : embedded SQLite store/queue/meter, local filesystem, local process executor, single local admin token. Zero external services.
  managed     : the orchestrator is hosted; customers bring workers + models. Needs multi-tenant auth. Executor is the customer's (not provisioned here).
  hosted      : the operator provisions execution for customers. REFUSES to start with a process-level executor (untrusted code needs container/microVM isolation).
Guards are enforced here, in code, not by documentation.
"""
from __future__ import annotations
import json, os
from dataclasses import dataclass
from pathlib import Path
from . import local, registry
from .contracts import LOCAL_TENANT
from .. import durable

MODES = ("self_hosted", "managed", "hosted")
class ConfigError(Exception): pass


@dataclass
class Services:
    mode: str; home: Path; store: object; executor: object; storage: object; models: object; auth: object; meter: object; quota: object
    def describe(self):
        return {"mode": self.mode, "home": str(self.home), "store": type(self.store).__name__, "executor": f"{type(self.executor).__name__} (isolation={getattr(self.executor, 'isolation', '?')})", "storage": type(self.storage).__name__,
                "models": type(self.models).__name__, "auth": type(self.auth).__name__, "meter": type(self.meter).__name__, "quota": type(self.quota).__name__}


def default_home(): return Path(os.environ.get("ORDIVYR_HOME") or Path.home() / ".local/state/ordivyr")


def load_config(home):
    p = Path(home) / "ordivyr.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _pick(cfg, contract, default):
    spec = cfg.get(contract)
    if not spec or spec.get("adapter", "embedded") == "embedded": return default()
    return registry.lookup(contract, spec["adapter"])(spec)


def build(cfg=None, home=None):
    home = Path(home or default_home()); home.mkdir(parents=True, exist_ok=True); cfg = cfg if cfg is not None else load_config(home); mode = cfg.get("mode", "self_hosted")
    if mode not in MODES: raise ConfigError(f"mode must be one of {MODES}")
    store = _pick(cfg, "store", lambda: durable.Store(home / "queue.db"))
    executor = _pick(cfg, "executor", lambda: local.LocalProcessExecutor())
    storage = _pick(cfg, "storage", lambda: local.FsStorage(home / "artifacts"))
    models = _pick(cfg, "models", lambda: local.ConfigModels(cfg.get("model_table", {})))
    if mode == "self_hosted": auth = _pick(cfg, "auth", lambda: local.LocalAuth(home / "admin.token")); meter = _pick(cfg, "meter", lambda: local.NullMeter())
    else: auth = _pick(cfg, "auth", lambda: local.TokenAuth(home / "auth.db")); meter = _pick(cfg, "meter", lambda: local.SqliteMeter(home / "usage.db"))
    quota = local.StaticQuota(cfg.get("quotas", {}))
    if mode in ("managed", "hosted") and isinstance(auth, local.LocalAuth): raise ConfigError(f"{mode} mode requires multi-tenant authentication; LocalAuth is single-user")
    if mode == "hosted" and getattr(executor, "isolation", "process") == "process": raise ConfigError("hosted mode refuses a process-level executor: untrusted customer code needs container or microVM isolation (register an executor adapter that provides it)")
    return Services(mode, home, store, executor, storage, models, auth, meter, quota)
