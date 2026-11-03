"""Plugin system. A plugin is a Python module (or entry point) with `register(api)`.

Kinds a plugin can add: `backend` (local LLM backend), `provider` (BYOK preset), `memory` (memory backend), `bridge` (external system),
`tool` (agent tool), `role` (model role), `contract_hook` (task-contract extension), `template_dir` (team templates).
Plugins execute code, so nothing is loaded implicitly: you must name a plugin directory (`--plugins DIR` / `ORDIVYR_PLUGINS`) or install a package
exposing the `ordivyr.plugins` entry-point group AND enable it with `PluginManager.enable(name)`. A failing plugin never breaks the host: the error is recorded.
"""
from __future__ import annotations
import importlib.metadata, importlib.util, os, sys
from pathlib import Path

KINDS = ("backend", "provider", "memory", "bridge", "tool", "role", "contract_hook", "template_dir")


class PluginAPI:
    def __init__(self, mgr, plugin): self._m, self.plugin = mgr, plugin
    def add(self, kind, name, obj):
        if kind not in KINDS: raise ValueError(f"unknown plugin kind {kind!r}; expected one of {KINDS}")
        if not name or not isinstance(name, str): raise ValueError("a plugin item needs a name")
        key = (kind, name)
        if key in self._m.items and self._m.items[key][0] != self.plugin: raise ValueError(f"{kind} {name!r} is already provided by {self._m.items[key][0]}")
        self._m.items[key] = (self.plugin, obj)
    def __getattr__(self, n):
        if n.startswith("add_") and n[4:] in KINDS: return lambda name, obj, _k=n[4:]: self.add(_k, name, obj)
        raise AttributeError(n)


class PluginManager:
    def __init__(self): self.items = {}; self.loaded = []; self.errors = {}
    def _run(self, name, register):
        before = dict(self.items)
        try: register(PluginAPI(self, name)); self.loaded.append(name)
        except Exception as e:
            self.items = before; self.errors[name] = f"{type(e).__name__}: {str(e)[:200]}"
    def load_dir(self, path):
        """Load every *.py (not starting with _) in an explicitly named directory."""
        d = Path(path)
        for f in sorted(d.glob("*.py")) if d.is_dir() else []:
            if f.name.startswith("_"): continue
            name = "ordivyr_plugin_" + f.stem
            try:
                spec = importlib.util.spec_from_file_location(name, f); mod = importlib.util.module_from_spec(spec); sys.modules[name] = mod; spec.loader.exec_module(mod)
                reg = getattr(mod, "register", None)
                if not callable(reg): raise AttributeError("no register(api) function")
            except Exception as e: self.errors[f.stem] = f"{type(e).__name__}: {str(e)[:200]}"; continue
            self._run(f.stem, reg)
    def discover_entry_points(self):
        return sorted(e.name for e in importlib.metadata.entry_points(group="ordivyr.plugins"))
    def enable(self, name):
        for e in importlib.metadata.entry_points(group="ordivyr.plugins"):
            if e.name == name:
                try: reg = e.load()
                except Exception as ex: self.errors[name] = f"{type(ex).__name__}: {str(ex)[:200]}"; return False
                self._run(name, reg); return name in self.loaded
        self.errors[name] = "no such entry point"; return False
    def of(self, kind): return {n: o for (k, n), (_, o) in self.items.items() if k == kind}
    def apply(self, core=None, teams=None, providers=None):
        """Wire loaded plugins into the host modules (contract hooks, provider presets, template dirs)."""
        if core:
            for n, h in self.of("contract_hook").items():
                if h not in core.CONTRACT_HOOKS: core.CONTRACT_HOOKS.append(h)
        if providers:
            for n, preset in self.of("provider").items(): providers.PRESETS.setdefault(n, preset)
    def summary(self):
        return {"loaded": self.loaded, "errors": self.errors, "items": sorted(f"{k}:{n}" for (k, n) in self.items)}


def from_env():
    m = PluginManager()
    for d in filter(None, os.environ.get("ORDIVYR_PLUGINS", "").split(os.pathsep)): m.load_dir(d)
    return m
