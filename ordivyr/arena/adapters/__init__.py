"""Adapter registry. Built-ins + any `*.py` dropped into $ORDIVYR_ARENA_ADAPTERS (each defines `ADAPTERS = [AdapterInstance, ...]`) = the plugin interface for future harnesses."""
from __future__ import annotations
import importlib.util, os
from pathlib import Path
from .base import Adapter, Lane, Invocation, Unavailable, NOT_TESTED
from .ordivyr_adapter import OrdivyrAdapter
from .competitors import HermesAdapter, OpenClawAdapter, external


def all_adapters():
    out = [OrdivyrAdapter(), HermesAdapter(), OpenClawAdapter()] + external()
    d = os.environ.get("ORDIVYR_ARENA_ADAPTERS")
    if d and Path(d).is_dir():
        for f in sorted(Path(d).glob("*.py")):
            spec = importlib.util.spec_from_file_location("arena_plugin_" + f.stem, f); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); out += list(getattr(m, "ADAPTERS", []))
    return out


def get(name):
    for a in all_adapters():
        if a.name == name: return a
    raise KeyError(f"unknown harness {name!r}; known: {[a.name for a in all_adapters()]}")
