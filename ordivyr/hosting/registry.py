"""Optional adapters register a factory under (contract, name). Nothing external is imported unless it is configured; the embedded defaults need no registration."""
from __future__ import annotations
_F = {}
def register(contract, name, factory): _F[(contract, name)] = factory
def lookup(contract, name):
    try: return _F[(contract, name)]
    except KeyError: raise KeyError(f"no {contract} adapter named {name!r} is registered (registered: {sorted(n for c, n in _F if c == contract)})")
