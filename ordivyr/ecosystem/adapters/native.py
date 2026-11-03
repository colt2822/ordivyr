"""Native ORDIVYR extensions: a Python module with `register(api)` (see ordivyr.plugins). IN-PROCESS and NOT sandboxed, so it is loaded only when the
user pinned trust to the plugin's exact current content hash. `api.add_tool(name, {...})` tools get the same host-side guards as every other tool."""
from __future__ import annotations
import importlib.util, sys
from pathlib import Path
from . import AdapterError
from .. import manifest as MF
from ... import plugins as PL


class Native:
    def __init__(self, manifest, plugin_dir, trusted_hash):
        if not trusted_hash or trusted_hash != MF.tree_hash(plugin_dir): raise AdapterError("native plugin is not trusted for its current content (ordivyr plugin trust)")
        f = Path(plugin_dir) / manifest["entry"]["module"]; name = f"ordivyr_native_{manifest['id']}"
        spec = importlib.util.spec_from_file_location(name, f); mod = importlib.util.module_from_spec(spec); sys.modules[name] = mod
        old = sys.dont_write_bytecode; sys.dont_write_bytecode = True         # never write caches into a hash-pinned plugin folder
        try: spec.loader.exec_module(mod)
        except Exception as e: raise AdapterError(f"plugin failed to load: {type(e).__name__}: {str(e)[:150]}")
        finally: sys.dont_write_bytecode = old
        if not callable(getattr(mod, "register", None)): raise AdapterError("native plugin has no register(api)")
        self.mgr = PL.PluginManager(); self.mgr._run(manifest["id"], mod.register)
        if self.mgr.errors: raise AdapterError("; ".join(self.mgr.errors.values()))
        self.fns = {n: o for n, o in self.mgr.of("tool").items() if callable(o.get("fn"))}
    def tools(self): return [{"name": n, "description": str(o.get("description", ""))[:300], "inputSchema": o.get("inputSchema") or {"type": "object", "properties": {}}, "readOnly": bool(o.get("readOnly"))} for n, o in self.fns.items()]
    def call(self, name, args):
        if name not in self.fns: raise AdapterError("unknown tool")
        return str(self.fns[name]["fn"](args))
    def extensions(self): return self.mgr
    def close(self): pass
