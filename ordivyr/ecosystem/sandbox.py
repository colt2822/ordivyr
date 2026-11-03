"""Permission enforcement at the host boundary.

Network (http adapters): host allowlist checked by the HOST before any request - real enforcement.
Environment: only granted env names reach an out-of-process plugin.
Processes (MCP stdio): wrapped in bubblewrap when installed: home hidden, root read-only, only granted paths bound, network unshared
unless a `net:` grant exists. Without a WORKING bwrap, stdio plugins are refused (fail closed) unless ORDIVYR_ALLOW_UNCONFINED=1, in which case they get a scrubbed env but NO filesystem/network confinement - reported by `confinement()`.
Granting any `net:` to a stdio plugin gives it the whole network (host filtering is only possible for requests the host makes itself).
"""
from __future__ import annotations
import os, shutil
from pathlib import Path
from urllib.parse import urlparse
from . import manifest as MF

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class Denied(PermissionError): pass


class Policy:
    def __init__(self, granted):
        self.granted = {MF.perm(p) for p in granted}
    def _args(self, kind): return {a for k, a in self.granted if k == kind}
    def has(self, kind, arg=""): return (kind, arg) in self.granted
    def check_url(self, url):
        u = urlparse(url); host = (u.hostname or "").lower(); hp = f"{host}:{u.port}" if u.port else host
        allow = {x.lower() for x in self._args("net")}
        if host in LOOPBACK:
            if "local" in allow or host in allow or hp in allow: return True
            raise Denied(f"network permission net:local (or net:{hp}) is not granted for {url[:80]}")
        if host in allow or hp in allow: return True
        raise Denied(f"network permission net:{host} is not granted")
    def env(self):
        base = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL") if k in os.environ}
        for n in self._args("env"):
            if n in os.environ: base[n] = os.environ[n]
        return base
    def check_exec(self, cmd):
        if cmd not in self._args("exec") and os.path.basename(cmd) not in self._args("exec"): raise Denied(f"exec permission for {cmd!r} is not granted")
    def fs_paths(self, kind): return sorted(self._args(kind))
    def allows_write_tools(self): return self.has("tool.write")


_BW_OK = {}
def _bwrap_works(bw):
    """bwrap can be installed yet unusable (user namespaces disabled): probe once instead of trusting `which`."""
    if bw not in _BW_OK:
        import subprocess
        try: _BW_OK[bw] = subprocess.run([bw, "--ro-bind", "/", "/", "--unshare-net", "true"], capture_output=True, timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError): _BW_OK[bw] = False
    return _BW_OK[bw]

def unconfined_allowed(): return os.environ.get("ORDIVYR_ALLOW_UNCONFINED") == "1"

def confinement():
    bw = shutil.which("bwrap")
    if bw and _bwrap_works(bw): return "bubblewrap"
    return "none (stdio plugins are refused unless ORDIVYR_ALLOW_UNCONFINED=1)" if not unconfined_allowed() else "none (ORDIVYR_ALLOW_UNCONFINED=1: stdio plugins run WITHOUT confinement)"


def wrap_command(policy, command, args, plugin_dir):
    """-> (argv list, mode). mode is 'bubblewrap' or 'env-only'."""
    exe = shutil.which(command) or command
    bw = shutil.which("bwrap")
    if not bw or not _bwrap_works(bw):
        if not unconfined_allowed(): raise Denied("no working bubblewrap: refusing to start a stdio plugin unconfined (install bubblewrap, or set ORDIVYR_ALLOW_UNCONFINED=1 to accept the risk)")
        return [exe, *args], "env-only"
    home = os.path.expanduser("~"); a = [bw, "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    if not any(k == "net" for k, _ in policy.granted): a.append("--unshare-net")
    if home and home != "/": a += ["--tmpfs", home]                      # hide everything under HOME (keys, histories, other plugins)
    hidden = (home, "/tmp")                                              # trees we blank out; a command living inside one must be re-bound read-only
    keeps = {str(plugin_dir)}
    for path in {exe, os.path.realpath(exe)}:
        if any(path.startswith(h.rstrip("/") + "/") for h in hidden if h and h != "/"):
            d = os.path.dirname(path); keeps.add(d)
            if os.path.exists(os.path.join(os.path.dirname(d), "pyvenv.cfg")): keeps.add(os.path.dirname(d))      # a venv: python needs pyvenv.cfg next to bin/
    for keep in sorted(keeps):
        a += ["--ro-bind", keep, keep]
    for p in policy.fs_paths("fs.read"):
        if os.path.exists(p): a += ["--ro-bind", p, p]
    for p in policy.fs_paths("fs.write"):
        if os.path.exists(p): a += ["--bind", p, p]
    return [*a, "--chdir", str(plugin_dir), "--", exe, *args], "bubblewrap"
