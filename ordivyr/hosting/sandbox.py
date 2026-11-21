"""Namespace sandbox executor (bubblewrap) behind the existing `Executor` contract: the first backend that is NOT plain process isolation.

Threat model, stated precisely. A run is confined by Linux user/pid/mount/ipc/uts/cgroup/net namespaces, an empty environment, a read-only root, one writable bind
mount (the tenant's own work directory), a private /tmp, dropped capabilities and rlimits (address space, CPU seconds, file size, open files, processes). It defeats the
ordinary "hostile customer script" cases: reading the host's files, secrets or other tenants' directories, reaching the network or host services, seeing or signalling
host processes, escaping by writing outside the work directory, exhausting memory/CPU/disk/processes of the host, or outliving its run.
It is NOT a hardware boundary: the sandbox shares the host kernel, so a kernel privilege-escalation bug is outside this layer. Run untrusted-at-scale
workloads on top of a microVM or user-space kernel (Firecracker, gVisor, Kata) by registering another `Executor`; this class is the verified local backend and the
reference for the contract tests (`isolation = "container"`). Seccomp filtering is not applied here.
"""
from __future__ import annotations
import json, os, shutil, signal, subprocess, threading, time
from pathlib import Path
from .contracts import ExecSpec

SYSTEM_RO = ("/usr",)
SYMLINKS = (("usr/bin", "/bin"), ("usr/sbin", "/sbin"), ("usr/lib", "/lib"), ("usr/lib64", "/lib64"))


def available():
    if not shutil.which("bwrap"): return False
    try: return subprocess.run(["bwrap", "--unshare-all", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "/usr/bin/true"], capture_output=True, timeout=10).returncode == 0
    except Exception: return False


class SandboxError(Exception): pass


class _Handle:
    def __init__(self, p, t0, audit, rec, out): self.p, self.t0, self.audit, self.rec, self.rc, self.timer, self.killed, self.out = p, t0, audit, rec, None, None, None, out
    def wait(self, timeout=None):
        try: self.rc = self.p.wait(timeout)
        except subprocess.TimeoutExpired: self.kill("wait-timeout"); self.rc = self.p.wait()
        if self.timer: self.timer.cancel()
        self._done(); return self.rc
    def kill(self, why="killed"):
        self.killed = self.killed or why
        try: os.killpg(self.p.pid, signal.SIGKILL)
        except OSError: pass
    def _done(self):
        if self.rec is None: return
        rec, self.rec = self.rec, None; rec.update(ev="end", rc=self.rc, wall_s=round(time.time() - self.t0, 3), killed=self.killed); self.audit(rec)
        for f in self.out:
            try: f.close()
            except Exception: pass
    def usage(self): return {"wall_s": round(time.time() - self.t0, 3), "rc": self.rc, "killed": self.killed}


class BubblewrapExecutor:
    isolation = "container"

    def __init__(self, root, tenant, audit_path=None, allow_network=False, ro_extra=(), default_mem_mb=512, default_cpu_s=60, default_procs=128, max_out_mb=16):
        if not tenant or "/" in tenant or tenant.startswith("."): raise SandboxError("bad tenant name")
        self.base = (Path(root).resolve() / tenant); self.base.mkdir(parents=True, exist_ok=True); self.tenant = tenant; self.allow_network = allow_network; self.ro_extra = tuple(ro_extra)
        self.dm, self.dc, self.dp, self.out_mb = default_mem_mb, default_cpu_s, default_procs, max_out_mb; self.audit_path = audit_path; self._lock = threading.Lock()
        if not available(): raise SandboxError("bubblewrap (bwrap) with unprivileged user namespaces is not available on this host")

    def audit(self, rec):
        rec = {"t": round(time.time(), 3), "tenant": self.tenant, **rec}
        if not self.audit_path: return
        with self._lock, open(self.audit_path, "a") as f: f.write(json.dumps(rec, sort_keys=True) + "\n")

    def start(self, spec: ExecSpec):
        cwd = Path(spec.cwd).resolve()
        if cwd != self.base and self.base not in cwd.parents: raise SandboxError("work directory is outside this tenant's area")     # tenant separation: a tenant's executor can only mount its own directory
        cwd.mkdir(parents=True, exist_ok=True)
        net = spec.network if spec.network in ("none", "inherit") else "none"
        if net == "inherit" and not self.allow_network: net = "none"                                                                # hosted default: the network is opt-IN per executor, never inherited
        argv = ["bwrap", "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", "--clearenv", "--cap-drop", "ALL", "--disable-userns"]
        if net == "inherit": argv.append("--share-net")
        for p in SYSTEM_RO + self.ro_extra: argv += ["--ro-bind", p, p]
        for tgt, link in SYMLINKS: argv += ["--symlink", tgt, link]
        argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(cwd), "/work", "--remount-ro", "/", "--chdir", "/work", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/work", "--setenv", "LANG", "C.UTF-8"]
        for k, v in (spec.env or {}).items():
            if k.isidentifier(): argv += ["--setenv", k, str(v)]
        mem, cpu, procs = spec.max_memory_mb or self.dm, spec.max_cpu_s or self.dc, spec.max_procs or self.dp
        argv += ["--", "/usr/bin/prlimit", f"--as={mem << 20}", f"--cpu={cpu}", f"--nproc={procs}", f"--fsize={self.out_mb << 20}", "--nofile=512", "--core=0", "--", *spec.argv]
        out = (open(cwd / ".stdout", "ab"), open(cwd / ".stderr", "ab"))
        rec = {"ev": "start", "argv0": os.path.basename(str(spec.argv[0])) if spec.argv else "", "network": net, "mem_mb": mem, "cpu_s": cpu, "procs": procs, "timeout_s": spec.timeout_s, "cwd": str(cwd.relative_to(self.base)) or "."}
        self.audit(dict(rec)); p = subprocess.Popen(argv, start_new_session=True, stdin=subprocess.DEVNULL, stdout=out[0], stderr=out[1], env={})
        h = _Handle(p, time.time(), self.audit, rec, out)
        if spec.timeout_s: h.timer = threading.Timer(spec.timeout_s, lambda: h.kill("timeout")); h.timer.daemon = True; h.timer.start()
        return h
