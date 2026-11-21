"""Isolation layers added on top of the bwrap namespace sandbox (sandbox.py).

  * seccomp deny-list (libseccomp via ctypes -> BPF -> `bwrap --seccomp FD`): removes the kernel attack surface a tenant job has no business using
    (ptrace, mount family, keyctl, bpf, perf, userfaultfd, io_uring, module/kexec/reboot, nested user namespaces, raw/netlink/packet/vsock sockets, ...).
  * cgroup v2 scope (`systemd-run --user --scope`): hard MemoryMax (swap off), TasksMax (fork-bomb bound), CPUQuota, applied to the whole process tree.
  * launcher prefix: an operator-supplied command prefix (e.g. `sudo -n systemd-run -p DynamicUser=yes ...`) so a root-installed deployment can give every tenant a distinct OS uid.

What this does NOT give: a separate kernel. A kernel 0-day reachable through an allowed syscall still escapes. Tenants who need a kernel boundary need a microVM (docs/board/ISOLATION.md).
"""
from __future__ import annotations
import ctypes, ctypes.util, os, shutil, subprocess, tempfile

DENY = """ptrace process_vm_readv process_vm_writev kcmp mount umount umount2 pivot_root chroot setns unshare move_mount open_tree fsopen fsconfig fsmount fspick mount_setattr
keyctl add_key request_key bpf perf_event_open userfaultfd io_uring_setup io_uring_enter io_uring_register kexec_load kexec_file_load init_module finit_module delete_module create_module
reboot swapon swapoff acct settimeofday clock_settime clock_adjtime adjtimex stime sethostname setdomainname iopl ioperm modify_ldt quotactl lookup_dcookie open_by_handle_at name_to_handle_at
fanotify_init nfsservctl syslog vhangup sysfs _sysctl uselib ustat personality pidfd_getfd seccomp landlock_create_ruleset mbind set_mempolicy migrate_pages move_pages vm86 vm86old""".split()
ENOSYS_ONLY = ["clone3"]                                           # glibc falls back to clone(2), whose flags we CAN inspect
BAD_FAMILIES = {15: "AF_KEY", 16: "AF_NETLINK", 17: "AF_PACKET", 31: "AF_BLUETOOTH", 38: "AF_ALG", 40: "AF_VSOCK"}
CLONE_NS_FLAGS = 0x10000000 | 0x00020000 | 0x08000000 | 0x40000000 | 0x20000000 | 0x04000000 | 0x02000000   # NEWUSER NEWNS NEWNET NEWPID NEWIPC NEWUTS NEWCGROUP (+ NEWTIME below)
CLONE_NEWTIME = 0x00000080

_ALLOW, _ERRNO = 0x7FFF0000, 0x00050000
_EQ, _MASKED_EQ = 4, 7


class _Cmp(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int), ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]


_lib = None


def _seccomp():
    global _lib
    if _lib is None:
        name = ctypes.util.find_library("seccomp")
        if not name: return None
        l = ctypes.CDLL(name, use_errno=True)
        l.seccomp_init.restype = ctypes.c_void_p; l.seccomp_init.argtypes = [ctypes.c_uint32]
        l.seccomp_release.argtypes = [ctypes.c_void_p]
        l.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        l.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p]
        l.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _lib = l
    return _lib


def seccomp_available():
    return _seccomp() is not None


def build_bpf(allow_userns=False):
    """-> raw BPF program bytes (what `bwrap --seccomp` reads), deny-list over an allow-by-default base. Raises RuntimeError if libseccomp is missing."""
    l = _seccomp()
    if l is None: raise RuntimeError("libseccomp not available")
    ctx = l.seccomp_init(_ALLOW)
    if not ctx: raise RuntimeError("seccomp_init failed")
    try:
        def add(action, name, cmp=None):
            nr = l.seccomp_syscall_resolve_name(name.encode())
            if nr < 0: return                                                 # not on this architecture
            arr = (_Cmp * 1)(cmp) if cmp else None
            rc = l.seccomp_rule_add_array(ctx, action, nr, 1 if cmp else 0, ctypes.cast(arr, ctypes.c_void_p) if cmp else None)
            if rc: raise RuntimeError(f"seccomp rule {name} failed: {rc}")
        eperm = _ERRNO | 1
        for n in DENY:
            if allow_userns and n in ("unshare", "setns", "mount", "umount", "umount2", "pivot_root", "chroot"): continue
            add(eperm, n)
        for n in ENOSYS_ONLY: add(_ERRNO | 38, n)
        for fam in BAD_FAMILIES: add(eperm, "socket", _Cmp(0, _EQ, fam, 0))
        add(eperm, "socketpair", _Cmp(0, _EQ, 16, 0))
        if not allow_userns:
            for flag in (0x10000000, 0x00020000, 0x08000000, 0x40000000, 0x20000000, 0x04000000, 0x02000000, CLONE_NEWTIME):
                add(eperm, "clone", _Cmp(0, _MASKED_EQ, flag, flag))
        r, w = os.pipe()
        try:
            if l.seccomp_export_bpf(ctx, w): raise RuntimeError("seccomp_export_bpf failed")
            os.close(w); w = -1; buf = b""
            while True:
                d = os.read(r, 65536)
                if not d: break
                buf += d
        finally:
            os.close(r)
            if w >= 0: os.close(w)
        return buf
    finally:
        l.seccomp_release(ctx)


def bpf_fd(allow_userns=False):
    """A read-only fd positioned at 0 holding the BPF program (pass via Popen pass_fds)."""
    f = tempfile.TemporaryFile(); f.write(build_bpf(allow_userns)); f.flush(); f.seek(0)
    fd = os.dup(f.fileno()); f.close(); os.set_inheritable(fd, True); return fd


_scope = {}


def scope_available():
    """Can this process create a user-delegated cgroup scope with memory+pids limits? (probed once, really)"""
    if "ok" not in _scope:
        ok = False
        if shutil.which("systemd-run"):
            try:
                r = subprocess.run(["systemd-run", "--user", "--scope", "--quiet", "-p", "MemoryMax=64M", "-p", "TasksMax=32", "--", "/usr/bin/true"], capture_output=True, timeout=15); ok = r.returncode == 0
            except (OSError, subprocess.TimeoutExpired): ok = False
        _scope["ok"] = ok
    return _scope["ok"]


def scope_prefix(mem_mb=None, tasks=None, cpu_pct=None, name=None, launcher=None):
    """Command prefix that runs the rest inside a resource-limited cgroup scope; `launcher` (list) overrides it entirely (root deployments: sudo -n systemd-run -p DynamicUser=yes ...). [] when unavailable."""
    if launcher: return list(launcher)
    if not scope_available(): return []
    c = ["systemd-run", "--user", "--scope", "--quiet", "--collect"]
    if name: c += ["--unit", name]
    if mem_mb: c += ["-p", f"MemoryMax={int(mem_mb)}M", "-p", "MemorySwapMax=0", "-p", f"MemoryHigh={int(mem_mb * 0.9)}M"]
    if tasks: c += ["-p", f"TasksMax={int(tasks)}"]
    if cpu_pct: c += ["-p", f"CPUQuota={int(cpu_pct)}%"]
    return c + ["--"]


# ------------------------------------------------------------------ cgroup v2 (direct; works for any unit with Delegate=yes or a systemd user session)
CGROOT = "/sys/fs/cgroup"


def _own_cg():
    for line in open("/proc/self/cgroup").read().splitlines():
        if line.startswith("0::"): return CGROOT + line[3:]
    return None


class Cgroups:
    """Per-workload cgroup v2 limits without root and without systemd-run: mkdir a child of a delegated subtree, set memory.max / memory.swap.max / pids.max / cpu.max, and move the child in
    from its own preexec (so the limit applies before its first instruction). Hierarchy: <base>/<name> (limits) with the supervisor itself parked in <base>/_main (cgroup v2 'no internal processes')."""
    def __init__(self, base=None):
        self.base = base; self.ok = False; self.why = ""
        try:
            own = base or _own_cg()
            if own is None or not os.path.isdir(own): self.why = "no cgroup v2"; return
            if not base:
                self.base = self._carve(own)
                if self.base is None: self.why = self.why or "no writable delegated cgroup subtree"; return
            avail = open(os.path.join(self.base, "cgroup.controllers")).read().split()
            want = [c for c in ("memory", "pids", "cpu") if c in avail]
            if "memory" not in want or "pids" not in want: self.why = f"controllers unavailable: {avail}"; return
            with open(os.path.join(self.base, "cgroup.subtree_control"), "w") as f: f.write(" ".join("+" + c for c in want))
            self.controllers = want; self.ok = True
        except OSError as e:
            self.why = f"{type(e).__name__}: {e}"

    def _carve(self, own):
        """Find a delegated cgroup we can own: try our own cgroup (fine for a Delegate=yes unit whose tree is ours), else carve `board-<pid>` out of the nearest writable ancestor (e.g. a user session)."""
        cand = [own] + [os.path.dirname(own)] * 0
        d = own
        for depth in range(4):
            try:
                if depth == 0: node = d
                else: node = os.path.join(d, f"board-{os.getpid()}"); os.makedirs(node, exist_ok=True)
                main = os.path.join(node, "_main"); os.makedirs(main, exist_ok=True)
                with open(os.path.join(main, "cgroup.procs"), "w") as f: f.write(str(os.getpid()))
                avail = open(os.path.join(node, "cgroup.controllers")).read().split()
                if "memory" in avail and "pids" in avail:
                    with open(os.path.join(node, "cgroup.subtree_control"), "w") as f: f.write(" ".join("+" + c for c in ("memory", "pids", "cpu") if c in avail))
                    return node
            except OSError as e: self.why = f"{type(e).__name__}: {e}"
            d = os.path.dirname(d)
            if not d.startswith(CGROOT + "/"): break
        return None

    def make(self, name, mem_mb=None, tasks=None, cpu_pct=None):
        """-> cgroup dir path. Raises OSError if unavailable."""
        if not self.ok: raise OSError("cgroups unavailable: " + self.why)
        path = os.path.join(self.base, name); os.makedirs(path, exist_ok=True)
        def w(k, v):
            with open(os.path.join(path, k), "w") as f: f.write(str(v))
        if mem_mb:
            w("memory.max", int(mem_mb) << 20); w("memory.swap.max", 0); w("memory.high", int(int(mem_mb) * 0.92) << 20)
            try: w("memory.oom.group", 1)
            except OSError: pass
        if tasks: w("pids.max", int(tasks))
        if cpu_pct and "cpu" in self.controllers: w("cpu.max", f"{int(cpu_pct) * 1000} 100000")
        return path

    @staticmethod
    def enter(path):
        """preexec_fn factory: the child moves itself into `path` before exec."""
        procs = os.path.join(path, "cgroup.procs")
        def f():
            fd = os.open(procs, os.O_WRONLY); os.write(fd, b"0"); os.close(fd)
        return f

    @staticmethod
    def stats(path):
        o = {}
        for k in ("memory.peak", "memory.current", "pids.current"):
            try: o[k] = int(open(os.path.join(path, k)).read())
            except (OSError, ValueError): pass
        try: o["oom_kill"] = int(dict(l.split() for l in open(os.path.join(path, "memory.events")).read().splitlines()).get("oom_kill", 0))
        except (OSError, ValueError): pass
        return o

    def leaf(self, path):
        """Make `path` an interior node (controllers delegated down) and return a fresh `path/_main` leaf the workload enters: v2 forbids processes in a cgroup that delegates controllers."""
        with open(os.path.join(path, "cgroup.subtree_control"), "w") as f: f.write(" ".join("+" + c for c in self.controllers))
        leaf = os.path.join(path, "_main"); os.makedirs(leaf, exist_ok=True); return leaf

    @staticmethod
    def destroy(path):
        """Kill everything in `path` (and below) and remove the tree."""
        try:
            with open(os.path.join(path, "cgroup.kill"), "w") as f: f.write("1")
        except OSError: pass
        import time
        for _ in range(60):
            for root, dirs, _f in os.walk(path, topdown=False):
                try: os.rmdir(root)
                except OSError: pass
            if not os.path.exists(path): return
            time.sleep(0.05)
