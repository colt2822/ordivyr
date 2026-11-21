"""Isolation for every harness invocation and every grader run.

  bwrap  : read-only /usr + /etc, tmpfs /tmp and /home, ONLY the lane folders writable, real HOME never mounted, no `--yolo`-style bypass anywhere.
           Network is shared with the host (the model server lives on loopback) - this is a recorded difference: harness network egress is NOT blocked.
           The grader runs with --unshare-net (no network at all).
  scope  : `systemd-run --user --scope` per invocation: the whole process tree is one cgroup -> accounting (cpu, memory.peak) and orphan detection/kill.
"""
from __future__ import annotations
import os, subprocess, sys
from pathlib import Path

RO_SYS = ["/usr", "/etc"]
SCOPERUN = str(Path(__file__).with_name("scoperun.py"))


def _norm(x): return (x, x) if isinstance(x, str) else tuple(x)


def bwrap_argv(lane, inv, net=True):
    a = ["bwrap", "--die-with-parent", "--unshare-all", "--new-session"] + (["--share-net"] if net else [])
    for p in RO_SYS: a += ["--ro-bind", p, p]
    a += ["--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/sbin", "/sbin", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home"]
    a += ["--bind", str(lane.home), getattr(inv, "home", "/arena-home"), "--bind", str(lane.ws), "/lane", "--bind", str(lane.escape), "/arena-escape"]
    for x in inv.ro:
        src, dst = _norm(x); a += ["--ro-bind", src, dst]
    for x in getattr(inv, "rw", []):
        src, dst = _norm(x); a += ["--bind", src, dst]
    a += ["--clearenv"]
    for k, v in inv.env.items(): a += ["--setenv", k, v]
    a += ["--chdir", "/lane/w", "--"] + list(inv.argv)
    return a


def scope_cmd(run_id, bw, stats, timeout, stdout, stderr, mem_max="16G"):
    return ["systemd-run", "--user", "--scope", "--collect", "-q", "--unit", f"arena-{run_id}", "-p", f"MemoryMax={mem_max}", "-p", "TasksMax=4096", "--",
            sys.executable, SCOPERUN, "--stats", str(stats), "--timeout", str(timeout), "--stdout", str(stdout), "--stderr", str(stderr), "--"] + bw


def kill_scope(run_id):
    """Simulated machine/process crash: SIGKILL every process of the invocation at once (no graceful shutdown for anything)."""
    return subprocess.run(["systemctl", "--user", "kill", "--signal=SIGKILL", f"arena-{run_id}.scope"], capture_output=True, text=True, timeout=30).returncode == 0


def scope_active(run_id):
    return subprocess.run(["systemctl", "--user", "is-active", f"arena-{run_id}.scope"], capture_output=True, text=True, timeout=30).stdout.strip() in ("active", "activating", "deactivating")


def pytest_env():
    """The grader needs pytest, which lives in the user site-packages on this machine: bind that directory read-only and point PYTHONPATH at it."""
    import importlib.util; sp = importlib.util.find_spec("pytest")
    if sp is None: raise RuntimeError("pytest is required for grading")
    return str(Path(sp.origin).resolve().parents[1])


def run_pytest(workdir, hidden, timeout=90):
    """Grade in a FRESH copy: agent output + hidden tests, no network, nothing outside the copy writable. -> (passed, tail, summary)."""
    import shutil, tempfile
    root = Path(tempfile.mkdtemp(prefix="arena-grade-")); g = root / "g"
    try:
        shutil.copytree(workdir, g, symlinks=False, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
        for k, v in hidden.items(): (g / k).write_text(v)
        site = pytest_env(); a = ["bwrap", "--die-with-parent", "--unshare-all", "--new-session"]
        for p in RO_SYS: a += ["--ro-bind", p, p]
        a += ["--ro-bind", site, "/pytest-site"]                  # a FIXED mount point: binding at the host path breaks when that path lies under /tmp (the tmpfs below hides it), e.g. a venv in /tmp
        a += ["--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(g), "/g", "--chdir", "/g", "--clearenv",
              "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "PYTHONPATH", "/pytest-site:/g", "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--setenv", "HOME", "/tmp", "--",
              "/usr/bin/python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x", "--no-header", "--rootdir", "/g", "/g"]
        try: p = subprocess.run(a, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired: return False, "grader timeout", "timeout"
        tail = (p.stdout + p.stderr)[-600:]; summ = tail.strip().splitlines()[-1] if tail.strip() else ""
        return p.returncode == 0, tail, summ
    finally: shutil.rmtree(root, ignore_errors=True)
