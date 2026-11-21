"""Runs one harness invocation INSIDE a transient systemd user scope (started by the engine with `systemd-run --user --scope`).

  python -m ordivyr.arena.scoperun --stats FILE --timeout S [--stdout F] [--stderr F] -- CMD...

Starts CMD in its own session, enforces the wall-clock timeout, then (before the scope disappears) records the scope's cgroup accounting
(cpu.stat usage, memory.peak, pids) and lists every process still alive in the scope after CMD exited = ORPHANS. Orphans are killed one by one
(never the whole cgroup, so this process can still write its stats). Stdlib only; no dependency on the rest of ordivyr.
"""
from __future__ import annotations
import argparse, json, os, signal, subprocess, sys, time


def cg_dir():
    rel = open("/proc/self/cgroup").read().strip().split(":")[-1]
    return "/sys/fs/cgroup" + rel


def read(path, default=None):
    try: return open(path).read()
    except OSError: return default


def procs(cg):
    return [int(x) for x in (read(cg + "/cgroup.procs", "") or "").split() if x.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--stats", required=True); ap.add_argument("--timeout", type=float, default=600); ap.add_argument("--stdout"); ap.add_argument("--stderr")
    ap.add_argument("--grace", type=float, default=1.5); ap.add_argument("cmd", nargs=argparse.REMAINDER); a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd; cg = cg_dir(); me = os.getpid(); t0 = time.time()
    so = open(a.stdout, "wb") if a.stdout else subprocess.DEVNULL; se = open(a.stderr, "wb") if a.stderr else subprocess.DEVNULL
    p = subprocess.Popen(cmd, stdout=so, stderr=se, stdin=subprocess.DEVNULL, start_new_session=True)
    timed_out = False
    try: rc = p.wait(a.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try: os.killpg(p.pid, signal.SIGKILL)
        except OSError: pass
        rc = p.wait()
    wall = time.time() - t0
    time.sleep(a.grace)                                            # daemons that detach on exit show up here
    left = [x for x in procs(cg) if x != me]
    cpu = {}
    for line in (read(cg + "/cpu.stat", "") or "").splitlines():
        k, _, v = line.partition(" ")
        if v.strip().isdigit(): cpu[k] = int(v)
    peak = read(cg + "/memory.peak"); orphans = []
    for pid in left:
        try: orphans.append({"pid": pid, "cmd": open(f"/proc/{pid}/cmdline").read().replace("\0", " ")[:160]})
        except OSError: pass
    for o in orphans:
        try: os.kill(o["pid"], signal.SIGKILL)
        except OSError: pass
    st = {"rc": rc, "timed_out": timed_out, "wall_s": round(wall, 3), "cpu_user_s": cpu.get("user_usec", 0) / 1e6, "cpu_sys_s": cpu.get("system_usec", 0) / 1e6,
          "mem_peak_mb": round(int(peak) / 1048576, 1) if peak and peak.strip().isdigit() else None, "orphans": orphans}
    open(a.stats, "w").write(json.dumps(st))
    return 0


if __name__ == "__main__": sys.exit(main())
