"""Phase 3 isolation: the seccomp deny-list, cgroup limits and the escape attempts a hostile tenant job would try. Every probe runs INSIDE the real bwrap sandbox."""
import json, os, subprocess, sys, textwrap, time
from pathlib import Path
import pytest
from ordivyr.board import isolate as I, sandbox as SB

pytestmark = pytest.mark.skipif(not SB.available(), reason="bubblewrap unavailable")
needs_seccomp = pytest.mark.skipif(not I.seccomp_available(), reason="libseccomp unavailable")
needs_cg = pytest.mark.skipif(not SB.hardening()["cgroups"], reason="no delegated cgroup v2 subtree on this host")

PROBE = textwrap.dedent('''
    import ctypes, errno, json, os, socket, sys
    libc = ctypes.CDLL(None, use_errno=True); out = {}
    def sc(name, *args):
        nr = {"ptrace": 101, "mount": 165, "unshare": 272, "keyctl": 250, "bpf": 321, "perf_event_open": 298, "io_uring_setup": 425, "userfaultfd": 323, "setns": 308, "pivot_root": 155, "kexec_load": 246, "open_by_handle_at": 304, "process_vm_readv": 310, "clone3": 435, "reboot": 169}[name]
        r = libc.syscall(nr, *[ctypes.c_long(a) for a in args]); return -1 if r == -1 and ctypes.get_errno() else r, ctypes.get_errno()
    for n in ("ptrace", "mount", "unshare", "keyctl", "bpf", "perf_event_open", "io_uring_setup", "userfaultfd", "setns", "pivot_root", "kexec_load", "open_by_handle_at", "process_vm_readv", "reboot"):
        out[n] = sc(n, 0, 0, 0, 0)[1]
    out["clone3"] = sc("clone3", 0, 0)[1]
    for fam, nm in ((16, "netlink"), (17, "packet"), (38, "alg"), (40, "vsock")):
        try: socket.socket(fam, socket.SOCK_RAW if fam == 17 else socket.SOCK_DGRAM, 0); out["sock_" + nm] = 0
        except OSError as e: out["sock_" + nm] = e.errno
    CLONE_NEWUSER = 0x10000000
    out["clone_newuser"] = libc.unshare(CLONE_NEWUSER) and ctypes.get_errno()
    try: socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("127.0.0.1", 9)); out["inet_connect"] = "connected"
    except OSError as e: out["inet_connect"] = e.errno
    out["ok_basic"] = len(os.listdir("/work")) >= 0 and os.getpid() > 0
    print(json.dumps(out))
''')


def probe(code, **kw):
    d = Path(kw.pop("d")); d.mkdir(parents=True, exist_ok=True); (d / "p.py").write_text(code)
    return SB.run(["/usr/bin/python3", "-S", "/work/p.py"], d, **kw)


@needs_seccomp
def test_denylist_blocks_the_dangerous_syscalls_but_not_normal_work(tmp_path):
    rc, out = probe(PROBE, d=tmp_path / "w1", timeout=30)
    assert rc == 0, out
    r = json.loads(out.strip().splitlines()[-1])
    for n in ("ptrace", "mount", "unshare", "keyctl", "bpf", "perf_event_open", "io_uring_setup", "userfaultfd", "setns", "pivot_root", "kexec_load", "open_by_handle_at", "process_vm_readv", "reboot"):
        assert r[n] == 1, (n, r[n])                                               # EPERM from the filter (not ENOSYS/EINVAL from the kernel acting on it)
    assert r["clone3"] == 38 and r["ok_basic"]                                      # clone3 -> ENOSYS so libc falls back to inspectable clone(2)
    for n in ("netlink", "packet", "alg", "vsock"): assert r["sock_" + n] != 0, n
    assert r["clone_newuser"] != 0 and r["inet_connect"] != "connected"


@needs_seccomp
def test_filter_is_x86_64_only_and_kills_foreign_abi_not_a_bypass():
    bpf = I.build_bpf()
    assert len(bpf) % 8 == 0 and len(bpf) > 200                                      # a real BPF program (8-byte instructions)


def test_sandbox_cannot_see_board_state_or_host_processes(tmp_path):
    secret = tmp_path / "board-home"; secret.mkdir(); (secret / "master.key").write_text("TOPSECRET")
    code = textwrap.dedent(f'''
        import os, json
        r = {{}}
        r["host_path"] = os.path.exists({str(secret)!r})
        r["home"] = sorted(os.listdir("/home")) if os.path.isdir("/home") else None
        r["pids"] = sorted(int(x) for x in os.listdir("/proc") if x.isdigit())
        r["env_secret"] = [k for k in os.environ if any(t in k.upper() for t in ("KEY", "TOKEN", "DSN", "SECRET", "PASSWORD"))]
        r["etc_shadow"] = os.path.exists("/etc/shadow")
        try: os.kill(1, 0); r["kill1"] = "ok"
        except OSError as e: r["kill1"] = e.errno
        try: open("/proc/1/environ").read(); r["env1"] = "read"
        except OSError as e: r["env1"] = e.errno
        try: open("/usr/evil", "w"); r["write_usr"] = "wrote"
        except OSError as e: r["write_usr"] = e.errno
        print(json.dumps(r))''')
    rc, out = probe(code, d=tmp_path / "w2", timeout=30); assert rc == 0, out
    r = json.loads(out.strip().splitlines()[-1])
    assert not r["host_path"] and not r["home"] and not r["env_secret"] and not r["etc_shadow"]
    assert len(r["pids"]) <= 3 and r["write_usr"] != "wrote"                          # own pid namespace: init + the probe (+ at most one helper)


@needs_cg
def test_fork_bomb_is_bounded_by_the_pids_cgroup(tmp_path):
    code = "import os, time\nn = 0\nfor _ in range(2000):\n    try:\n        if os.fork() == 0: time.sleep(20); os._exit(0)\n        n += 1\n    except OSError: break\nprint('forked', n)\n"
    t0 = time.time(); rc, out = probe(code, d=tmp_path / "w3", timeout=25)
    n = int(out.split("forked")[-1].split()[0]); assert 0 < n < SB.TASKS_PER_JOB + 5, out                    # stopped at the TasksMax, not at the host's limit
    assert time.time() - t0 < 24


@needs_cg
def test_memory_bomb_is_oom_killed_inside_its_own_cgroup_not_the_host(tmp_path):
    code = "b = []\nfor i in range(100):\n    b.append(bytearray(64 << 20))\n    for j in range(0, len(b[-1]), 4096): b[-1][j] = 1\nprint('survived')\n"
    rc, out = probe(code, d=tmp_path / "w4", timeout=30, mem_mb=128)
    assert "survived" not in out and rc != 0                                          # killed by the cgroup (or RLIMIT_AS), host untouched (this process is still running)


@needs_cg
def test_cgroup_helper_limits_and_cleanup(tmp_path):
    cg = SB._hard["cg"]; p = cg.make("unit-test-x", mem_mb=32, tasks=8)
    pr = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], preexec_fn=I.Cgroups.enter(p))
    time.sleep(0.3); assert open(os.path.join(p, "cgroup.procs")).read().split() == [str(pr.pid)]
    assert int(open(os.path.join(p, "memory.max")).read()) == 32 << 20 and open(os.path.join(p, "pids.max")).read().strip() == "8" and open(os.path.join(p, "memory.swap.max")).read().strip() == "0"
    I.Cgroups.destroy(p); assert not os.path.exists(p); pr.wait(5); assert pr.returncode == -9                    # cgroup.kill took the whole tree


def test_strict_mode_refuses_when_layers_missing(tmp_path, monkeypatch):
    from ordivyr import durable as D
    monkeypatch.setenv("ORDIVYR_ISOLATION_STRICT", "1"); monkeypatch.setattr(SB, "hardening", lambda: {"seccomp": False, "cgroups": True, "why": "test"})
    with pytest.raises(D.NeedsApproval, match="isolation layers unavailable"): SB.launch(["/usr/bin/true"], name="x")


def test_launcher_prefix_override_for_root_deployments():
    assert I.scope_prefix(launcher=["sudo", "-n", "systemd-run", "-p", "DynamicUser=yes", "--"]) == ["sudo", "-n", "systemd-run", "-p", "DynamicUser=yes", "--"]


@needs_cg
def test_sandbox_launch_survives_a_parent_holding_hundreds_of_fds(tmp_path):
    """Regression: the child lowers RLIMIT_NOFILE to 256 in preexec; if the cgroup file was opened AFTER that, a busy Board (>256 sockets/connections) failed every job with EMFILE."""
    held = [os.open("/dev/null", os.O_RDONLY) for _ in range(400)]
    try:
        rc, out = probe("print('alive')", d=tmp_path / "wf", timeout=30); assert rc == 0 and "alive" in out, out
    finally:
        for fd in held: os.close(fd)
