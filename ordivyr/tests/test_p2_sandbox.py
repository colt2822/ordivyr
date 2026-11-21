"""P2 sandbox: escape and privilege-boundary tests against REAL bubblewrap runs (skipped if unprivileged namespaces are unavailable on the host)."""
import json, os, socket, subprocess, sys, threading, time
from pathlib import Path
import pytest
from ordivyr.hosting import sandbox as SB
from ordivyr.hosting.contracts import ExecSpec, Executor
from ordivyr.hosting import modes

pytestmark = pytest.mark.skipif(not SB.available(), reason="bubblewrap/user namespaces unavailable")


@pytest.fixture
def box(tmp_path):
    ex = SB.BubblewrapExecutor(tmp_path / "tenants", "acme", audit_path=str(tmp_path / "audit.jsonl")); wd = tmp_path / "tenants" / "acme" / "run1"; wd.mkdir(parents=True); return ex, wd, tmp_path


def sh(ex, wd, code, **kw):
    spec = ExecSpec(["/usr/bin/python3", "-I", "-c", code], str(wd), timeout_s=kw.pop("timeout_s", 20), **kw); h = ex.start(spec); h.wait(30)
    return h, (wd / ".stdout").read_text() if (wd / ".stdout").exists() else "", (wd / ".stderr").read_text() if (wd / ".stderr").exists() else ""


def test_contract_and_registration(box):
    ex, wd, _ = box; assert isinstance(ex, Executor) and ex.isolation == "container"
    h, out, err = sh(ex, wd, "print(6*7)"); assert h.rc == 0 and out.strip() == "42"


def test_hosted_mode_accepts_this_backend_but_not_process_isolation(tmp_path):
    from ordivyr.hosting import registry; registry.register("executor", "bwrap-test", lambda spec=None, **kw: SB.BubblewrapExecutor(tmp_path / "t", "acme"))
    assert modes.build({"mode": "hosted", "executor": {"adapter": "bwrap-test"}}, tmp_path).executor.isolation == "container"


def test_host_filesystem_secrets_and_other_tenants_are_invisible(box):
    ex, wd, tmp = box; (tmp / "tenants" / "beta").mkdir(); (tmp / "tenants" / "beta" / "secret.txt").write_text("BETA-SECRET")
    secret = Path.home() / ".ordivyr_escape_probe"; secret.write_text("HOST-SECRET")
    try:
        h, out, err = sh(ex, wd, f"""
import os, glob
print(sorted(os.listdir('/')))
for p in ({str(secret)!r}, {str(tmp / 'tenants' / 'beta' / 'secret.txt')!r}, '/etc/shadow', '/root', '/home'):
    print(p, os.path.exists(p))
print(glob.glob('/work/../*'))
""")
    finally: secret.unlink()
    assert "HOST-SECRET" not in out and "BETA-SECRET" not in out
    assert "False" in out and "True" not in out.split("\n", 1)[1].replace("/work", "")           # none of the probed host paths exist inside


def test_root_is_read_only_and_writes_stay_in_the_work_dir(box):
    ex, wd, tmp = box
    h, out, err = sh(ex, wd, """
import os
def tryw(p):
    try: open(p, 'w').write('x'); return 'WROTE'
    except OSError as e: return type(e).__name__
print(tryw('/usr/evil'), tryw('/etc/evil'), tryw('/evil'), tryw('/work/ok'), tryw('/tmp/ok'))
""")
    r = out.split()
    assert all(x != "WROTE" and "Error" in x for x in r[:3]); assert r[3] == "WROTE" and (wd / "ok").exists()
    assert not (tmp / "ok").exists() and not Path("/tmp/ok").exists() and not Path("/evil").exists()                      # /tmp inside is a private tmpfs


def test_environment_is_empty_and_host_secrets_do_not_leak(box, monkeypatch):
    ex, wd, _ = box; monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leakme"); monkeypatch.setenv("ANTHROPIC_API_KEY", "leakme2")
    h, out, err = sh(ex, wd, "import os; print(sorted(os.environ))", env={"TASK_ID": "7"})
    assert "leakme" not in out and "AWS" not in out and "ANTHROPIC" not in out and "TASK_ID" in out


def test_no_network_by_default_even_if_the_spec_asks_for_it(box):
    ex, wd, _ = box; srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]; hits = []
    threading.Thread(target=lambda: [hits.append(srv.accept()) for _ in range(1)], daemon=True).start()
    h, out, err = sh(ex, wd, f"""
import socket
s = socket.socket(); s.settimeout(3)
try: s.connect(('127.0.0.1', {port})); print('CONNECTED')
except OSError as e: print('blocked', type(e).__name__)
""", network="inherit")
    assert "blocked" in out and "CONNECTED" not in out and not hits; srv.close()
    assert "share-net" not in json.dumps(open(ex.audit_path).read()) and '"network": "none"' in open(ex.audit_path).read()


def test_network_only_when_the_operator_enables_it(tmp_path):
    ex = SB.BubblewrapExecutor(tmp_path / "t", "acme", allow_network=True); wd = tmp_path / "t" / "acme" / "r"; wd.mkdir(parents=True)
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]
    h, out, err = sh(ex, wd, f"import socket; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', {port})); print('CONNECTED')", network="inherit")
    assert "CONNECTED" in out; srv.close()


def test_pid_namespace_hides_and_cannot_signal_host_processes(box):
    ex, wd, _ = box; victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        h, out, err = sh(ex, wd, f"""
import os, signal
print(len([x for x in os.listdir('/proc') if x.isdigit()]) < 10, os.getpid() < 50)
try: os.kill({victim.pid}, signal.SIGKILL); print('SIGNALLED')
except OSError as e: print('cannot', type(e).__name__)
""")
        assert "True True" in out and "SIGNALLED" not in out and victim.poll() is None
    finally: victim.kill()


def test_capabilities_dropped_and_privileged_operations_fail(box):
    ex, wd, _ = box
    h, out, err = sh(ex, wd, """
import os, ctypes
st = open('/proc/self/status').read()
print([l for l in st.splitlines() if l.startswith(('CapEff', 'CapPrm', 'NoNewPrivs'))])
libc = ctypes.CDLL(None, use_errno=True)
print('mount', libc.mount(b'none', b'/work', b'tmpfs', 0, None), ctypes.get_errno())
print('unshare-userns', libc.unshare(0x10000000), ctypes.get_errno())     # CLONE_NEWUSER: nested user namespaces are disabled
print('chroot', libc.chroot(b'/work'), ctypes.get_errno())
try: open('/proc/sysrq-trigger', 'w').write('b'); print('SYSRQ')
except OSError as e: print('sysrq-blocked')
""")
    assert "CapEff': '0000000000000000'" in out.replace('\t', "'").replace("CapEff:", "CapEff':") or "0000000000000000" in out
    assert "mount -1" in out and "chroot -1" in out and "unshare-userns -1" in out and "SYSRQ" not in out


def test_memory_limit_is_enforced(box):
    ex, wd, _ = box
    h, out, err = sh(ex, wd, "x = bytearray(900 * 1024 * 1024); print('ALLOCATED')", max_memory_mb=256)
    assert "ALLOCATED" not in out and (h.rc != 0 or "MemoryError" in err)


def test_cpu_and_wall_limits_kill_runaways_and_leave_no_processes(box):
    ex, wd, _ = box; t = time.time()
    h = ex.start(ExecSpec(["/usr/bin/python3", "-I", "-c", "import subprocess, time\nsubprocess.Popen(['/usr/bin/sleep','300'])\nwhile True: pass"], str(wd), timeout_s=2, max_cpu_s=60)); h.wait(15)
    assert time.time() - t < 10 and h.killed == "timeout" and h.rc != 0; time.sleep(0.5)
    left = subprocess.run(["pgrep", "-f", "sleep 300"], capture_output=True, text=True).stdout.split(); assert left == [], f"leftover processes: {left}"


def test_cpu_rlimit_kills_a_tight_loop_before_the_wall_clock(box):
    ex, wd, _ = box; t = time.time(); h, out, err = sh(ex, wd, "while True: pass", max_cpu_s=1, timeout_s=30); assert time.time() - t < 15 and h.rc != 0 and h.killed is None


def test_output_size_is_capped(tmp_path):
    ex = SB.BubblewrapExecutor(tmp_path / "t", "acme", max_out_mb=1); wd = tmp_path / "t" / "acme" / "r"; wd.mkdir(parents=True)
    h, out, err = sh(ex, wd, "open('/work/big','wb').write(b'x' * (50 * 1024 * 1024))"); assert h.rc != 0 and (wd / "big").stat().st_size <= 1024 * 1024


def test_process_limit_contains_a_fork_bomb(box):
    ex, wd, _ = box
    h, out, err = sh(ex, wd, """
import os
n = 0
try:
    while n < 5000:
        pid = os.fork()
        if pid == 0:
            import time; time.sleep(5); os._exit(0)
        n += 1
except OSError: pass
print('forks', n)
""", max_procs=40, timeout_s=15)
    forks = int(out.split("forks")[1].split()[0]); assert forks < 200


def test_cannot_use_another_tenants_directory_or_escape_the_base(tmp_path):
    ex = SB.BubblewrapExecutor(tmp_path / "t", "acme"); (tmp_path / "t" / "beta").mkdir(parents=True)
    for bad in (tmp_path / "t" / "beta", tmp_path, Path("/"), tmp_path / "t" / "acme" / ".." / "beta"):
        with pytest.raises(SB.SandboxError): ex.start(ExecSpec(["/usr/bin/true"], str(bad)))
    for bad in ("../x", "a/b", ".hidden", ""):
        with pytest.raises(SB.SandboxError): SB.BubblewrapExecutor(tmp_path / "t", bad)


def test_symlink_in_workdir_cannot_reach_host_files(box):
    ex, wd, tmp = box; target = tmp / "hostfile.txt"; target.write_text("HOSTDATA"); (wd / "link").symlink_to(target)
    h, out, err = sh(ex, wd, "print(open('/work/link').read())"); assert "HOSTDATA" not in out and h.rc != 0


def test_audit_log_records_start_end_limits_and_kills(box):
    ex, wd, tmp = box; sh(ex, wd, "print(1)"); h = ex.start(ExecSpec(["/usr/bin/sleep", "30"], str(wd), timeout_s=1)); h.wait(10)
    recs = [json.loads(l) for l in open(tmp / "audit.jsonl")]; assert [r["ev"] for r in recs] == ["start", "end", "start", "end"]
    assert recs[0]["tenant"] == "acme" and recs[0]["network"] == "none" and recs[0]["mem_mb"] == 512 and recs[3]["killed"] == "timeout"
