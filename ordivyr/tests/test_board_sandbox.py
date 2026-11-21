"""Adversarial tests for the namespace sandbox. Each test plays a hostile tenant: the code under test runs INSIDE the sandbox and tries to reach host secrets, other tenants, the network or the host."""
import json, os, socket, subprocess, sys, threading, time, textwrap, pytest
from pathlib import Path
from ordivyr.board import sandbox as SB, contract as C, runtime_adapter as RA
from ordivyr.board.service import Forbidden, Unavailable
from ordivyr.tests.board_support import World, wait_for

pytestmark = pytest.mark.skipif(not SB.available(), reason="bubblewrap sandbox not available")


def py(code, wd, **kw): return SB.run(["/usr/bin/python3", "-S", "-c", textwrap.dedent(code)], wd, **kw)


def test_host_filesystem_secrets_and_other_tenants_are_invisible(tmp_path):
    host = tmp_path / "host"; (host / "gw").mkdir(parents=True); (host / "gw" / "secrets.json").write_text('{"k":"sk-live-SECRET"}'); (host / "tenantB").mkdir(); (host / "tenantB" / "plan.txt").write_text("B-SECRET")
    (host / "board.db").write_text("DB"); (Path.home() / ".bwrap-probe-secret").write_text("HOME-SECRET")
    try:
        rc, out = py(f"""
            import os
            hits = []
            for p in ({str(host / 'gw' / 'secrets.json')!r}, {str(host / 'tenantB' / 'plan.txt')!r}, {str(host / 'board.db')!r}, {str(Path.home() / '.bwrap-probe-secret')!r}, '/etc/passwd', '/etc/shadow', '/root', '/home', '/var', '/run/user', '/proc/1/environ'):
                try:
                    open(p).read() if os.path.isfile(p) else os.listdir(p); hits.append(p)
                except Exception: pass
            print('HITS', hits); print('ROOT', sorted(os.listdir('/')))""", tmp_path / "wsA")
        assert rc == 0, out; assert "HITS []" in out or "HITS ['/proc/1/environ']" in out, out          # /proc/1 is the SANDBOX's own init, not the host's
        assert "/home" not in out.split("ROOT")[1] and "var" not in out.split("ROOT")[1]
    finally: (Path.home() / ".bwrap-probe-secret").unlink(missing_ok=True)


def test_writes_are_confined_to_the_workspace_and_tmp_is_private(tmp_path):
    rc, out = py("""
        import os
        res = {}
        for p in ('/usr/evil', '/opt/code/ordivyr/evil.py', '/etc/evil', '/evil', '/run/evil', '/ho' + 'me/evil'):
            try: open(p, 'w').write('x'); res[p] = 'WROTE'
            except Exception as e: res[p] = 'blocked'
        open('/work/ok.txt', 'w').write('mine'); open('/tmp/priv.txt', 'w').write('tmp')
        print(res)""", tmp_path / "ws")
    assert rc == 0 and "WROTE" not in out, out
    assert (tmp_path / "ws" / "ok.txt").read_text() == "mine" and not Path("/tmp/priv.txt").exists()
    assert not Path("/opt/code/ordivyr/evil.py").exists()


def test_no_network_not_even_host_loopback_or_abstract_sockets(tmp_path):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]
    try:
        rc, out = py(f"""
            import socket
            r = {{}}
            for name, addr in (('host-loopback', ('127.0.0.1', {port})), ('internet', ('1.1.1.1', 80)), ('dns', ('8.8.8.8', 53))):
                try: socket.create_connection(addr, 2); r[name] = 'CONNECTED'
                except Exception as e: r[name] = 'blocked'
            print(r)""", tmp_path / "ws")
        assert rc == 0 and "CONNECTED" not in out, out
        srv.settimeout(0.3)
        with pytest.raises(socket.timeout): srv.accept()                    # nothing reached the host listener
    finally: srv.close()


def test_process_and_environment_isolation(tmp_path, monkeypatch):
    monkeypatch.setenv("HOST_SECRET_TOKEN", "leak-me"); monkeypatch.setenv("ORDIVYR_GATEWAY_HOME", "/host/gw")
    rc, out = py(f"""
        import os, signal
        print('ENV', 'HOST_SECRET_TOKEN' in os.environ, 'ORDIVYR_GATEWAY_HOME' in os.environ, 'HOME' in os.environ)
        print('PIDS', sorted(int(x) for x in os.listdir('/proc') if x.isdigit()))
        try: os.kill({os.getpid()}, 0); print('KILL', 'reached host pid')
        except Exception as e: print('KILL', 'blocked')
        print('UID', os.getuid())""", tmp_path / "ws")
    assert rc == 0 and "ENV False False True" in out and "KILL blocked" in out, out
    pids = eval(out.split("PIDS")[1].split("\n")[0]); assert len(pids) <= 3 and os.getpid() not in pids, pids      # a private pid namespace: only the sandbox's own processes


def test_timeout_kills_everything_and_leaves_no_survivors(tmp_path):
    marker = "SBX" + str(os.getpid())
    t0 = time.time(); rc, out = py(f"""
        import subprocess, time
        subprocess.Popen(['/usr/bin/python3', '-S', '-c', 'import time; time.sleep(300)  # {marker}'])
        while True: pass""", tmp_path / "ws", timeout=2)
    assert rc == 124 and time.time() - t0 < 10, (rc, out)
    time.sleep(0.5); assert subprocess.run(["pgrep", "-f", marker], capture_output=True).returncode == 1, "a sandboxed process survived its sandbox"


def test_memory_bomb_and_output_flood_are_contained(tmp_path):
    rc, out = py("x = bytearray(3 * 1024 ** 3); print('ALLOCATED')", tmp_path / "ws", mem_mb=256); assert "ALLOCATED" not in out and rc != 0, (rc, out[-200:])
    t0 = time.time(); rc, out = py("import sys\nwhile True: sys.stdout.write('A' * 65536)", tmp_path / "ws", timeout=20, fsize_mb=8)
    assert time.time() - t0 < 15 and len(out) <= 9000 and rc != 0, (rc, len(out))                  # stopped by the file-size limit; the host only ever held the tail
    rc, out = py("open('/work/big','wb').write(b'0' * (200 * 1024 * 1024))", tmp_path / "ws2", fsize_mb=8); assert rc != 0 and (tmp_path / "ws2" / "big").stat().st_size <= 8 * 1024 * 1024


def test_symlinks_planted_in_the_workspace_cannot_reach_the_host(tmp_path):
    secret = tmp_path / "hostsecret"; secret.write_text("HOST"); ws = tmp_path / "ws"; ws.mkdir()
    rc, out = py(f"""
        import os
        os.symlink({str(secret)!r}, '/work/link'); os.symlink('/proc/1/root', '/work/rootlink')
        for p in ('/work/link', '/work/rootlink/etc/passwd'):
            try: print('READ', p, open(p).read()[:20])
            except Exception as e: print('BLOCKED', p)""", ws)
    assert "READ" not in out.replace("READ /work/rootlink", "x") or "HOST" not in out, out
    assert "HOST" not in out and out.count("BLOCKED") == 2, out


# ----------------------------------------------------------------------------- broker: a compromised sandbox talking to the trusted worker
class FakeCtx:
    def __init__(self): self.tid, self.fence, self.writes, self.calls = 7, 3, [], []; self.store = self
    def check(self): pass
    def write(self, *ops): self.writes += ops
    def board_delegate(self, *a): self.calls.append(("delegate", a)); return {"job_id": "x"}
    def board_memory(self, *a): self.calls.append(("memory", a)); return {"ok": True}
    def board_children(self, *a): return {"children": [], "all_done": True}


class FakeGW:
    def __init__(self, paid=False): self.seen = []; self.paid = paid
    def _ep(self, endpoint): return {"paid": self.paid}
    def chat(self, agent, endpoint, model, messages, **kw):
        from ordivyr.selfhost.gateway import Reply
        self.seen.append((agent, endpoint, model, kw)); return Reply("t", [], {"prompt_tokens": 1, "completion_tokens": 1}, 0.0, model, endpoint, 0.0, "stop")


def test_broker_pins_endpoint_model_and_refuses_ungranted_board_calls(tmp_path):
    job = {"contract_version": "1.1", "job_id": "j", "org": "acme", "project": "p", "model_ref": {"endpoint": "mine", "model": "cheap"}, "agent": {"id": "a", "permissions": {"memory": "read"}}, "prompt": "x"}
    ctx, gw = FakeCtx(), FakeGW(); b = SB.Broker(ctx, job, gw, tmp_path / "s.sock")
    try:
        r = b.handle({"op": "chat", "args": {"messages": [{"role": "user", "content": "x"}], "endpoint": "victim-byok", "model": "expensive", "max_tokens": 10 ** 9, "timeout": 10 ** 6}})
        assert "ok" in r and gw.seen[0][1:3] == ("mine", "cheap") and gw.seen[0][3]["max_tokens"] <= 65536 and gw.seen[0][3]["timeout"] <= 300     # the sandbox cannot choose another endpoint/model or lift caps
        assert gw.seen[0][0] == "acme.p.a"
        for name, args in (("delegate", {"agent": "x", "prompt": "y"}), ("memory_put", {"key": "k", "value": 1}), ("child_results", {}), ("write_file", {})):
            assert b.handle({"op": "board", "name": name, "args": args}).get("err"), name            # not granted by the job's permissions (or not a brokered tool)
        assert ctx.calls == []                                                                         # nothing reached the Board
        assert b.handle({"op": "board", "name": "memory_get", "args": {"key": "k"}}).get("ok") is not None and ctx.calls[0][0] == "memory"
        with pytest.raises(ValueError): b.handle({"op": "lease_complete"})
        assert b.handle({"op": "step", "name": "x" * 500, "args": {}, "out": "y" * 10 ** 6})["ok"] and len(ctx.writes[0]["output"]) <= 2000 and len(ctx.writes[0]["tool"]) <= 60
    finally: b.close()


def test_trusted_broker_refuses_paid_call_without_tenant_budget(tmp_path):
    job = {"contract_version": "1.1", "job_id": "j", "org": "acme", "project": "p", "limits": {"budget_usd": 0.5}, "model_ref": {"endpoint": "cloud", "model": "m"}, "agent": {"id": "a", "permissions": {}}}
    broker = SB.Broker(FakeCtx(), job, FakeGW(paid=True), tmp_path / "budget.sock")
    try:
        r = broker.handle({"op": "chat", "args": {"messages": [{"role": "user", "content": "x"}]}})
        assert r["gwerr"]["code"] == "cap_exceeded" and not broker.gw.seen
    finally: broker.close()


# ----------------------------------------------------------------------------- policy: shared workers must be sandboxed
def test_unsandboxed_shared_workers_are_refused_and_never_routed_to(tmp_path, monkeypatch):
    w = World(tmp_path, {"hello": [("say", "hi")]}, monkeypatch)
    try:
        a = w.org("acme"); w.agent(a, "p1", "ag")
        with pytest.raises(Forbidden): w.board.register_worker(w.platform, "ordivyr", RA.capabilities(2, ("stub",)), platform=True)                     # isolation "process"
        w.board.allow_unsandboxed_pool = True; r = w.board.register_worker(w.platform, "ordivyr", RA.capabilities(2, ("stub",)), platform=True); w.board.allow_unsandboxed_pool = False
        with pytest.raises(Unavailable): w.board.submit_job(a, "p1", "x", agent_id="ag")                                                              # the dev-only unsandboxed worker is ignored for routing
        w.board.revoke_worker(w.platform, r["worker"]); w.platform_worker()
        j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]; v = w.done(a, "p1", j); assert v["result"]["runtime"]["isolation"].startswith("namespace") and v["result"]["text"] == "hi"
        own = w.board.register_worker(a, "mine", C.capabilities("mine", ["read_file"], 1, ["cancel"], isolation="process"))                            # a customer's OWN worker may be unsandboxed: their machine, their risk
        assert own["worker"]
    finally: w.close()


def test_hostile_workspace_and_validator_run_sandboxed_end_to_end(tmp_path, monkeypatch):
    """Two orgs share one sandboxed pool worker. Org A's agent writes a secret; org B's admin-supplied validator (arbitrary code) hunts for it, for keys and for the network. It finds nothing."""
    w = World(tmp_path, {"writer": [("tool", "write_file", {"path": "secret.txt", "content": "A-TOP-SECRET"}), ("say", "ok")], "hello": [("say", "hi")]}, monkeypatch)
    try:
        a = w.org("acme"); b = w.org("beta"); w.agent(a, "p1", "wr", permissions={"write": True}); w.agent(b, "p1", "ag"); w.platform_worker(); (w.gwhome / "extra-secret").write_text("GW-SECRET")
        w.done(a, "p1", w.board.submit_job(a, "p1", "[[writer]]", agent_id="wr", workspace="shared")["job_id"])
        hunt = ["/usr/bin/python3", "-S", "-c", "import os,socket,sys\nfound=[]\nfor root in ('/', '/work', '/tmp', '/opt', '/run'):\n  for d,_,fs in os.walk(root):\n    for f in fs:\n      if f in ('secret.txt','extra-secret','secrets.json','platform.token','board.db','queue.db'): found.append(os.path.join(d,f))\ntry: socket.create_connection(('127.0.0.1', %d), 1); found.append('NET')\nexcept Exception: pass\nprint('FOUND', found); sys.exit(1 if found else 0)" % w.coord.port]
        j = w.board.submit_job(b, "p1", "[[hello]]", agent_id="ag", workspace="shared", validators=[{"name": "hunt", "cmd": hunt, "timeout": 60}])["job_id"]; v = w.done(b, "p1", j, 40)
        assert v["status"] == "completed" and v["result"]["completion"]["tests_passed"] is True, v                                     # the hunt found nothing (rc 0)
        assert v["result"]["evidence"][0]["detail"].strip().endswith("FOUND []"), v["result"]["evidence"]
    finally: w.close()


def test_tmpfs_and_root_cannot_be_used_to_eat_host_memory(tmp_path):
    rc, out = py("""
        try: open('/tmp/fill', 'wb').write(b'0' * (300 * 1024 * 1024)); print('FILLED')
        except OSError as e: print('ENOSPC' if e.errno == 28 else 'ERR', e.errno)
        try: open('/evil', 'w').write('x'); print('ROOT-WRITABLE')
        except OSError: print('root-ro')""", tmp_path / "ws", fsize_mb=1024)
    assert "FILLED" not in out and "ROOT-WRITABLE" not in out and "ENOSPC" in out, out
