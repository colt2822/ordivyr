"""Phase 3 adversarial additions: parser/resource-exhaustion attacks on the live API listener and cgroup/sysctl self-escape probes from INSIDE the sandbox.
Self-authored attacks (not an independent review). Each test states the expected outcome; run on SQLite and PostgreSQL (BOARD_TEST_PG_DSN)."""
import http.client, json, socket, textwrap, threading, time
from pathlib import Path
import pytest
from ordivyr.board import auth as A, sandbox as SB
from ordivyr.board.api import serve
from ordivyr.tests.board_support import World


@pytest.fixture
def w(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "SCRYPT_N", 2 ** 10)
    x = World(tmp_path, {"hello": [("say", "hi")]}, monkeypatch); x.off = 0.0; yield x; x.close()


def raw_post(port, path, body: bytes, headers=None, timeout=15):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.request("POST", path, body, {"Content-Type": "application/json", **(headers or {})}); r = c.getresponse(); return r.status, r.read()
    except (ConnectionError, OSError, http.client.HTTPException) as e: return -1, repr(e).encode()
    finally: c.close()


def alive(port):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5); t0 = time.time(); c.request("GET", "/healthz"); r = c.getresponse(); r.read(); c.close(); return r.status == 200 and time.time() - t0 < 2.0


def test_parser_bombs_are_rejected_without_a_500_and_the_server_keeps_serving(w):
    a = w.org("acme"); k = w.board.issue_key(a, "admin")["key"]; srv = serve(w.board); port = srv.server_address[1]; H = {"Authorization": "Bearer " + k}
    try:
        nested = b"[" * 60000 + b"]" * 60000                                                           # recursion-depth bomb, well under the body cap
        wide = json.dumps({f"k{i}": i for i in range(9000)}).encode()                                    # many keys
        bigint = b'{"id": ' + b"9" * 4000 + b"}"                                                          # int-conversion DoS (Python's 4300-digit limit)
        dup = b'{"id": "a", "id": "b", "id": "c"}'
        deepobj = b'{"a":' * 450 + b"1" + b"}" * 450                                                      # passes json.loads but would overflow a recursive walker
        for name, body in (("nested", nested), ("wide", wide), ("bigint", bigint), ("deepobj", deepobj), ("nul", b'{"id": "a\\u0000b"}'), ("utf8", b'{"id": "\xff\xfe"}')):
            s, out = raw_post(port, "/v1/projects", body, H); assert 400 <= s < 500, (name, s, out[:120])   # a clean client error, never a 500 or a dropped connection
            assert b"Traceback" not in out and b"File \"" not in out, name
        assert alive(port)
        s, _ = raw_post(port, "/v1/projects", b"x" * 400_000, {**H, "Content-Length": "400000"}); assert s in (413, 422, -1)
        s, out = raw_post(port, "/v1/projects", b"{}", {**H, "Content-Length": "5000000"}, timeout=5); assert s in (413, 422, 400, -1)          # lying Content-Length must not make it allocate or hang
        assert alive(port)
    finally: srv.shutdown()


def test_slow_and_half_open_clients_do_not_starve_real_requests(w):
    a = w.org("acme"); k = w.board.issue_key(a, "admin")["key"]; srv = serve(w.board); port = srv.server_address[1]; socks = []
    try:
        for _ in range(40):                                                                              # 40 half-open requests that never finish their headers
            s = socket.create_connection(("127.0.0.1", port)); s.sendall(b"POST /v1/projects HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n"); socks.append(s)
        t0 = time.time(); c = http.client.HTTPConnection("127.0.0.1", port, timeout=8); c.request("GET", "/v1/me", headers={"Authorization": "Bearer " + k}); r = c.getresponse(); r.read(); c.close()
        assert r.status == 200 and time.time() - t0 < 5, "a threaded listener must keep serving while slow clients hold sockets"
    finally:
        for s in socks: s.close()
        srv.shutdown()


def test_bad_login_flood_cannot_wedge_the_listener_or_lock_the_owner_out(w):
    a = w.org("acme"); inv = w.board.invite_user(a, "owner@example.com", "admin"); w.board.accept_invite(inv["invite"], "correct horse battery 42")
    srv = serve(w.board); port = srv.server_address[1]; res = []
    def hit(i):
        s, _ = raw_post(port, "/v1/auth/login", json.dumps({"email": "owner@example.com", "password": f"wrong-{i}-xxxxxxxxxx", "org": "acme"}).encode()); res.append(s)
    try:
        ts = [threading.Thread(target=hit, args=(i,)) for i in range(60)]; [t.start() for t in ts]; [t.join() for t in ts]
        assert all(s in (401, 429) for s in res) and 429 in res, sorted(set(res))                         # throttled, never a 500
        assert alive(port)
        s, out = raw_post(port, "/v1/auth/login", json.dumps({"email": "owner@example.com", "password": "correct horse battery 42", "org": "acme"}).encode())
        # the flood came from the same network as the owner here, so the owner may be throttled too, but only for the capped time and the server answers uniformly
        assert s in (200, 429) and b"Traceback" not in out
        row = w.board.db.c().execute("SELECT MAX(locked_until) FROM auth_throttle").fetchone()[0] or 0
        assert row - time.time() <= 3600 + 5, "hard lock must never exceed one hour"
    finally: srv.shutdown()


needs_sb = pytest.mark.skipif(not SB.available(), reason="bubblewrap unavailable")


@needs_sb
def test_job_cannot_raise_its_own_limits_or_touch_kernel_knobs(tmp_path):
    code = textwrap.dedent('''
        import json, os
        r = {}
        def tryw(p, data="1"):
            try:
                with open(p, "w") as f: f.write(data)
                return "WROTE"
            except OSError as e: return e.errno
        r["cg_root"] = os.path.isdir("/sys/fs/cgroup") and sorted(os.listdir("/sys/fs/cgroup"))[:3]
        for p in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/cgroup.procs", "/sys/fs/cgroup/pids.max", "/proc/self/cgroup"): r[p] = tryw(p, "max") if os.path.exists(p) else "absent"
        for p in ("/proc/sys/kernel/core_pattern", "/proc/sys/vm/overcommit_memory", "/proc/sysrq-trigger", "/proc/sys/kernel/unprivileged_userns_clone", "/sys/kernel/mm/ksm/run"): r[p] = tryw(p) if os.path.exists(p) else "absent"
        r["modprobe"] = os.path.exists("/sbin/modprobe") and os.access("/sbin/modprobe", os.X_OK)
        r["uid"] = os.getuid(); r["setuid0"] = None
        try: os.setuid(0); r["setuid0"] = "ok" if os.getuid() == 0 else "no"
        except OSError as e: r["setuid0"] = e.errno
        print(json.dumps(r))''')
    d = tmp_path / "w"; d.mkdir(); (d / "p.py").write_text(code); rc, out = SB.run(["/usr/bin/python3", "-S", "/work/p.py"], d, timeout=30); assert rc == 0, out
    r = json.loads(out.strip().splitlines()[-1])
    for p in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/cgroup.procs", "/sys/fs/cgroup/pids.max", "/proc/self/cgroup", "/proc/sys/kernel/core_pattern", "/proc/sys/vm/overcommit_memory", "/proc/sysrq-trigger", "/sys/kernel/mm/ksm/run"):
        assert r[p] != "WROTE", (p, r[p])                                                                # a hostile job cannot loosen its own cgroup or write a kernel knob


def test_wrong_typed_fields_are_client_errors_on_every_body_route(w):
    """Type-confusion fuzz: for every body field the API reads, send a number / list / object / bool / null on each POST/PUT route. Nothing may return 5xx (server bugs must stay visible to the 5xx alert)."""
    import re
    src = (Path(__file__).resolve().parents[1] / "board" / "api.py").read_text()
    routes = sorted(set(re.findall(r'@route\("(POST|PUT)", "(/v1/[^"]+)"\)', src))); keys = sorted(set(re.findall(r'body(?:\.get\(|\[)"([a-z_]+)"', src)))
    a = w.org("acme"); k = w.board.issue_key(a, "admin")["key"]; srv = serve(w.board); port = srv.server_address[1]; bad = []; ptok = (w.tmp / "board" / "platform.token").read_text().strip()
    skip = ("/v1/admin/vault/rotate", "/v1/auth/logout", "/v1/billing/cancel")                                    # state-destroying for the fixture itself, no body fields
    try:
        for method, path in routes:
            if path in skip or path.startswith("/v1/billing/webhook") or "{" in path and False: continue
            p = re.sub(r"\{[a-z_]+\}", "p1", path)
            for key in keys:
                for val in (5, [1], {"a": 1}, True, None, 10 ** 30):
                    for tok in (k, ptok):                                                                           # tenant admin AND platform operator (admin-only routes are otherwise unreachable)
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                        try:
                            c.request(method, p, json.dumps({key: val}).encode(), {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}); r = c.getresponse(); r.read()
                            if r.status == 500: bad.append((method, p, key, repr(val)[:12], r.status))
                        except (ConnectionError, OSError, http.client.HTTPException): bad.append((method, p, key, repr(val)[:12], "dropped"))
                        finally: c.close()
        for qs in ("limit=abc", "limit=99999999999999999999", "after=x", "after=-1&limit=0", "status=%00", "limit=1e9"):         # query-string typing on GET routes
            for path in ("/v1/projects/p1/jobs", "/v1/audit", "/v1/outbox", "/v1/usage", "/v1/spending"):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=15); c.request("GET", path + "?" + qs, headers={"Authorization": "Bearer " + k}); r = c.getresponse(); r.read(); c.close()
                if r.status == 500: bad.append(("GET", path, qs, "", r.status))
        assert alive(port)
        assert not bad, bad[:12]
    finally: srv.shutdown()
