import socket, pytest
from ordivyr.tests.board_support import World
from ordivyr.board import api as A


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {}, monkeypatch); x.srv = A.serve(x.board); x.api_port = x.srv.server_address[1]; yield x; x.srv.shutdown(); x.close()


def raw(port, request, wait=3.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    s.sendall(request); s.settimeout(wait)
    try: data = s.recv(400)
    except socket.timeout: data = b"<timeout: server kept waiting for a body>"
    s.close(); return data.split(b"\r\n")[0].decode(errors="replace")


@pytest.mark.parametrize("cl", ["-5", "abc", "1e3", "99999999999999999999"])
def test_api_rejects_bad_content_length_without_500_or_hanging(w, cl):
    line = raw(w.api_port, f"POST /v1/projects/p/jobs HTTP/1.1\r\nHost: x\r\nContent-Length: {cl}\r\n\r\n".encode())
    assert line.split()[1] in ("400", "401", "413", "422"), line


@pytest.mark.parametrize("cl,expect", [("-5", "400"), ("abc", "400"), ("17000000", "413"), ("99999999999999999999", "413")])
def test_lease_api_refuses_bad_or_oversized_bodies_before_reading_them(w, cl, expect):
    line = raw(w.coord.port, f"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {cl}\r\n\r\n".encode())
    assert line.split()[1] == expect, line


def test_lease_api_still_serves_normal_requests_and_rejects_bad_tokens(w):
    body = b'{"m":"counts","a":[],"k":{}}'
    line = raw(w.coord.port, b"POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer nope\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    assert line.split()[1] == "401", line


def test_shutdown_meters_a_job_that_finished_since_the_last_tick(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi")]}, monkeypatch)
    try:
        admin = x.org("acme"); x.agent(admin, "p1", "ag"); x.platform_worker()
        jid = x.board.submit_job(admin, "p1", "go [[hello]]", agent_id="ag")["job_id"]; x.done(admin, "p1", jid)
        kinds = lambda: {r[0] for r in x.board.db.c().execute("SELECT kind FROM meter WHERE job_id=?", (jid,)).fetchall()}
        assert "jobs_completed" not in kinds()               # no background loop running: still unmetered
        x.board.stop_loop(); assert "jobs_completed" in kinds()
        x.board.stop_loop(); n = x.board.db.c().execute("SELECT COUNT(*) FROM meter WHERE job_id=?", (jid,)).fetchone()[0]
        assert n == len(kinds())                              # exactly once: a second pass adds nothing
    finally: x.close()


@pytest.mark.parametrize("lead,members", [("a", True), ("a", 10 ** 30), (10 ** 30, ["b"]), (["a"], ["b"]), ("a", [1]), ("a", [["b"]]), (None, ["b"])])
def test_team_definition_with_wrong_types_is_a_client_error_not_a_500(tmp_path, monkeypatch, lead, members):
    from ordivyr.board.service import Invalid
    x = World(tmp_path, {}, monkeypatch)
    try:
        admin = x.org("acme"); x.agent(admin, "p1", "a"); x.agent(admin, "p1", "b")
        with pytest.raises(Invalid): x.board.define_team(admin, "p1", "t", lead, members)
        assert x.board.define_team(admin, "p1", "t", "a", ["b"])["members"] == ["b"]
    finally: x.close()


@pytest.mark.parametrize("kw", [dict(domains=5), dict(domains=True), dict(domains=[1]), dict(jwks=[1]), dict(jwks={"keys": 5}), dict(issuer=5), dict(client_id=["x"])])
def test_sso_configuration_with_wrong_types_is_a_client_error(tmp_path, monkeypatch, kw):
    from ordivyr.board.service import Invalid
    x = World(tmp_path, {}, monkeypatch)
    try:
        admin = x.org("acme")
        args = dict(issuer="https://idp.example", client_id="c", alg="RS256", jwks={"keys": [{"kty": "RSA"}]}, domains=["example.com"]) | kw
        with pytest.raises(Invalid): x.board.set_sso(admin, **args)
    finally: x.close()


def test_no_backslash_inside_fstring_expressions_so_python_311_can_import_everything():
    """Python 3.11 rejects `f"{x + '\\n'}"` (allowed from 3.12). The package declares >=3.11, so catch it on any interpreter."""
    import ast, pathlib
    root = pathlib.Path(__file__).resolve().parents[1]; bad = []
    for path in root.rglob("*.py"):
        src = path.read_text(); tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FormattedValue):
                seg = ast.get_source_segment(src, node.value) or ""
                if "\\" in seg: bad.append(f"{path.relative_to(root)}:{node.lineno}")
    assert not bad, bad
