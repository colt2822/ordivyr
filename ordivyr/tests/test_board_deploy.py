import datetime, json, os, ssl, subprocess, sys, threading, time, urllib.request, urllib.error, pytest
from pathlib import Path
from ordivyr.board import backup as BK
from ordivyr.board.api import serve
from ordivyr.tests.board_support import World
from ordivyr.tests.test_board_postgres import DSN, pgbin

PW = "correct horse battery 42"


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi")]}, monkeypatch); yield x; x.close()


def call(url, method, path, body=None, tok=None, raw=None, headers=None, ctx=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url + path, data, {"Content-Type": "application/json", **({"Authorization": "Bearer " + tok} if tok else {}), **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx) as r: return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e: return e.code, e.read(), dict(e.headers)


def J(r): return json.loads(r[1])


def test_new_endpoints_end_to_end_with_roles_and_tenant_scoping(w):
    a = w.org("acme"); b = w.org("beta"); ak = w.board.issue_key(a, "admin")["key"]; bk = w.board.issue_key(b, "admin")["key"]; vk = w.board.issue_key(a, "viewer")["key"]; logs = []
    srv = serve(w.board, access_log=logs.append); url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        assert J(call(url, "GET", "/v1/spending", tok=ak))["limits"]["gateway_budget_usd"] is None
        assert call(url, "PUT", "/v1/spending/limits", {"gateway_budget_usd": 5}, ak)[0] == 200 and call(url, "PUT", "/v1/spending/limits", {"gateway_budget_usd": 1}, vk)[0] == 403
        assert call(url, "PUT", "/v1/secrets/api_key", {"value": "S3CRET"}, ak)[0] == 200
        r = call(url, "GET", "/v1/secrets", tok=ak); assert [s["name"] for s in J(r)["secrets"]] == ["api_key"] and b"S3CRET" not in r[1]
        assert J(call(url, "GET", "/v1/secrets", tok=bk))["secrets"] == [] and call(url, "GET", "/v1/secrets", tok=vk)[0] == 403
        assert call(url, "DELETE", "/v1/secrets/api_key", tok=bk)[0] == 404 and call(url, "DELETE", "/v1/secrets/api_key", tok=ak)[0] == 200
        assert J(call(url, "GET", "/v1/health", tok=ak))["status"] in ("ok",) and J(call(url, "GET", "/v1/spending", tok=ak))["limits"]["gateway_budget_usd"] == 5 and call(url, "GET", "/v1/alerts", tok=vk)[0] == 200
        assert call(url, "GET", "/v1/hosted", tok=ak)[0] == 200 and call(url, "POST", "/v1/hosted/h-nope/stop", {}, ak)[0] == 404 and call(url, "POST", "/v1/hosted/x/explode", {}, ak)[0] == 404
        assert call(url, "GET", "/metrics")[0] == 401 and call(url, "GET", "/metrics", tok=ak)[0] == 401
        m = call(url, "GET", "/metrics", tok=(w.tmp / "board" / "platform.token").read_text().strip()); assert m[0] == 200 and b"board_up 1" in m[1] and b"acme" not in m[1] and "text/plain" in m[2]["Content-Type"]
        assert any(l["status"] == 200 and l["who"] and l["who"].startswith("admin:acme") for l in logs) and "S3CRET" not in json.dumps(logs) and ak not in json.dumps(logs)       # access log: no bodies, no tokens
    finally: srv.shutdown()


# ------------------------------------------------------------------ TLS with a real handshake
def selfsigned(d):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization as S
    from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1()); n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]); now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=2))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(k, hashes.SHA256()))
    (d / "c.pem").write_bytes(c.public_bytes(S.Encoding.PEM)); (d / "k.pem").write_bytes(k.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption())); (d / "k.pem").chmod(0o600); return str(d / "c.pem"), str(d / "k.pem")


def test_tls_handshake_hsts_and_plaintext_rejected_on_both_listeners(w, tmp_path):
    from ordivyr.board.coordinator import BoardCoordinator, BoardRemote
    from ordivyr.board import runtime_adapter as RA
    cert, key = selfsigned(tmp_path); a = w.org("acme"); ak = w.board.issue_key(a, "admin")["key"]; srv = serve(w.board, tls=(cert, key)); port = srv.server_address[1]
    co = BoardCoordinator(w.board, tls=(cert, key)).start(); good = ssl.create_default_context(cafile=cert)
    try:
        s, body, h = call(f"https://localhost:{port}", "GET", "/v1/me", tok=ak, ctx=good); assert s == 200 and "max-age" in h.get("Strict-Transport-Security", "")
        with pytest.raises(urllib.error.URLError): call(f"https://localhost:{port}", "GET", "/v1/me", tok=ak, ctx=ssl.create_default_context())                      # untrusted cert: client refuses
        with pytest.raises(Exception): call(f"http://127.0.0.1:{port}", "GET", "/v1/me", tok=ak)                                                                    # plaintext to a TLS port goes nowhere
        assert srv.socket.context.minimum_version == ssl.TLSVersion.TLSv1_2 and co.httpd.socket.context.minimum_version == ssl.TLSVersion.TLSv1_2          # TLS 1.2 floor on both listeners
        tok = w.board.register_worker(a, "ordivyr", RA.capabilities(1, ("stub",)))["token"]; os.environ["ORDIVYR_LEASE_CA"] = cert
        try:
            r = BoardRemote(f"https://localhost:{co.port}", tok, timeout=5); assert r.claim_many_wait("w", "n", 5, None, 1, wait_s=0) == []                      # the worker protocol over verified TLS
            os.environ.pop("ORDIVYR_LEASE_CA"); 
            with pytest.raises(Exception): BoardRemote(f"https://localhost:{co.port}", tok, timeout=5).claim_many_wait("w", "n", 5, None, 1, wait_s=0)           # system CA store does not trust it
        finally: os.environ.pop("ORDIVYR_LEASE_CA", None)
    finally: srv.shutdown(); co.stop()


# ------------------------------------------------------------------ backup / restore drill
def populate(w):
    a = w.org("acme"); w.agent(a, "p1", "ag"); w.board.put_secret(a, "k", "SEALED-VALUE"); w.platform_worker()
    inv = w.board.invite_user(a, "u@corp.com", "admin"); w.board.accept_invite(inv["invite"], PW); j = w.board.submit_job(a, "p1", "[[hello]]", agent_id="ag")["job_id"]; w.done(a, "p1", j, 40); w.board.reconcile()
    w.adm_key = w.board.issue_key(a, "admin")["key"]; return a, j


@pytest.mark.skipif(bool(DSN), reason="SQLite-home backup; the PostgreSQL drill below covers the PG run")
def test_sqlite_backup_while_serving_then_restore_drill(w, tmp_path, monkeypatch):
    from ordivyr.board import auth as A
    monkeypatch.setattr(A, "SCRYPT_N", 2 ** 10); a, j = populate(w); out = tmp_path / "bk"
    stop = threading.Event()
    def churn():
        i = 0
        while not stop.is_set(): w.board.put_secret(a, f"n{i % 5}", "v"); i += 1
    t = threading.Thread(target=churn); t.start()
    try: man = BK.backup(w.board.home, out)
    finally: stop.set(); t.join()
    assert man["audit_ok"] and man["counts"]["jobs"] == 1 and "master.key" not in json.dumps(man["files"]) and not (out / "master.key").exists()
    assert oct(out.stat().st_mode & 0o777) == "0o700" and oct((out / "board.db").stat().st_mode & 0o777) == "0o600" and BK.verify_backup(out)["created"]
    new = tmp_path / "restored"; rep = BK.restore(out, new); assert rep["ok"] and rep["restored"]["jobs"] == 1 and "audit chain" in rep["verified"]
    from ordivyr.board.service import Board
    r = Board(new)                                                                                                  # a Board over the restored files: everything works
    assert r.db.verify_audit()[0] and r.get_job(r.principal(w.adm_key), "p1", j)["status"] == "completed"      # an API key issued before the snapshot still authenticates, and the finished job is there
    assert r.login("u@corp.com", PW)["session"] and r.db.c().execute("SELECT COUNT(*) FROM secrets WHERE name='k'").fetchone()[0] == 1       # sessions/keys/hash tables restored
    with pytest.raises(Exception): r._secret_value("acme", None, "k")                                               # no master.key was restored: sealed values stay sealed (by design)
    import shutil; shutil.copy2(w.board.home / "master.key", new / "master.key"); r2 = Board(new); assert r2._secret_value("acme", None, "k") == "SEALED-VALUE"      # ...until the separately-kept key is supplied
    with pytest.raises(BK.BackupError, match="already has"): BK.restore(out, new)                                  # never overwrites
    (out / "board.db").write_bytes((out / "board.db").read_bytes()[:-9] + b"corruption")
    with pytest.raises(BK.BackupError, match="corrupt"): BK.verify_backup(out)
    with pytest.raises(BK.BackupError, match="corrupt"): BK.restore(out, tmp_path / "r3")
    with pytest.raises(BK.BackupError): BK.backup(w.board.home, out)                                                # non-empty output dir refused


@pytest.mark.skipif(bool(DSN), reason="SQLite-home CLI drill")
def test_cli_backup_restore_roundtrip(w, tmp_path):
    a, j = populate(w); out = tmp_path / "cli-bk"; env = {**os.environ, "PYTHONPATH": os.getcwd()}
    r = subprocess.run([sys.executable, "-m", "ordivyr.board", "backup", "--home", str(w.board.home), "--out", str(out)], env=env, capture_output=True, text=True); assert r.returncode == 0, r.stderr
    r = subprocess.run([sys.executable, "-m", "ordivyr.board", "restore", "--from", str(out), "--home", str(tmp_path / "cli-restored")], env=env, capture_output=True, text=True); assert r.returncode == 0 and '"ok": true' in r.stdout, r.stderr
    r = subprocess.run([sys.executable, "-m", "ordivyr.board", "restore", "--from", str(out), "--home", str(tmp_path / "cli-restored")], env=env, capture_output=True, text=True); assert r.returncode == 2 and "already has" in r.stderr


@pytest.mark.skipif(not (DSN and pgbin("pg_dump") and pgbin("pg_restore")), reason="needs BOARD_TEST_PG_DSN and pg_dump/pg_restore")
def test_postgres_backup_restore_drill(w, tmp_path, monkeypatch):
    import psycopg
    from ordivyr.board import auth as A
    from ordivyr.board.service import Board
    monkeypatch.setattr(A, "SCRYPT_N", 2 ** 10); a, j = populate(w); out = tmp_path / "pgbk"; pgb = str(Path(pgbin("pg_dump")).parent)
    man = BK.backup(None, out, dsn=w.dsn, pg_bin=pgb); assert man["backend"] == "postgres" and man["audit_ok"] and BK.verify_backup(out)
    name = "bt_restore_" + os.urandom(3).hex(); c = psycopg.connect(DSN, autocommit=True); c.execute(f'CREATE DATABASE "{name}"'); dsn2 = DSN.replace("/postgres?", f"/{name}?", 1)
    try:
        rep = BK.restore(out, dsn=dsn2, pg_bin=pgb); assert rep["ok"] and rep["restored"]["jobs"] == 1
        with pytest.raises(BK.BackupError, match="not empty"): BK.restore(out, dsn=dsn2, pg_bin=pgb)
        r = Board(w.tmp / "board", dsn=dsn2); assert r.db.backend == "postgres" and r.db.verify_audit()[0] and r.login("u@corp.com", PW)["session"]
        assert r._secret_value("acme", None, "k") == "SEALED-VALUE"                                               # same master.key file in the same home
        r.db.close(); r.store.close()
    finally: c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'); c.close()


def test_dashboard_assets_are_served_and_csp_clean(w):
    import re
    srv = serve(w.board); url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        for path, ctype in (("/", "text/html"), ("/dashboard.js", "javascript"), ("/dashboard.css", "text/css"), ("/mark.svg", "image/svg+xml")):
            s, raw, h = call(url, "GET", path); assert s == 200 and ctype in h["Content-Type"] and "default-src 'none'" in h["Content-Security-Policy"], path
    finally: srv.shutdown()
    st = Path(__file__).resolve().parents[1] / "board" / "static"; html = (st / "index.html").read_text(); js = (st / "dashboard.js").read_text(); css = (st / "dashboard.css").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html) and not re.search(r"\sstyle=", html) and not re.search(r"\son\w+=", html)         # CSP: no inline script/style/handlers
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js and "document.write" not in js and "eval(" not in js and ".style." not in js
    assert "localStorage" not in js and "sessionStorage" not in js                                                                       # the session token lives in memory only
    assert "@import" not in css and "url(http" not in css and "@font-face" not in css                                                     # no external fetches (CSP blocks them anyway)
