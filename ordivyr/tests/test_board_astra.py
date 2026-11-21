"""Independent audit regressions; no inference or external services."""
import json, os, secrets, threading
import pytest
from ordivyr.board.service import Board
from ordivyr.board.runtime_adapter import capabilities


@pytest.fixture
def b(tmp_path):
    admin_dsn = os.environ.get("BOARD_TEST_PG_DSN")
    dsn = None
    if admin_dsn:
        import psycopg
        name = "astra_" + secrets.token_hex(6)
        with psycopg.connect(admin_dsn, autocommit=True) as c:
            c.execute(f'CREATE DATABASE "{name}"')
        dsn = admin_dsn.replace('/postgres?', f'/{name}?')
    board = Board(tmp_path, dsn=dsn)
    platform = board.principal(board.init_platform())
    admin = board.principal(board.create_org(platform, "acme", plan="team")["admin_key"])
    board.create_project(admin, "p")
    board.register_worker(admin, "ordivyr", capabilities(2, ()))
    yield board, admin
    board.db.close()
    if dsn:
        board.store.close()
        with psycopg.connect(admin_dsn, autocommit=True) as c:
            c.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


def agent(board, admin, name, permissions):
    board.define_agent(admin, "p", name, {"permissions": permissions})


def test_unrestricted_delegation_cannot_gain_secrets(b):
    board, admin = b
    agent(board, admin, "parent", {"delegate": True})
    agent(board, admin, "privileged", {"secrets": ["customer-key"]})
    board.submit_job(admin, "p", "inspect", agent_id="parent")
    t = board.store.claim("test")
    with pytest.raises(PermissionError, match="escalate"):
        board.w_delegate(t["id"], t["fence"], {"agent": "privileged", "prompt": "read secret"})


def test_explicit_delegation_grant_still_allows_named_secret_agent(b):
    board, admin = b
    agent(board, admin, "parent", {"delegate": ["privileged"]})
    agent(board, admin, "privileged", {"secrets": ["customer-key"]})
    board.submit_job(admin, "p", "inspect", agent_id="parent")
    t = board.store.claim("test")
    assert board.w_delegate(t["id"], t["fence"], {"agent": "privileged", "prompt": "read secret"})["job_id"]


def test_cancel_before_queue_admission_releases_reservation(b, monkeypatch):
    board, admin = b
    agent(board, admin, "a", {})
    monkeypatch.setattr(board, "_redrive", lambda *a, **k: None)
    j = board.submit_job(admin, "p", "inspect", agent_id="a", limits={"budget_usd": 1})
    board.cancel_job(admin, "p", j["job_id"])
    assert board._reserved(board.db.c(), "acme") == (0, 0)


def test_dashboard_reads_do_not_take_queue_writer_transactions(b):
    board, admin = b
    agent(board, admin, "a", {})
    for i in range(12):
        board.submit_job(admin, "p", str(i), agent_id="a")
    before = board.store.tx_count
    rows = board.list_jobs(admin, "p")
    assert len(rows) == 12
    assert board.store.tx_count == before
    assert len(board.list_jobs(admin, "p", limit=-1)) <= 1


def test_bulk_reads_preserve_decoded_result_and_missing_ids(b):
    board, admin = b
    agent(board, admin, "a", {})
    board.submit_job(admin, "p", "inspect", agent_id="a")
    t = board.store.claim("test")
    board.store.begin(t["id"], t["fence"])
    board.store.complete(t["id"], t["fence"], {"text": "ok"})
    rows = board.store.get_many([t["id"], 999999, t["id"]])
    assert rows == {t["id"]: board.store.get(t["id"])}
    assert rows[t["id"]]["result"] == {"text": "ok"}
    assert board.store.get_many([]) == {}


@pytest.mark.skipif(not os.environ.get("BOARD_TEST_PG_DSN"), reason="private PG required")
@pytest.mark.parametrize('scope', ['global', 'tenant', 'node'])
def test_postgres_claims_cannot_race_capacity(b, scope):
    from concurrent.futures import ThreadPoolExecutor
    board, _ = b
    store = board.store
    store.set_cap(1 if scope == 'global' else 100)
    store.tenant_set('race', max_active=1 if scope == 'tenant' else 100)
    if scope == 'node':
        store.node_report('n', capacity=1)
    for i in range(12):
        store.submit('kind' + str(i), {}, tenant='race')
    gate = threading.Barrier(12)
    def claim(i):
        gate.wait(timeout=10)
        return store.claim('w' + str(i), node='n', ttl=60, kinds=['kind' + str(i)])
    with ThreadPoolExecutor(12) as pool:
        results = list(pool.map(claim, range(12)))
    assert sum(r is not None for r in results) == 1


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf')])
def test_nonfinite_metering_is_rejected(value):
    from ordivyr.board.contract import make_result, validate_result
    assert validate_result(make_result('j', 'completed', 'done', usage={'cost_usd': value}))


def test_gateway_spend_reservation_is_central_fenced_and_survives_board_restart(b):
    from concurrent.futures import ThreadPoolExecutor
    from ordivyr.board.errors import QuotaError
    board, admin = b
    with board.db.tx() as c: c.execute("UPDATE projects SET budget_usd=1.0 WHERE org='acme' AND id='p'")
    agent(board, admin, "metered", {})
    j = board.submit_job(admin, "p", "paid call", agent_id="metered", limits={"budget_usd": 0.5})["job_id"]
    from ordivyr.board.service import Board
    t = board.store.claim("meter-test"); other = Board(board.home, store=board.store)
    def reserve(amount):
        try: return other.w_gateway_spend(t["id"], t["fence"], "reserve", secrets.token_urlsafe(12), amount)
        except Exception as e: return e
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(reserve, (0.3, 0.3)))
    assert sum(not isinstance(x, Exception) for x in results) == 1
    rid = board.db.c().execute("SELECT request_id FROM gateway_calls WHERE job_id=?", (j,)).fetchone()[0]
    board.w_gateway_spend(t["id"], t["fence"], "settle", rid, 0.2, {"prompt_tokens": 17, "completion_tokens": 4})
    summary = other.w_gateway_spend(t["id"], t["fence"], "summary")
    assert summary == {"cost_usd": 0.2, "uncertain_usd": 0.0, "prompt_tokens": 17, "completion_tokens": 4, "cache_read_tokens": 0, "cache_write_tokens": 0}


def test_uncertain_gateway_charge_retains_reservation_and_budget(b):
    board, admin = b
    with board.db.tx() as c: c.execute("UPDATE projects SET budget_usd=1.0 WHERE org='acme' AND id='p'")
    agent(board, admin, "metered", {})
    j = board.submit_job(admin, "p", "paid call", agent_id="metered", limits={"budget_usd": 0.5})["job_id"]
    from ordivyr.board.service import Board
    t = board.store.claim("meter-test"); req = "request-uncertain"; other = Board(board.home, store=board.store)
    board.w_gateway_spend(t["id"], t["fence"], "reserve", req, 0.4)
    board.w_gateway_spend(t["id"], t["fence"], "uncertain", req, 0.4)
    with pytest.raises(Exception, match="budget"):
        board.w_gateway_spend(t["id"], t["fence"], "reserve", "request-next", 0.2)
    assert other.w_gateway_spend(t["id"], t["fence"], "summary")["uncertain_usd"] == 0.4


def test_broker_bounds_frames_before_newline(monkeypatch):
    import socket
    from ordivyr.board import sandbox as sb
    monkeypatch.setattr(sb, 'MAX_MSG', 128)
    broker = object.__new__(sb.Broker)
    broker.handle = lambda m: {'ok': True}
    left, right = socket.socketpair()
    thread = threading.Thread(target=broker._conn, args=(left,), daemon=True)
    thread.start()
    try:
        right.settimeout(1)
        right.sendall(b'x' * 129)
        assert b'too_large' in right.recv(1024)
    finally:
        right.close()
        thread.join(2)


