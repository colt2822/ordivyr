import json
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from ordivyr.selfhost.gateway import Gateway, GatewayError


def test_gateway_enforces_durable_job_budget_from_provider_usage(tmp_path):
    def http(method, url, headers, body, timeout):
        return 200, json.dumps({"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 5, "completion_tokens": 1}}).encode()
    g = Gateway(tmp_path, http=http)
    g.add_endpoint("cloud", "custom", "https://provider.example", key="test", models=["m"])
    g.authorize("cloud", daily_usd=10, total_usd=10, per_request_usd=10)
    g.set_price("m", 100, 100)
    messages = [{"role": "user", "content": "hello"}]
    budget = g._estimate(g._ep("cloud"), "m", messages, 1) * 1.01
    r = g.chat("tenant.project.agent", "cloud", "m", messages, max_tokens=1, spend_scope="job-1", spend_limit_usd=budget)
    assert r.usage["prompt_tokens"] == 5 and r.cost_usd == pytest.approx(0.0006)
    with pytest.raises(GatewayError, match="job spending budget"):
        g.chat("tenant.project.agent", "cloud", "m", messages, max_tokens=1, spend_scope="job-1", spend_limit_usd=budget)
    assert g.db.execute("SELECT COUNT(*) FROM scoped_spend WHERE scope='job-1' AND status='ok'").fetchone()[0] == 1


def test_https_gateway_transport_rejects_private_dns_answers(tmp_path, monkeypatch):
    import socket
    g = Gateway(tmp_path)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(GatewayError, match="non-permitted address"):
        g._post({"base": "https://attacker.example", "id": "e"}, "/v1", {}, {}, 1)


def test_job_budget_reservations_serialize_concurrent_calls(tmp_path):
    def http(method, url, headers, body, timeout):
        time.sleep(0.1)
        return 200, json.dumps({"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 5, "completion_tokens": 1}}).encode()
    g = Gateway(tmp_path, http=http)
    g.add_endpoint("cloud", "custom", "https://provider.example", key="test", models=["m"])
    g.authorize("cloud", daily_usd=10, total_usd=10, per_request_usd=10); g.set_price("m", 100, 100)
    args = ("tenant.project.agent", "cloud", "m", [{"role": "user", "content": "hello"}])
    budget = g._estimate(g._ep("cloud"), "m", args[3], 1) * 1.5
    def call(_):
        try: return g.chat(*args, max_tokens=1, spend_scope="concurrent-job", spend_limit_usd=budget)
        except GatewayError as e: return e
    with ThreadPoolExecutor(2) as pool: results = list(pool.map(call, range(2)))
    assert sum(not isinstance(r, GatewayError) for r in results) == 1
    assert g.db.execute("SELECT COUNT(*) FROM scoped_spend WHERE scope='concurrent-job' AND status='ok'").fetchone()[0] == 1


def test_provider_timeout_keeps_uncertain_job_reservation(tmp_path):
    g = Gateway(tmp_path, http=lambda *a: (_ for _ in ()).throw(TimeoutError("provider response lost")))
    g.add_endpoint("cloud", "custom", "https://provider.example", key="test", models=["m"])
    g.authorize("cloud", daily_usd=10, total_usd=10, per_request_usd=10); g.set_price("m", 100, 100)
    args = ("tenant.project.agent", "cloud", "m", [{"role": "user", "content": "hello"}])
    budget = g._estimate(g._ep("cloud"), "m", args[3], 1) * 1.5
    with pytest.raises(GatewayError): g.chat(*args, max_tokens=1, spend_scope="uncertain-job", spend_limit_usd=budget)
    assert g.db.execute("SELECT status FROM scoped_spend WHERE scope='uncertain-job'").fetchone()[0] == "uncertain"
    with pytest.raises(GatewayError, match="job spending budget"):
        g.chat(*args, max_tokens=1, spend_scope="uncertain-job", spend_limit_usd=budget)
