import json, urllib.request, urllib.error, pytest
from ordivyr.tests.board_support import World
from ordivyr.board import api as A, runtime_adapter as RA


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {"hello": [("say", "hi")]}, monkeypatch); x.srv = A.serve(x.board, limits={"auth_fail": (4, 60)}); x.api = f"http://127.0.0.1:{x.srv.server_address[1]}"; yield x; x.srv.shutdown(); x.close()


def call(w, method, path, tok=None, body=None, headers=None):
    req = urllib.request.Request(w.api + path, json.dumps(body).encode() if body is not None else None, {**({"Authorization": "Bearer " + tok} if tok else {}), "Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return r.status, json.loads(r.read() or b"{}"), r.headers
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}"), e.headers


def setup(w):
    pt = (w.tmp / "board" / "platform.token").read_text()
    s, a, _ = call(w, "POST", "/v1/admin/orgs", pt, {"id": "acme", "plan": "team"}); assert s == 200; s, b, _ = call(w, "POST", "/v1/admin/orgs", pt, {"id": "beta", "plan": "team"})
    for tok in (a["admin_key"], b["admin_key"]):
        assert call(w, "POST", "/v1/projects", tok, {"id": "p1"})[0] == 200
        assert call(w, "PUT", "/v1/projects/p1/agents/ag", tok, {"model_ref": {"endpoint": "stub", "model": "m"}, "system": "x"})[0] == 200
    w.platform_worker(); return pt, a["admin_key"], b["admin_key"]


def test_full_flow_and_cross_org_isolation_over_http(w):
    pt, ka, kb = setup(w)
    s, j, _ = call(w, "POST", "/v1/projects/p1/jobs", ka, {"prompt": "go [[hello]]", "agent_id": "ag"}); assert s == 200; jid = j["job_id"]
    v = __import__("ordivyr.tests.board_support", fromlist=["wait_for"]).wait_for(lambda: (lambda r: r if r["status"] == "completed" else None)(call(w, "GET", f"/v1/projects/p1/jobs/{jid}", ka)[1]), 20)
    assert v["result"]["text"] == "hi"
    for method, path, body in (("GET", f"/v1/projects/p1/jobs/{jid}", None), ("POST", f"/v1/projects/p1/jobs/{jid}/cancel", {}), ("GET", f"/v1/projects/p1/jobs/{jid}/events", None)):
        s, r, _ = call(w, method, path, kb, body); assert s == 404 and r["error"]["code"] == "not_found", (path, s, r)        # same project name, other org: not found, not forbidden
    assert call(w, "GET", "/v1/projects/p1/jobs", kb)[1]["jobs"] == []
    sm, mk, _ = call(w, "POST", "/v1/keys", ka, {"role": "member", "project": "p1"}); assert sm == 200 and call(w, "GET", "/v1/projects/p1/jobs", mk["key"])[0] == 200
    assert call(w, "POST", "/v1/projects", mk["key"], {"id": "x"})[0] == 403 and call(w, "PUT", "/v1/projects/p1/agents/evil", mk["key"], {"permissions": {"write": True}})[0] == 403
    assert call(w, "GET", "/v1/projects/p2/jobs", mk["key"])[0] == 404
    s, r, _ = call(w, "GET", f"/v1/projects/p1/jobs/{jid}", pt); assert s == 403                                                # platform operator does not read customer jobs
    assert call(w, "DELETE", f"/v1/keys/{mk['kid']}", ka)[0] == 200 and call(w, "GET", "/v1/projects/p1/jobs", mk["key"])[0] == 401


def test_caller_cannot_inject_scope_or_spec_fields(w):
    pt, ka, kb = setup(w)
    for extra in ({"org": "beta"}, {"project": "p2"}, {"spec": {"org": "beta"}}, {"contract_version": "1.0"}, {"parent": {"job_id": "x", "depth": 0}}, {"job_id": "j-fixed"}):
        s, r, _ = call(w, "POST", "/v1/projects/p1/jobs", ka, {"prompt": "x", "agent_id": "ag", **extra}); assert s == 422, (extra, s, r)
    s, r, _ = call(w, "POST", "/v1/projects/p1/jobs", ka, {"prompt": "x", "agent_id": "ag", "model_ref": {"endpoint": "stub", "model": "m", "api_key": "sk-abcdefghijklmnopqrstuv"}}); assert s == 422 and "credential" in r["error"]["message"]
    assert call(w, "POST", "/v1/projects/p1/jobs", ka, {"prompt": "x", "agent_id": "ag", "limits": {"max_turns": 10 ** 9}})[0] == 422
    assert call(w, "POST", "/v1/projects/p1/jobs", ka, [1])[0] == 422 and call(w, "POST", "/v1/projects/p1/jobs", ka, {"prompt": "x", "agent_id": "nope"})[0] == 404


def test_auth_failures_rate_limit_and_hygiene(w):
    pt, ka, kb = setup(w)
    codes = [call(w, "GET", "/v1/me", t)[0] for t in ("", "garbage", "ordb_" + "x" * 40, "Bearer", "x")]; assert codes[:4] == [401] * 4 and 429 in codes       # 4 failures allowed per window, then throttled
    s, r, h = call(w, "GET", "/v1/me", ka); assert s == 200 and r["org"] == "acme" and h["Cache-Control"] == "no-store" and h["X-Content-Type-Options"] == "nosniff"
    with urllib.request.urlopen(w.api + "/", timeout=5) as r: page = r.read().decode(); csp = r.headers["Content-Security-Policy"]
    assert "ORDIVYR Board" in page and "script-src 'self'" in csp and "unsafe-inline" not in csp and "<script>" not in page.replace('<script src="/dashboard.js"></script>', "")
    js = urllib.request.urlopen(w.api + "/dashboard.js", timeout=5).read().decode(); assert "innerHTML" not in js and "eval(" not in js                       # API data is only ever inserted as text
    assert call(w, "GET", "/v1/nope", ka)[0] == 404


def test_hooks_over_http_and_no_secret_in_listings(w):
    pt, ka, kb = setup(w)
    s, h, _ = call(w, "POST", "/v1/projects/p1/schedules", ka, {"name": "hook", "prompt": "[[hello]]", "agent_id": "ag", "webhook": True}); assert s == 200
    assert call(w, "POST", "/v1/hooks/s-nope/xxxx")[0] == 404 and call(w, "POST", h["hook_path"][:-3] + "abc")[0] == 404
    s, r, _ = call(w, "POST", h["hook_path"], headers={"Idempotency-Key": "evt-9"}); assert s == 202
    assert call(w, "POST", h["hook_path"], headers={"Idempotency-Key": "evt-9"})[1]["job_id"] == r["job_id"]
    s, reg, _ = call(w, "POST", "/v1/workers", ka, {"engine": "ordivyr", "capabilities": RA.capabilities(1, ("stub",))}); assert s == 200 and reg["token"].startswith("ordw_")
    listing = json.dumps([call(w, "GET", p, ka)[1] for p in ("/v1/workers", "/v1/projects/p1/schedules", "/v1/projects/p1/jobs", "/v1/audit", "/v1/usage")])
    assert reg["token"] not in listing and h["hook_path"].rsplit("/", 1)[1] not in listing and ka not in listing
    assert call(w, "POST", "/v1/admin/workers", ka, {"engine": "ordivyr", "capabilities": RA.capabilities(1)})[0] == 403          # customers cannot register shared pool workers


def test_public_bind_is_refused_without_the_flag(w):
    with pytest.raises(SystemExit): A.serve(w.board, host="0.0.0.0", port=0)
