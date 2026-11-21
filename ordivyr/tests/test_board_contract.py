import copy, importlib.util, sys, pytest
from ordivyr.board import contract as C, conformance as CF


def job(**kw): j = CF.base_job(); j.update(kw); return j


def test_contract_module_is_standalone():
    """Lite must be able to vendor contract.py alone: no ORDIVYR imports, stdlib only."""
    import ast, pathlib
    tree = ast.parse(pathlib.Path(C.__file__).read_text()); mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import): mods |= {a.name.split(".")[0] for a in n.names}
        if isinstance(n, ast.ImportFrom): assert n.level == 0, "relative import"; mods.add((n.module or "").split(".")[0])
    assert mods <= {"re", "__future__"}, mods


def test_valid_job_and_required_fields():
    assert C.validate_job(job()) == []
    for k in ("org", "project", "job_id", "prompt", "agent"):
        j = job(); j.pop(k); assert C.validate_job(j), k
    assert C.validate_job(job(org="../x"))


def test_version_gate():
    assert C.version_ok("1.7") and C.version_ok(1) and not C.version_ok("2.0") and not C.version_ok(None) and not C.version_ok("x")
    assert any("unsupported" in p for p in C.validate_job(job(contract_version="2.0")))


def test_secrets_rejected_anywhere_but_the_prompt():
    assert C.validate_job(job(model_ref={"endpoint": "e", "model": "m", "api_key": "x"}))
    assert C.validate_job(job(labels={"note": "sk-ant-abcdefghijklmnop"}))
    assert C.validate_job(job(agent={"id": "a", "system": "use key AIzaSyA1234567890123456789012345"}))
    assert C.validate_job(job(prompt="the key is sk-abcdefghijklmnopqrstuvwxyz")) == []     # user prompt text is user data, not a credential channel


@pytest.mark.parametrize("perms,tools,tool,ok", [
    ({"write": False}, None, "write_file", False), ({"write": True}, None, "write_file", True), ({"write": True}, ["read_file"], "write_file", False),
    ({}, None, "read_file", True), ({}, ["grep"], "read_file", False), ({"web": False}, None, "fetch_url", False), ({"web": True}, None, "fetch_url", True),
    ({"terminal": "none"}, None, "terminal_run", False), ({"terminal": "task"}, None, "terminal_run", True), ({}, None, "delegate", False),
    ({"delegate": True}, None, "delegate", True), ({"delegate": True}, ["read_file"], "delegate", False), ({}, None, "mystery_tool", False), ({}, ["mystery_tool"], "mystery_tool", True)])
def test_tool_allowed_matrix(perms, tools, tool, ok):
    assert C.tool_allowed(job(agent={"id": "a", "permissions": perms, "tools": tools}), tool) is ok


def test_limits_and_parent_validation():
    assert C.validate_job(job(limits={"max_turns": 0})) and C.validate_job(job(limits={"nope": 1})) and C.validate_job(job(limits={"budget_usd": True}))
    assert C.validate_job(job(parent={"job_id": "p"})) and not C.validate_job(job(parent={"job_id": "p", "depth": 2}))


def test_result_roundtrip_and_invariants():
    r = C.make_result("j", "completed", "done", "ok", usage={"turns": 2}, comp=C.completion(model_said_done=True)); assert C.validate_result(r) == []
    assert r["usage"]["cache_read_tokens"] == 0 and r["completion"]["tests_passed"] is None
    bad = copy.deepcopy(r); bad["usage"].pop("cost_usd"); assert C.validate_result(bad)
    bad = copy.deepcopy(r); bad["completion"]["tests_passed"] = False; assert C.validate_result(bad)       # claims done while its own tests failed
    bad = copy.deepcopy(r); bad["completion"]["syntax_ok"] = "yes"; assert C.validate_result(bad)
    f = C.make_result("j", "failed", "error", error=("model_unavailable", "down")); assert f["error"]["retryable"] is True and C.validate_result(f) == []
    h = C.make_result("j", "held", "error", error=("needs_owner", "approve")); assert C.validate_result(h) == []
    assert C.validate_result(C.make_result("j", "held", "error", error=("internal", "x")))             # held only for human-action codes
    assert C.validate_result({"status": "failed"})
    with pytest.raises(ValueError): C.make_result("j", "failed", "error", error=("made_up", "x"))


def test_capabilities():
    c = C.capabilities("lite", ["read_file", "grep"], 4, ["cancel", "resume"]); assert C.validate_capabilities(c) == []
    assert C.validate_capabilities({**c, "engine": "Bad Name"}) and C.validate_capabilities({**c, "features": ["teleport"]}) and C.validate_capabilities({**c, "max_concurrency": 0})
    c0 = C.capabilities("lite", ["read_file", "grep"], 4, ["resume"])
    assert C.requirements_met(job(agent={"id": "a", "tools": ["grep"]}), c0) is False       # no `cancel` -> not dispatchable
    c2 = C.capabilities("lite", ["read_file", "grep"], 4, ["cancel"])
    assert C.requirements_met(job(agent={"id": "a", "tools": ["grep"]}), c2) and not C.requirements_met(job(agent={"id": "a", "tools": ["write_file"]}), c2)


# --- a reference runtime proving the conformance harness is satisfiable (and catches a bad one)
def good_runtime(j, ctl):
    if not C.version_ok(j.get("contract_version")): return C.make_result(j["job_id"], "failed", "error", error=("unsupported_version", "no"))
    if C.validate_job(j): return C.make_result(j["job_id"], "failed", "error", error=("invalid_job", "bad"))
    if "write_file" in j["prompt"]:
        ctl.tool_attempts.append(("write_file", C.tool_allowed(j, "write_file")))
    for _ in range(50):
        if ctl.cancelled(): return C.make_result(j["job_id"], "cancelled", "cancelled")
        if "long time" not in j["prompt"]: break
    return C.make_result(j["job_id"], "completed", "done", "hi", comp=C.completion(model_said_done=True))


def test_conformance_reference_runtime_passes():
    res = CF.check_runtime(good_runtime); assert all(ok for _, ok, _ in res), res


def test_conformance_detects_a_runtime_that_ignores_permissions_and_cancel():
    def bad(j, ctl):
        if "write_file" in j["prompt"]: ctl.tool_attempts.append(("write_file", True))
        r = C.make_result(j["job_id"], "completed", "done"); r["usage"].pop("turns"); return r
    res = {n: ok for n, ok, _ in CF.check_runtime(bad)}
    assert not res["ungranted_tool_never_executed"] and not res["cancel_honoured"] and not res["usage_keys"] and not res["unsupported_version_refused"]
