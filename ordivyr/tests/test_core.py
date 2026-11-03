import json, pytest
from ordivyr import core

def two():
    b = core.new_board("t"); a = core.new_agent(0, 0, "A"); c = core.new_agent(200, 0, "B")
    b["agents"] += [a, c]; b["edges"].append(core.new_edge(a["id"], c["id"])); return b, a, c

def test_valid_two_agents():
    b, a, c = two(); assert core.validate(b)["errors"] == []

def test_empty_board_blocks():
    assert core.validate(core.new_board())["errors"]

def test_cycle_detected():
    b, a, c = two(); b["edges"].append(core.new_edge(c["id"], a["id"]))
    assert any("cycle" in e for e in core.validate(b)["errors"])

def test_self_edge_and_dangling():
    b, a, c = two(); b["edges"].append(core.new_edge(a["id"], a["id"])); b["edges"].append(core.new_edge(a["id"], "zzz"))
    errs = core.validate(b)["errors"]; assert any("itself" in e for e in errs) and any("missing" in e for e in errs)

def test_unknown_model_and_paid_warning():
    b, a, c = two(); a["model"] = "nope"; c["model"] = "codex.01"
    v = core.validate(b, {"det.01": {}, "codex.01": {}}, lambda m: m == "codex.01")
    assert any("not a connected" in e for e in v["errors"]) and any("paid" in w for w in v["warnings"])

def test_limits_bounds():
    b, a, c = two(); a["limits"]["max_seconds"] = 99999; a["limits"]["concurrency"] = 0
    assert len(core.validate(b)["errors"]) == 2

def test_subagent_budget_cannot_exceed_parent():
    b, a, c = two(); a["subagents"] = {"enabled": True, "max": 2, "limits": core.default_limits(token_budget=999999)}
    assert any("subagent" in e for e in core.validate(b)["errors"])

def test_compile_order_and_dependencies():
    b, a, c = two(); specs = core.compile_board(b, "do it", "R1")
    assert [s["agent_id"] for s in specs] == [a["id"], c["id"]] and specs[1]["depends_on_agents"] == [a["id"]]
    assert specs[0]["request_id"] == f"{core.REQUEST_PREFIX}:R1:{a['id']}" and "do it" in specs[0]["description"]

def test_paused_agent_skipped_and_link_dropped():
    b, a, c = two(); a["paused"] = True; specs = core.compile_board(b, "m", "R")
    assert len(specs) == 1 and specs[0]["depends_on_agents"] == []

def test_templates_validate_and_have_expected_shape():
    T = core.builtin_templates(); assert len(T) >= 5
    for t in T.values(): assert core.validate(t["board"])["errors"] == [], t["key"]
    full = T["full-organization"]["board"]
    assert len(full["agents"]) == 14 and len(full["departments"]) == 3

def test_export_import_roundtrip_and_hostile():
    b = core.builtin_templates()["sales-team"]["board"]
    r = core.import_board(json.dumps(core.export_board(b)), {"det.01": {}})
    assert len(r["agents"]) == len(b["agents"]) and core.validate(r)["errors"] == []
    evil = {"agents": [{"id": "x", "name": "n", "model": "rm -rf", "__proto__": 1}], "edges": [], "departments": []}
    assert core.import_board(evil, {"det.01": {}})["agents"][0]["model"] == "det.01"
    with pytest.raises(ValueError): core.import_board({"schema": 99})
    with pytest.raises(ValueError): core.import_board("[]")

def test_instantiate_fresh_ids():
    b = core.builtin_templates()["sales-team"]["board"]; c = core.instantiate(b, 10, 10, " copy")
    assert not {a["id"] for a in b["agents"]} & {a["id"] for a in c["agents"]}
    assert all(e["from"] in {a["id"] for a in c["agents"]} for e in c["edges"])
    assert core.validate(c)["errors"] == []

def test_report_back_arrow_is_not_a_cycle():
    b, a, c = two(); b["edges"].append(core.new_edge(c["id"], a["id"], kind="report"))
    assert core.validate(b)["errors"] == []
    assert core.compile_board(b, "m", "R")[1]["depends_on_agents"] == [a["id"]]

def test_approval_edge_compiles_to_draft():
    b, a, c = two(); b["edges"][0]["approval"] = True
    s = core.compile_board(b, "m", "R"); assert s[1]["contract"].get("draft") is True and "draft" not in s[0]["contract"]
