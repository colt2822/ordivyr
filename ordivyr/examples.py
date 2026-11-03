"""The five-agent reference organisation used by the built-in template, the docs and the verification suite."""
from __future__ import annotations
from . import core, gambits as G


def five_agent_board(name="GOD + Research, Coding, QA, Outreach"):
    b = core.new_board(name); ag = {}
    def mk(key, nm, x, y, skills, tools=(), dept=None, **kw):
        a = core.new_agent(x, y, nm, id=f"a-{key}", dept=dept, **kw)
        a["license"]["skills"] = list(skills); a["tools"] = list(tools); ag[key] = a; b["agents"].append(a); return a
    eng = core.new_department("Engineering", 300, 250, 420, 200, id="d-eng"); out = core.new_department("Outreach", 780, 250, 200, 200, id="d-out")
    out["policy"]["paid_allowed"] = False; out["policy"]["tools_deny"] = ["shell", "code_exec"]; out["policy"]["max_autonomy"] = "supervised"
    out["policy"]["agent_limits"]["token_budget"] = 20000
    eng["policy"]["agent_limits"]["max_seconds"] = 300
    b["departments"] += [eng, out]
    mk("god", "GOD", 480, 20, ["research"], ["browser"], soul="Calm, decisive owner of the mission.", instructions="Route work to the right department. Never do the work yourself.")
    mk("research", "Research", 120, 280, ["research"], ["browser"], instructions="Find and cite sources.")
    mk("coding", "Coding", 330, 300, ["coding"], ["shell", "file_write", "code_exec"], dept="d-eng", instructions="Implement changes with tests.")
    mk("qa", "QA", 530, 300, ["qa"], ["shell"], dept="d-eng", instructions="Verify Coding's output; reject anything unverified.")
    mk("outreach", "Outreach", 810, 300, ["outreach"], ["browser"], dept="d-out", instructions="Draft outreach; nothing is sent without approval.")
    ag["coding"]["license"]["fallbacks"] = []          # configured per scenario
    E = lambda s, t, **kw: b["edges"].append(core.new_edge(ag[s]["id"], ag[t]["id"], **kw))
    for t in ("research", "coding", "outreach"): E("god", t, kind="both")
    E("coding", "qa", kind="delegate")
    b["events"] = ["deploy-approved"]
    R = G.new_rule
    ag["god"]["gambits"] = [
        R("task_type", "delegate", **{"if": {"kind": "task_type", "value": "coding"}, "then": {"kind": "delegate", "target": ag["coding"]["id"]}}),
        R("task_type", "delegate", **{"if": {"kind": "task_type", "value": "research"}, "then": {"kind": "delegate", "target": ag["research"]["id"]}}),
        R("task_type", "delegate", **{"if": {"kind": "task_type", "value": "outreach"}, "then": {"kind": "delegate", "target": ag["outreach"]["id"]}}),
        R("no_worker", "ask_drex", **{"if": {"kind": "no_worker"}, "then": {"kind": "ask_drex", "target": ""}}),
    ]
    ag["coding"]["gambits"] = [
        R("budget", "stop_paid", **{"if": {"kind": "budget", "metric": "tokens", "pct": 100}, "then": {"kind": "stop_paid", "target": "", "scope": "agent"}}),
        R("task_failed", "escalate", **{"if": {"kind": "task_failed", "count": 2}, "then": {"kind": "escalate", "target": "manager"}}),
        R("task_completed", "send_to", **{"if": {"kind": "task_completed"}, "then": {"kind": "send_to", "target": ag["qa"]["id"]}}),
    ]
    ag["qa"]["gambits"] = [R("task_completed", "notify", **{"if": {"kind": "task_completed"}, "then": {"kind": "notify", "target": ""}})]
    return b
