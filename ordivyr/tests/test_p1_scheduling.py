"""P1 scheduling & token efficiency: no wave barrier, bounded concurrency, cancellation, paid exclusivity, stale tool-output pruning, Anthropic prompt-cache markers."""
import json, threading, time
import pytest
from ordivyr import core, runner as RUN, agentloop as AL


class SlowLLM:
    """Per-agent delay by the name in the system prompt; records start/end times."""
    def __init__(self, delays): self.backends = {"fake": object()}; self.delays = delays; self.t = {}; self.lock = threading.Lock(); self.active = 0; self.peak = 0; self.t0 = time.time()
    def chat(self, backend, model, system, messages, **kw):
        name = system.split(".")[0].replace("You are ", "")
        with self.lock: self.active += 1; self.peak = max(self.peak, self.active); self.t.setdefault(name, [None, None])[0] = time.time() - self.t0
        time.sleep(self.delays.get(name, 0.05))
        with self.lock: self.active -= 1; self.t[name][1] = time.time() - self.t0
        return "ok:" + name, 3, "fake:m"


def diamond():
    """boss -> fast, slow ; fast -> fastchild ; slow -> join(fast+slow)."""
    b = core.new_board("T")
    for i, n in enumerate(("Boss", "Fast", "Slow", "FastChild", "Join")): b["agents"].append(core.new_agent(0, 0, n, id=n.lower(), model="fake:m"))
    for f, t in (("boss", "fast"), ("boss", "slow"), ("fast", "fastchild"), ("fast", "join"), ("slow", "join")): b["edges"].append({"id": f"{f}-{t}", "from": f, "to": t, "kind": "delegate"})
    return b


def test_dependent_starts_when_its_own_prerequisite_finishes_not_when_the_wave_does():
    llm = SlowLLM({"Fast": 0.05, "Slow": 0.8, "FastChild": 0.05}); r = RUN.Runner(diamond(), "m", llm=llm, parallel=4).run()
    assert r["status"] == "done" and llm.t["FastChild"][0] < llm.t["Slow"][1] - 0.4          # FastChild began long before Slow finished (a wave barrier would have held it)
    assert llm.t["Join"][0] >= llm.t["Slow"][1] - 0.01                                      # Join still waits for BOTH prerequisites


def test_wave_scheduler_still_available_and_slower():
    a = SlowLLM({"Fast": 0.05, "Slow": 0.6, "FastChild": 0.3}); t = time.time(); RUN.Runner(diamond(), "m", llm=a, parallel=4, scheduler="event").run(); ev = time.time() - t
    b = SlowLLM({"Fast": 0.05, "Slow": 0.6, "FastChild": 0.3}); t = time.time(); RUN.Runner(diamond(), "m", llm=b, parallel=4, scheduler="wave").run(); wv = time.time() - t
    assert ev < wv - 0.15


def test_concurrency_is_bounded():
    b = core.new_board("T"); b["agents"].append(core.new_agent(0, 0, "Boss", id="boss", model="fake:m"))
    for i in range(10): b["agents"].append(core.new_agent(0, 0, f"W{i}", id=f"w{i}", model="fake:m")); b["edges"].append({"id": f"e{i}", "from": "boss", "to": f"w{i}", "kind": "delegate"})
    llm = SlowLLM({f"W{i}": 0.1 for i in range(10)}); r = RUN.Runner(b, "m", llm=llm, parallel=3).run(); assert r["status"] == "done" and llm.peak == 3


def test_failure_blocks_only_dependants_in_event_mode():
    class Boom(SlowLLM):
        def chat(self, backend, model, system, messages, **kw):
            if system.startswith("You are Slow."): raise RuntimeError("boom")
            return super().chat(backend, model, system, messages, **kw)
    r = RUN.Runner(diamond(), "m", llm=Boom({}), parallel=4).run(); s = {k: v["status"] for k, v in r["agents"].items()}
    assert s == {"boss": "done", "fast": "done", "slow": "failed", "fastchild": "done", "join": "blocked"} and r["status"] == "partial"


def test_cancellation_stops_new_starts_and_reports_cancelled():
    llm = SlowLLM({"Boss": 0.05, "Fast": 0.3, "Slow": 0.3}); rn = RUN.Runner(diamond(), "m", llm=llm, parallel=4)
    threading.Timer(0.2, rn.cancel).start(); r = rn.run()
    assert r["status"] == "cancelled" and r["agents"]["join"]["status"] == "skipped" and r["agents"]["fastchild"]["status"] == "skipped"
    assert r["agents"]["fast"]["status"] == "done"                             # in-flight agents finish; nothing new starts


def test_default_sequential_transcript_unchanged():
    a = RUN.Runner(diamond(), "m", llm=SlowLLM({}), run_id="r").run(); b = RUN.Runner(diamond(), "m", llm=SlowLLM({}), run_id="r", scheduler="wave").run()
    assert [x["msg"] for x in a["log"]] == [x["msg"] for x in b["log"]] and a["status"] == "done"


# ---------------------------------------------------------------- token efficiency
def long_run(prune):
    """Scripted provider: asks for read_file 8 times (each result ~8,000 chars), then answers. Returns (bodies sent, tokens)."""
    sent = []; n = {"i": 0}
    def http(method, url, headers, data, timeout):
        body = json.loads(data); sent.append(body); n["i"] += 1
        if n["i"] <= 8: msg = {"role": "assistant", "content": "", "tool_calls": [{"id": f"c{n['i']}", "type": "function", "function": {"name": "read_file", "arguments": json.dumps({"path": f"big{n['i']}.txt"})}}]}
        else: msg = {"role": "assistant", "content": "done"}
        return 200, json.dumps({"choices": [{"message": msg}], "usage": {"total_tokens": 1}}).encode()
    import tempfile, pathlib
    d = pathlib.Path(tempfile.mkdtemp()); [(d / f"big{k}.txt").write_text("".join(f"file {k} line {i} " + "x" * 40 + "\n" for i in range(400))) for k in range(1, 9)]
    st = {}; text, tk, used, steps, stop = AL.run("openai", "https://api.example.com/v1", "k", "m", "sys", "go", AL.ToolBox(d), http=http, max_steps=12, prune=prune, stats=st)
    return sent, text, st


def test_stale_tool_outputs_are_elided_but_recent_ones_and_answer_survive(monkeypatch):
    monkeypatch.setattr(AL, "COMPACT_AT", 1)          # compaction is pressure-triggered now (history is append-only below COMPACT_AT); simulate pressure
    sent_p, text_p, st = long_run(True); sent_n, text_n, _ = long_run(False)
    size = lambda sent: sum(len(json.dumps(b["messages"])) for b in sent)
    assert text_p == text_n == "done" and size(sent_p) < size(sent_n) * 0.8 and st["pruned_chars"] > 0       # measured 301,653 -> 223,773 chars (-25.8%) over a 9-request loop with 8 distinct 8 KB results (proxy for input tokens)
    last = sent_p[-1]["messages"]; tools = [m for m in last if m.get("role") == "tool"]
    assert all(len(m["content"]) > 5000 for m in tools[-AL.STALE_KEEP:]) and "elided to save tokens" in tools[0]["content"]


def test_prune_is_idempotent_and_leaves_short_results():
    msgs = [{"role": "tool", "content": "short"}] + [{"role": "tool", "content": "y" * 3000} for _ in range(6)]
    c1 = AL.prune_stale(msgs, "openai"); assert c1 > 0 and msgs[0]["content"] == "short" and AL.prune_stale(msgs, "openai") == 0


def test_anthropic_prompt_cache_markers_only_for_anthropic_hosts():
    seen = []
    def http(method, url, headers, data, timeout): seen.append(json.loads(data)); return 200, json.dumps({"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 1, "output_tokens": 1}}).encode()
    import tempfile, pathlib
    box = AL.ToolBox(pathlib.Path(tempfile.mkdtemp()))
    AL.run("anthropic", "https://api.anthropic.com", "k", "m", "SYS", "hi", box, http=http); AL.run("anthropic", "https://proxy.example.com", "k", "m", "SYS", "hi", box, http=http)
    a, b = seen; assert a["system"][0]["cache_control"] == {"type": "ephemeral"} and a["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert b["system"] == "SYS" and "cache_control" not in json.dumps(b)
