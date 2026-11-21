import json, tempfile, threading, time, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from ordivyr import agentloop as AL, providers as PV
from test_agentloop import seq_http, oa_call, oa_text


def multi_call(calls):
    return {"choices": [{"message": {"role": "assistant", "content": "", "tool_calls": [{"id": f"c{i}", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}} for i, (n, a) in enumerate(calls)]}}], "usage": {"total_tokens": 10}}


class SlowBox(AL.ToolBox):
    def __init__(self, *a, **k): super().__init__(*a, **k); self.order = []
    def call(self, name, args): self.order.append(("start", name)); time.sleep(0.2); self.order.append(("end", name)); return super().call(name, args)


class Parallel(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp()); [(self.d / f"f{i}.txt").write_text(f"file {i}") for i in range(4)]

    def test_read_only_batch_runs_concurrently_and_keeps_order(self):
        box = SlowBox(self.d, write=True); seen = []
        calls = [("read_file", {"path": f"f{i}.txt"}) for i in range(4)]
        t = time.time(); text, _, _, steps, why = AL.run("openai", "http://127.0.0.1:9", "k", "m", "s", "p", box, http=seq_http([multi_call(calls), oa_text("ok")], seen)); el = time.time() - t
        self.assertEqual((why, steps), ("done", 2)); self.assertLess(el, 0.5, "4 x 0.2s reads must overlap")
        tool_msgs = [m for m in seen[1]["messages"] if m["role"] == "tool"]
        self.assertEqual([m["content"] for m in tool_msgs], [f"     1\tfile {i}" for i in range(4)]); self.assertEqual([m["tool_call_id"] for m in tool_msgs], ["c0", "c1", "c2", "c3"])

    def test_batch_with_a_write_stays_sequential(self):
        box = SlowBox(self.d, write=True)
        calls = [("write_file", {"path": "n.txt", "content": "new"}), ("read_file", {"path": "n.txt"})]
        seen = []; AL.run("openai", "http://127.0.0.1:9", "k", "m", "s", "p", box, http=seq_http([multi_call(calls), oa_text("ok")], seen))
        self.assertEqual(box.order, [("start", "write_file"), ("end", "write_file"), ("start", "read_file"), ("end", "read_file")])
        self.assertEqual([m["content"] for m in seen[1]["messages"] if m["role"] == "tool"][1], "     1\tnew")           # the read saw the write

    def test_on_step_fires_in_call_order(self):
        steps = []; calls = [("read_file", {"path": f"f{i}.txt"}) for i in range(3)]
        AL.run("openai", "http://127.0.0.1:9", "k", "m", "s", "p", AL.ToolBox(self.d), http=seq_http([multi_call(calls), oa_text("ok")]), on_step=lambda n, a, o: steps.append(o))
        self.assertEqual(steps, ["     1\tfile 0", "     1\tfile 1", "     1\tfile 2"])


class Dedupe(unittest.TestCase):
    def test_identical_repeated_output_is_stubbed_once(self):
        d = Path(tempfile.mkdtemp()); (d / "big.txt").write_text("x" * 2000); seen = []
        AL.run("openai", "http://127.0.0.1:9", "k", "m", "s", "p", AL.ToolBox(d), http=seq_http([oa_call("read_file", {"path": "big.txt"}, "a"), oa_call("read_file", {"path": "big.txt"}, "b"), oa_text("ok")], seen))
        tools = [m["content"] for m in seen[2]["messages"] if m["role"] == "tool"]
        self.assertEqual(tools, ["     1\t" + "x" * 2000, AL.DUP_STUB])       # append-only: the EARLIER message is untouched, the repeat is the pointer

    def test_changed_output_is_never_stubbed(self):
        d = Path(tempfile.mkdtemp()); (d / "f.txt").write_text("a" * 500); seen = []
        def http(method, url, headers, data, timeout):
            seen.append(json.loads(data)); n = len(seen)
            if n == 1: return 200, json.dumps(oa_call("read_file", {"path": "f.txt"}, "a")).encode()
            if n == 2: (d / "f.txt").write_text("b" * 500); return 200, json.dumps(oa_call("read_file", {"path": "f.txt"}, "b")).encode()
            return 200, json.dumps(oa_text("ok")).encode()
        AL.run("openai", "http://127.0.0.1:9", "k", "m", "s", "p", AL.ToolBox(d), http=http)
        self.assertEqual([m["content"] for m in seen[2]["messages"] if m["role"] == "tool"], ["     1\t" + "a" * 500, "     1\t" + "b" * 500])


class KeepAlive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conns = []; cls.mode = {"close": False}
        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def setup(s): super().setup(); cls.conns.append(1)
            def log_message(s, *a): pass
            def do_POST(s):
                n = int(s.headers.get("Content-Length") or 0); s.rfile.read(n); b = b'{"ok":1}'
                s.send_response(200 if s.path != "/err" else 500); s.send_header("Content-Length", str(len(b)))
                if cls.mode["close"]: s.send_header("Connection", "close")
                s.end_headers(); s.wfile.write(b)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), H); cls.port = cls.srv.server_address[1]; threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def setUp(self): [c.close() for c in PV._TL.__dict__.get('pool', {}).values()]; PV._TL.__dict__.pop('pool', None)

    def test_one_connection_serves_many_calls(self):
        self.conns.clear(); self.mode["close"] = False
        for _ in range(5): self.assertEqual(PV._urlopen("POST", f"http://127.0.0.1:{self.port}/v1", {"Content-Type": "application/json"}, b"{}", 5), (200, b'{"ok":1}'))
        self.assertEqual(len(self.conns), 1)

    def test_server_close_falls_back_to_new_connection_and_errors_pass_through(self):
        self.conns.clear(); self.mode["close"] = True
        for _ in range(3): self.assertEqual(PV._urlopen("POST", f"http://127.0.0.1:{self.port}/v1", {}, b"{}", 5)[0], 200)
        self.assertEqual(len(self.conns), 3); self.mode["close"] = False
        self.assertEqual(PV._urlopen("POST", f"http://127.0.0.1:{self.port}/err", {}, b"{}", 5)[0], 500)

    def test_stale_pooled_connection_is_retried_once(self):
        self.mode["close"] = False; url = f"http://127.0.0.1:{self.port}/v1"; PV._urlopen("POST", url, {}, b"{}", 5)
        pool = PV._TL.pool; c = next(iter(pool.values())); c.sock.close()                  # simulate the server having dropped the idle connection
        self.assertEqual(PV._urlopen("POST", url, {}, b"{}", 5)[0], 200)

    def test_unreachable_is_a_provider_error(self):
        with self.assertRaises(PV.ProviderError): PV._urlopen("POST", "http://127.0.0.1:1/x", {}, b"{}", 2)


if __name__ == "__main__": unittest.main()


# ---------------------------------------------------------------- Runner: parallel waves
import copy
from ordivyr import core, runner as RUN


class FakeLLM:
    def __init__(self, delay=0.0): self.backends = {"fake": object()}; self.delay = delay; self.active = 0; self.peak = 0; self.lock = threading.Lock(); self.order = []
    def chat(self, backend, model, system, messages, **kw):
        with self.lock: self.active += 1; self.peak = max(self.peak, self.active)
        time.sleep(self.delay)
        with self.lock: self.active -= 1; self.order.append(system[:0] + messages[0]["text"][:0])
        return "out:" + system.split("\n")[0][:30], 7, "fake:m"


def fan_board(n=4):
    b = core.new_board("T"); mgr = core.new_agent(0, 0, "Boss", id="boss", model="fake:m"); b["agents"].append(mgr)
    for i in range(n):
        b["agents"].append(core.new_agent(0, 0, f"W{i}", id=f"w{i}", model="fake:m")); b["edges"].append({"id": f"e-b{i}", "from": "boss", "to": f"w{i}", "kind": "delegate"})
    b["agents"].append(core.new_agent(0, 0, "Join", id="join", model="fake:m"))
    for i in range(n): b["edges"].append({"id": f"e-j{i}", "from": f"w{i}", "to": "join", "kind": "delegate"})
    return b


class RunnerParallel(unittest.TestCase):
    def test_default_is_sequential(self):
        llm = FakeLLM(0.05); r = RUN.Runner(fan_board(), "m", llm=llm).run()
        self.assertEqual(r["status"], "done"); self.assertEqual(llm.peak, 1)

    def test_workers_overlap_but_boss_first_and_join_last(self):
        llm = FakeLLM(0.2); t = time.time(); r = RUN.Runner(fan_board(4), "m", llm=llm, parallel=4).run(); el = time.time() - t
        self.assertEqual(r["status"], "done"); self.assertEqual(llm.peak, 4); self.assertLess(el, 0.2 * 3 + 0.2, "boss + 4 parallel workers + join = 3 serial slots, not 6")

    def test_same_result_as_sequential(self):
        a = RUN.Runner(fan_board(4), "mission", llm=FakeLLM(), run_id="r").run(); b = RUN.Runner(fan_board(4), "mission", llm=FakeLLM(), parallel=4, run_id="r").run()
        strip = lambda r: {k: {kk: vv for kk, vv in v.items() if kk != "retries"} for k, v in r["agents"].items()}
        self.assertEqual(strip(a), strip(b)); self.assertEqual([x["msg"] for x in a["log"]], [x["msg"] for x in b["log"]])

    def test_a_failing_agent_blocks_only_its_dependants(self):
        class Boom(FakeLLM):
            def chat(self, backend, model, system, messages, **kw):
                if system.startswith("You are W1."): raise RuntimeError("boom")
                return super().chat(backend, model, system, messages, **kw)
        r = RUN.Runner(fan_board(3), "m", llm=Boom(), parallel=3).run()
        self.assertEqual(r["agents"]["w1"]["status"], "failed"); self.assertEqual(r["agents"]["w0"]["status"], "done"); self.assertEqual(r["agents"]["join"]["status"], "blocked")


class PaidNeverBatched(unittest.TestCase):
    def test_paid_agents_run_one_at_a_time_even_with_parallel(self):
        b = fan_board(3)
        for a in b["agents"]: a["model"] = "acct.p"; a["license"]["paid_allowed"] = True
        state = {"active": 0, "peak": 0}; lock = threading.Lock()
        def http(method, url, headers, data, timeout):
            with lock: state["active"] += 1; state["peak"] = max(state["peak"], state["active"])
            time.sleep(0.05)
            with lock: state["active"] -= 1
            return 200, json.dumps({"choices": [{"message": {"content": "ok"}}], "usage": {"total_tokens": 1}}).encode()
        acc = {"p": {"protocol": "openai", "base": "https://api.example.com/v1", "key": "k", "model": "m"}}
        r = RUN.Runner(b, "m", accounts=acc, allow_paid=True, approve=lambda a, why: True, http=http, parallel=4).run()
        self.assertEqual(r["status"], "done", r["agents"]); self.assertEqual(state["peak"], 1)
