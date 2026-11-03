import json, unittest
from ordivyr import notify as N

B = {"name": "Shop", "agents": [{"id": "a1", "name": "Ada"}, {"id": "a2", "name": "Bo"}]}
def snap(**ag): return {"run": {"run_id": "R1", "status": "RUNNING"}, "agents": {k: {"task_id": "T" + k, **v} for k, v in ag.items()}}


class T(unittest.TestCase):
    def test_each_transition_fires_once(self):
        seen = set(); s = snap(a1={"column": "HUMAN_APPROVAL", "status": "waiting"}, a2={"status": "error"})
        e = N.events(s, B, seen); self.assertEqual(sorted(x["kind"] for x in e), ["approval", "error"])
        self.assertEqual(N.events(s, B, seen), [])                                                       # the 2s ticker must not repeat itself
        s2 = snap(a1={"column": "REVIEW", "question": "which folder?"}); k = [x["kind"] for x in N.events(s2, B, seen)]; self.assertEqual(k, ["question"])

    def test_run_finished(self):
        s = snap(a1={"column": "REVIEW"}); s["run"]["status"] = "DONE"; k = [x["kind"] for x in N.events(s, B, set())]; self.assertIn("run_done", k)

    def test_payload_has_names_not_prompts_and_webhook_rules(self):
        sent = []
        class R: 
            def read(self): return b""
        uo = lambda req, timeout: sent.append(json.loads(req.data)) or R()
        ev = {"kind": "approval", "agent": "Ada", "text": "Ada is waiting", "room": "Shop"}
        self.assertEqual(N.deliver({"webhook": "https://hooks.example/x"}, ev, urlopen=uo), ["webhook"])
        self.assertEqual(set(sent[0]), {"text", "kind", "agent", "room", "source"})
        self.assertEqual(N.deliver({"webhook": "http://evil.example/x"}, ev, urlopen=uo), [])           # plain http only for loopback
        self.assertEqual(N.deliver({"webhook": "http://127.0.0.1:9/x"}, ev, urlopen=uo), ["webhook"])
        with self.assertRaises(ValueError): N.check_webhook("ftp://x"); 

    def test_desktop_degrades_quietly(self):
        self.assertEqual(N.deliver({"desktop": True}, {"room": "r", "text": "t"}, which=lambda b: None), [])
        calls = []; self.assertEqual(N.deliver({"desktop": True}, {"room": "r", "text": "t"}, which=lambda b: "/bin/x", run=lambda a, **k: calls.append(a)), ["desktop"]); self.assertEqual(calls[0][0], "notify-send")


if __name__ == "__main__": unittest.main()
