import json, tempfile, unittest
from pathlib import Path
from ordivyr import teams as T, core, gambits as G

W = {"det.01": {"id": "det.01", "paid": False}}
ACC = [{"id": "claude-work", "provider": "claude", "model": "", "enabled": True, "connected": True}, {"id": "off", "provider": "anthropic", "model": "claude-opus-5-5", "enabled": False, "connected": True}]


class Builtins(unittest.TestCase):
    def test_the_five_templates_exist(self):
        self.assertEqual([k for k, t in T.builtin().items() if "local" not in t["tags"]], ["saas-dev-team", "research-department", "youtube-production-team", "business-operations-team", "crypto-research-team"])

    def test_every_template_builds_a_board_that_validates_with_no_errors(self):
        for k, t in {k: t for k, t in T.builtin().items() if "local" not in t["tags"]}.items():
            b, needs = T.build(t, [], W); v = core.validate(b, W, lambda m: False)
            self.assertEqual(v["errors"], [], k); self.assertTrue(needs, k)
            self.assertTrue(all(a["model"] == "det.01" for a in b["agents"]), "unconnected -> free default, never a made-up paid worker")

    def test_each_template_has_the_promised_features(self):
        for k, t in {k: t for k, t in T.builtin().items() if "local" not in t["tags"]}.items():
            ag = t["agents"]
            self.assertGreaterEqual(len(ag), 5, k)
            self.assertTrue(all(a["instructions"] and a["role"] and a["model"]["suggest"] for a in ag), k)
            self.assertTrue(any(a["subagents"].get("enabled") for a in ag), f"{k}: subagents"); self.assertTrue(any(a["gambits"] for a in ag), f"{k}: gambits")
            self.assertTrue(any(b["memory"] != "none" for b in t["bridges"]) or t["shared_memory"], f"{k}: memory"); self.assertTrue(t["shared_memory"], k)
            self.assertTrue(all(a["limits"] for a in ag), f"{k}: limits"); self.assertTrue(len({b["kind"] for b in t["bridges"]}) >= 2, f"{k}: delegation + reporting")
            self.assertTrue(any(a["license"].get("autonomy") for a in ag), k)
            self.assertFalse(T.SECRET_RE.search(json.dumps(t)), k)

    def test_safety_defaults(self):
        c = T.builtin()["crypto-research-team"]; allt = {t for a in c["agents"] for t in a["tools"]}
        self.assertFalse(allt & {"wallet", "trade"}); self.assertIn("not financial advice", json.dumps(c).lower())
        biz = T.builtin()["business-operations-team"]; front = [a for a in biz["agents"] if a["dept"] == "front"]
        self.assertTrue(front and not any(set(a["tools"]) & {"shell", "code_exec"} for a in front)); self.assertFalse(any(a["license"].get("paid_allowed") and a["dept"] for a in biz["agents"]))
        for t in T.builtin().values():
            self.assertTrue(all(a["license"].get("autonomy", "supervised") != "autonomous" for a in t["agents"]), "no template starts fully autonomous")

    def test_gambit_targets_resolve_to_real_agents(self):
        b, _ = T.build(T.builtin()["saas-dev-team"], [], W); ids = {a["id"] for a in b["agents"]}
        for a in b["agents"]:
            for r in a["gambits"]:
                tg = r["then"].get("target")
                self.assertTrue(tg in ids or tg in ("", "manager", "auto"), (a["name"], tg))

    def test_build_twice_gives_distinct_ids(self):
        t = T.builtin()["research-department"]; a, _ = T.build(t, [], W); b, _ = T.build(t, [], W)
        self.assertFalse({x["id"] for x in a["agents"]} & {x["id"] for x in b["agents"]})


class Models(unittest.TestCase):
    def test_connected_matching_account_is_used_else_free_default(self):
        w = {**W, "acct.claude-work": {}, "acct.off": {}}
        b, needs = T.build(T.builtin()["saas-dev-team"], ACC, w)
        self.assertIn("acct.claude-work", {a["model"] for a in b["agents"]}); self.assertNotIn("acct.off", {a["model"] for a in b["agents"]})
        b2, n2 = T.build(T.builtin()["saas-dev-team"], ACC, W)              # worker not registered -> never invents one
        self.assertTrue(all(a["model"] == "det.01" for a in b2["agents"]))

    def test_paid_choice_still_needs_licence(self):
        w = {**W, "acct.claude-work": {"paid": True}}
        b, _ = T.build(T.builtin()["saas-dev-team"], ACC, w); v = core.validate(b, w, lambda m: m.startswith("acct."))
        self.assertFalse(v["errors"], v["errors"])           # strong-tier agents are licensed for paid; Play still holds each run for approval


class Json(unittest.TestCase):
    def test_roundtrip_board_to_template_and_back(self):
        b, _ = T.build(T.builtin()["youtube-production-team"], [], W); doc = T.from_board(b, "My team", "mine")
        self.assertEqual(doc["schema"], T.SCHEMA); b2, _ = T.build(doc, [], W)
        self.assertEqual([a["name"] for a in b2["agents"]], [a["name"] for a in b["agents"]]); self.assertEqual(len(b2["edges"]), len(b["edges"]))
        self.assertEqual(core.validate(b2, W, lambda m: False)["errors"], []); self.assertEqual(sum(len(a["gambits"]) for a in b2["agents"]), sum(len(a["gambits"]) for a in b["agents"]))

    def test_rejects_bad_documents(self):
        good = json.loads(json.dumps(T.builtin()["saas-dev-team"]))
        for mut, msg in ((lambda d: d.update(schema="x"), "not an ORDIVYR"), (lambda d: d.update(key="Bad Key"), "key"), (lambda d: d.update(agents=[]), "at least one"),
                         (lambda d: d["bridges"].append({"from": "nope", "to": "lead"}), "bridge"), (lambda d: d["agents"].append(dict(d["agents"][0])), "duplicate"),
                         (lambda d: d["agents"][0].update(instructions="use sk-abcdefghijklmnopqrstuvwx"), "secret")):
            d = json.loads(json.dumps(good)); mut(d)
            with self.assertRaises(T.TemplateError) as cm: T.clean(d)
            self.assertIn(msg, str(cm.exception))
        with self.assertRaises(T.TemplateError): T.clean("{not json")
        with self.assertRaises(T.TemplateError): T.clean("x" * (T.MAX_BYTES + 1))

    def test_unknown_fields_and_capabilities_are_dropped(self):
        d = json.loads(json.dumps(T.builtin()["saas-dev-team"])); d["agents"][0]["tools"] += ["rm_rf"]; d["agents"][0]["evil"] = "x"; d["bridges"][0]["color"] = "url(javascript:1)"
        t = T.clean(d); self.assertNotIn("rm_rf", t["agents"][0]["tools"]); self.assertNotIn("evil", t["agents"][0]); self.assertEqual(t["bridges"][0]["color"], "")

    def test_user_templates_save_list_delete_and_cannot_shadow_builtins(self):
        home = tempfile.mkdtemp(); t = T.save_user(home, T.builtin()["saas-dev-team"])
        self.assertTrue(t["key"].startswith("my-")); self.assertIn(t["key"], T.user_templates(home)); self.assertTrue(T.catalog(home)[t["key"]]["user"])
        self.assertEqual(len([k for k in T.catalog(home) if not k.startswith("my-") and "local" not in T.catalog(home)[k]["tags"]]), 5)
        T.delete_user(home, t["key"]); self.assertNotIn(t["key"], T.user_templates(home))
        with self.assertRaises(T.TemplateError): T.delete_user(home, "../x")
        (Path(home) / "team-templates" / "junk.json").write_text("{nope"); self.assertEqual(T.user_templates(home), {})       # a bad shared file never breaks the list

    def test_summary_has_no_instructions(self):
        s = T.summary(T.builtin()["saas-dev-team"]); self.assertNotIn("instructions", json.dumps(s)); self.assertEqual(len(s["agents"]), 6)


if __name__ == "__main__": unittest.main()
