import os, sys, tempfile, unittest, pathlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from ordivyr.nova_memory.store import NovaMemory, Principal, vec, _idf_cos
from ordivyr.nova_memory import retrieval_bench as RB

class T(unittest.TestCase):
    def test_idf_prefers_rare_terms_over_boilerplate(self):
        docs = [("boiler", vec("task service tests change small module request")), ("rare", vec("webhook hmac signature rawbody"))] + [(f"n{i}", vec("task service tests change small module request config")) for i in range(30)]
        q = vec("Task for the service: partner webhook signature rejected. Add tests and keep the change small.")
        top = max(_idf_cos(q, docs))[1]
        self.assertEqual(top, "rare")
    def test_flag_off_matches_plain_cosine_ranking_shape(self):
        d = pathlib.Path(tempfile.mkdtemp()); P = Principal.make("T", "P", "a", read=["n"], write=["n"])
        for flag in (True, False):
            m = NovaMemory(d / f"{flag}.db", query_idf=flag); m.add(P, "n", "semantic", "cache", "Invalidate the product cache after writes.", "t")
            self.assertTrue(m.search(P, "product cache invalidate", namespaces=["n"]))
    def test_idf_does_not_widen_scope(self):
        d = pathlib.Path(tempfile.mkdtemp()); A = Principal.make("T", "P", "a", read=["n"], write=["n"]); B = Principal.make("T", "P", "b", read=["other"], write=["other"])
        m = NovaMemory(d / "x.db"); m.add(A, "n", "semantic", "secret plan", "Launch codename is aurora.", "t")
        self.assertEqual(m.search(B, "launch codename aurora", namespaces=["n"]), [])
        self.assertEqual(m.search(B, "launch codename aurora"), [])
    def test_bench_smoke_is_deterministic(self):
        r1 = RB.evaluate(RB.load_cases("dev"), 20, 1000, "verified", "nova"); r2 = RB.evaluate(RB.load_cases("dev"), 20, 1000, "verified", "nova")
        self.assertEqual(r1, r2); self.assertTrue(0 <= r1["hit1"] <= r1["pack"] <= 1)
    def test_heldout_set_is_disjoint_from_dev(self):
        dev = {c[0] for c in RB.load_cases("dev")}; held = {c[0] for c in RB.load_cases("held")}
        self.assertFalse(dev & held); self.assertEqual(len(held), 14)

if __name__ == "__main__": unittest.main()
