import json, sqlite3, pytest
from ordivyr.nova_memory import NovaMemory, Principal, AccessDenied, NovaBackend, capture_run, Validation


class Clk:
    t = 1000.0
    def __call__(self): return self.t


@pytest.fixture
def env(tmp_path):
    clk = Clk(); m = NovaMemory(tmp_path / "n.db", clock=clk)
    a = Principal.make("T1", "P", "alice", read=["team"], write=["team"])
    v = Principal.make("T1", "P", "verifier", read=["team"], write=["team"], can_verify=True)
    return m, a, v, clk


def test_tenant_and_project_isolation(env):
    m, a, v, _ = env
    mid = m.add(a, "team", "semantic", "db", "the production database password rotation happens monthly", "t")
    other_t = Principal.make("T2", "P", "mallory", read=["team"], write=["team"])
    other_p = Principal.make("T1", "Q", "alice", read=["team"], write=["team"])
    for o in (other_t, other_p):
        assert m.search(o, "database password rotation") == []
        with pytest.raises(KeyError): m.get(o, mid)
        with pytest.raises(KeyError): m.delete(o, mid)
    assert m.export(other_t) == ""


def test_namespace_grants_enforced(env):
    m, a, _, _ = env
    with pytest.raises(AccessDenied): m.add(a, "finance", "semantic", "x", "secret salary data", "t")
    priv = Principal.make("T1", "P", "bob")
    m.add(priv, "agent/bob", "episodic", "mine", "bobs private note about widgets", "t")
    assert m.search(a, "widgets") == []                          # alice cannot read bob's private namespace
    assert m.search(a, "widgets", namespaces=["agent/bob"]) == []  # nor request it


def test_candidate_needs_independent_verification(env):
    m, a, v, _ = env
    mid = m.add(a, "team", "semantic", "t", "api uses cursor pagination", "t")
    with pytest.raises(AccessDenied): m.verify(a, mid, {"passed": True, "validator": "ci", "ref": "r1"})        # no verifier role
    with pytest.raises(ValueError): m.verify(v, mid, {"passed": False, "validator": "ci", "ref": "r1"})
    selfv = Principal.make("T1", "P", "alice", read=["team"], write=["team"], can_verify=True)
    with pytest.raises(AccessDenied): m.verify(selfv, mid, {"passed": True, "validator": "ci", "ref": "r1"})     # author cannot verify
    m.verify(v, mid, {"passed": True, "validator": "ci", "ref": "r1"})
    assert m.get(a, mid)["trust"] == "verified"
    assert [h["trust"] for h in m.search(a, "pagination")] == ["verified"]


def test_verified_outranks_candidate_and_candidates_can_be_excluded(env):
    m, a, v, _ = env
    c = m.add(a, "team", "semantic", "cache", "cache ttl is sixty seconds", "t")
    g = m.add(a, "team", "semantic", "cache", "cache ttl is three hundred seconds verified", "t"); m.verify(v, g, {"passed": True, "validator": "ci", "ref": "r"})
    hits = m.search(a, "cache ttl seconds"); assert hits[0]["id"] == g
    assert [h["id"] for h in m.search(a, "cache ttl", include_candidates=False)] == [g]


def test_supersession_hides_old_and_keeps_history(env):
    m, a, v, _ = env
    old = m.add(a, "team", "semantic", "db", "we use postgres 12", "t")
    new = m.correct(a, old, "we use postgres 16", "upgrade done")
    assert [h["id"] for h in m.search(a, "postgres")] == [new]
    d = m.get(a, old); assert d["trust"] == "superseded" and d["superseded_by"] == new
    assert [x["action"] for x in d["history"]] == ["added", "superseded"]
    assert m.get(a, new)["supersedes"] == old


def test_delete_leaves_no_content_and_retention_expires(env):
    m, a, _, clk = env
    mid = m.add(a, "team", "semantic", "x", "ephemeral zebra fact", "t", ttl_s=100)
    keep = m.add(a, "team", "semantic", "y", "durable giraffe fact", "t")
    clk.t += 101
    assert m.search(a, "zebra") == []                           # expired rows are never returned, even before purge
    assert m.purge_expired() == 1
    m.delete(a, keep)
    raw = sqlite3.connect(str(m.path)); dump = "".join(str(r) for t in ("mem", "mem_fts", "hist") for r in raw.execute(f"SELECT * FROM {t}"))
    assert "zebra" not in dump and "giraffe" not in dump
    assert raw.execute("SELECT COUNT(*) FROM tomb").fetchone()[0] == 2


def test_delete_scope_erases_tenant_only(env):
    m, a, _, _ = env
    m.add(a, "team", "semantic", "x", "tenant one fact alpha", "t")
    b = Principal.make("T2", "P", "b", read=["team"], write=["team"]); m.add(b, "team", "semantic", "x", "tenant two fact beta", "t")
    assert m.delete_scope("T1") == 1
    assert m.search(a, "alpha") == [] and len(m.search(b, "beta")) == 1


def test_export_import_roundtrip_demotes_trust(env, tmp_path):
    m, a, v, _ = env
    mid = m.add(a, "team", "procedural", "deploy", "run make release then tag", "t", evidence=[{"ref": "e1"}]); m.verify(v, mid, {"passed": True, "validator": "ci", "ref": "r"})
    dump = m.export(a); rec = json.loads(dump); assert rec["trust"] == "verified" and rec["history"][-1]["action"] == "verified"
    m2 = NovaMemory(tmp_path / "other.db"); assert m2.import_jsonl(a, dump) == 1
    assert m2.search(a, "release tag")[0]["trust"] == "candidate"


def test_dedupe_and_reobserve(env):
    m, a, _, _ = env
    i1 = m.add(a, "team", "semantic", "t", "Use blue-green deploys", "t"); i2 = m.add(a, "team", "semantic", "t2", "use blue green deploys!", "t")
    assert i1 == i2 and len(m.search(a, "blue green deploys")) == 1


def test_token_budget_respected(env):
    m, a, _, _ = env
    for i in range(30): m.add(a, "team", "semantic", f"fact {i}", f"widget calibration step number {i} " + "detail " * 30, "t")
    pk = m.pack(a, "widget calibration", budget_tokens=200)
    assert 0 < pk["tokens"] <= 200 and 0 < len(pk["ids"]) < 30


def test_version_filter(env):
    m, a, _, _ = env
    m.add(a, "team", "semantic", "api", "endpoint is /v1/items", "t", version="1.x"); m.add(a, "team", "semantic", "api", "endpoint is /v2/items", "t", version="2.x")
    assert [h["version"] for h in m.search(a, "endpoint items", version="2.x")] == ["2.x"]


def test_capture_run_only_learns_validated_fixes(env):
    m, a, v, _ = env
    ids = capture_run(m, a, "team", "fix flaky build", "passed", Validation(True, "ci", "run-7"), failure="used cached venv", fix="rebuild venv from lockfile")
    kinds = [m.get(a, i)["kind"] for i in ids]; assert kinds == ["episodic", "corrective"]
    ids2 = capture_run(m, a, "team", "try shortcut", "unvalidated", None, failure="x broke", fix="guess")
    assert [m.get(a, i)["kind"] for i in ids2] == ["episodic"]            # unvalidated fix is not promoted to a lesson
    assert all(m.get(a, i)["trust"] == "candidate" for i in ids + ids2)   # capture never self-verifies


def test_runner_backend_adapter(env):
    m, a, _, _ = env
    b = NovaBackend(m, "T1", "P"); b.remember("alice", "team", "note", "the staging cluster is named orion")
    assert "orion" in b.recall("alice", "team", "staging cluster") and b.recall("alice", "other", "staging") == ""


def test_hybrid_finds_morphological_variants_lexical_misses(tmp_path):
    m = NovaMemory(tmp_path / "s.db"); a = Principal.make("T", "P", "a", read=["t"], write=["t"])
    m.add(a, "t", "semantic", "caching", "Invalidate the cache layer whenever configuration reloads occur", "t")
    assert m.search(a, "reloading configurations", mode="semantic")


def test_near_identical_facts_differing_by_a_digit_are_not_merged(env):
    m, a, _, _ = env
    i1 = m.add(a, "team", "semantic", "r", "svc runs in region us-east-1", "t"); i2 = m.add(a, "team", "semantic", "r", "svc runs in region us-east-2", "t")
    assert i1 != i2 and len(m.search(a, "svc region")) == 2


def test_cli_roundtrip_and_error_exit(tmp_path, capsys):
    from ordivyr.nova_memory import cli
    db = str(tmp_path / "c.db")
    assert cli.main([db, "add", "rotate keys quarterly", "--kind", "procedural"]) == 0
    mid = json.loads(capsys.readouterr().out)["id"]
    assert cli.main([db, "search", "key rotation"]) == 0 and mid in capsys.readouterr().out
    assert cli.main([db, "verify", "--id", mid, "--validator", "ci", "--ref", "r1"]) == 2                       # author may not verify own memory
    capsys.readouterr()
    assert cli.main([db, "verify", "--id", mid, "--validator", "ci", "--ref", "r1", "--agent", "reviewer"]) == 0
    assert cli.main([db, "get", "--id", mid]) == 0 and '"trust": "verified"' in capsys.readouterr().out


def test_cli_can_select_nova_backend(tmp_path):
    from ordivyr import cli
    class A: memory = str(tmp_path / "r.db"); tenant = "T"; project = "P"
    b = cli.NOVA_BACKEND(A); b.remember("x", "team", "n", "queue depth alarm is at forty"); assert "forty" in b.recall("x", "team", "alarm")
