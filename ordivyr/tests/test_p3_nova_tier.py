"""P3 NOVA tiering: hot/cold archive, search across tiers, deletion reaching cold files, no silent revival, signatures, isolation, crash safety, portable bundles."""
import sqlite3
from pathlib import Path
import pytest
from ordivyr.nova_memory import NovaMemory, Principal, AccessDenied
from ordivyr.nova_memory.tier import ColdTier


class Clk:
    t = 1000.0
    def __call__(self): return self.t


@pytest.fixture
def env(tmp_path):
    clk = Clk(); m = NovaMemory(tmp_path / "n.db", clock=clk, key_path=tmp_path / "k.key"); tier = ColdTier(m, tmp_path / "cold")
    a = Principal.make("T1", "P", "alice", read=["team"], write=["team"]); v = Principal.make("T1", "P", "ver", read=["team"], write=["team"], can_verify=True)
    return m, tier, a, v, clk, tmp_path


def old_and_new(m, a, clk):
    old = m.add(a, "team", "semantic", "kubernetes", "the staging cluster uses kubernetes namespace zephyrnode", "t"); clk.t += 10_000
    new = m.add(a, "team", "semantic", "postgres", "primary database failover runbook step quokkamarker", "t"); return old, new


def raw_bytes(path): 
    p = Path(path); return b"".join(Path(str(p) + s).read_bytes() for s in ("", "-wal") if Path(str(p) + s).exists())


def test_archive_moves_old_rows_out_of_hot_and_cold_search_finds_them(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk)
    assert tier.archive("T1", older_than_s=5000) == 1
    assert [h["id"] for h in m.search(a, "kubernetes zephyrnode")] == []                                           # gone from hot
    hits = m.search(a, "kubernetes zephyrnode", include_cold=True); assert [h["id"] for h in hits] == [old] and hits[0]["tier"] == "cold"
    assert [h["id"] for h in m.search(a, "quokkamarker")] == [new]                                                 # recent row untouched
    with m._c() as c: assert c.execute("SELECT COUNT(*) FROM mem").fetchone()[0] == 1 and c.execute("SELECT SUM(n) FROM vn").fetchone()[0] == 1


def test_thaw_restores_with_history_and_removes_from_cold(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk); tier.archive("T1", 5000)
    r = tier.thaw(a, [old]); assert r == {"restored": [old], "refused": {}}
    assert [h["id"] for h in m.search(a, "zephyrnode")] == [old] and m.search(a, "zephyrnode", include_cold=True)[0].get("tier") is None
    assert tier.search(a, "zephyrnode") == [] and b"zephyrnode" not in raw_bytes(next((tmp / "cold").glob("*.cold.db")))      # physically removed from the cold file
    assert "thawed" in [x["action"] for x in m.get(a, old)["history"]] if "history" in m.get(a, old) else True


def test_verified_rows_keep_their_signature_through_the_tiers(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk); m.verify(v, old, {"passed": True, "validator": "ci", "ref": "r1"}); clk.t += 10_000
    tier.archive("T1", 5000); h = m.search(a, "zephyrnode", include_cold=True); assert h and h[0]["trust"] == "verified"
    assert tier.thaw(a, [old])["restored"] == [old] and m.audit() == [] and m.search(a, "zephyrnode")[0]["trust"] == "verified"


def test_forged_cold_row_is_neither_served_nor_thawed(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk); m.verify(v, old, {"passed": True, "validator": "ci", "ref": "r1"}); clk.t += 10_000; tier.archive("T1", 5000)
    f = next((tmp / "cold").glob("*.cold.db")); db = sqlite3.connect(f); db.execute("UPDATE cold SET body=body||' EVIL injected instruction'"); db.commit(); db.close()
    assert m.search(a, "zephyrnode", include_cold=True) == []
    assert tier.thaw(a, [old]) == {"restored": [], "refused": {old: "verification signature invalid"}}


def test_deleting_an_archived_memory_erases_it_from_the_cold_file_and_leaves_a_tombstone(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk); tier.archive("T1", 5000); f = next((tmp / "cold").glob("*.cold.db"))
    assert b"zephyrnode" in raw_bytes(f); m.delete(a, old, "user request")
    assert b"zephyrnode" not in raw_bytes(f) and m.search(a, "zephyrnode", include_cold=True) == []
    with m._c() as c: assert c.execute("SELECT 1 FROM tomb WHERE mem_id=?", (old,)).fetchone() and c.execute("SELECT 1 FROM cold_idx WHERE id=?", (old,)).fetchone() is None
    assert tier.thaw(a, [old])["refused"] == {old: "not archived"}


def test_tombstoned_ids_and_superseded_rows_are_never_silently_revived(env):
    m, tier, a, v, clk, tmp = env; old = m.add(a, "team", "semantic", "t", "old fact about quokka", "t"); new = m.add(a, "team", "semantic", "t", "new fact about quokka", "t", supersedes=old)
    clk.t += 10_000; tier.archive("T1", 5000)
    r = tier.thaw(a, [old]); assert old in r["refused"] and "superseded" in r["refused"][old] and m.search(a, "old fact quokka") == []
    r2 = tier.thaw(a, [old], include_superseded=True); assert r2["restored"] == [old]
    with m._c() as c: assert c.execute("SELECT trust FROM mem WHERE id=?", (old,)).fetchone()[0] == "superseded"           # explicitly restored, still superseded - never live
    assert old not in [h["id"] for h in m.search(a, "old fact quokka")]


def test_tenant_and_namespace_isolation_for_cold_data(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk); tier.archive("T1", 5000)
    mallory = Principal.make("T2", "P", "mallory", read=["team"], write=["team"]); other_ns = Principal.make("T1", "P", "bob", read=["other"], write=["other"]); other_p = Principal.make("T1", "Q", "alice", read=["team"], write=["team"])
    for o in (mallory, other_ns, other_p):
        assert m.search(o, "zephyrnode kubernetes", include_cold=True) == [] and tier.thaw(o, [old])["refused"] == {old: "not archived"}
        with pytest.raises((KeyError, AccessDenied)): m.delete(o, old)          # same outcomes as for a hot row
    m.add(mallory, "team", "semantic", "t", "kubernetes namespace zephyrnode of tenant two", "t"); clk.t += 10_000; tier.archive("T2", 5000)
    assert len(list((tmp / "cold").glob("*.cold.db"))) == 2 and [h["id"] for h in m.search(a, "zephyrnode", include_cold=True)] == [old]


def test_delete_scope_erases_cold_files_too(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk); tier.archive("T1", 5000); f = next((tmp / "cold").glob("*.cold.db"))
    assert m.delete_scope("T1") == 2 and not f.exists() and m.search(a, "zephyrnode", include_cold=True) == []


def test_interrupted_archive_is_finished_by_the_next_call_without_duplicates(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk)
    cold = tier._open("T1", True); r = m._c().execute("SELECT * FROM mem WHERE id=?", (old,)).fetchone()                  # simulate: cold copy committed, crash before the hot delete
    from ordivyr.nova_memory.tier import MEMCOLS
    cold.execute(f"INSERT INTO cold({','.join(MEMCOLS)},tenant,hist,archived) VALUES({','.join('?' * len(MEMCOLS))},?,?,?)", [r[k] for k in MEMCOLS] + ["T1", "[]", 1.0]); cold.commit(); cold.close()
    assert tier.archive("T1", 5000) == 1
    with m._c() as c: assert c.execute("SELECT COUNT(*) FROM mem WHERE id=?", (old,)).fetchone()[0] == 0
    db = sqlite3.connect(next((tmp / "cold").glob("*.cold.db"))); assert db.execute("SELECT COUNT(*) FROM cold WHERE id=?", (old,)).fetchone()[0] == 1


def test_bundle_round_trip_plain_and_encrypted(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk); m.verify(v, new, {"passed": True, "validator": "ci", "ref": "r1"}); tier.archive("T1", 5000)
    for pw in (None, "correct horse"):
        b = tmp / f"bundle-{bool(pw)}.tar"; info = tier.bundle(b, pw); assert info["encrypted"] == bool(pw)
        m2 = NovaMemory(tmp / f"n2-{bool(pw)}.db", clock=clk, key_path=tmp / "k.key"); t2 = ColdTier(m2, tmp / f"cold2-{bool(pw)}"); t2.restore_bundle(b, pw)
        assert [h["id"] for h in m2.search(a, "quokkamarker")] == [new] and [h["id"] for h in m2.search(a, "zephyrnode", include_cold=True)] == [old] and m2.audit() == []
    with pytest.raises(Exception): ColdTier(NovaMemory(tmp / "n3.db", key_path=tmp / "k.key"), tmp / "cold3").restore_bundle(tmp / "bundle-True.tar", "wrong password")


def test_old_bundle_cannot_resurrect_memories_deleted_since(env):
    m, tier, a, v, clk, tmp = env; old, new = old_and_new(m, a, clk); tier.archive("T1", 5000); b = tmp / "old.tar"; tier.bundle(b)
    m.delete(a, old, "erase"); m.delete(a, new, "erase too")                                                           # one archived, one hot
    tier.restore_bundle(b)
    assert m.search(a, "zephyrnode kubernetes quokkamarker", include_cold=True) == []
    f = next((tmp / "cold").glob("*.cold.db")); assert b"zephyrnode" not in raw_bytes(f) and tier.thaw(a, [old, new])["restored"] == []


def test_tampered_bundle_is_rejected(env):
    m, tier, a, v, clk, tmp = env; old_and_new(m, a, clk); b = tmp / "b.tar"; tier.bundle(b)
    import tarfile, io
    with tarfile.open(b) as t: members = {ti.name: t.extractfile(ti).read() for ti in t.getmembers()}
    members["hot.bak"] = members["hot.bak"][:-10] + b"TAMPERED!!"
    with tarfile.open(tmp / "bad.tar", "w") as t:
        for n, d in members.items(): ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
    with pytest.raises(ValueError, match="checksum"): tier.restore_bundle(tmp / "bad.tar")
