"""P1 NOVA Memory at scale: indexed retrieval keeps tenant/namespace isolation, deletion guarantees, authenticated verification and exact incremental statistics."""
import sqlite3, threading
import pytest
from ordivyr.nova_memory import NovaMemory, Principal, AccessDenied, store as S
from ordivyr.nova_memory.scale_bench import corpus


@pytest.fixture
def big(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "INDEX_MIN", 50)                                   # force the indexed path on a small corpus
    m = NovaMemory(tmp_path / "n.db", key_path=tmp_path / "k.key"); a = Principal.make("T1", "P", "alice", read=["team"], write=["team"])
    v = Principal.make("T1", "P", "ver", read=["team"], write=["team"], can_verify=True)
    items, marks = corpus(400, topics=40, per_topic=25, planted=10); ids = m.add_many(a, items)
    return m, a, v, ids, marks, tmp_path


def stats_match_recount(m):
    with m._c() as c:
        n = {(r["tenant"], r["project"]): r["n"] for r in c.execute("SELECT * FROM vn")}
        want_n = {(r[0], r[1]): r[2] for r in c.execute("SELECT tenant, project, COUNT(*) FROM mem GROUP BY 1,2")}
        df = {(r[0], r[1], r[2]): r[3] for r in c.execute("SELECT * FROM vdf WHERE df>0")}
        want_df = {(r[0], r[1], r[2]): r[3] for r in c.execute("SELECT m.tenant, m.project, CAST(j.key AS INTEGER), COUNT(*) FROM mem m, json_each(m.vec) j GROUP BY 1,2,3")}
    return {k: v for k, v in n.items() if v} == want_n and df == want_df


def test_indexed_path_finds_planted_notes_and_is_used(big):
    m, a, v, ids, marks, _ = big
    hit = 0
    for k, (idx, q) in marks.items():
        got = [h["id"] for h in m.search(a, q, k=5)]; assert m.last_path == "indexed"; hit += ids[idx] in got
    assert hit == len(marks)


def test_indexed_agrees_with_exact_on_top_hits(big, monkeypatch):
    m, a, v, ids, marks, _ = big; q = marks[0][1]
    fast = [h["id"] for h in m.search(a, q, k=8)]; monkeypatch.setattr(S, "INDEX_MIN", 10 ** 9); slow = [h["id"] for h in m.search(a, q, k=8)]
    assert m.last_path == "exact" and fast[0] == slow[0] and len(set(fast) & set(slow)) >= 6


def test_tenant_namespace_and_candidate_isolation_on_indexed_path(big):
    m, a, v, ids, marks, _ = big; q = marks[1][1]
    other_t = Principal.make("T2", "P", "mallory", read=["team"], write=["team"]); other_ns = Principal.make("T1", "P", "bob", read=["other"], write=["other"])
    assert m.search(other_t, q) == [] and m.search(other_ns, q) == []
    m.add(other_t, "team", "semantic", "other tenant", "zzz private " + q, "x")                            # another tenant's data must not alter or appear in a's results
    assert all(h["id"] in ids for h in m.search(a, q, k=8))
    assert [h["id"] for h in m.search(a, q, k=8, include_candidates=False)] == []                          # nothing is verified yet


def test_deletion_removes_note_and_statistics_and_survives_compact(big):
    m, a, v, ids, marks, tmp = big; idx, q = marks[2]; victim = ids[idx]; assert victim in [h["id"] for h in m.search(a, q, k=5)]
    m.delete(v, victim, "gdpr")
    assert victim not in [h["id"] for h in m.search(a, q, k=8)] and stats_match_recount(m)
    raw = open(tmp / "n.db", "rb").read() + (open(str(tmp / "n.db") + "-wal", "rb").read() if (tmp / "n.db-wal").exists() else b"")
    marker = q.split()[-1].encode(); assert marker not in raw                                                # the planted marker word is physically gone (secure_delete + compact)
    with m._c() as c: assert c.execute("SELECT 1 FROM tomb WHERE mem_id=?", (victim,)).fetchone()


def test_statistics_are_exact_after_adds_dups_deletes_and_scope_erasure(big):
    m, a, v, ids, marks, _ = big; assert stats_match_recount(m)
    m.add(a, "team", "semantic", "t", "x " + marks[3][1], "s"); m.add(a, "team", "semantic", "t", "x " + marks[3][1], "s")                                 # exact duplicate is not double counted
    for i in ids[:25]: m.delete(v, i, "r")
    assert stats_match_recount(m)
    m.delete_scope("T1", "P"); assert stats_match_recount(m)
    with m._c() as c: assert c.execute("SELECT COALESCE(SUM(n),0) FROM vn").fetchone()[0] == 0


def test_verified_rows_still_authenticated_and_forgery_never_served(big):
    m, a, v, ids, marks, tmp = big; idx, q = marks[4]; mid = ids[idx]
    m.verify(v, mid, {"passed": True, "validator": "ci", "ref": "r1"}); assert [h["trust"] for h in m.search(a, q, k=1)] == ["verified"] and m.audit() == []
    sqlite3.connect(tmp / "n.db").execute("UPDATE mem SET body=body||' tampered' WHERE id=?", (mid,)).connection.commit()          # edit in place without the key
    assert m.audit() == [mid] and m.audit(tenant="T1", project="P", limit=1000) == [mid] and m.audit(tenant="T2") == []
    assert mid not in [h["id"] for h in m.search(a, q, k=8)]


def test_restore_recomputes_statistics_reapplies_deletion_and_reopens_connections(big):
    m, a, v, ids, marks, tmp = big; bk = tmp / "b.bak"; m.backup(bk); idx, q = marks[5]
    m.delete(v, ids[idx], "after-backup"); old_conn = m._c()
    m.restore(bk)                                                              # the backup still contains the note; the recorded deletion must win
    assert m._c() is not old_conn and ids[idx] not in [h["id"] for h in m.search(a, q, k=8)] and stats_match_recount(m)


def test_migration_from_v2_backfills_statistics(tmp_path):
    p = tmp_path / "o.db"; m = NovaMemory(p, key_path=tmp_path / "k.key"); a = Principal.make("T", "P", "a", read=["team"], write=["team"])
    m.add_many(a, [{"ns": "team", "kind": "semantic", "title": f"t{i}", "body": f"alpha beta gamma delta {i}", "source": "s"} for i in range(30)]); m.close()
    c = sqlite3.connect(p); c.executescript("DROP TRIGGER mem_stats_ai; DROP TRIGGER mem_stats_ad; DROP TABLE vdf; DROP TABLE vn; DELETE FROM meta WHERE k='stats_v3'; UPDATE meta SET v='2' WHERE k='schema';"); c.commit(); c.close()
    m2 = NovaMemory(p, key_path=tmp_path / "k.key"); assert stats_match_recount(m2)
    with m2._c() as c: assert c.execute("SELECT v FROM meta WHERE k='schema'").fetchone()[0] == "3"


def test_connection_reuse_per_thread_and_maintenance_rate_limit(tmp_path):
    t = [1000.0]; m = NovaMemory(tmp_path / "n.db", key_path=tmp_path / "k.key", clock=lambda: t[0]); assert m._c() is m._c()
    other = []; th = threading.Thread(target=lambda: other.append(m._c())); th.start(); th.join(); assert other[0] is not m._c()
    assert m.maintain() is None; t[0] += S.MAINT_EVERY + 1; assert m.maintain() == {"expired": 0} and m.maintain() is None


def test_add_many_matches_add_semantics(tmp_path):
    m = NovaMemory(tmp_path / "n.db", key_path=tmp_path / "k.key"); a = Principal.make("T", "P", "a", read=["team"], write=["team"])
    ids = m.add_many(a, [{"ns": "team", "kind": "semantic", "title": "t", "body": "same body text here", "source": "s"}] * 3); assert len(set(ids)) == 1
    with pytest.raises(AccessDenied): m.add_many(a, [{"ns": "secret", "kind": "semantic", "title": "t", "body": "b", "source": "s"}])
    with pytest.raises(ValueError): m.add_many(a, [{"ns": "team", "kind": "bogus", "title": "t", "body": "b", "source": "s"}])
