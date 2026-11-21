"""Authenticated verifiers, signed verification, retention/deletion/backup, migration."""
import os, sqlite3, stat, pytest
from ordivyr.nova_memory import NovaMemory, Principal, AccessDenied

OK = {"passed": True, "validator": "ci", "ref": "r"}
mk = lambda a, **k: Principal.make("T", "P", a, read=["team"], write=["team"], **k)


@pytest.fixture
def m(tmp_path): return NovaMemory(tmp_path / "n.db")


def test_files_are_private(m):
    assert stat.S_IMODE(os.stat(m.path).st_mode) == 0o600 and stat.S_IMODE(os.stat(m.path.with_suffix(".key")).st_mode) == 0o600


def test_enrolled_verifier_needs_secret_and_can_verify_flag_alone_is_not_enough(m):
    mid = m.add(mk("alice"), "team", "semantic", "t", "claim one", "s")
    secret = m.enroll_verifier("reviewer")
    claimed = mk("mallory", can_verify=True)                         # self-declared verifier role
    with pytest.raises(AccessDenied): m.verify(claimed, mid, OK)
    with pytest.raises(AccessDenied): m.verify(mk("reviewer"), mid, OK)                              # right id, no credential
    with pytest.raises(AccessDenied): m.verify(mk("reviewer"), mid, OK, credential="wrong")
    with pytest.raises(AccessDenied): m.verify(mk("mallory"), mid, OK, credential=secret)            # stolen secret presented under another identity
    m.verify(mk("reviewer"), mid, OK, credential=secret); assert m.get(mk("alice"), mid)["trust"] == "verified"
    assert m.get(mk("alice"), mid)["integrity"] == "ok"


def test_revoked_verifier_loses_access_and_secret_not_stored_in_clear(m):
    secret = m.enroll_verifier("rev"); mid = m.add(mk("alice"), "team", "semantic", "t", "claim two", "s")
    assert m.revoke_verifier("rev")
    with pytest.raises(AccessDenied): m.verify(mk("rev"), mid, OK, credential=secret)
    assert secret.encode() not in m.path.read_bytes()


def test_strict_mode_has_no_open_role(tmp_path):
    s = NovaMemory(tmp_path / "s.db", strict=True); mid = s.add(mk("alice"), "team", "semantic", "t", "claim", "s")
    with pytest.raises(AccessDenied): s.verify(mk("bob", can_verify=True), mid, OK)


def test_db_only_attacker_cannot_mint_verified_memory(m):
    a = mk("alice"); mid = m.add(a, "team", "semantic", "poison", "launch codes are 0000", "s")
    raw = sqlite3.connect(str(m.path)); raw.execute("UPDATE mem SET trust='verified' WHERE id=?", (mid,)); raw.commit(); raw.close()      # direct DB write, no signing key
    assert m.search(a, "launch codes") == [] and m.get(a, mid)["integrity"] == "tampered" and m.audit() == [mid]


def test_editing_a_verified_body_in_place_is_detected(m):
    a = mk("alice"); v = mk("bob", can_verify=True); mid = m.add(a, "team", "semantic", "t", "port is 8080", "s"); m.verify(v, mid, OK)
    raw = sqlite3.connect(str(m.path)); raw.execute("UPDATE mem SET body='port is 1' WHERE id=?", (mid,)); raw.commit(); raw.close()
    assert m.audit() == [mid] and all(h["id"] != mid for h in m.search(a, "port"))


def test_deletion_is_physical_after_compact(m):
    a = mk("alice"); mid = m.add(a, "team", "semantic", "t", "zebra unicorn confidential phrase", "s")
    m.delete(a, mid)
    blob = b"".join(open(f, "rb").read() for f in (m.path, str(m.path) + "-wal") if os.path.exists(f))
    assert b"unicorn" not in blob


def test_backup_restore_roundtrip_and_erasure_survives(m, tmp_path):
    a = mk("alice"); keep = m.add(a, "team", "semantic", "k", "keep this fact please", "s"); gone = m.add(a, "team", "semantic", "g", "erase this fact later", "s")
    b = m.backup(tmp_path / "bk" / "n.bak"); assert not b["encrypted"] and stat.S_IMODE(os.stat(tmp_path / "bk" / "n.bak").st_mode) == 0o600
    m.delete(a, gone)                                                # user exercises erasure AFTER the backup was taken
    r = m.restore(tmp_path / "bk" / "n.bak"); assert r["deletions_reapplied"] == 1
    assert m.search(a, "erase") == [] and len(m.search(a, "keep fact")) == 1 and m.audit() == []


def test_corrupted_backup_is_refused_and_live_db_untouched(m, tmp_path):
    a = mk("alice"); m.add(a, "team", "semantic", "k", "important fact stays", "s"); m.backup(tmp_path / "x.bak")
    data = bytearray((tmp_path / "x.bak").read_bytes()); data[200] ^= 0xFF; (tmp_path / "x.bak").write_bytes(bytes(data))
    with pytest.raises(ValueError): m.restore(tmp_path / "x.bak")
    assert len(m.search(a, "important fact")) == 1


def test_encrypted_backup(m, tmp_path):
    pytest.importorskip("cryptography"); a = mk("alice"); m.add(a, "team", "semantic", "k", "secret roadmap quartz", "s")
    m.backup(tmp_path / "e.bak", password="pw1")
    assert b"quartz" not in (tmp_path / "e.bak").read_bytes() and b"SQLite format" not in (tmp_path / "e.bak").read_bytes()
    with pytest.raises(ValueError): m.restore(tmp_path / "e.bak", password="bad")
    with pytest.raises(ValueError): m.restore(tmp_path / "e.bak")
    assert m.restore(tmp_path / "e.bak", password="pw1")["restored"]


def test_restore_without_key_needs_explicit_reseal(m, tmp_path):
    a = mk("alice"); v = mk("bob", can_verify=True); mid = m.add(a, "team", "semantic", "t", "durable verified fact", "s"); m.verify(v, mid, OK); m.backup(tmp_path / "b.bak")
    fresh = NovaMemory(tmp_path / "other" / "n.db"); fresh.restore(tmp_path / "b.bak")                # new machine: different signing key
    assert fresh.audit() == [mid] and fresh.search(a, "durable") == []                                  # not trusted until the operator says so
    assert fresh.reseal() == 1 and fresh.audit() == [] and len(fresh.search(a, "durable")) == 1


def test_v1_database_migrates_and_keeps_verified(tmp_path):
    db = tmp_path / "old.db"; m = NovaMemory(db); a = mk("alice"); v = mk("bob", can_verify=True); mid = m.add(a, "team", "semantic", "t", "legacy verified fact", "s"); m.verify(v, mid, OK)
    c = sqlite3.connect(str(db)); c.execute("UPDATE meta SET v='1' WHERE k='schema'"); c.execute("UPDATE mem SET vsig=NULL, vhash=NULL, verifier=NULL"); c.commit(); c.close()
    m2 = NovaMemory(db); assert m2.get(a, mid)["trust"] == "verified" and m2.get(a, mid)["integrity"] == "ok" and m2.audit() == []
    assert any(h["action"] == "migrated-signed" for h in m2.get(a, mid)["history"])


def test_cli_enroll_verify_backup_flow(tmp_path, capsys):
    from ordivyr.nova_memory import cli
    db = str(tmp_path / "c.db"); sf = str(tmp_path / "rev.secret")
    assert cli.main([db, "add", "rotate keys quarterly"]) == 0; import json; mid = json.loads(capsys.readouterr().out)["id"]
    assert cli.main([db, "enroll-verifier", "--id", "reviewer", "--file", sf]) == 0 and stat.S_IMODE(os.stat(sf).st_mode) == 0o600; capsys.readouterr()
    assert cli.main([db, "verify", "--id", mid, "--validator", "ci", "--ref", "r", "--agent", "reviewer"]) == 2                    # no credential
    assert cli.main([db, "verify", "--id", mid, "--validator", "ci", "--ref", "r", "--agent", "reviewer", "--credential-file", sf]) == 0
    assert cli.main([db, "audit"]) == 0 and cli.main([db, "backup", "--file", str(tmp_path / "c.bak")]) == 0
