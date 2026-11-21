"""Phase 3 account security: account/IP-aware throttling, 1-hour hard cap, IP-rotation resistance, second-factor restoration, no victim lockout."""
import time
import pytest
from ordivyr.board import auth as A
from ordivyr.board.accounts import AuthFailed
from ordivyr.tests.board_support import World
from ordivyr.tests.test_board_accounts import human, PW

HOME, ATTACK = "198.51.100.7", "203.0.113."


@pytest.fixture
def w(tmp_path, monkeypatch):
    x = World(tmp_path, {}, monkeypatch); x.off = 0.0; x.board.clock = x.board.db.clock = lambda: time.time() + x.off; yield x; x.close()


def bad(w, email="v@corp.com", ip=None, n=1, pw="not-the-password-1"):
    for _ in range(n):
        try: w.board.login(email, pw, ip=ip)
        except AuthFailed: pass


def mfa_user(w, email="v@corp.com"):
    a = w.org("acme"); human(w, a, email); w.admin = a
    p = w.board.principal(w.board.login(email, PW, ip=HOME)["session"]); sec = w.board.mfa_begin(p)["secret"]; w.off += 31
    r = w.board.mfa_confirm(p, A.totp_now(sec, time.time() + w.off)); w.rec = r["recovery_codes"]
    w.off += 31; code = A.totp_now(sec, time.time() + w.off); w.board.login_mfa(w.board.login(email, PW, ip=HOME)["mfa_token"], code, ip=HOME)   # HOME becomes a known network (full login)
    return sec


def test_attacker_cannot_lock_the_owner_out(w):
    a = w.org("acme"); human(w, a, "v@corp.com"); assert w.board.login("v@corp.com", PW, ip=HOME)["session"]       # owner has logged in from HOME before
    bad(w, ip=ATTACK + "5", n=5)                                                                                    # attacker hammers from one address
    with pytest.raises(AuthFailed): w.board.login("v@corp.com", PW, ip=ATTACK + "5")                                # attacker's own network is blocked, even with a (leaked) right password
    assert w.board.login("v@corp.com", PW, ip=HOME)["session"]                                                      # the owner is NOT
    assert w.board.login("v@corp.com", PW, ip="198.51.100.200")["session"]                                          # same /24 = same network for "known"


def test_ip_rotation_hits_the_account_guard_but_known_networks_keep_working(w):
    a = w.org("acme"); human(w, a, "v@corp.com"); w.board.login("v@corp.com", PW, ip=HOME)
    for i in range(20): bad(w, ip=f"203.0.{i}.9")                                                                    # 20 different /24s, one try each: per-IP counters never trip
    with pytest.raises(AuthFailed): w.board.login("v@corp.com", PW, ip="203.0.99.9")                                 # a NEW network is refused even with the right password: the account is guarded
    assert w.board.login("v@corp.com", PW, ip=HOME)["session"]                                                      # the owner's known network still works
    w.off += 3601; assert w.board.login("v@corp.com", PW, ip="203.0.99.9")["session"]                               # nothing locks for more than one hour


def test_hard_cap_is_one_hour_even_after_many_failures(w):
    a = w.org("acme"); human(w, a, "v@corp.com")
    for _ in range(40): bad(w, ip=ATTACK + "5"); w.off += 1                                                          # keeps hammering (during blocks too)
    r = w.board.db.c().execute("SELECT locked_until FROM auth_throttle WHERE ipk='203.0.113.0/24'").fetchone()
    assert r["locked_until"] - (time.time() + w.off) <= 3600 + 2
    g = w.board.db.c().execute("SELECT locked_until FROM auth_throttle WHERE ipk='*'").fetchone()
    assert g is None or g["locked_until"] is None or g["locked_until"] - (time.time() + w.off) <= 3600 + 2
    w.off += 3601; assert w.board.login("v@corp.com", PW, ip=ATTACK + "5")["session"]


def test_second_factor_restores_a_guarded_account_and_is_itself_throttled(w):
    sec = mfa_user(w)
    for i in range(20): bad(w, ip=f"203.0.{i}.9")
    with pytest.raises(AuthFailed): w.board.login("v@corp.com", PW, ip="192.0.2.50")                                 # owner on a hotel network: guarded out
    for i in range(5):
        with pytest.raises(AuthFailed): w.board.unlock_account("v@corp.com", "%06d" % (i + 3), ip="192.0.2.50")
    with pytest.raises(AuthFailed): w.board.unlock_account("v@corp.com", A.totp_now(sec, time.time() + w.off), ip="192.0.2.50")   # unlock path is throttled too (can't be used to grind TOTP)
    assert w.board.login("v@corp.com", PW, ip=HOME).get("mfa_required")                                             # but the known network was never affected
    w.off += 901; w.off += 30
    assert w.board.unlock_account("v@corp.com", A.totp_now(sec, time.time() + w.off), ip="192.0.2.50")["ok"]
    r = w.board.login("v@corp.com", PW, ip="192.0.2.50"); assert r.get("mfa_required")                               # guard lifted (password stage passes again; MFA still required)


def test_recovery_code_unlocks_and_password_reset_clears(w):
    mfa_user(w)
    for i in range(20): bad(w, ip=f"203.0.{i}.9")
    with pytest.raises(AuthFailed): w.board.login("v@corp.com", PW, ip="192.0.2.50")
    with pytest.raises(AuthFailed): w.board.unlock_account("v@corp.com", "nonsense", ip="192.0.2.50")
    assert w.board.unlock_account("v@corp.com", w.rec[0], ip="192.0.2.50")["ok"]                                    # a recovery code restores access
    with pytest.raises(AuthFailed): w.board.unlock_account("v@corp.com", w.rec[0], ip="192.0.2.50")                 # ... exactly once
    assert w.board.login("v@corp.com", PW, ip="192.0.2.50").get("mfa_required")
    for i in range(20): bad(w, ip=f"203.0.{i}.10")                                                                   # guarded again; now the email-proof path
    with pytest.raises(AuthFailed): w.board.login("v@corp.com", PW, ip="192.0.2.51")
    uid = w.board.db.c().execute("SELECT id FROM users WHERE email='v@corp.com'").fetchone()[0]
    tok = w.board.issue_password_reset(w.admin, uid)["reset_token"]; w.board.reset_password(tok, "brand new passphrase 77")
    assert w.board.login("v@corp.com", "brand new passphrase 77", ip="192.0.2.51").get("mfa_required")


def test_unknown_accounts_get_the_same_answers_and_no_state(w):
    n0 = w.board.db.c().execute("SELECT COUNT(*) FROM auth_throttle").fetchone()[0]
    for _ in range(8): bad(w, email="ghost@corp.com", ip=ATTACK + "5")
    with pytest.raises(AuthFailed): w.board.unlock_account("ghost@corp.com", "123456", ip=ATTACK + "5")
    assert w.board.db.c().execute("SELECT COUNT(*) FROM auth_throttle").fetchone()[0] == n0                          # nothing is stored for emails that do not exist (no table-filling)


def test_throttle_state_is_shared_across_processes(w):
    a = w.org("acme"); human(w, a, "v@corp.com"); other = w.reborn(); other.clock = other.db.clock = w.board.clock
    for _ in range(3):
        try: other.login("v@corp.com", "bad-guess-1234567", ip=ATTACK + "5")
        except AuthFailed: pass
    bad(w, ip=ATTACK + "5", n=2)
    with pytest.raises(AuthFailed): other.login("v@corp.com", PW, ip=ATTACK + "5")


def test_account_guard_refusal_never_outlasts_one_hour_for_a_never_seen_network(w):
    """The guard blocks unknown networks while an attacker rotates addresses, but the mission's hard cap applies to it too: 61 minutes after the last failure a first login from a brand-new /24 works."""
    a = w.org("acme"); human(w, a, "v@corp.com"); w.board.login("v@corp.com", PW, ip=HOME)
    for i in range(40): bad(w, ip=f"203.0.{i}.9")                                                                    # rotate through 40 networks: the guard trips
    with pytest.raises(AuthFailed): w.board.login("v@corp.com", PW, ip="192.0.2.77")                                 # a never-seen network is refused while guarded (even with the right password)
    locks = [r[0] for r in w.board.db.c().execute("SELECT locked_until FROM auth_throttle WHERE locked_until IS NOT NULL").fetchall()]
    assert locks and max(locks) - time.time() <= 3600 + 5, "no throttle row may lock for more than one hour"
    w.off += 3600 + 60
    assert w.board.login("v@corp.com", PW, ip="192.0.2.77")["session"], "after one hour a new network must be able to sign in with the right password"
