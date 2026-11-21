import base64, json, time, pytest
from ordivyr.board import auth as A

try:
    import cryptography  # noqa
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
needs_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")


def test_password_hashing_policy_and_timing_helper():
    h = A.hash_password("correct horse battery staple", n=2 ** 12); assert A.verify_password("correct horse battery staple", h) and not A.verify_password("wrong", h) and h != A.hash_password("correct horse battery staple", n=2 ** 12)
    assert not A.verify_password("x", "garbage") and not A.verify_password("x", "scrypt$a$b$c$d$e")
    for bad in ("short", "password", "aaaaaaaaaaaaaaaa", "ownername-1", "x" * 300): 
        with pytest.raises(A.AuthError): A.check_password_policy(bad, "ownername@x.com")
    A.check_password_policy("a long, unusual passphrase 42", "me@x.com"); A.burn_password_time("anything")


def test_totp_matches_rfc6238_vectors_and_is_single_use():
    secret = base64.b32encode(b"12345678901234567890").decode()                                    # RFC 6238 Appendix B (SHA-1), 8 digits truncated to the last 6
    for t, expect in ((59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (1234567890, "005924"), (2000000000, "279037")): assert A.totp_now(secret, t) == expect
    now = 1_700_000_000; code = A.totp_now(secret, now); c = A.totp_verify(secret, code, now); assert c == now // 30
    assert A.totp_verify(secret, code, now, last_counter=c) is None                                     # replay of the same code refused
    assert A.totp_verify(secret, code, now + 30) == c and A.totp_verify(secret, code, now + 300) is None   # +-1 step tolerated, 5 minutes later not
    assert A.totp_verify(secret, "12345", now) is None and A.totp_verify(secret, "abcdef", now) is None and A.totp_verify(secret, None, now) is None
    assert "otpauth://totp/" in A.otpauth_uri("ABC", "a@b.com") and len(set(A.new_recovery_codes())) == 10


# ---- OIDC: sign tokens with locally generated keys (STUB IdP) and attack the verifier
def make_keys():
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    from cryptography.hazmat.primitives import serialization as S
    rsak = rsa.generate_private_key(65537, 2048); n = rsak.public_key().public_numbers(); eck = ec.generate_private_key(ec.SECP256R1()); en = eck.public_key().public_numbers(); edk = ed25519.Ed25519PrivateKey.generate()
    i2b = lambda i, l=None: i.to_bytes(l or (i.bit_length() + 7) // 8, "big")
    jwks = {"keys": [{"kty": "RSA", "kid": "r1", "use": "sig", "n": A.b64(i2b(n.n)), "e": A.b64(i2b(n.e))}, {"kty": "EC", "kid": "e1", "crv": "P-256", "x": A.b64(i2b(en.x, 32)), "y": A.b64(i2b(en.y, 32))},
                     {"kty": "OKP", "kid": "o1", "crv": "Ed25519", "x": A.b64(edk.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw))}]}
    return {"RS256": (rsak, "r1"), "ES256": (eck, "e1"), "EdDSA": (edk, "o1")}, jwks


def sign(priv, alg, kid, claims, hdr_alg=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec, utils
    h = A.b64(json.dumps({"alg": hdr_alg or alg, "kid": kid}).encode()); p = A.b64(json.dumps(claims).encode()); m = f"{h}.{p}".encode()
    if alg == "RS256": s = priv.sign(m, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256": r, sv = utils.decode_dss_signature(priv.sign(m, ec.ECDSA(hashes.SHA256()))); s = r.to_bytes(32, "big") + sv.to_bytes(32, "big")
    else: s = priv.sign(m)
    return f"{h}.{p}.{A.b64(s)}"


def good(now): return {"iss": "https://idp.test", "aud": "client-1", "sub": "u1", "email": "Ann@Corp.com", "email_verified": True, "exp": now + 300, "iat": now, "nonce": "n1"}


@needs_crypto
@pytest.mark.parametrize("alg", ["RS256", "ES256", "EdDSA"])
def test_oidc_accepts_valid_tokens_for_each_algorithm(alg):
    keys, jwks = make_keys(); now = time.time(); k, kid = keys[alg]
    c = A.verify_id_token(sign(k, alg, kid, good(now)), jwks, alg, "https://idp.test", "client-1", nonce="n1", now=now, allowed_domains=["corp.com"]); assert c["sub"] == "u1"


@needs_crypto
def test_oidc_rejects_every_attack():
    keys, jwks = make_keys(); now = time.time(); rk, rid = keys["RS256"]; ek, eid = keys["ES256"]
    def chk(tok, alg="RS256", **kw):
        kw = {"issuer": "https://idp.test", "audience": "client-1", "nonce": "n1", "now": now, **kw}
        with pytest.raises(A.AuthError) as e: A.verify_id_token(tok, jwks, alg, kw.pop("issuer"), kw.pop("audience"), **kw)
        return str(e.value)
    ok = good(now)
    assert "signature" in chk(sign(rk, "RS256", rid, ok)[:-6] + "AAAAAA")                          # tampered signature
    forged = sign(rk, "RS256", rid, {**ok, "email": "boss@corp.com"}).split("."); orig = sign(rk, "RS256", rid, ok).split("."); assert "signature" in chk(".".join([orig[0], forged[1], orig[2]]))      # payload swapped
    assert "algorithm" in chk(sign(rk, "RS256", rid, ok, hdr_alg="none"))                          # alg=none
    hs = A.b64(json.dumps({"alg": "HS256", "kid": rid}).encode()) + "." + A.b64(json.dumps(ok).encode()) + "." + A.b64(b"x" * 32); assert "algorithm" in chk(hs)      # HS256 confusion
    assert "algorithm" in chk(sign(ek, "ES256", eid, ok), alg="RS256")                             # provider pinned to RS256, token claims ES256
    assert "signing key" in chk(sign(rk, "RS256", "unknown-kid", ok))
    assert "issuer" in chk(sign(rk, "RS256", rid, {**ok, "iss": "https://evil.test"})) and "audience" in chk(sign(rk, "RS256", rid, {**ok, "aud": "other-client"}))
    assert "expired" in chk(sign(rk, "RS256", rid, {**ok, "exp": now - 3600})) and "not yet" in chk(sign(rk, "RS256", rid, {**ok, "nbf": now + 3600}))
    assert "nonce" in chk(sign(rk, "RS256", rid, {**ok, "nonce": "replayed"})) and "verified" in chk(sign(rk, "RS256", rid, {**ok, "email_verified": False})) and "verified" in chk(sign(rk, "RS256", rid, {**ok, "email_verified": "true"}))
    assert "domain" in chk(sign(rk, "RS256", rid, {**ok, "email": "x@evil.com"}), allowed_domains=["corp.com"]) and "subject" in chk(sign(rk, "RS256", rid, {**{k: v for k, v in ok.items() if k != "sub"}}))
    assert "audience" in chk(sign(rk, "RS256", rid, {**ok, "aud": ["client-1", "x"]})) and "malformed" in chk("not.a.jwt.at.all") and "malformed" in chk("")
    assert "not allowed" in chk(sign(rk, "RS256", rid, ok), alg="HS256")
