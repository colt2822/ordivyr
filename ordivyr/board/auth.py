"""Authentication primitives (no I/O, no database): passwords (scrypt), TOTP (RFC 6238) + recovery codes, and OIDC ID-token verification (RS256/ES256/EdDSA via `cryptography`).

Design rules: uniform failures (never reveal which factor was wrong), constant-time comparisons, algorithms pinned by the PROVIDER CONFIG (never by the token header: no `alg:none`, no HS/RS confusion),
every time-based check takes `now` explicitly so it is testable.
"""
from __future__ import annotations
import base64, hashlib, hmac, json, secrets, struct, time

# ------------------------------------------------------------------ passwords
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
COMMON = frozenset("password passw0rd 123456789012 qwertyuiop12 letmein123456 administrator iloveyou1234 welcome12345 changeme1234".split())


class AuthError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def check_password_policy(pw, email=""):
    if not isinstance(pw, str) or len(pw) < 12: raise AuthError("weak_password", "password must be at least 12 characters")
    if len(pw) > 256: raise AuthError("weak_password", "password too long")
    low = pw.lower()
    if low in COMMON or (email and email.split("@")[0].lower() in low and len(email.split("@")[0]) > 3) or len(set(pw)) < 5: raise AuthError("weak_password", "password is too easy to guess")


def hash_password(pw, n=None):
    n = n or SCRYPT_N; salt = secrets.token_bytes(16); dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, maxmem=128 * 1024 * 1024, dklen=32)
    return f"scrypt${n}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(dk)}"


def verify_password(pw, stored):
    try:
        _, n, r, p, salt, dk = stored.split("$"); calc = hashlib.scrypt(pw.encode(), salt=unb64(salt), n=int(n), r=int(r), p=int(p), maxmem=128 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(calc, unb64(dk))
    except (ValueError, TypeError): return False


DUMMY_HASH = None
def burn_password_time(pw):
    """Unknown user: spend the same time a real verification costs, so login timing does not reveal which emails exist."""
    global DUMMY_HASH
    if DUMMY_HASH is None: DUMMY_HASH = hash_password("dummy-password-for-timing")
    verify_password(pw if isinstance(pw, str) else "", DUMMY_HASH)


# ------------------------------------------------------------------ TOTP (RFC 6238, SHA-1, 30 s, 6 digits) + recovery codes
def totp_secret(): return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def hotp(secret, counter, digits=6):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8)); h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest(); o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def totp_now(secret, now=None): return hotp(secret, int((now or time.time()) // 30))


def totp_verify(secret, code, now=None, last_counter=-1, window=1):
    """-> the matched counter (store it as last_counter: a code can be used ONCE) or None."""
    code = str(code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6): return None
    c0 = int((now or time.time()) // 30); hit = None
    for d in range(-window, window + 1):
        if hmac.compare_digest(hotp(secret, c0 + d), code) and c0 + d > last_counter: hit = c0 + d
    return hit


def otpauth_uri(secret, email, issuer="ORDIVYR"):
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def new_recovery_codes(n=10): return [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(n)]
def hash_recovery(code): return hashlib.sha256(code.strip().lower().encode()).hexdigest()


def opaque_token(prefix): return prefix + secrets.token_urlsafe(32)
def hash_token(t): return hashlib.sha256(str(t).encode()).hexdigest()


# ------------------------------------------------------------------ OIDC ID-token verification
def _jwk_key(jwk):
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    kt = jwk.get("kty")
    if kt == "RSA": return rsa.RSAPublicNumbers(int.from_bytes(unb64(jwk["e"]), "big"), int.from_bytes(unb64(jwk["n"]), "big")).public_key()
    if kt == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}[jwk["crv"]]
        return ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(jwk["x"]), "big"), int.from_bytes(unb64(jwk["y"]), "big"), curve).public_key()
    if kt == "OKP" and jwk.get("crv") == "Ed25519": return ed25519.Ed25519PublicKey.from_public_bytes(unb64(jwk["x"]))
    raise AuthError("bad_jwk", "unsupported key type")


def verify_id_token(token, jwks, alg, issuer, audience, nonce=None, now=None, skew=60, allowed_domains=()):
    """Validate an OIDC ID token against a PROVIDER-CONFIGURED algorithm and key set. -> claims dict. Raises AuthError('invalid_token', ...) on any problem."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec, utils
    from cryptography.exceptions import InvalidSignature
    now = now or time.time()
    def bad(why): raise AuthError("invalid_token", why)
    if alg not in ("RS256", "ES256", "EdDSA"): bad("provider algorithm not allowed")
    try:
        h64, p64, s64 = token.split("."); hdr = json.loads(unb64(h64)); claims = json.loads(unb64(p64)); sig = unb64(s64)
    except (ValueError, TypeError, AttributeError): bad("malformed token")
    if hdr.get("alg") != alg: bad("token algorithm does not match the provider configuration")           # blocks alg=none and HS256-with-public-key confusion
    kid = hdr.get("kid"); keys = [k for k in (jwks or {}).get("keys", []) if (kid is None or k.get("kid") == kid) and k.get("use", "sig") == "sig"]
    if not keys: bad("no matching signing key")
    msg = f"{h64}.{p64}".encode(); ok = False
    for jwk in keys:
        try:
            pk = _jwk_key(jwk)
            if alg == "RS256": pk.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "ES256":
                if len(sig) != 64: continue
                pk.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), msg, ec.ECDSA(hashes.SHA256()))
            else: pk.verify(sig, msg)
            ok = True; break
        except (InvalidSignature, AuthError, KeyError, ValueError, TypeError): continue
    if not ok: bad("signature verification failed")
    if claims.get("iss") != issuer: bad("issuer mismatch")
    aud = claims.get("aud"); aud = aud if isinstance(aud, list) else [aud]
    if audience not in aud or (len(aud) > 1 and claims.get("azp") != audience): bad("audience mismatch")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] + skew < now: bad("token expired")
    if isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] - skew > now: bad("token not yet valid")
    if isinstance(claims.get("iat"), (int, float)) and claims["iat"] - skew > now: bad("token issued in the future")
    if nonce is not None and not hmac.compare_digest(str(claims.get("nonce") or ""), str(nonce)): bad("nonce mismatch")
    if not claims.get("sub"): bad("no subject")
    email = str(claims.get("email") or "").lower()
    if not email or claims.get("email_verified") is not True: bad("provider has not verified the email address")
    if allowed_domains and email.rsplit("@", 1)[-1] not in {d.lower() for d in allowed_domains}: bad("email domain not allowed for this organization")
    return claims
