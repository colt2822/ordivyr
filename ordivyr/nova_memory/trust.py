"""Verifier authentication, verification signatures, and backup/restore for NOVA Memory (stdlib; encryption of backups uses `cryptography` only if present)."""
from __future__ import annotations
import hashlib, hmac, json, os, secrets, sqlite3, time
from pathlib import Path

SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


def hash_secret(secret: str, salt: bytes) -> bytes: return hashlib.scrypt(secret.encode(), salt=salt, **SCRYPT)


def new_secret() -> str: return secrets.token_urlsafe(32)


def load_or_create_key(path: Path) -> bytes:
    """Server signing key, kept OUT of the database (separate 0600 file). A party who can only write the database cannot mint verified memories."""
    path = Path(path)
    if path.exists():
        if path.stat().st_mode & 0o077: os.chmod(path, 0o600)
        return bytes.fromhex(path.read_text().strip())
    k = secrets.token_bytes(32); fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f: f.write(k.hex())
    return k


def content_hash(kind, title, body, ns, version) -> str: return hashlib.sha256(json.dumps([kind, title, body, ns, version or ""]).encode()).hexdigest()


def sign(key: bytes, mid, chash, verifier, tenant, project) -> str: return hmac.new(key, f"{mid}|{chash}|{verifier}|{tenant}|{project}".encode(), hashlib.sha256).hexdigest()


def sig_ok(key, row) -> bool:
    if not row["vsig"] or not row["vhash"]: return False
    if content_hash(row["kind"], row["title"], row["body"], row["ns"], row["version"]) != row["vhash"]: return False      # content changed after verification
    return hmac.compare_digest(sign(key, row["id"], row["vhash"], row["verifier"], row["tenant"], row["project"]), row["vsig"])


# ---- backup / restore ----
def _aes(password: str, salt: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM          # optional dependency, imported lazily
    return AESGCM(hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024))


def backup_db(src_path, dest, password=None):
    """Consistent online copy via SQLite's backup API + sha256 manifest. With `password`, the file is AES-256-GCM encrypted (needs the optional `cryptography` package)."""
    dest = Path(dest); dest.parent.mkdir(parents=True, exist_ok=True); tmp = dest.with_suffix(dest.suffix + ".tmp")
    s = sqlite3.connect(str(src_path)); d = sqlite3.connect(str(tmp)); s.backup(d); d.execute("PRAGMA journal_mode=DELETE"); d.close(); s.close()
    raw = tmp.read_bytes(); tmp.unlink(); digest = hashlib.sha256(raw).hexdigest()
    if password:
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12); blob = b"NOVAENC1" + salt + nonce + _aes(password, salt).encrypt(nonce, raw, b"nova-backup")
    else: blob = raw
    fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f: f.write(blob)
    Path(str(dest) + ".manifest.json").write_text(json.dumps({"sha256_plain": digest, "encrypted": bool(password), "created": time.time(), "format": "nova-sqlite-v1"}))
    return {"path": str(dest), "sha256_plain": digest, "encrypted": bool(password)}


def read_backup(path, password=None) -> bytes:
    blob = Path(path).read_bytes(); man = json.loads(Path(str(path) + ".manifest.json").read_text())
    if blob.startswith(b"NOVAENC1"):
        if not password: raise ValueError("backup is encrypted: password required")
        salt, nonce, ct = blob[8:24], blob[24:36], blob[36:]
        try: raw = _aes(password, salt).decrypt(nonce, ct, b"nova-backup")
        except Exception as e: raise ValueError("wrong password or corrupted backup") from e
    else: raw = blob
    if hashlib.sha256(raw).hexdigest() != man["sha256_plain"]: raise ValueError("backup integrity check failed (sha256 mismatch)")
    return raw
