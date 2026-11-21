"""Envelope for secrets at rest: AES-256-GCM with the tenant coordinates bound in as AAD, so a ciphertext copied to another org/project/name (or another user's MFA slot) does not decrypt.

The master key lives OUTSIDE the database (a 0600 file, or env ORDIVYR_BOARD_MASTER_KEY for container secrets): a database dump or backup alone reveals nothing. The key file holds one `kid base64` line per
key, newest LAST; sealing uses the newest, opening tries the key named in the blob, so keys can be rotated without re-encrypting everything at once (`rewrap`).
"""
from __future__ import annotations
import base64, os, secrets, stat
from pathlib import Path


class VaultError(Exception): pass


class Vault:
    def __init__(self, path=None, env="ORDIVYR_BOARD_MASTER_KEY"):
        self.path = Path(path) if path else None; self.keys = {}; self.order = []
        e = os.environ.get(env)
        if e: self._add("env", e.strip())
        elif self.path:
            if not self.path.exists(): self._create()
            m = self.path.stat().st_mode
            if m & (stat.S_IRWXG | stat.S_IRWXO): raise VaultError(f"{self.path} is readable by group/other: chmod 600 it (refusing to use the master key)")
            for ln in self.path.read_text().split("\n"):
                if ln.strip(): kid, k = ln.split(); self._add(kid, k)
        if not self.keys: raise VaultError("no master key configured")

    def _add(self, kid, b64):
        k = base64.b64decode(b64)
        if len(k) != 32: raise VaultError("master key must be 32 bytes")
        self.keys[kid] = k; self.order.append(kid)

    def _create(self, kid="k1"):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f: f.write(f"{kid} {base64.b64encode(secrets.token_bytes(32)).decode()}\n")

    def rotate(self):
        """Add a new newest key (old ones stay for opening). Returns its id."""
        if not self.path: raise VaultError("rotation needs a key file")
        kid = f"k{len(self.order) + 1}"
        with open(self.path, "a") as f: f.write(f"{kid} {base64.b64encode(secrets.token_bytes(32)).decode()}\n")
        self._add(kid, self.path.read_text().strip().split("\n")[-1].split()[1]); return kid

    @staticmethod
    def _aesgcm(k):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(k)

    def seal(self, plaintext, aad):
        pt = plaintext.encode() if isinstance(plaintext, str) else plaintext; kid = self.order[-1]; nonce = secrets.token_bytes(12)
        return f"v1.{kid}." + base64.urlsafe_b64encode(nonce + self._aesgcm(self.keys[kid]).encrypt(nonce, pt, aad.encode())).decode()

    def open(self, blob, aad):
        try:
            v, kid, b = blob.split(".", 2); raw = base64.urlsafe_b64decode(b); return self._aesgcm(self.keys[kid]).decrypt(raw[:12], raw[12:], aad.encode())
        except Exception as e: raise VaultError("cannot decrypt (wrong key, wrong context, or tampered)") from e

    def rewrap(self, blob, aad): return self.seal(self.open(blob, aad), aad)
