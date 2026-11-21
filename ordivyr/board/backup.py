"""Backup, verification and restore for Board (SQLite homes and PostgreSQL).

A backup is a directory: the database files (SQLite online-backup snapshots, or a `pg_dump -Fc` archive) + `manifest.json` (sha256 of every file, schema version, audit-chain head, table counts).
It deliberately does NOT contain `master.key`: a stolen backup alone reveals no secret, MFA seed or hosted-worker token. Back the key up SEPARATELY (see docs/board/OPERATIONS.md); without it sealed values are unrecoverable by design.
`verify_backup` re-hashes the files; `restore` refuses a non-empty target, then proves the restored copy: integrity check, audit hash chain, schema version, and counts vs the manifest.
"""
from __future__ import annotations
import hashlib, json, os, shutil, sqlite3, subprocess, time
from pathlib import Path

COUNT_TABLES = ("orgs", "projects", "keys", "users", "memberships", "jobs", "meter", "audit", "agents", "workers", "secrets", "subscriptions", "invoices")


class BackupError(Exception): pass


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""): h.update(ch)
    return h.hexdigest()


def _bin(pg_bin, name):
    p = str(Path(pg_bin) / name) if pg_bin else shutil.which(name)
    if not p or not Path(p).exists(): raise BackupError(f"{name} not found (pass --pg-bin)")
    return p


def _counts(conn, qmark):
    out = {}
    for t in COUNT_TABLES:
        try: out[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except Exception: out[t] = None
    return out


def _board_facts(db):
    ok, bad = db.verify_audit(); head = db.c().execute("SELECT h FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    return {"schema_version": db.schema_version(), "audit_ok": ok, "audit_head": head[0] if head else None, "counts": _counts(db.c(), None)}


PERSONAL = ('selfhost.json', 'admin.token', 'worker.token', 'lite-worker.token')      # credentials + model config of a personal install made by `ordivyr-board init`


def backup(home, out_dir, dsn=None, pg_bin=None, include_personal=False):
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()): raise BackupError("output directory must be empty")
    out.mkdir(parents=True, exist_ok=True); os.chmod(out, 0o700); files = {}
    if dsn:
        from .db import DB
        db = DB(None, dsn=dsn); pre = _board_facts(db); db.close()
        dump = out / "board.dump"; r = subprocess.run([_bin(pg_bin, "pg_dump"), "--format=custom", "--no-owner", "--file", str(dump), dsn], capture_output=True, text=True)
        if r.returncode: raise BackupError("pg_dump failed: " + r.stderr[:300])
        files["board.dump"] = dump; backend = "postgres"
    else:
        home = Path(home); backend = "sqlite"
        for name in ("board.db", "queue.db"):
            src = home / name
            if not src.exists(): continue
            s = sqlite3.connect(src); d = sqlite3.connect(out / name); s.backup(d)                       # online, consistent snapshot: safe while Board is serving
            if d.execute("PRAGMA integrity_check").fetchone()[0] != "ok": raise BackupError(f"{name}: integrity check failed on the copy")
            d.close(); s.close(); files[name] = out / name
        from .db import DB
        db = DB(out / "board.db"); pre = _board_facts(db); db.close()                                   # facts come from the snapshot itself: exact
    if include_personal and not dsn:                                     # opt-in: these hold the owner token and the model API key, so the backup then needs the same care as them
        pd = out / "personal"; pd.mkdir(mode=0o700)
        for name in PERSONAL:
            if (home / name).is_file(): shutil.copy2(home / name, pd / name); files["personal/" + name] = pd / name
        if (home / "gateway").is_dir():
            shutil.copytree(home / "gateway", pd / "gateway")
            for q in sorted((pd / "gateway").rglob("*")):
                if q.is_file(): files[str(q.relative_to(out))] = q
    for p in files.values(): os.chmod(p, 0o600)
    man = {"format": 1, "created": time.time(), "backend": backend, "files": {n: {"sha256": _sha(p), "bytes": p.stat().st_size} for n, p in files.items()}, **pre,
           "personal": any(n.startswith("personal/") for n in files), "note": "master.key is NOT in this backup; keep it separately or sealed values (secrets, MFA seeds, hosted tokens) cannot be recovered"}
    (out / "manifest.json").write_text(json.dumps(man, indent=1)); os.chmod(out / "manifest.json", 0o600); return man


def verify_backup(bdir):
    b = Path(bdir); man = json.loads((b / "manifest.json").read_text()); bad = []
    for n, m in man["files"].items():
        p = b / n
        if not p.exists() or _sha(p) != m["sha256"]: bad.append(n)
    if bad: raise BackupError("backup files are missing or corrupt: " + ", ".join(bad))
    return man


def restore(bdir, home=None, dsn=None, pg_bin=None):
    """-> verification report. Refuses to overwrite: SQLite needs an empty/new home, PostgreSQL an empty database."""
    b = Path(bdir); man = verify_backup(b); from .db import DB
    if man["backend"] == "sqlite":
        if dsn: raise BackupError("this is a SQLite backup; restore it to a home directory")
        home = Path(home); fresh = not home.exists(); home.mkdir(parents=True, exist_ok=True)
        if fresh: os.chmod(home, 0o700)
        if (home / "board.db").exists() or (home / "queue.db").exists(): raise BackupError("target home already has Board databases: restore into an empty directory")
        for n in man["files"]:
            dest = home / (n[len("personal/"):] if n.startswith("personal/") else n); dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(b / n, dest); os.chmod(dest, 0o600)
        db = DB(home / "board.db")
    else:
        if not dsn: raise BackupError("this is a PostgreSQL backup; give --pg-dsn of an EMPTY database")
        import psycopg
        with psycopg.connect(dsn) as c:
            if c.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'").fetchone()[0]: raise BackupError("target database is not empty")
        r = subprocess.run([_bin(pg_bin, "pg_restore"), "--no-owner", "--dbname", dsn, str(b / "board.dump")], capture_output=True, text=True)
        if r.returncode: raise BackupError("pg_restore failed: " + r.stderr[:300])
        db = DB(None, dsn=dsn)
    got = _board_facts(db); db.close(); problems = []
    if not got["audit_ok"]: problems.append("audit hash chain broken")
    if got["schema_version"] < man["schema_version"]: problems.append("schema older than backup")
    for t, n in (man["counts"] or {}).items():
        if n is not None and (got["counts"].get(t) is None or got["counts"][t] < n): problems.append(f"{t}: {got['counts'].get(t)} rows < {n} in manifest")
    if man["backend"] == "sqlite" and got["audit_head"] != man["audit_head"]: problems.append("audit head differs from manifest")
    if problems: raise BackupError("restore verification FAILED: " + "; ".join(problems))
    return {"ok": True, "restored": got["counts"], "schema_version": got["schema_version"], "audit_head": got["audit_head"], "verified": ["file hashes", "audit chain", "schema version", "row counts"]}
