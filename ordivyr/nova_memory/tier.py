"""Optional hot/cold tiering for NOVA Memory with portable (optionally encrypted) bundles.

HOT  = the normal NovaMemory database (fast, fully indexed, what search() reads).
COLD = one SQLite file PER TENANT holding archived rows (content + history + the verification signature), searchable on request (`include_cold=True`) through its own FTS index.
The hot database keeps only a content-free routing row per archived memory (`cold_idx`: id, tenant, project, ns, trust) so deletion and access control still know where a memory is.

Guarantees (each has a test):
  * tenant isolation  : a tenant's cold data lives in its own file; every read/thaw is additionally filtered by tenant/project and the principal's namespace grants
  * verification      : signed rows keep vhash/vsig/verifier byte-for-byte; cold search and thaw re-check the signature and never serve or restore a forged row
  * deletion          : delete()/delete_scope()/retention reach into the cold file (secure_delete + VACUUM) and leave only the id-level tombstone, same as hot rows
  * no silent revival : thaw refuses tombstoned ids, and refuses superseded rows unless the caller asks for them explicitly (they come back as 'superseded', never as live)
  * crash safety      : cold copy is committed BEFORE the hot delete; an interrupted archive is finished by the next call (both steps are idempotent per id)
  * portability       : bundle()/restore_bundle() package hot + every cold file with a sha256 manifest (AES-256-GCM per file when a password is given and `cryptography` is installed);
                        restore re-applies the live database's deletions so an old bundle cannot resurrect erased memories
"""
from __future__ import annotations
import hashlib, io, json, os, sqlite3, tarfile, tempfile, time
from pathlib import Path
from . import store as S, trust as TR

COLD_SCHEMA = """
CREATE TABLE IF NOT EXISTS cold(rid INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, project TEXT NOT NULL, ns TEXT NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
  source TEXT NOT NULL, evidence TEXT NOT NULL, version TEXT, trust TEXT NOT NULL, author TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL, expires REAL, supersedes TEXT,
  superseded_by TEXT, bodyhash TEXT NOT NULL, vec TEXT NOT NULL, vhash TEXT, vsig TEXT, verifier TEXT, tenant TEXT NOT NULL, hist TEXT NOT NULL, archived REAL NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS cold_fts USING fts5(title, body, tokenize='porter unicode61');
"""
IDX = "CREATE TABLE IF NOT EXISTS cold_idx(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, project TEXT NOT NULL, ns TEXT NOT NULL, trust TEXT NOT NULL, archived REAL NOT NULL)"
MEMCOLS = ("id", "project", "ns", "kind", "title", "body", "source", "evidence", "version", "trust", "author", "created", "updated", "expires", "supersedes", "superseded_by", "bodyhash", "vec", "vhash", "vsig", "verifier")


class ColdTier:
    def __init__(self, mem: S.NovaMemory, root):
        self.mem, self.root = mem, Path(root); self.root.mkdir(parents=True, exist_ok=True); os.chmod(self.root, 0o700); mem.cold = self
        with mem._lock, mem._c() as c: c.execute(IDX)

    # ---- files
    def _file(self, tenant): return self.root / (hashlib.sha256(tenant.encode()).hexdigest()[:20] + ".cold.db")
    def _open(self, tenant, create=False):
        f = self._file(tenant)
        if not f.exists() and not create: return None
        c = sqlite3.connect(str(f), timeout=15); c.row_factory = sqlite3.Row; c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA secure_delete=ON"); c.executescript(COLD_SCHEMA); os.chmod(f, 0o600); return c

    # ---- archive
    def archive(self, tenant, older_than_s, project=None, limit=5000):
        """Move rows not touched for `older_than_s` seconds (verified, candidate or superseded) to the tenant's cold file. Returns the number moved."""
        cut = self.mem.clock() - older_than_s; m = self.mem
        with m._lock, m._c() as h:
            q = "SELECT * FROM mem WHERE tenant=? AND updated<?" + (" AND project=?" if project else "") + " ORDER BY updated LIMIT ?"
            rows = h.execute(q, [tenant, cut, *([project] if project else []), limit]).fetchall()
            if not rows: return 0
            cold = self._open(tenant, True)
            try:
                with cold:
                    for r in rows:
                        hist = [dict(x) for x in h.execute("SELECT ts,actor,action,detail FROM hist WHERE mem_id=? ORDER BY seq", (r["id"],))]
                        if cold.execute("SELECT 1 FROM cold WHERE id=?", (r["id"],)).fetchone(): continue                       # interrupted earlier archive: already copied
                        cur = cold.execute(f"INSERT INTO cold({','.join(MEMCOLS)},tenant,hist,archived) VALUES({','.join('?' * len(MEMCOLS))},?,?,?)", [r[k] for k in MEMCOLS] + [tenant, json.dumps(hist), m.clock()])
                        cold.execute("INSERT INTO cold_fts(rowid,title,body) VALUES(?,?,?)", (cur.lastrowid, r["title"], r["body"]))
            finally: cold.close()
            for r in rows:                                                                                                      # cold copy is durable: now remove from hot
                h.execute("INSERT OR REPLACE INTO cold_idx VALUES(?,?,?,?,?,?)", (r["id"], tenant, r["project"], r["ns"], r["trust"], m.clock()))
                h.execute("DELETE FROM mem_fts WHERE rowid=?", (r["rid"],)); h.execute("DELETE FROM mem WHERE id=?", (r["id"],)); h.execute("DELETE FROM hist WHERE mem_id=?", (r["id"],))
        m.compact(vacuum=False); return len(rows)

    # ---- read
    def search(self, p, query, k=8, kinds=None, include_candidates=True):
        cold = self._open(p.tenant)
        if cold is None: return []
        qm = " OR ".join(f'"{t}"' for t in dict.fromkeys(S.toks(query)))
        if not qm: return []
        ns = sorted(p.read); trusts = ("verified", "candidate") if include_candidates else ("verified",)
        where = f"c.project=? AND c.tenant=? AND c.ns IN ({','.join('?' * len(ns))}) AND c.trust IN ({','.join('?' * len(trusts))}) AND (c.expires IS NULL OR c.expires>?)"
        args = [p.project, p.tenant, *ns, *trusts, self.mem.clock()]
        if kinds: where += f" AND c.kind IN ({','.join('?' * len(kinds))})"; args += list(kinds)
        out = []
        try:
            for rank, r in enumerate(cold.execute(f"SELECT c.* FROM cold_fts f JOIN cold c ON c.rid=f.rowid WHERE cold_fts MATCH ? AND {where} ORDER BY bm25(cold_fts,3.0,1.0) LIMIT ?", [qm, *args, k * 3])):
                if r["trust"] == "verified" and not TR.sig_ok(self.mem._key, r): continue
                s = (1 / (60 + rank)) * S.TRUST_WEIGHT[r["trust"]] * (1.15 if r["kind"] == "corrective" else 1.0)
                out.append({"id": r["id"], "score": s, "kind": r["kind"], "ns": r["ns"], "title": r["title"], "body": r["body"], "trust": r["trust"], "source": r["source"], "version": r["version"], "created": r["created"], "updated": r["updated"], "tier": "cold"})
        finally: cold.close()
        return out

    def owns(self, p, mid):
        with self.mem._c() as c: return c.execute("SELECT 1 FROM cold_idx WHERE id=? AND tenant=? AND project=?", (mid, p.tenant, p.project)).fetchone() is not None

    # ---- thaw
    def thaw(self, p, ids, include_superseded=False):
        """Bring archived memories back to hot. Returns {'restored': [...], 'refused': {id: reason}}."""
        m, done, refused = self.mem, [], {}
        cold = self._open(p.tenant)
        if cold is None: return {"restored": [], "refused": {i: "not archived" for i in ids}}
        try:
            with m._lock, m._c() as h:
                for mid in ids:
                    ix = h.execute("SELECT * FROM cold_idx WHERE id=? AND tenant=? AND project=?", (mid, p.tenant, p.project)).fetchone()
                    if not ix or ix["ns"] not in p.read: refused[mid] = "not archived"; continue                                 # other tenants'/namespaces' ids look exactly like missing ones
                    if h.execute("SELECT 1 FROM tomb WHERE mem_id=?", (mid,)).fetchone(): refused[mid] = "deleted"; continue
                    r = cold.execute("SELECT * FROM cold WHERE id=?", (mid,)).fetchone()
                    if r is None: refused[mid] = "missing"; continue
                    if r["trust"] == "superseded" and not include_superseded: refused[mid] = "superseded (pass include_superseded=True to restore it as superseded)"; continue
                    if r["trust"] == "verified" and not TR.sig_ok(m._key, r): refused[mid] = "verification signature invalid"; continue
                    h.execute(f"INSERT INTO mem({','.join(MEMCOLS)},tenant) VALUES({','.join('?' * len(MEMCOLS))},?)", [r[k] for k in MEMCOLS] + [p.tenant])
                    h.execute("INSERT INTO mem_fts(rowid,title,body) VALUES((SELECT rid FROM mem WHERE id=?),?,?)", (mid, r["title"], r["body"]))
                    for x in json.loads(r["hist"]): h.execute("INSERT INTO hist(mem_id,ts,actor,action,detail) VALUES(?,?,?,?,?)", (mid, x["ts"], x["actor"], x["action"], x["detail"]))
                    m._hist(h, mid, p.agent, "thawed"); h.execute("DELETE FROM cold_idx WHERE id=?", (mid,)); self._purge_row(cold, r["rid"]); done.append(mid)
        finally: cold.close()
        self._shrink(p.tenant); return {"restored": done, "refused": refused}

    # ---- deletion reaches the cold file
    def _purge_row(self, cold, rid):
        cold.execute("DELETE FROM cold_fts WHERE rowid=?", (rid,)); cold.execute("DELETE FROM cold WHERE rid=?", (rid,)); cold.commit()

    def _shrink(self, tenant):
        cold = self._open(tenant)
        if cold is None: return
        try: cold.execute("INSERT INTO cold_fts(cold_fts) VALUES('optimize')"); cold.commit(); cold.execute("PRAGMA wal_checkpoint(TRUNCATE)"); cold.execute("VACUUM"); cold.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally: cold.close()

    def purge(self, c, mid, actor, reason):
        """Called by NovaMemory._delete for an id that is not in hot: erase it from the cold file and leave only the tombstone. `c` is the caller's hot connection/transaction."""
        ix = c.execute("SELECT * FROM cold_idx WHERE id=?", (mid,)).fetchone()
        if not ix: return False
        cold = self._open(ix["tenant"])
        if cold is not None:
            try:
                r = cold.execute("SELECT rid FROM cold WHERE id=?", (mid,)).fetchone()
                if r: self._purge_row(cold, r["rid"])
            finally: cold.close()
        c.execute("DELETE FROM cold_idx WHERE id=?", (mid,)); c.execute("INSERT OR REPLACE INTO tomb VALUES(?,?,?,?,?,?)", (mid, ix["tenant"], ix["project"], self.mem.clock(), actor, reason))
        self._pending_shrink = ix["tenant"]; return True

    def purge_scope(self, tenant, project=None):
        with self.mem._c() as c:
            ids = [r[0] for r in c.execute("SELECT id FROM cold_idx WHERE tenant=?" + (" AND project=?" if project else ""), [tenant, *([project] if project else [])])]
            for i in ids: self.purge(c, i, "admin", "erasure")
        if ids:
            if project is None: self._file(tenant).unlink(missing_ok=True); [Path(str(self._file(tenant)) + s).unlink(missing_ok=True) for s in ("-wal", "-shm")]
            else: self._shrink(tenant)
        return len(ids)

    def finish_pending(self):
        t = getattr(self, "_pending_shrink", None)
        if t: self._pending_shrink = None; self._shrink(t)

    # ---- portable bundle
    def bundle(self, dest, password=None):
        """One tar: hot backup + each tenant's cold file + manifest. Files are individually encrypted when a password is given."""
        dest = Path(dest); dest.parent.mkdir(parents=True, exist_ok=True); tmp = Path(tempfile.mkdtemp(prefix="novabundle-")); man = {"format": "nova-bundle-v1", "created": time.time(), "files": {}, "encrypted": bool(password)}
        self.mem.backup(tmp / "hot.bak", password); files = {"hot.bak": tmp / "hot.bak"}
        for f in sorted(self.root.glob("*.cold.db")):
            self.mem.compact(vacuum=False); TR.backup_db(f, tmp / (f.name + ".bak"), password); files[f.name + ".bak"] = tmp / (f.name + ".bak")
        with tarfile.open(dest, "w") as t:
            for name, path in list(files.items()):
                for nm, pth in ((name, path), (name + ".manifest.json", Path(str(path) + ".manifest.json"))): man["files"][nm] = hashlib.sha256(pth.read_bytes()).hexdigest(); t.add(pth, arcname=nm)
            data = json.dumps(man).encode(); ti = tarfile.TarInfo("manifest.json"); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
        os.chmod(dest, 0o600); return {"path": str(dest), "files": list(man["files"]), "encrypted": bool(password)}

    def restore_bundle(self, src, password=None):
        tmp = Path(tempfile.mkdtemp(prefix="novarestore-"))
        with tarfile.open(src) as t:
            for ti in t.getmembers():
                if "/" in ti.name or ti.name.startswith("."): raise ValueError("unsafe path in bundle")
            t.extractall(tmp, filter="data")
        man = json.loads((tmp / "manifest.json").read_text())
        for name, h in man["files"].items():
            if hashlib.sha256((tmp / name).read_bytes()).hexdigest() != h: raise ValueError(f"bundle file {name} failed its checksum")
        with self.mem._c() as c: live_tomb = [dict(r) for r in c.execute("SELECT * FROM tomb")]
        res = self.mem.restore(tmp / "hot.bak", password)                       # hot: re-applies the live deletions
        for name in man["files"]:
            if name.endswith(".cold.db.bak"):
                raw = TR.read_backup(tmp / name, password); dst = self.root / name[:-4]
                for suf in ("", "-wal", "-shm"): Path(str(dst) + suf).unlink(missing_ok=True)
                dst.write_bytes(raw); os.chmod(dst, 0o600)
        with self.mem._lock, self.mem._c() as c:
            c.execute(IDX)
            for t_ in live_tomb: c.execute("INSERT OR IGNORE INTO tomb VALUES(?,?,?,?,?,?)", (t_["mem_id"], t_["tenant"], t_["project"], t_["ts"], t_["actor"], t_["reason"]))
            for f in self.root.glob("*.cold.db"):
                cold = sqlite3.connect(str(f)); cold.row_factory = sqlite3.Row
                try:
                    for r in cold.execute("SELECT id, tenant, project, ns, trust FROM cold"): c.execute("INSERT OR REPLACE INTO cold_idx VALUES(?,?,?,?,?,?)", (r["id"], r["tenant"], r["project"], r["ns"], r["trust"], self.mem.clock()))
                finally: cold.close()
            for (mid,) in c.execute("SELECT mem_id FROM tomb").fetchall(): self.purge(c, mid, "system", "reapplied after bundle restore")
        self.finish_pending(); return {**res, "cold_files": sum(1 for n in man["files"] if n.endswith(".cold.db.bak"))}
