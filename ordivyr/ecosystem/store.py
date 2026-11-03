"""Plugin store: install / verify / enable / grant / audit. Pure file operations - installing never executes plugin code.

Layout under <home>:  plugins/<id>/ (the installed tree)   plugins.lock.json (content hash per plugin)
                      plugin-state.json (enabled, grants, native trust pin)   plugin-audit.jsonl (every host-mediated call)
"""
from __future__ import annotations
import hashlib, io, json, os, shutil, tarfile, tempfile, time, zipfile
from pathlib import Path
from . import manifest as MF

MAX_FILES = 2000; MAX_BYTES = 50 * 1024 * 1024


class StoreError(ValueError): pass


def _safe_extract(archive, dest):
    n = 0; total = 0
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for i in z.infolist():
                if i.is_dir(): continue
                n += 1; total += i.file_size
                if n > MAX_FILES or total > MAX_BYTES: raise StoreError("archive is too large")
                if (i.external_attr >> 28) == 0xA: raise StoreError("symlinks are not allowed in a plugin archive")
                t = (Path(dest) / i.filename).resolve()
                if Path(dest).resolve() not in t.parents: raise StoreError(f"unsafe path in archive: {i.filename}")
                t.parent.mkdir(parents=True, exist_ok=True); t.write_bytes(z.read(i))
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as t:
            for m in t.getmembers():
                if m.isdir(): continue
                if not m.isreg(): raise StoreError(f"only regular files are allowed in a plugin archive ({m.name})")
                n += 1; total += m.size
                if n > MAX_FILES or total > MAX_BYTES: raise StoreError("archive is too large")
                tgt = (Path(dest) / m.name).resolve()
                if Path(dest).resolve() not in tgt.parents: raise StoreError(f"unsafe path in archive: {m.name}")
                tgt.parent.mkdir(parents=True, exist_ok=True); tgt.write_bytes(t.extractfile(m).read())
    else: raise StoreError("not a zip or tar archive")
    # a single top-level folder is unwrapped
    kids = list(Path(dest).iterdir())
    if len(kids) == 1 and kids[0].is_dir() and not (Path(dest) / MF.MANIFEST).exists():
        inner = kids[0]; tmp = Path(dest).with_name(Path(dest).name + "-u"); inner.rename(tmp); shutil.rmtree(dest); tmp.rename(dest)


class PluginStore:
    def __init__(self, home):
        self.home = Path(home); self.dir = self.home / "plugins"; self.dir.mkdir(parents=True, exist_ok=True)
        self.lock_p, self.state_p, self.audit_p = self.home / "plugins.lock.json", self.home / "plugin-state.json", self.home / "plugin-audit.jsonl"
    # ------------------------------------------------------------ json state
    def _rd(self, p):
        try: return json.loads(p.read_text("utf-8"))
        except (OSError, ValueError): return {}
    def _wr(self, p, d):
        tmp = p.with_suffix(".tmp"); tmp.write_text(json.dumps(d, indent=1, sort_keys=True)); os.chmod(tmp, 0o600); tmp.replace(p)
    # ------------------------------------------------------------ install
    def install(self, source, force=False, sha256=None, origin_note=""):
        """source: a folder or a .zip/.tar archive containing ordivyr-plugin.json. Returns the manifest. Never runs anything."""
        src = Path(source)
        if not src.exists(): raise StoreError("source not found")
        if sha256 and src.is_file():
            if hashlib.sha256(src.read_bytes()).hexdigest() != sha256.lower(): raise StoreError("archive sha256 does not match the pinned value")
        stage = Path(tempfile.mkdtemp(prefix="ordivyr-stage-", dir=self.home))
        try:
            tree = stage / "t"
            if src.is_dir():
                n = 0; total = 0
                for f in src.rglob("*"):
                    if f.is_symlink(): raise StoreError(f"symlink not allowed in a plugin: {f.relative_to(src)}")
                    if f.is_file():
                        n += 1; total += f.stat().st_size
                        if n > MAX_FILES or total > MAX_BYTES: raise StoreError("plugin is too large")
                shutil.copytree(src, tree, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"))
            else:
                tree.mkdir(); _safe_extract(src, tree)
            mp = tree / MF.MANIFEST
            if not mp.is_file(): raise StoreError(f"{MF.MANIFEST} not found at the top of the plugin")
            m = MF.clean(mp.read_text("utf-8"))
            if m["runtime"] == "native" and not (tree / m["entry"]["module"]).is_file(): raise StoreError("native entry module is missing")
            dst = self.dir / m["id"]
            if dst.exists() and not force: raise StoreError(f"{m['id']} is already installed (use force to replace; grants are kept only if permissions are unchanged)")
            old = self.get(m["id"]) if dst.exists() else None
            for f in tree.rglob("*"):                                      # no executable bits survive install
                if f.is_file(): os.chmod(f, 0o644)
            if dst.exists(): shutil.rmtree(dst)
            shutil.move(str(tree), str(dst))
            lock = self._rd(self.lock_p); lock[m["id"]] = {"hash": MF.tree_hash(dst), "version": m["version"], "installed": time.time(), "note": origin_note[:120]}; self._wr(self.lock_p, lock)
            st = self._rd(self.state_p); cur = st.get(m["id"], {})
            keep = old and set(old["permissions"]) == set(m["permissions"])
            st[m["id"]] = {"enabled": False, "grants": cur.get("grants", []) if keep else [], "native_trust": ""}; self._wr(self.state_p, st)
            self.audit("install", m["id"], {"version": m["version"]})
            return m
        finally: shutil.rmtree(stage, ignore_errors=True)
    def install_manifest(self, doc, files=None, force=False, note=""):
        """Used by importers: write a manifest (+ optional text files {relpath: content}) into a temp tree and install it."""
        m = MF.clean(doc); tmp = Path(tempfile.mkdtemp(prefix="ordivyr-imp-", dir=self.home))
        try:
            (tmp / MF.MANIFEST).write_text(json.dumps(m, indent=1))
            for rel, text in (files or {}).items():
                t = (tmp / rel).resolve()
                if tmp.resolve() not in t.parents: raise StoreError("unsafe file path")
                t.parent.mkdir(parents=True, exist_ok=True); t.write_text(text)
            return self.install(tmp, force=force, origin_note=note)
        finally: shutil.rmtree(tmp, ignore_errors=True)
    # ------------------------------------------------------------ query
    def ids(self): return sorted(p.name for p in self.dir.iterdir() if (p / MF.MANIFEST).is_file())
    def get(self, pid):
        p = self.dir / pid / MF.MANIFEST
        if not MF.ID_RE.match(pid or "") or not p.is_file(): raise StoreError(f"unknown plugin {pid!r}")
        return MF.clean(p.read_text("utf-8"))
    def path(self, pid): self.get(pid); return self.dir / pid
    def state(self, pid): return {"enabled": False, "grants": [], "native_trust": "", **self._rd(self.state_p).get(pid, {})}
    def verify(self, pid):
        """Does the installed tree still match the hash recorded at install time?"""
        want = self._rd(self.lock_p).get(pid, {}).get("hash")
        try: ok = bool(want) and MF.tree_hash(self.path(pid)) == want
        except MF.ManifestError: ok = False
        return ok
    def list(self):
        out = []
        for pid in self.ids():
            try: m = self.get(pid)
            except (StoreError, MF.ManifestError): continue
            s = self.state(pid)
            out.append({"id": pid, "name": m["name"], "version": m["version"], "runtime": m["runtime"], "origin": m["origin"], "enabled": s["enabled"], "verified": self.verify(pid),
                        "requested": m["permissions"], "granted": s["grants"], "pending": sorted(set(m["permissions"]) - set(s["grants"])), "native_trusted": bool(s["native_trust"])})
        return out
    # ------------------------------------------------------------ decisions (explicit, per plugin)
    def _set(self, pid, **kw):
        self.get(pid); st = self._rd(self.state_p); cur = {"enabled": False, "grants": [], "native_trust": "", **st.get(pid, {})}; cur.update(kw); st[pid] = cur; self._wr(self.state_p, st)
    def grant(self, pid, perms):
        m = self.get(pid); req = set(m["permissions"]); add = set()
        for p in perms:
            k, a = MF.perm(p); p = f"{k}:{a}" if a else k
            if p not in req: raise StoreError(f"{p!r} was not requested by {pid}; a plugin can only be granted what its manifest declares")
            add.add(p)
        self._set(pid, grants=sorted(set(self.state(pid)["grants"]) | add)); self.audit("grant", pid, {"perms": sorted(add)})
    def revoke(self, pid, perms=None):
        cur = set(self.state(pid)["grants"]); self._set(pid, grants=sorted(cur - set(perms)) if perms else []); self.audit("revoke", pid, {"perms": sorted(perms or cur)})
    def enable(self, pid):
        if not self.verify(pid): raise StoreError(f"{pid} does not match its recorded hash (modified after install?); reinstall it")
        self._set(pid, enabled=True); self.audit("enable", pid, {})
    def disable(self, pid): self._set(pid, enabled=False); self.audit("disable", pid, {})
    def trust_native(self, pid, tree_hash):
        """Pin in-process execution to ONE exact content hash. Any later change to the plugin voids the trust."""
        m = self.get(pid)
        if m["runtime"] != "native": raise StoreError("only native plugins need trust")
        if tree_hash != MF.tree_hash(self.path(pid)): raise StoreError("hash mismatch: review the current code and pass its hash (ordivyr plugin inspect shows it)")
        self._set(pid, native_trust=tree_hash); self.audit("trust_native", pid, {"hash": tree_hash[:16]})
    def uninstall(self, pid):
        self.get(pid); shutil.rmtree(self.dir / pid)
        for p in (self.lock_p, self.state_p):
            d = self._rd(p); d.pop(pid, None); self._wr(p, d)
        self.audit("uninstall", pid, {})
    # ------------------------------------------------------------ audit
    def audit(self, event, pid, detail):
        line = json.dumps({"t": round(time.time(), 3), "event": event, "plugin": pid, **{k: (str(v)[:300] if not isinstance(v, (int, float, list, dict)) else v) for k, v in detail.items()}})
        with open(self.audit_p, "a") as f: f.write(line + "\n")
        try: os.chmod(self.audit_p, 0o600)
        except OSError: pass
    def read_audit(self, limit=100):
        try: return [json.loads(x) for x in self.audit_p.read_text().splitlines()[-limit:]]
        except OSError: return []
