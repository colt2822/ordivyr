"""Model Hub: search Hugging Face, list files (size/quant/license/gating/vision projector), recommend for THIS hardware, download safely, manage installs.

Safety rules (each is tested):
  * Downloads go to `<models_dir>/hub/<repo>/<file>.part` (HTTP Range resume), are verified against the SHA-256 Hugging Face publishes for LFS files, then atomically renamed.
  * Cancel is cooperative and leaves the `.part` so a later start resumes; `purge_partial` removes it.
  * Only files THIS hub downloaded are ever deleted (manifest-checked, path must stay inside `<models_dir>/hub`). Other model folders are listed read-only via `external_dirs`.
  * 401/403 is reported as `gated` (needs a token / accepted license), never as a crash. A token is only sent to huggingface.co hosts.
  * Not enough disk -> refused before a byte is written.
Network access goes through `Hub.opener` (default urllib) so tests use a local HF-shaped server; nothing here loads or launches a model.
"""
from __future__ import annotations
import hashlib, json, os, re, shutil, threading, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from .. import hw as HW

HF = "https://huggingface.co"
DISK_MARGIN_MB = 1024
_QUANT = re.compile(r"(?<![A-Za-z0-9])((?:UD-)?(?:IQ\d(?:_[A-Z0-9]+)*|Q\d(?:_[A-Z0-9]+)*|BF16|F16|F32|MXFP4))(?![A-Za-z0-9])", re.I)
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SHARD = re.compile(r"-\d{5}-of-\d{5}")

class HubError(RuntimeError):
    def __init__(self, code, msg): super().__init__(msg); self.code = code

class _NoAuthOnForeignRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        n = super().redirect_request(req, fp, code, msg, headers, newurl)
        if n is not None and urllib.parse.urlparse(newurl).hostname != urllib.parse.urlparse(req.full_url).hostname: n.headers.pop("Authorization", None); n.unredirected_hdrs.pop("Authorization", None)
        return n

def _default_open(url, headers, timeout):
    return urllib.request.build_opener(_NoAuthOnForeignRedirect).open(urllib.request.Request(url, headers=headers), timeout=timeout)

def classify(name):
    n = name.lower()
    if n.endswith(".gguf"): return "mmproj" if "mmproj" in n.rsplit("/", 1)[-1] else "weights"
    if n.endswith(".safetensors"): return "weights"
    return "other"

def quant_of(name):
    m = _QUANT.search(name.rsplit("/", 1)[-1]); return m.group(1).upper() if m else None

def fmt_of(name): return "gguf" if name.lower().endswith(".gguf") else "safetensors" if name.lower().endswith(".safetensors") else None

class Hub:
    def __init__(self, models_dir, opener=None, token=None, external_dirs=(), timeout=30, hf=None):
        self.hf = (hf or HF).rstrip("/")
        self.root = Path(models_dir); self.dir = self.root / "hub"; self.dir.mkdir(parents=True, exist_ok=True); self.manifest_path = self.root / "hub-manifest.json"
        self.opener = opener or _default_open; self.token = token or os.environ.get("HF_TOKEN"); self.external = [Path(p) for p in external_dirs]; self.timeout = timeout
        self.jobs = {}; self._lock = threading.Lock(); self._seq = 0

    # ---------------------------------------------------------------- HTTP
    def _hdr(self, url, extra=None):
        h = {"User-Agent": "ordivyr-hub/1", **(extra or {})}
        if self.token and (urllib.parse.urlparse(url).hostname or "").endswith("huggingface.co"): h["Authorization"] = "Bearer " + self.token
        return h
    def _json(self, url):
        try:
            with self.opener(url, self._hdr(url), self.timeout) as r: return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403): raise HubError("gated", f"{url}: access requires a Hugging Face token / accepted license (HTTP {e.code})")
            if e.code == 404: raise HubError("not_found", f"{url}: not found")
            raise HubError("http", f"{url}: HTTP {e.code}")
        except (urllib.error.URLError, OSError) as e: raise HubError("network", f"cannot reach {url}: {e}")

    # ---------------------------------------------------------------- discovery
    def search(self, query, limit=20, gguf=True, sort="downloads"):
        q = {"search": query, "limit": str(min(max(1, limit), 100)), "sort": sort, "direction": "-1", "full": "false"}
        if gguf: q["filter"] = "gguf"
        out = []
        for m in self._json(f"{self.hf}/api/models?" + urllib.parse.urlencode(q)):
            lic = next((t.split(":", 1)[1] for t in m.get("tags", []) if t.startswith("license:")), None)
            out.append({"id": m.get("id") or m.get("modelId"), "downloads": m.get("downloads"), "likes": m.get("likes"), "license": lic, "gated": m.get("gated") or False,
                        "pipeline": m.get("pipeline_tag"), "gguf": "gguf" in m.get("tags", []), "updated": m.get("lastModified")})
        return out

    def files(self, repo, rev="main"):
        d = self._json(f"{self.hf}/api/models/{urllib.parse.quote(repo, safe='/')}/revision/{urllib.parse.quote(rev, safe='')}?blobs=true")
        fl = []
        for s in d.get("siblings", []):
            n = s["rfilename"]; k = classify(n)
            if k == "other": continue
            fl.append({"name": n, "size": s.get("size") or (s.get("lfs") or {}).get("size") or 0, "sha256": (s.get("lfs") or {}).get("sha256"), "kind": k, "format": fmt_of(n), "quant": quant_of(n),
                       "group": _SHARD.sub("", n)})
        card = d.get("cardData") or {}; lic = card.get("license") or next((t.split(":", 1)[1] for t in d.get("tags", []) if t.startswith("license:")), None)
        return {"id": d.get("id", repo), "rev": d.get("sha") or rev, "license": lic, "gated": d.get("gated") or False, "pipeline": d.get("pipeline_tag"), "tags": d.get("tags", []),
                "vision": any(f["kind"] == "mmproj" for f in fl) or "image-text-to-text" in (d.get("pipeline_tag") or ""), "files": fl}

    def variants(self, info):
        """Group weight files (shards together) into installable variants."""
        g = {}
        for f in info["files"]:
            if f["kind"] != "weights": continue
            v = g.setdefault(f["group"], {"name": f["group"], "files": [], "size": 0, "quant": f["quant"], "format": f["format"]}); v["files"].append(f["name"]); v["size"] += f["size"]
        return sorted(g.values(), key=lambda v: v["size"])

    def projector_for(self, info, variant=None):
        ps = [f for f in info["files"] if f["kind"] == "mmproj"]
        if not ps: return None
        pref = sorted(ps, key=lambda f: (0 if (f["quant"] or "") in ("F16", "BF16") else 1, f["size"])); return pref[0]["name"]

    def recommend(self, info, hw, ctx=4096, allowed_gpus=None, engines=("llama.cpp",)):
        """Rank this repo's variants for THIS hardware. Never recommends something that does not fit; `allowed_gpus` restricts which GPU indexes may be used (others are invisible)."""
        gpus = [g for g in hw.gpus if allowed_gpus is None or g.index in allowed_gpus]; view = HW.Hardware(gpus, hw.cpu_threads, hw.ram_mb, hw.os, hw.disk_free_mb, hw.disk_path); out = []
        for v in self.variants(info):
            if v["format"] == "gguf" and "llama.cpp" not in engines and "ollama" not in engines: continue
            need = int(v["size"] / 1048576 * 1.05 + (ctx / 1024) * 64 + 400); fit = HW.fits(view, need) if v["format"] == "gguf" else {"where": None, "split": False}
            out.append({**v, "need_mb": need, "fits": fit["where"] is not None, "where": fit["where"], "split": fit["split"], "disk_ok": need and v["size"] / 1048576 + DISK_MARGIN_MB <= (hw.disk_free_mb or 10 ** 9)})
        ok = [o for o in out if o["fits"] and o["disk_ok"]]
        best = max((o for o in ok if o["where"] != "cpu"), key=lambda o: o["size"], default=None) or max(ok, key=lambda o: o["size"], default=None)   # largest quant that fits on a GPU; CPU only as fallback
        return {"best": best["name"] if best else None, "variants": out}

    # ---------------------------------------------------------------- manifest / installed
    def _load(self):
        try: return json.loads(self.manifest_path.read_text())
        except (OSError, ValueError): return {"models": {}}
    def _save(self, m):
        t = self.manifest_path.with_suffix(".tmp"); t.write_text(json.dumps(m, indent=1)); os.replace(t, self.manifest_path)
    def installed(self):
        m = self._load()["models"]; out = [{"id": k, **v, "managed": True, "present": all((self.root / f["path"]).exists() for f in v["files"])} for k, v in m.items()]
        for d in self.external:
            for p in sorted(d.glob("*.gguf")) if d.is_dir() else []:
                out.append({"id": "external/" + p.name, "managed": False, "read_only": True, "files": [{"path": str(p), "size": p.stat().st_size}], "present": True, "kind": "mmproj" if "mmproj" in p.name.lower() else "weights"})
        return out
    def path_of(self, model_id):
        m = self._load()["models"].get(model_id)
        if not m: raise HubError("not_installed", f"{model_id} is not installed by the hub")
        w = [f for f in m["files"] if f["kind"] == "weights"]; return {"weights": str(self.root / w[0]["path"]), "mmproj": next((str(self.root / f["path"]) for f in m["files"] if f["kind"] == "mmproj"), None), "format": m["format"], "quant": m.get("quant")}
    def remove(self, model_id):
        m = self._load(); e = m["models"].get(model_id)
        if not e: raise HubError("not_installed", f"{model_id} was not installed by the hub; refusing to delete anything")
        n = 0
        for f in e["files"]:
            p = (self.root / f["path"]).resolve()
            if self.dir.resolve() not in p.parents: raise HubError("unsafe_path", f"{p} is outside the hub directory; refusing")
            if p.exists(): p.unlink(); n += 1
            for q in (p.parent,):
                try:
                    while q != self.dir.resolve() and not any(q.iterdir()): q.rmdir(); q = q.parent
                except OSError: pass
        del m["models"][model_id]; self._save(m); return {"removed_files": n}
    def purge_partial(self):
        n = 0
        for p in self.dir.rglob("*.part"): p.unlink(); n += 1
        return n

    # ---------------------------------------------------------------- download
    def start(self, repo, variant, rev="main", with_projector=True, hw=None):
        """Begin (or resume) installing one variant (+ vision projector). Returns the job id; poll `job(id)`."""
        if not _REPO.match(repo or "") or ".." in repo: raise HubError("bad_repo", f"{repo!r} is not a valid owner/name repository id")
        info = self.files(repo, rev)
        if info["gated"] and not self.token: raise HubError("gated", f"{repo} is gated: set a Hugging Face token (and accept the license on huggingface.co)")
        vs = {v["name"]: v for v in self.variants(info)}
        if variant not in vs: raise HubError("no_such_variant", f"{variant!r} not in {sorted(vs)}")
        names = list(vs[variant]["files"]); proj = self.projector_for(info) if with_projector else None
        if proj: names.append(proj)
        by = {f["name"]: f for f in info["files"]}; todo = [by[n] for n in names]; total = sum(f["size"] for f in todo)
        for f in todo:
            if ".." in Path(f["name"]).parts or f["name"].startswith("/"): raise HubError("unsafe_path", f"refusing path {f['name']!r}")
        have = sum((self._part(repo, f["name"]).stat().st_size if self._part(repo, f["name"]).exists() else 0) for f in todo)
        free = (hw.disk_free_mb if hw else HW.detect(disk_path=str(self.dir)).disk_free_mb) * 1048576
        if free and total - have + DISK_MARGIN_MB * 1048576 > free: raise HubError("disk_full", f"need {(total - have) // 1048576} MiB + {DISK_MARGIN_MB} MiB margin, {free // 1048576} MiB free")
        with self._lock: self._seq += 1; jid = f"dl{self._seq}"
        job = {"id": jid, "repo": repo, "variant": variant, "state": "queued", "total": total, "done": 0, "files": [f["name"] for f in todo], "error": None, "started": time.time(), "cancel": threading.Event(), "bps": 0.0}
        self.jobs[jid] = job; t = threading.Thread(target=self._run, args=(job, info, todo), daemon=True, name=jid); job["thread"] = t; t.start(); return jid
    def job(self, jid):
        j = self.jobs[jid]; return {k: v for k, v in j.items() if k not in ("cancel", "thread")}
    def cancel(self, jid): self.jobs[jid]["cancel"].set()
    def wait(self, jid, timeout=None):
        self.jobs[jid]["thread"].join(timeout); return self.job(jid)

    def _part(self, repo, name): return self.dir / repo / (name + ".part")
    def _final(self, repo, name): return self.dir / repo / name

    def _run(self, job, info, todo):
        job["state"] = "running"; repo = job["repo"]; got = []
        try:
            base = 0
            for f in todo:
                if job["cancel"].is_set(): job["state"] = "cancelled"; return
                path = self._fetch(job, repo, info["rev"], f, base)
                if path is None or job["cancel"].is_set(): job["state"] = "cancelled"; return
                got.append({"path": str(path.relative_to(self.root)), "size": f["size"], "sha256": f["sha256"], "kind": f["kind"], "name": f["name"], "verified": "sha256" if f["sha256"] else "size"}); base += f["size"]
            if job["cancel"].is_set(): job["state"] = "cancelled"; return
            first = next(f for f in todo if f["kind"] == "weights"); m = self._load()
            m["models"][f"{repo}:{job['variant']}"] = {"repo": repo, "rev": info["rev"], "variant": job["variant"], "license": info["license"], "format": first["format"], "quant": first["quant"], "files": got, "installed_at": time.time(), "vision": any(g["kind"] == "mmproj" for g in got)}
            self._save(m); job["state"] = "done"
        except HubError as e: job["state"] = "gated" if e.code == "gated" else "failed"; job["error"] = f"{e.code}: {e}"
        except Exception as e: job["state"] = "failed"; job["error"] = f"{type(e).__name__}: {e}"

    def _fetch(self, job, repo, rev, f, base):
        final, part = self._final(repo, f["name"]), self._part(repo, f["name"]); part.parent.mkdir(parents=True, exist_ok=True); size = f["size"]
        if final.exists() and final.stat().st_size == size and self._sha(final, f) is True: job["done"] = base + size; return final
        url = f"{self.hf}/{urllib.parse.quote(repo, safe='/')}/resolve/{urllib.parse.quote(rev, safe='')}/{urllib.parse.quote(f['name'])}"
        for attempt in range(2):
            have = part.stat().st_size if part.exists() else 0
            if have > size: part.unlink(); have = 0
            if have < size:
                hdr = self._hdr(url, {"Range": f"bytes={have}-"} if have else {})
                try: r = self.opener(url, hdr, self.timeout)
                except urllib.error.HTTPError as e:
                    if e.code in (401, 403): raise HubError("gated", f"{f['name']}: HTTP {e.code} (token/license required)")
                    if e.code == 416: have = size; r = None
                    else: raise HubError("http", f"{f['name']}: HTTP {e.code}")
                if r is not None:
                    with r:
                        if have and getattr(r, "status", getattr(r, "code", 200)) != 206: have = 0          # server ignored Range: restart this file
                        t0 = time.time(); n0 = have
                        with open(part, "ab" if have else "wb") as o:
                            while True:
                                if job["cancel"].is_set(): return None
                                b = r.read(1 << 20)
                                if not b: break
                                o.write(b); have += len(b); job["done"] = base + have; job["bps"] = (have - n0) / max(1e-6, time.time() - t0)
            if part.stat().st_size != size:
                if attempt == 0 and part.stat().st_size < size: continue                 # truncated stream: one resume attempt
                raise HubError("size_mismatch", f"{f['name']}: got {part.stat().st_size} bytes, expected {size}")
            job["state"] = "verifying"; ok = self._sha(part, f)
            if ok is False: part.unlink(); raise HubError("checksum", f"{f['name']}: SHA-256 mismatch (partial discarded)")
            os.replace(part, final); job["state"] = "running"; job["done"] = base + size; return final
        raise HubError("incomplete", f"{f['name']}: download did not complete")

    @staticmethod
    def _sha(path, f):
        if not f.get("sha256"): return None
        h = hashlib.sha256()
        with open(path, "rb") as i:
            for b in iter(lambda: i.read(1 << 22), b""): h.update(b)
        return h.hexdigest() == f["sha256"]
