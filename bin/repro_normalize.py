#!/usr/bin/env python3
"""Normalize a built sdist for reproducibility, then verify.

python -m build regenerates egg-info/PKG-INFO on every invocation, so those
tar members carry fresh mtimes and the gzip container gets a fresh timestamp.
Fix: rewrite every tar member's mtime to SOURCE_DATE_EPOCH (default: newest
commit), zero the uid/gid/uname/gname, and re-gzip with `gzip -n` semantics.

Usage: repro_normalize.py <dist-dir> [sdist.tar.gz ...]
Exit 0 if all sdists normalized; run it twice and hash-compare to verify.
"""
import gzip, io, os, subprocess, sys, tarfile
from pathlib import Path


def source_date_epoch(repo: Path) -> int:
    v = os.environ.get("SOURCE_DATE_EPOCH")
    if v: return int(v)
    out = subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=repo, capture_output=True, text=True)
    return int(out.stdout.strip() or 0)


def normalize(p: Path, epoch: int) -> None:
    raw = gzip.decompress(p.read_bytes())
    src = tarfile.open(fileobj=io.BytesIO(raw))
    buf = io.BytesIO()
    dst = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
    for m in src.getmembers():
        m.mtime, m.uid, m.gid, m.uname, m.gname = epoch, 0, 0, "root", "root"
        m.mode = 0o644 if m.isfile() else 0o755
        dst.addfile(m, src.extractfile(m) if m.isfile() else None)
    dst.close()
    # gzip with mtime=0 and no original name (equivalent to gzip -n)
    tmp = p.with_suffix(".tar.gz.norm")
    with open(tmp, "wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0) as gz:
            gz.write(buf.getvalue())
    tmp.replace(p)


def main() -> int:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    repo = Path.cwd()
    epoch = source_date_epoch(repo)
    sdists = [Path(a) for a in sys.argv[2:]] or sorted(dist.glob("*.tar.gz"))
    for s in sdists:
        normalize(s, epoch)
        print(f"normalized {s} (mtime={epoch})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
