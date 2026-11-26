"""Per-node isolated workspaces for parallel coding agents, with a pre-promotion conflict check.
open(src, name): a git worktree when src is a clean-enough git repo, else `cp -a --reflink=auto` (instant copy-on-write on btrfs/xfs, plain copy elsewhere).
Each workspace records the sha256 of every file at creation (the BASE). promote() copies back ONLY files this node changed, and refuses (nothing copied) if any of
them was also changed in the source since the base - so parallel nodes never silently overwrite one another."""
import hashlib, os, shutil, subprocess, tempfile
from pathlib import Path

SKIP = {".git", ".venv", "node_modules", "__pycache__"}


class Conflict(Exception):
    def __init__(self, files): super().__init__("conflicting changes in: " + ", ".join(files)); self.files = files


def snapshot(d):
    out = {}
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in SKIP]
        for f in files:
            p = Path(root) / f
            if f != ".git" and p.is_file() and not p.is_symlink(): out[str(p.relative_to(d))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


class Workspace:
    def __init__(self, src, dest, base, mode): self.src, self.dir, self.base, self.mode = Path(src), Path(dest), base, mode
    def changes(self):
        """-> (added, modified, deleted) relative paths, versus the base."""
        now = snapshot(self.dir); add = sorted(set(now) - set(self.base)); mod = sorted(k for k in now if k in self.base and now[k] != self.base[k]); dele = sorted(set(self.base) - set(now))
        return add, mod, dele
    def conflicts(self):
        cur = snapshot(self.src); add, mod, dele = self.changes(); bad = []
        for f in add: 
            if f in cur: bad.append(f)                                    # both created it
        for f in mod + dele:
            if cur.get(f) != self.base.get(f): bad.append(f)               # the source moved under us
        return sorted(bad)
    def promote(self):
        bad = self.conflicts()
        if bad: raise Conflict(bad)
        add, mod, dele = self.changes()
        for f in add + mod: (self.src / f).parent.mkdir(parents=True, exist_ok=True); shutil.copy2(self.dir / f, self.src / f)
        for f in dele: (self.src / f).unlink(missing_ok=True)
        return {"added": add, "modified": mod, "deleted": dele}
    def close(self):
        if self.mode == "worktree": subprocess.run(["git", "-C", str(self.src), "worktree", "remove", "--force", str(self.dir)], capture_output=True)
        shutil.rmtree(self.dir, ignore_errors=True)


def open_workspace(src, name="node", parent=None):
    src = Path(src).resolve(); dest = Path(tempfile.mkdtemp(prefix=f"ordivyr-ws-{name}-", dir=parent)); shutil.rmtree(dest)
    if (src / ".git").exists() and not subprocess.run(["git", "-C", str(src), "status", "--porcelain"], capture_output=True, text=True).stdout.strip():
        r = subprocess.run(["git", "-C", str(src), "worktree", "add", "--detach", str(dest)], capture_output=True)
        if r.returncode == 0: return Workspace(src, dest, snapshot(dest), "worktree")          # base = what the workspace really contains (ignored files are not checked out)
    r = subprocess.run(["cp", "-a", "--reflink=auto", str(src), str(dest)], capture_output=True)
    if r.returncode != 0: shutil.copytree(src, dest, symlinks=True)
    return Workspace(src, dest, snapshot(dest), "copy")
