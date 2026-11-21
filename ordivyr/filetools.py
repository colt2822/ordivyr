"""File tools for the agent loop: paginated line-numbered read, surgical exact-match edit, bounded repository search, head+tail output retention with task-local spill.

Every function takes the ToolBox (for its confined `_path`, `root` and spill dir) and raises ToolError-compatible `ValueError`s that the box turns into `ERROR: ...` results.
Nothing here follows symlinks out of the working folder and nothing writes without the box's write grant (checked by the caller)."""
from __future__ import annotations
import difflib, os, re, tempfile, time
from pathlib import Path

READ_DEFAULT_LINES = 400
READ_MAX_LINES = 2000
READ_MAX_CHARS = 30_000          # per call; a longer window is cut at a line boundary and says where to continue
READ_MAX_FILE = 8_000_000        # a bigger file is searched, not read whole
LINE_CAP = 2000                  # one absurdly long line (minified bundle) is cut and flagged
SEARCH_SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".next", "target", ".idea", ".gradle", ".ordivyr-spill"}
SEARCH_MAX_FILE = 1_000_000
GREP_MAX_MATCHES = 100
GREP_LINE_CAP = 240
FIND_MAX = 300
SEARCH_SECONDS = 10


class FileToolError(ValueError): pass


def _text(p: Path):
    """-> (text, newline) with newlines UNtranslated; refuses binary and oversized files."""
    if p.stat().st_size > READ_MAX_FILE: raise FileToolError(f"file is {p.stat().st_size} bytes; too large to read whole - use grep to find the part you need")
    b = p.read_bytes()
    if b"\0" in b[:8192]: raise FileToolError("binary file")
    t = b.decode("utf-8", "replace")
    return t, ("\r\n" if t.count("\r\n") * 2 > t.count("\n") else "\n")      # CRLF when most newlines are CRLF


def resolve(box, rel):
    """read-side path: a workspace file, or `spill:N` (a saved long tool output of THIS box)."""
    rel = str(rel or "")
    if rel.startswith("spill:"):
        name = rel[6:]
        if not name.isdigit(): raise FileToolError("bad spill reference")
        p = box.spill_dir() / name
        if not p.is_file(): raise FileToolError("no such spill")
        return p
    p = box._path(rel)
    if not p.is_file(): raise FileToolError("not a file")
    return p


def read_file(box, args):
    p = resolve(box, args.get("path")); t, _ = _text(p)
    lines = t.split("\n")
    if lines and lines[-1] == "": lines.pop()
    total = len(lines)
    try: off = max(1, int(args.get("offset") or 1)); lim = int(args.get("limit") or READ_DEFAULT_LINES)
    except (TypeError, ValueError): raise FileToolError("offset and limit must be integers")
    lim = max(1, min(lim, READ_MAX_LINES))
    if total == 0: return "(empty file)"
    if off > total: raise FileToolError(f"offset {off} is past the end ({total} lines)")
    out, used, end = [], 0, off - 1
    for i in range(off - 1, min(total, off - 1 + lim)):
        ln = lines[i].rstrip("\r"); cut = len(ln) > LINE_CAP
        row = f"{i + 1:>6}\t{ln[:LINE_CAP]}" + (f" [line cut at {LINE_CAP} of {len(ln)} chars]" if cut else "")
        if used + len(row) > READ_MAX_CHARS and out: break
        out.append(row); used += len(row) + 1; end = i + 1
    body = "\n".join(out)
    if end < total: body += f"\n[showing lines {off}-{end} of {total}; call read_file again with offset={end + 1} to continue]"
    elif off > 1: body += f"\n[end of file: lines {off}-{end} of {total}]"
    return body


def _norm_lines(s, mode):
    return [(ln.rstrip() if mode == "rstrip" else ln.strip()) for ln in s.split("\n")]


def _indent(s): return s[:len(s) - len(s.lstrip())]


def _tolerant(text_lines, old, new):
    """Whitespace-tolerant match, accepted ONLY when it is unique. -> (start_line, n_lines, new_text) or None."""
    ol = old.split("\n")
    for mode in ("rstrip", "strip"):
        want = _norm_lines(old, mode); hay = _norm_lines("\n".join(text_lines), mode); hits = [i for i in range(0, len(hay) - len(want) + 1) if hay[i:i + len(want)] == want]
        if len(hits) == 1:
            i = hits[0]; fi, oi = _indent(text_lines[i]), _indent(ol[0])
            nl = new.split("\n")
            if mode == "strip" and fi != oi: nl = [(fi + ln[len(oi):]) if ln.startswith(oi) else ln for ln in nl]
            return i, len(want), "\n".join(nl)
        if len(hits) > 1: return None
    return None


def _hint(text, old):
    first = next((ln.strip() for ln in old.split("\n") if ln.strip()), "")
    if not first: return ""
    lines = text.split("\n"); cands = difflib.get_close_matches(first, [ln.strip() for ln in lines], n=1, cutoff=0.6)
    if not cands: return ""
    i = next(k for k, ln in enumerate(lines) if ln.strip() == cands[0])
    return f" Closest line is {i + 1}: {lines[i].strip()[:120]!r}. Re-read that region with read_file and copy the text exactly."


def edit_file(box, args):
    path = args.get("path"); old = args.get("old_string"); new = args.get("new_string"); every = bool(args.get("replace_all"))
    if not isinstance(old, str) or not isinstance(new, str): raise FileToolError("old_string and new_string must be strings")
    if old == "": raise FileToolError("old_string is empty; use write_file to create a file")
    if old == new: raise FileToolError("old_string and new_string are identical; nothing to change")
    p = box._path(path)
    if not p.is_file(): raise FileToolError("not a file")
    if ".git" in p.relative_to(box.root).parts: raise FileToolError("not allowed")
    t, nl = _text(p); crlf = nl == "\r\n"
    if crlf: old, new = old.replace("\r\n", "\n").replace("\n", "\r\n"), new.replace("\r\n", "\n").replace("\n", "\r\n")
    n = t.count(old)
    if n == 1 or (n > 1 and every):
        pos = t.find(old); line = t.count("\n", 0, pos) + 1; res = t.replace(old, new) if every else t[:pos] + new + t[pos + len(old):]; how = f"{n} exact match(es)"
    elif n > 1:
        ls = [t.count("\n", 0, m.start()) + 1 for m in re.finditer(re.escape(old), t)][:8]
        raise FileToolError(f"old_string matches {n} places (lines {', '.join(map(str, ls))}); add surrounding lines to make it unique, or set replace_all=true to change every one")
    else:
        flat = t.replace("\r\n", "\n") if crlf else t; tl = flat.split("\n"); hit = _tolerant(tl, old.replace("\r\n", "\n"), new.replace("\r\n", "\n"))
        if hit is None: raise FileToolError("old_string was not found (and no unambiguous whitespace-insensitive match exists)." + _hint(flat, old.replace("\r\n", "\n")))
        i, k, repl = hit; tl[i:i + k] = repl.split("\n"); res = "\n".join(tl); line = i + 1; how = "whitespace-tolerant unique match"
        if crlf: res = res.replace("\n", "\r\n")
    if len(res) > 2_000_000: raise FileToolError("result too large")
    atomic_write(p, res)
    return f"edited {path} at line {line} ({how})"


def atomic_write(p: Path, text: str):
    """write beside the target then rename: a crash or a second writer never leaves a half-written file. Keeps the file mode; text is written untranslated."""
    mode = p.stat().st_mode & 0o7777 if p.exists() else 0o644
    fd, tmp = tempfile.mkstemp(prefix=".ordivyr-", dir=str(p.parent))
    try:
        with os.fdopen(fd, "wb") as f: f.write(text.encode("utf-8"))
        os.chmod(tmp, mode); os.replace(tmp, p)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def _walk(box, sub, deadline):
    root = box._path(sub or ".")
    if root.is_file(): yield root; return
    for dp, dns, fns in os.walk(root, followlinks=False):
        dns[:] = sorted(d for d in dns if d not in SEARCH_SKIP and not os.path.islink(os.path.join(dp, d)))
        for f in sorted(fns):
            fp = Path(dp) / f
            if fp.is_symlink(): continue
            yield fp
        if time.monotonic() > deadline: return


def grep(box, args):
    pat = args.get("pattern")
    if not isinstance(pat, str) or not pat: raise FileToolError("pattern is required")
    flags = re.I if args.get("ignore_case") else 0
    try: rx = re.compile(pat if args.get("regex") else re.escape(pat), flags)
    except re.error as e: raise FileToolError(f"bad regex: {e}")
    glob = args.get("glob"); deadline = time.monotonic() + SEARCH_SECONDS; hits = []; files = 0; more = False
    for fp in _walk(box, args.get("path"), deadline):
        if glob and not fp.match(glob): continue
        try:
            if fp.stat().st_size > SEARCH_MAX_FILE: continue
            b = fp.read_bytes()
        except OSError: continue
        if b"\0" in b[:4096]: continue
        files += 1; rel = fp.relative_to(box.root)
        for i, ln in enumerate(b.decode("utf-8", "replace").split("\n"), 1):
            if rx.search(ln):
                if len(hits) >= GREP_MAX_MATCHES: more = True; break
                hits.append(f"{rel}:{i}: {ln.strip()[:GREP_LINE_CAP]}")
        if more: break
    if not hits: return f"no matches ({files} files searched)"
    return "\n".join(hits) + (f"\n[stopped at {GREP_MAX_MATCHES} matches; narrow the pattern, path or glob]" if more else "")


def find_files(box, args):
    glob = args.get("glob") or "*"; deadline = time.monotonic() + SEARCH_SECONDS; out = []; more = False
    for fp in _walk(box, args.get("path"), deadline):
        rel = fp.relative_to(box.root)
        if fp.match(glob) or rel.match(glob):
            if len(out) >= FIND_MAX: more = True; break
            out.append(str(rel))
    return ("\n".join(out) if out else "no files matched") + (f"\n[stopped at {FIND_MAX} files; narrow the glob or path]" if more else "")


def retain(box, out, limit):
    """Keep the head AND the tail of a long result (errors and summaries live at the end), save the whole thing in a task-local spill the model can page through."""
    if not isinstance(out, str) or len(out) <= limit: return out
    n = box.spill(out); head = int(limit * 0.7); tail = limit - head
    return f"{out[:head]}\n[... {len(out) - limit} chars omitted from the middle; full output ({len(out)} chars) saved as spill:{n} - read it with read_file path=\"spill:{n}\" and offset/limit ...]\n{out[-tail:]}"
