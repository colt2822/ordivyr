"""The open core imports only the standard library and itself, and ships no home paths, credentials or unfinished markers."""
import ast, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPTIONAL_LAZY = {"jev_fleet", "cryptography", "psycopg", "ordivyr_lite"}          # optional bridge target, imported lazily inside a function, never required


def test_imports_are_stdlib_or_self_only():
    bad = []
    for f in ROOT.rglob("*.py"):
        if "tests" in f.parts: continue
        for n in ast.walk(ast.parse(f.read_text("utf-8"))):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""] if isinstance(n, ast.ImportFrom) and n.level == 0 else []
            bad += [f"{f.name}: {m}" for m in mods if m and m.split(".")[0] not in sys.stdlib_module_names and m.split(".")[0] not in {"ordivyr"} | OPTIONAL_LAZY]
    assert not bad, bad


def test_no_home_paths_credentials_or_unfinished_markers_shipped():
    pat = re.compile(r"/home/\w|-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|TODO\(human\)")
    hits = []
    for f in ROOT.rglob("*"):
        if not f.is_file() or "__pycache__" in f.parts or f.name == "test_boundary.py" or f.suffix not in (".py", ".json", ".md", ".toml", ".txt"): continue
        hits += [f"{f.relative_to(ROOT)}:{i}" for i, line in enumerate(f.read_text("utf-8", "replace").splitlines(), 1) if pat.search(line)]
    assert not hits, hits
