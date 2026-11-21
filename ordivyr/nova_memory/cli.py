"""ordivyr nova DB ACTION ... : inspect and manage NOVA Memory from the shell (local file, no network)."""
import argparse, json, sys
from .store import NovaMemory, Principal, KINDS


def main(argv):
    p = argparse.ArgumentParser(prog="ordivyr nova"); p.add_argument("db"); p.add_argument("action", choices=["add", "search", "pack", "get", "verify", "reject", "correct", "delete", "export", "import", "stats", "purge", "enroll-verifier", "revoke-verifier", "backup", "restore", "audit", "reseal", "compact"])
    p.add_argument("text", nargs="?", default=""); p.add_argument("--tenant", default="local"); p.add_argument("--project", default="default"); p.add_argument("--agent", default="cli")
    p.add_argument("--ns", default="shared"); p.add_argument("--kind", default="semantic", choices=KINDS); p.add_argument("--title"); p.add_argument("--source", default="cli"); p.add_argument("--id")
    p.add_argument("--validator"); p.add_argument("--ref"); p.add_argument("--reason", default="cli"); p.add_argument("--budget", type=int, default=400); p.add_argument("--mode", default="hybrid", choices=["hybrid", "lexical", "semantic"])
    p.add_argument("--credential-file"); p.add_argument("--password-file"); p.add_argument("--strict", action="store_true"); p.add_argument("--version"); p.add_argument("--ttl", type=float); p.add_argument("--file")
    a = p.parse_args(argv); m = NovaMemory(a.db, strict=a.strict)
    rd = lambda f: open(f).read().strip() if f else None
    pr = Principal.make(a.tenant, a.project, a.agent, read=[a.ns], write=[a.ns], can_verify=a.action in ("verify", "reject"))
    out = lambda o: print(json.dumps(o, indent=1, default=str)) if not isinstance(o, str) else print(o)
    try:
        if a.action == "add": out({"id": m.add(pr, a.ns, a.kind, a.title or a.text[:60], a.text, a.source, version=a.version, ttl_s=a.ttl)})
        elif a.action == "search": out(m.search(pr, a.text, mode=a.mode, version=a.version))
        elif a.action == "pack": out(m.pack(pr, a.text, a.budget, mode=a.mode, version=a.version))
        elif a.action == "get": out(m.get(pr, a.id))
        elif a.action == "verify": m.verify(pr, a.id, {"passed": True, "validator": a.validator, "ref": a.ref}, credential=rd(a.credential_file)); out({"verified": a.id})
        elif a.action == "enroll-verifier":
            sec = m.enroll_verifier(a.id or a.agent)
            if a.file: fd = __import__("os").open(a.file, __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_EXCL, 0o600); open(fd, "w").write(sec); out({"enrolled": a.id or a.agent, "secret_file": a.file})
            else: out({"enrolled": a.id or a.agent, "secret": sec, "note": "shown once; only a scrypt hash is stored"})
        elif a.action == "revoke-verifier": out({"revoked": m.revoke_verifier(a.id or a.agent)})
        elif a.action == "backup": out(m.backup(a.file, rd(a.password_file)))
        elif a.action == "restore": out(m.restore(a.file, rd(a.password_file)))
        elif a.action == "audit": bad = m.audit(); out({"tampered_verified_memories": bad}); return 3 if bad else 0
        elif a.action == "reseal": out({"resealed": m.reseal()})
        elif a.action == "compact": m.compact(); out({"compacted": True})
        elif a.action == "reject": m.reject(pr, a.id, a.reason); out({"rejected": a.id})
        elif a.action == "correct": out({"id": m.correct(pr, a.id, a.text, a.reason)})
        elif a.action == "delete": out({"deleted": m.delete(pr, a.id, a.reason)})
        elif a.action == "export": out(m.export(pr, a.ns))
        elif a.action == "import": out({"imported": m.import_jsonl(pr, open(a.file).read())})
        elif a.action == "stats": out(m.stats(pr))
        elif a.action == "purge": out({"purged": m.purge_expired()})
    except (PermissionError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    return 0
