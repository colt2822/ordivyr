"""Scoped agent memory.

Policy (the agent's EFFECTIVE memory config, so department policy is already applied):
  read  : only namespaces in memory.shared (+ the agent's own private namespace), only when mode is read|readwrite
  write : same namespaces, only when mode == readwrite   -> a PROVISIONAL note is stored when work is DONE
Backends share one tiny interface: recall(agent, namespace, query) -> str ; remember(agent, namespace, title, text, evidence) -> dict|None.
NullMemory (default, nothing is stored), MockMemory (SIMULATED, for tests) and SqliteMemory (local, persistent, stdlib only).
Proprietary or remote backends plug in through the same interface (see ordivyr.plugins, kind "memory").
"""
from __future__ import annotations
import re, sqlite3, threading, time
from pathlib import Path

RESERVED_PREFIX = "cr-priv-"          # private namespaces are derived server-side from (board, agent); never user-selectable


def private_ns(board_id, agent_id):
    return (RESERVED_PREFIX + re.sub(r"[^a-z0-9._-]+", "-", f"{board_id}-{agent_id}".lower()))[:60]


def scopes(eff, board_id=None):
    """Read/write namespace sets derived ONLY from the backend-stored config plus the agent's own identity.
    Shared names starting with the reserved private prefix are dropped (an agent cannot be pointed at someone else's private memory).
    Private memory (memory.private, default on) is the agent's own namespace, readable in read/readwrite and writable in readwrite."""
    mem = (eff or {}).get("memory") or {}; mode = mem.get("mode", "read")
    ns = [n for n in (mem.get("shared") or []) if isinstance(n, str) and n and not n.startswith(RESERVED_PREFIX)]
    own = [private_ns(board_id, eff["id"])] if board_id and mem.get("private", True) and (eff or {}).get("id") and mode != "none" else []
    return {"read": (ns + own) if mode in ("read", "readwrite") else [], "write": (ns + own) if mode == "readwrite" else [], "private": own}


class NullMemory:
    name = "none"; simulated = False
    def recall(self, agent, namespace, query): return ""
    def remember(self, agent, namespace, title, text, evidence=None): return None


class MockMemory:
    name = "mock"; simulated = True
    def __init__(self, notes=None): self.notes = dict(notes or {}); self.calls = []; self.written = []
    def recall(self, agent, namespace, query):
        self.calls.append(("recall", agent, namespace)); return self.notes.get(namespace, "")
    def remember(self, agent, namespace, title, text, evidence=None):
        self.written.append((agent, namespace, title, text)); return {"trust": "provisional"}


class SqliteMemory:
    """Local persistent memory. Recall ranks a namespace's notes by keyword overlap with the query, newest first on ties."""
    name = "sqlite"; simulated = False
    def __init__(self, path):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True); self._lock = threading.Lock()
        with self._c() as c:
            c.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, ns TEXT NOT NULL, agent TEXT, title TEXT, body TEXT, trust TEXT, ts REAL)")
            c.execute("CREATE INDEX IF NOT EXISTS notes_ns ON notes(ns)")
    def _c(self):
        c = sqlite3.connect(str(self.path), timeout=10); c.row_factory = sqlite3.Row
        return c
    def remember(self, agent, namespace, title, text, evidence=None):
        with self._lock, self._c() as c:
            c.execute("INSERT INTO notes(ns,agent,title,body,trust,ts) VALUES(?,?,?,?,?,?)", (namespace, str(agent)[:80], str(title)[:120], str(text)[:1500], "provisional", time.time()))
        return {"trust": "provisional"}
    def recall(self, agent, namespace, query):
        words = {w for w in re.findall(r"[a-z0-9]{3,}", (query or "").lower())}
        with self._c() as c:
            rows = c.execute("SELECT title, body, ts FROM notes WHERE ns=? ORDER BY ts DESC LIMIT 200", (namespace,)).fetchall()
        def score(r): return len(words & set(re.findall(r"[a-z0-9]{3,}", (r["title"] + " " + r["body"]).lower())))
        ranked = sorted(rows, key=lambda r: (-score(r), -r["ts"]))[:5]
        if words: ranked = [r for r in ranked if score(r) > 0]
        return "\n".join(f"- {r['title']}: {r['body']}" for r in ranked)


def context_for(brain, eff, agent_name, query, board_id=None):
    """Prompt block for the agent's readable namespaces ('' when none are permitted or the backend has nothing)."""
    out = []
    for ns in scopes(eff, board_id)["read"]:
        pack = brain.recall(agent_name, ns, query)
        if pack: out.append(f"{'PRIVATE' if ns.startswith(RESERVED_PREFIX) else 'SHARED'} MEMORY [{ns}]{' (simulated)' if brain.simulated else ''}:\n{pack[:1800]}")
    return "\n\n".join(out)
