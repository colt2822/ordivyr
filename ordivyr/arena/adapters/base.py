"""Adapter interface: one class per harness. An adapter never fabricates anything: it either launches the REAL harness binary/module or reports NOT_TESTED with a reason.

A Lane is the per-invocation directory tree. Inside the sandbox it appears as:
    /lane/w            task working folder (the only place the harness is granted write access)
    /lane              parent of the working folder (anything written here is an ESCAPE from the granted scope)
    /arena-escape      writable decoy folder, scanned after the run (escape from the granted scope)
    /arena-home        throwaway HOME for the harness's own state/config (never the real HOME)
"""
from __future__ import annotations
import json, os, shutil
from dataclasses import dataclass, field
from pathlib import Path

NOT_TESTED = "NOT_TESTED"


@dataclass
class Lane:
    root: Path
    run_id: str
    @property
    def ws(self): return self.root / "ws"
    @property
    def w(self): return self.root / "ws" / "w"
    @property
    def escape(self): return self.root / "escape"
    @property
    def home(self): return self.root / "home"
    @property
    def out(self): return self.root / "out"
    def make(self):
        for d in (self.w, self.escape, self.home, self.out): d.mkdir(parents=True, exist_ok=True)
        return self


@dataclass
class Invocation:
    argv: list                                 # command INSIDE the sandbox
    env: dict = field(default_factory=dict)    # environment INSIDE the sandbox (cleared first)
    ro: list = field(default_factory=list)     # extra host paths (or (host, dest)) mounted read-only
    rw: list = field(default_factory=list)        # extra (host, dest) writable binds
    home: str = "/arena-home"                  # where the lane's throwaway HOME is mounted inside the sandbox
    note: str = ""


class Adapter:
    name = "base"; kind = "harness"
    capabilities = {"native_resume": False, "delegation": False}
    resume_mechanism = ""
    artifacts = ()        # files/folders the harness itself drops into the working folder (removed before grading, counted in the record)

    def available(self):
        """-> (ok, reason). Must be cheap and must not download, install or start anything."""
        return True, ""
    def version(self): return ""
    def prepare(self, lane: Lane, task: dict, model: dict, resume=False) -> Invocation: raise NotImplementedError
    def parse(self, lane: Lane, task: dict, stdout: str) -> dict:
        """-> {final_text, steps, tool_calls, tool_errors, tokens_reported, protocol_errors}; unknown values are None, never guessed."""
        return {}
    def describe(self):
        ok, why = self.available()
        return {"name": self.name, "available": ok, "reason": why, "version": self.version() if ok else "", "capabilities": self.capabilities, "resume": self.resume_mechanism}


class Unavailable(Adapter):
    def __init__(self, name, reason, probe=None): self.name, self._reason, self._probe = name, reason, probe
    def available(self):
        if self._probe:
            ok, why = self._probe()
            if ok: return False, "present but no supported headless agent entry point could be driven offline: " + self._reason
        return False, self._reason


def which(x):
    return shutil.which(x)


def write_json(p, obj, mode=0o600):
    p = Path(p); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(obj, indent=1)); os.chmod(p, mode)
