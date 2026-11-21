"""Adapters for competitor harnesses. They launch the REAL installed binaries - no simulation. Parity rules applied to every harness:
  * same model server, same weights, same sampling server flags, same task prompt, same working folder, same wall-clock limit;
  * file tools only (read/write/edit): shell, web, browser, messaging, sub-agent and scheduling tools are NOT enabled;
  * NO bypass flags (`--yolo`, auto-approve, sandbox-disable); approvals stay at the harness default;
  * a throwaway HOME / state dir per run: the user's real ~/.hermes, ~/.openclaw and ORDIVYR state are never mounted.
Differences that cannot be removed (system prompts, tool schemas, tool names, resume mechanics) are recorded in docs/arena/METHODOLOGY.md."""
from __future__ import annotations
import json, os, subprocess
from pathlib import Path
from .. import suite
from .base import Adapter, Invocation, Unavailable, which, write_json

HOME = Path.home()


class HermesAdapter(Adapter):
    name = "hermes"
    capabilities = {"native_resume": True, "delegation": False}
    resume_mechanism = "`hermes chat -c <session-name> --create-if-missing` re-opens the named session and re-sends the task (transcript is kept in the data root)"
    BIN = HOME / ".hermes/hermes-agent/.hermes/bin/hermes"
    PREP_HOME = str(HOME / "ordivyr-arena-20261103/ws/hermes-smoke/home"); PREP_PATH = PREP_HOME + "/.hermes"   # absolute path the template runtime was prepared at (venv paths are baked in): per-run copies are mounted back at this path
    TEMPLATE = HOME / "ordivyr-arena-20261103/hermes-template/.hermes"      # prepared once (first-start dependency preparation); mounted as a read-only overlay base

    def available(self):
        if not self.BIN.exists(): return False, "hermes binary not found"
        if not self.TEMPLATE.exists(): return False, f"prepared isolated Hermes data root missing at {self.TEMPLATE}"
        return True, ""
    def version(self):
        try: return subprocess.run([str(self.BIN), "--version"], capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"}).stdout.strip().splitlines()[0]
        except Exception: return "unknown"

    def prepare(self, lane, task, model, resume=False):
        (lane.home / "prompt.txt").write_text(suite.full_prompt(task)); dst = lane.home / ".hermes"
        if not dst.exists():                                            # fresh per-run data root cloned from the prepared template (offline); a resume keeps the one the killed run left behind
            import shutil
            dst.mkdir()
            for e in self.TEMPLATE.iterdir():
                if e.name in ("installs", "cache"): subprocess.run(["cp", "-al", str(e), str(dst / e.name)], check=True)     # big, read-mostly: hard-linked
                elif e.is_dir(): shutil.copytree(e, dst / e.name, symlinks=True)
                else: shutil.copy2(e, dst / e.name)
        argv = [str(self.BIN), "chat", "--safe-mode", "--provider", "custom", "--base-url", model["base"], "--api-key", model["key"], "-m", model["name"], "-t", "file",
                "--max-turns", str(task["limits"]["max_steps"]), "--in", "/lane/w", "--query-file", self.PREP_HOME + "/prompt.txt", "-Q", "--format", "stream-json", "-c", f"arena-{lane.run_id}", "--create-if-missing"]
        return Invocation(argv=argv, env={"HOME": self.PREP_HOME, "HERMES_HOME": self.PREP_PATH, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                          ro=[str(HOME / ".hermes/hermes-agent"), str(HOME / ".hermes/tools")], home=self.PREP_HOME)

    def parse(self, lane, task, stdout):
        out = {"final_text": None, "steps": 0, "tool_calls": 0, "tool_errors": 0, "tokens_reported": None, "protocol_errors": 0}; texts = []
        for line in stdout.splitlines():
            try: e = json.loads(line)
            except ValueError: continue
            t = e.get("type")
            if t == "tool_use": out["tool_calls"] += 1
            elif t == "tool_result":
                o = str(e.get("output", ""))
                if '"error"' in o[:200].lower() or o.lower().startswith("error"): out["tool_errors"] += 1
            elif t == "text": texts.append(e.get("text", ""))
            elif t == "result":
                tk = e.get("tokens") or {}; out["tokens_reported"] = tk.get("total"); out["final_text"] = (e.get("text") or "")[:300]; out["exit_code"] = e.get("exit_code")
        out["steps"] = out["tool_calls"]; return out


class OpenClawAdapter(Adapter):
    name = "openclaw"
    capabilities = {"native_resume": True, "delegation": False}
    resume_mechanism = "`openclaw agent --local --session-id <id>` re-opens the persisted session transcript in the state dir"
    artifacts = ("AGENTS.md", "BOOTSTRAP.md", "HEARTBEAT.md", "IDENTITY.md", "SOUL.md", "TOOLS.md", "USER.md", "openclaw-workspace-state.json", ".git", ".openclaw")
    BIN = HOME / ".npm-global/lib/node_modules/openclaw/openclaw.mjs"

    @staticmethod
    def _node():
        """The real node binary (the `node` on PATH is a proto shim that needs the real HOME, which the sandbox never mounts)."""
        c = sorted((HOME / ".proto/tools/node").glob("*/bin/node"))
        return str(c[-1]) if c else (which("node") or "/usr/bin/node")

    def available(self):
        if not self.BIN.exists(): return False, "openclaw not installed"
        if not Path(self._node()).exists(): return False, "node not found"
        return True, ""
    def version(self):
        try: return subprocess.run([self._node(), str(self.BIN), "--version"], capture_output=True, text=True, timeout=60).stdout.strip().splitlines()[0]
        except Exception: return "unknown"

    def prepare(self, lane, task, model, resume=False):
        (lane.home / "prompt.txt").write_text(suite.full_prompt(task)); (lane.home / "state").mkdir(exist_ok=True)
        cfg = {"models": {"providers": {"arena": {"baseUrl": model["base"], "apiKey": model["key"], "api": "openai-completions",
               "models": [{"id": model["name"], "name": "arena", "reasoning": False, "input": ["text"], "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0}, "contextWindow": model["ctx"], "maxTokens": 4096}]}}},
               "agents": {"defaults": {"model": {"primary": f"arena/{model['name']}"}, "workspace": "/lane/w"}}, "tools": {"allow": ["read", "write", "edit"]}}
        write_json(lane.home / "openclaw.json", cfg)
        node = self._node(); nodedir = str(Path(node).parent)
        argv = [node, str(self.BIN), "agent", "--local", "--agent", "main", "--message-file", "/arena-home/prompt.txt", "--json", "--timeout", str(task["limits"]["timeout_s"]), "--session-id", f"arena-{lane.run_id}"]
        return Invocation(argv=argv, env={"HOME": "/arena-home", "OPENCLAW_STATE_DIR": "/arena-home/state", "OPENCLAW_CONFIG_PATH": "/arena-home/openclaw.json", "PATH": f"{nodedir}:/usr/bin:/bin", "LANG": "C.UTF-8"},
                          ro=[str(HOME / ".npm-global/lib/node_modules/openclaw"), nodedir])

    def parse(self, lane, task, stdout):
        out = {"final_text": None, "steps": 0, "tool_calls": 0, "tool_errors": 0, "tokens_reported": None, "protocol_errors": 0}
        try:
            j = json.loads(stdout[stdout.index("{"):]); am = (j.get("meta") or {}).get("agentMeta") or {}; u = am.get("usage") or {}
            out["tokens_reported"] = u.get("total"); out["final_text"] = " | ".join(p.get("text", "") for p in j.get("payloads", []))[:300]; out["exit_code"] = 0
            sf = am.get("sessionFile")
            if sf:
                p = Path(str(sf).replace("/arena-home", str(lane.home)))
                if p.exists():
                    for line in p.read_text().splitlines():
                        try: e = json.loads(line)
                        except ValueError: continue
                        m = e.get("message") or {}
                        if m.get("role") == "assistant":
                            out["tool_calls"] += sum(1 for c in (m.get("content") or []) if isinstance(c, dict) and c.get("type") in ("toolCall", "tool_use"))
                        if m.get("role") in ("toolResult", "tool") and m.get("isError"): out["tool_errors"] += 1
        except (ValueError, KeyError): out["protocol_errors"] += 1
        out["steps"] = out["tool_calls"]; return out


def _deepseek_probe():
    return (HOME / "deepseek-harness/apps/cli/lib/bin.js").exists(), ""


def external():
    return [
        Unavailable("deepseek-harness", "no headless agent entry point can be driven offline: the checkout's CLI (`dsh`) is a profile launcher whose agent profile needs the published Python SDK (`pip install deepseek-harness-sdk`, a download) and an unbuilt TypeScript runtime (apps/cli/lib/bin.js missing); installing/building it is outside this milestone's no-download rule", _deepseek_probe),
        Unavailable("openhands", "not installed (no `openhands` command or package on this machine); installing it requires downloads that this milestone does not authorise"),
        Unavailable("opencode", "not installed (no `opencode` command on this machine); installing it requires downloads that this milestone does not authorise"),
    ]
