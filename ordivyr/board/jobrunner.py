"""Runs INSIDE the sandbox: reads the job, runs the shared execution core, and talks to the trusted worker only through the broker socket. No network, no keys, no lease credentials."""
from __future__ import annotations
import json, os, socket, subprocess, sys, time


class Rpc:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX); self.s.connect(path); self.f = self.s.makefile("rwb")
    def call(self, **m):
        self.f.write(json.dumps(m).encode() + b"\n"); self.f.flush(); line = self.f.readline()
        if not line: raise SystemExit(3)                    # broker gone (cancelled / lease lost): stop at once
        return json.loads(line)


def main():
    from ..selfhost.gateway import Reply, GatewayError
    from . import runtime_adapter as RA
    job = json.load(open("/run/b/job.json")); rpc = Rpc(os.environ["BOARD_SOCK"])
    class GW:
        def chat(self, agent, endpoint, model, messages, tools=None, max_tokens=512, timeout=120, **kw):
            r = rpc.call(op="chat", args={"messages": messages, "tools": tools, "max_tokens": max_tokens, "timeout": timeout})
            if "gwerr" in r: g = r["gwerr"]; raise GatewayError(g["code"], g["msg"], g.get("endpoint"), g.get("retryable", False))
            if "err" in r: raise GatewayError("bad_request", r["err"].get("msg", "refused"), endpoint)
            o = r["ok"]; return Reply(o["text"], o["tool_calls"], o["usage"], o["cost_usd"], o["model"], o["endpoint"], o["latency_s"], o.get("finish", ""))
    class Tools(RA.BoardTools):
        def __init__(self): self.job = job
        def call(self, name, args):
            if not RA.C.tool_allowed(job, name): return "ERROR: tool_not_granted"
            r = rpc.call(op="board", name=name, args=args)
            return "ERROR: " + r["err"]["msg"] if "err" in r else json.dumps(r["ok"])[:8000]
    def on_step(name, args, out): rpc.call(op="step", name=name, args=args, out=str(out)[:2000])
    def validate(v):
        try: p = subprocess.run(v["cmd"] if isinstance(v["cmd"], list) else v["cmd"].split(), cwd="/work", capture_output=True, timeout=v.get("timeout", 60)); return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")[-4000:]
        except subprocess.TimeoutExpired: return 124, "validator timed out"
        except OSError as e: return 127, str(e)
    from pathlib import Path
    try: r, _ = RA.execute_job(job, Path("/work"), GW(), on_step, Tools(), validate)
    except GatewayError as e: rpc.call(op="gwfail", code=e.code, msg=str(e), retryable=e.retryable); return
    except Exception as e: rpc.call(op="fatal", msg=f"internal: {type(e).__name__}: {e}"[:600]); return
    rpc.call(op="done", result=r)


if __name__ == "__main__": main()
