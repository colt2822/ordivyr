"""P0.1 end-to-end recovery proof with REAL processes: supervisor, workers, model server, sink, and N1/N4 worker nodes over ssh tunnels.

  python -m ordivyr.tests.durable_e2e OUTDIR [--skip-nodes]

Every scenario injects a real fault (SIGKILL / SIGSTOP / severed ssh tunnel) and then checks the durable database + side-effect ledger. Verdicts -> OUTDIR/verdicts.json.
The model endpoint is a scripted OpenAI-compatible server (a process, not an LLM): recovery behaviour is what is under test, not model quality.
"""
import json, os, signal, subprocess, sys, time, traceback
from pathlib import Path
from ordivyr import durable as D

TAG = "ordp01"; MODEL_PORT, SINK_PORT, COORD_PORT = 18471, 18472, 18473; TTL = 4
class E:
    def __init__(self, out, nodes):
        self.out = Path(out); self.out.mkdir(parents=True, exist_ok=True); self.work = Path.home() / "ordivyr-p01-20261103" / time.strftime("run-%H%M%S"); self.work.mkdir(parents=True)
        self.nodes = nodes; self.sup = None; self.db = self.work / "q.db"; self.ledger = self.work / "ledger.jsonl"; self.store = D.Store(self.db); self.root = str(Path(__file__).resolve().parents[2])
    def cfg(self, workers=3, nodes=None, maxc=8):
        c = {"db": str(self.db), "ws": str(self.work / "ws"), "run": str(self.work / "sup"), "tag": TAG, "ttl": TTL, "workers": workers, "port": COORD_PORT, "max_concurrency": maxc,
             "services": [{"name": "model", "health": f"http://127.0.0.1:{MODEL_PORT}/health", "cmd": [sys.executable, "-m", "ordivyr.tests.durable_support", "model", str(MODEL_PORT), TAG]},
                          {"name": "sink", "health": f"http://127.0.0.1:{SINK_PORT}/health", "cmd": [sys.executable, "-m", "ordivyr.tests.durable_support", "sink", str(SINK_PORT), str(self.ledger), TAG]}],
             "nodes": nodes or []}
        p = self.work / f"{TAG}-cfg.json"; p.write_text(json.dumps(c)); return p
    def start(self, **kw):
        cfg = self.cfg(**kw); self.sup = subprocess.Popen([sys.executable, "-m", "ordivyr.durable_sup", str(cfg)], env=dict(os.environ, PYTHONPATH=self.root), start_new_session=True,
                                                         stdout=open(self.work / "sup.out", "a"), stderr=subprocess.STDOUT)
        self.wait(lambda: all(self.healthy(p) for p in (MODEL_PORT, SINK_PORT)), 30, "services up"); return self
    @staticmethod
    def healthy(port):
        import urllib.request
        try: return urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1).status == 200
        except Exception: return False
    def stop(self):
        if self.sup and self.sup.poll() is None:
            os.killpg(self.sup.pid, signal.SIGTERM)
            try: self.sup.wait(60)
            except subprocess.TimeoutExpired: os.killpg(self.sup.pid, 9)
        self.sup = None
    def hard_kill_everything(self):
        """Stand-in for a power cut: SIGKILL the supervisor, every worker and every service. No handlers run, no sockets are closed politely."""
        pids = [self.sup.pid] if self.sup else []
        for l in open(self.work / "sup" / "supervisor.jsonl"):
            j = json.loads(l)
            if j["kind"] in ("worker_start", "service_start", "tunnel_up"): pids.append(j["pid"])
        for p in set(pids):
            try: os.killpg(p, 9)
            except OSError: pass
        subprocess.run(["pkill", "-9", "-f", f"[{TAG[0]}]{TAG[1:]}-"]); self.sup = None; time.sleep(0.5)
    def wait(self, pred, t, what):
        end = time.time() + t
        while time.time() < end:
            v = pred()
            if v: return v
            time.sleep(0.2)
        raise AssertionError(f"timeout waiting for {what}")
    def sup_events(self, kind=None): return [j for j in (json.loads(l) for l in open(self.work / "sup" / "supervisor.jsonl")) if kind is None or j["kind"] == kind]
    def rows(self): return [json.loads(l) for l in open(self.ledger)] if self.ledger.exists() else []
    def done(self, ids, t=120): self.wait(lambda: all(self.store.get(i)["state"] in D.TERMINAL for i in ids), t, f"tasks {ids} terminal")
    def agent(self, key, n=3, delay=1.0, validators=None, sink=False, sinkopts=None, max_attempts=4):
        files = {"main.py": "print('ok')\n", **{f"f{i}.txt": f"data {i}\n" for i in range(n - 1)}}
        p = {"base": f"http://127.0.0.1:{MODEL_PORT}/v1", "model": "scripted-1", "prompt": json.dumps({"files": files, "delay": delay}), "request_timeout": 5,
             "validators": validators if validators is not None else [{"name": "runs", "cmd": ["python3", "main.py"]}]}
        if sink: p["sink"] = {"url": f"http://127.0.0.1:{SINK_PORT}", **(sinkopts or {})}
        return self.store.submit("agent", p, key, max_attempts)
    def holder(self, tid): g = self.store.get(tid); return g["lease_owner"]
    def worker_pid(self, name): return [j["pid"] for j in self.sup_events("worker_start") if j["name"] == name][-1]

def result(checks, evidence=None): return {"pass": all(checks.values()), "checks": checks, "evidence": evidence or {}}

def s_agent_kill(e):
    t = e.agent("s1-agent", n=4, delay=1.5); e.wait(lambda: (e.store.get(t)["checkpoint"] or {}).get("phase") == "generating" and (e.store.get(t)["checkpoint"] or {}).get("step", 0) >= 1, 60, "mid-generation")
    victim = e.holder(t); os.killpg(e.worker_pid(victim), 9); e.done([t]); g = e.store.get(t); h = [x["kind"] for x in e.store.history(t)]
    return result({"completed": g["state"] == "completed", "attempts>=2": g["attempt"] >= 2, "lease_expired_event": "lease_expired" in h, "worker_respawned": any(j["name"] == victim for j in e.sup_events("worker_died")),
                   "validated": all(v["ok"] for v in e.store.evidence(t)) and len(e.store.evidence(t)) == 1, "final_dir": (Path(e.work) / "ws" / str(t) / "final" / "main.py").exists(), "audit_clean": e.store.audit() == []},
                  {"task": t, "killed_worker": victim, "history": h})

def s_model_kill(e):
    t = e.agent("s2-model", n=4, delay=1.5); e.wait(lambda: (e.store.get(t)["checkpoint"] or {}).get("step", 0) >= 1, 60, "mid-generation"); before = len(e.sup_events("service_start"))
    pid = [j["pid"] for j in e.sup_events("service_start") if j["name"] == "model"][-1]; os.killpg(pid, 9); e.done([t], 150); g = e.store.get(t); h = [x["kind"] for x in e.store.history(t)]
    return result({"completed": g["state"] == "completed", "model_server_detected_down": any(j["name"] == "model" for j in e.sup_events("service_down")), "model_server_restarted": len(e.sup_events("service_start")) > before,
                   "released_or_retried": "released" in h or g["attempt"] >= 2 or "lease_expired" in h, "model_healthy_after": e.healthy(MODEL_PORT), "audit_clean": e.store.audit() == []}, {"task": t, "history": h, "infra_releases": g["infra"]})

def s_lease_fencing(e):
    marker = e.work / "fence-tokens.txt"
    code = f"import os,time; t=os.urandom(4).hex(); open({str(marker)!r},'a').write(t+'\\n'); time.sleep(6); print(t)"
    t = e.store.submit("exec", {"code": code}, "s5-fence", 4); e.wait(lambda: e.store.get(t)["state"] in ("running", "validating") and marker.exists(), 30, "running"); old = e.store.get(t); wpid = e.worker_pid(old["lease_owner"])
    os.kill(wpid, signal.SIGSTOP)                                                              # frozen worker: no heartbeats, lease must expire
    e.wait(lambda: e.store.get(t)["fence"] > old["fence"], 40, "reclaimed by another worker"); os.kill(wpid, signal.SIGCONT)      # old worker wakes up holding a dead fence
    e.done([t], 60); time.sleep(3); g = e.store.get(t); toks = marker.read_text().split(); h = e.store.history(t); log = (e.work / "sup" / f"{old['lease_owner']}.log").read_text()
    commits = [x for x in h if x["kind"] == "commit"]
    return result({"completed": g["state"] == "completed", "exactly_one_commit": len(commits) == 1, "commit_by_new_fence": commits[0]["fence"] > old["fence"], "two_executions_happened": len(toks) >= 2,
                   "result_is_newer_token": g["result"]["stdout"].strip() == toks[-1] and toks[0] != toks[-1], "stale_worker_rejected": "stale" in log, "audit_clean": e.store.audit() == []},
                  {"task": t, "stale_fence": old["fence"], "commit": commits, "tokens": toks, "worker_log_tail": log[-300:]})

def s_duplicate(e):
    key = "s6-dup"; t = e.agent(key, n=2, delay=0, sink=True, sinkopts={"delay_after": 8}); e.wait(lambda: any(r["key"] == f"{key}:publish" for r in e.rows()), 60, "sink received effect")
    owner = e.holder(t); os.killpg(e.worker_pid(owner), 9)                                     # killed after the effect landed, before it was acknowledged
    e.done([t], 90); g = e.store.get(t); rows = [r for r in e.rows() if r["key"] == f"{key}:publish"]; again = e.agent(key, n=2, delay=0, sink=True, sinkopts={"delay_after": 8}); ops = e.store.operations(t)
    return result({"completed": g["state"] == "completed", "one_ledger_row": len(rows) == 1, "retry_happened": g["attempt"] >= 2, "reconciled_not_resent": any(o["note"] == "reconciled" for o in ops) or g["result"]["sink"]["seq"] == rows[0]["seq"],
                   "resubmit_same_key_same_task": again == t, "still_one_row": len([r for r in e.rows() if r["key"] == f"{key}:publish"]) == 1, "audit_clean": e.store.audit() == []}, {"task": t, "ledger": rows, "operations": ops})

def s_validation(e):
    c1, c2 = e.work / "v1.count", e.work / "v2.count"
    v = [{"name": "fast", "cmd": ["python3", "-c", f"open({str(c1)!r},'a').write('x')"]}, {"name": "slow", "cmd": ["python3", "-c", f"import time; open({str(c2)!r},'a').write('x'); time.sleep(8)"]}]
    t = e.agent("s7-valid", n=2, delay=0, validators=v); e.wait(lambda: c2.exists() and any(x["name"] == "fast" for x in e.store.evidence(t)), 60, "validation in flight")
    ev1 = [x for x in e.store.evidence(t) if x["name"] == "fast"][0]; os.killpg(e.worker_pid(e.holder(t)), 9); e.done([t], 120)
    evs = {x["name"]: x for x in e.store.evidence(t)}; g = e.store.get(t); ops = [x["kind"] for x in e.store.history(t)]
    return result({"completed": g["state"] == "completed", "fast_evidence_preserved": evs["fast"]["id"] == ev1["id"] and evs["fast"]["ts"] == ev1["ts"], "fast_not_rerun": c1.read_text() == "x", "slow_rerun_once": c2.read_text() == "xx",
                   "all_evidence_ok": all(x["ok"] for x in evs.values()) and len(evs) == 2, "audit_clean": e.store.audit() == []}, {"task": t, "evidence": list(evs.values()), "history": ops})

def s_concurrent(e):
    ids = [e.agent(f"s8-a{i}", n=2, delay=0.2, sink=True) for i in range(12)] + [e.store.submit("exec", {"code": f"print({i})", "sink": {"url": f"http://127.0.0.1:{SINK_PORT}"}}, f"s8-x{i}") for i in range(28)]
    victim = e.store.submit("exec", {"code": "import time; time.sleep(60)"}, "s8-cancel", 1); e.wait(lambda: e.store.get(victim)["state"] in ("running", "validating"), 60, "cancel target running"); e.store.cancel(victim)
    e.done(ids + [victim], 240); cs = e.store.counts(); gs = [e.store.get(i) for i in ids]; keys = [r["key"] for r in e.rows() if r["key"].startswith("s8-")]
    return result({"all_terminal": all(g["state"] in D.TERMINAL for g in gs), "all_completed": all(g["state"] == "completed" for g in gs), "cancelled": e.store.get(victim)["state"] == "cancelled", "one_row_per_task": len(keys) == len(set(keys)) == 40,
                   "single_commit_each": all([x["kind"] for x in e.store.history(i)].count("commit") == 1 for i in ids), "audit_clean": e.store.audit() == []}, {"counts": cs})

def s_restart(e):
    ids = [e.agent(f"s3-r{i}", n=4, delay=1.0, sink=True) for i in range(6)] + [e.store.submit("exec", {"code": "import time; time.sleep(5); print('x')"}, f"s3-x{i}") for i in range(4)]
    e.wait(lambda: sum(e.store.get(i)["state"] in D.ACTIVE for i in ids) >= 3, 60, "work in flight"); e.hard_kill_everything()
    gone = not e.healthy(MODEL_PORT); snap = {i: e.store.get(i)["state"] for i in ids}; survived = all(s in D.RECOVERABLE + D.TERMINAL for s in snap.values()) and any(s in D.ACTIVE for s in snap.values())
    ids2 = [e.agent(f"s3-r{i}", n=4, delay=1.0, sink=True) for i in range(6)]                       # resubmitting after restart must not duplicate work
    ev0 = len(e.sup_events("recover")); e.start(workers=3); e.done(ids, 240); keys = [r["key"] for r in e.rows() if r["key"].startswith("s3-")]
    return result({"processes_were_killed": gone, "tasks_survived_with_recoverable_state": survived, "resubmit_returns_same_ids": ids2 == ids[:6], "recover_event_logged": len(e.sup_events("recover")) > ev0,
                   "all_completed_after_restart": all(e.store.get(i)["state"] == "completed" for i in ids), "no_duplicate_effects": len(keys) == len(set(keys)) == 6, "audit_clean": e.store.audit() == []}, {"snapshot_after_kill": snap})

def s_multinode(e, nodes):
    ns = [{"name": n, "ssh": n, "dir": "$HOME/ordp01", "workers": 1, "extra": "--no-self-abort"} for n in nodes]
    e.start(workers=0, nodes=ns); e.wait(lambda: len(e.sup_events("remote_workers_start")) >= len(nodes), 120, "remote workers"); sl = "import time,os; time.sleep(14); print(os.uname().nodename)"
    a = e.store.submit("exec", {"code": sl}, "s4-a", 5); time.sleep(0.5); b = e.store.submit("exec", {"code": sl}, "s4-b", 5)
    e.wait(lambda: e.store.get(a)["lease_node"] and e.store.get(b)["lease_node"] and e.store.get(a)["state"] in D.ACTIVE and e.store.get(b)["state"] in D.ACTIVE, 90, "both nodes busy"); na = e.store.get(a)["lease_node"]; f_old = e.store.get(a)["fence"]
    t0 = time.time(); e.sup_call("block", na); e.wait(lambda: e.store.get(a)["fence"] > f_old or e.store.get(a)["state"] == "queued", 40, "lease expiry after disconnect"); time.sleep(8); e.sup_call("unblock", na)
    e.done([a, b], 200); time.sleep(5); ga = e.store.get(a); h = e.store.history(a); commits = [x for x in h if x["kind"] == "commit"]; nodes_used = [x["node"] for x in h if x["kind"] == "claimed"]
    logs = subprocess.run(["ssh", "-o", "BatchMode=yes", na, "cat $HOME/ordp01/*.log"], capture_output=True, text=True, timeout=30).stdout
    # second disconnect on the other node while a fresh task runs there
    c = e.store.submit("exec", {"code": "import time,os; time.sleep(10); print(os.uname().nodename)"}, "s4-c", 5); e.wait(lambda: e.store.get(c)["state"] in D.ACTIVE, 60, "c running"); nc = e.store.get(c)["lease_node"]; e.sup_call("block", nc)
    e.done([c], 200); gc = e.store.get(c); e.sup_call("unblock", nc)
    return result({"a_completed": ga["state"] == "completed", "a_single_commit": len(commits) == 1, "a_reassigned_with_new_fence": len(nodes_used) >= 2 and commits[0]["fence"] > f_old, "a_committed_by_new_fence": commits[0]["fence"] > f_old,
                   "old_node_commit_rejected": "stale" in logs, "c_completed_after_disconnect": gc["state"] == "completed", "c_moved_to_other_node": len({x["node"] for x in e.store.history(c) if x["kind"] == "claimed"}) >= 2,
                   "audit_clean": e.store.audit() == []}, {"a_claims": nodes_used, "a_commit": commits, "c_history": [(x["kind"], x["node"]) for x in e.store.history(c)], "node_log_tail": logs[-400:]})

def main():
    out = Path(sys.argv[1]); nodes = [] if "--skip-nodes" in sys.argv else ["n1", "n4"]; e = E(out, nodes); verdicts = {}
    def block_hook(action, node):                                                                  # fault injection goes through a control file the supervisor process polls
        (e.work / "sup" / "control").write_text(json.dumps({"action": action, "node": node}))
    e.sup_call = lambda action, node: (block_hook(action, node), time.sleep(2.5))
    plan = [("crash_agent_kill", s_agent_kill), ("model_server_kill", s_model_kill), ("lease_fencing_sigstop", s_lease_fencing), ("duplicate_protection", s_duplicate), ("validation_interrupt", s_validation),
            ("concurrent_workers", s_concurrent), ("restart_survival", s_restart)]
    try:
        e.start(workers=3)
        for name, fn in plan:
            t0 = time.time()
            try: verdicts[name] = fn(e)
            except Exception as ex: verdicts[name] = {"pass": False, "error": f"{type(ex).__name__}: {ex}", "trace": traceback.format_exc()[-1500:]}
            verdicts[name]["seconds"] = round(time.time() - t0, 1); print(name, "PASS" if verdicts[name]["pass"] else "FAIL", flush=True)
        if nodes:
            e.stop(); t0 = time.time()
            try: verdicts["multinode_disconnect"] = s_multinode(e, nodes)
            except Exception as ex: verdicts["multinode_disconnect"] = {"pass": False, "error": f"{type(ex).__name__}: {ex}", "trace": traceback.format_exc()[-1500:]}
            verdicts["multinode_disconnect"]["seconds"] = round(time.time() - t0, 1); print("multinode_disconnect", "PASS" if verdicts["multinode_disconnect"]["pass"] else "FAIL", flush=True)
    finally:
        e.stop(); time.sleep(1)
    me = os.getpid(); ps = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True).stdout.splitlines()
    left = [l for l in ps if TAG in l and str(me) not in l.split()[0] and "ps -eo" not in l]
    remote = {}
    for n in nodes: remote[n] = subprocess.run(["ssh", "-o", "BatchMode=yes", n, f"pgrep -af '[{TAG[0]}]{TAG[1:]}-' ; true"], capture_output=True, text=True, timeout=30).stdout.strip()
    verdicts["clean_shutdown"] = result({"no_local_orphans": not left, "no_remote_orphans": not any(remote.values()), "ports_closed": not any(E.healthy(p) for p in (MODEL_PORT, SINK_PORT))}, {"left": left, "remote": remote})
    verdicts["_meta"] = {"work": str(e.work), "db": str(e.db), "ledger": str(e.ledger), "when": time.strftime("%FT%TZ", time.gmtime()), "model": "scripted OpenAI-compatible server (process), not an LLM", "final_counts": e.store.counts()}
    (out / "verdicts.json").write_text(json.dumps(verdicts, indent=2, default=str)); print(json.dumps({k: v.get("pass") for k, v in verdicts.items() if not k.startswith("_")}))

if __name__ == "__main__": main()
