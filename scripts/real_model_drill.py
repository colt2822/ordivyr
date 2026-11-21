"""Real-model drill against an INSTALLED wheel and a model endpoint YOU authorise: tool-using job + kill -9 mid-job recovery."""
import json, os, signal, subprocess, sys, time, urllib.request, urllib.error, shutil
from pathlib import Path
BIN = Path(sys.argv[1]); W = Path(sys.argv[2]); shutil.rmtree(W, ignore_errors=True); W.mkdir(parents=True)
# usage: real_model_drill.py <venv/bin> <workdir> <base-url> <model> <key-file>
BASE, MODEL, KEY = sys.argv[3], sys.argv[4], sys.argv[5]; H = str(W / "home"); API, LEASE = 18881, 18882
r = subprocess.run([BIN / "ordivyr-board", "init", "--home", H, "--model", MODEL, "--base-url", BASE, "--key-file", KEY], capture_output=True, text=True); print("init rc", r.returncode, r.stderr[-200:])
def up():
    p = subprocess.Popen([BIN / "ordivyr-board", "up", "--home", H, "--port", str(API), "--lease-port", str(LEASE)], stdout=open(W / "up.out", "a"), stderr=open(W / "up.err", "a"))
    for _ in range(60):
        try: urllib.request.urlopen(f"http://127.0.0.1:{API}/healthz", timeout=1); return p
        except Exception: time.sleep(.5)
    raise SystemExit("no start")
ak = (Path(H) / "admin.token").read_text().strip()
def call(m, path, body=None):
    q = urllib.request.Request(f"http://127.0.0.1:{API}{path}", json.dumps(body).encode() if body is not None else None, {"Authorization": "Bearer " + ak, "Content-Type": "application/json"}, method=m)
    try:
        with urllib.request.urlopen(q, timeout=20) as x: return x.status, json.loads(x.read() or b"{}")
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")
def wait(jid, t=240):
    t0 = time.time()
    while time.time() - t0 < t:
        s = call("GET", f"/v1/projects/main/jobs/{jid}")[1]
        if s.get("status") in ("completed", "failed", "cancelled", "held"): return s
        time.sleep(2)
    return s
p = up()
# 1: real tool-using task
s, j = call("POST", "/v1/projects/main/jobs", {"agent_id": "coder", "prompt": "Create a file named result.txt containing exactly the word PINEAPPLE, then read it back to confirm, then reply with one short sentence."}); print("submit", s, j.get("job_id"))
d = wait(j["job_id"]); print("job1:", d.get("status"), "attempt", d.get("attempt"), "| result:", json.dumps(d.get("result"))[:300]); print("usage/meter:", json.dumps({k: d.get(k) for k in d if k in ("usage", "cost", "tokens", "error", "failure")})[:300])
for f in (Path(H) / "ws").rglob("result.txt"): print("FILE", f.name, repr(f.read_text()))
# 2: crash mid-job with real model
s, j2 = call("POST", "/v1/projects/main/jobs", {"agent_id": "coder", "prompt": "Write a 300-word explanation of fenced leases in a file named lease.md, then read the first line back and reply done."})
for _ in range(40):
    if call("GET", f"/v1/projects/main/jobs/{j2['job_id']}")[1].get("status") == "running": break
    time.sleep(.5)
time.sleep(4); os.kill(p.pid, signal.SIGKILL); p.wait(); print("SIGKILL mid-job"); time.sleep(1); p = up()
d2 = wait(j2["job_id"]); print("job2:", d2.get("status"), "attempt", d2.get("attempt"), "| result:", json.dumps(d2.get("result"))[:200])
for f in (Path(H) / "ws").rglob("lease.md"): print("FILE lease.md bytes", len(f.read_bytes()))
print("spending:", json.dumps(call("GET", "/v1/spending")[1])[:300])
os.kill(p.pid, signal.SIGTERM); p.wait(30)
