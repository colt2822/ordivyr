"""Release drill against an INSTALLED wheel: crash recovery, durable job, memory, backup/restore. Stub model (no real model, no spend)."""
import json, os, signal, subprocess, sys, time, threading, urllib.request, urllib.error, shutil, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
BIN = Path(sys.argv[1]); W = Path(sys.argv[2]); shutil.rmtree(W, ignore_errors=True); W.mkdir(parents=True)
first = {"n": 0}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"]))); first["n"] += 1
        if first["n"] == 1: time.sleep(6)            # first call hangs long enough to be killed mid-job
        out = json.dumps({"model": "m", "choices": [{"message": {"role": "assistant", "content": "DONE-OK"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 5, "completion_tokens": 3}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); srv.daemon_threads = True; threading.Thread(target=srv.serve_forever, daemon=True).start()
murl = f"http://127.0.0.1:{srv.server_address[1]}/v1"
env = {**os.environ}
def up(home, api, lease):
    p = subprocess.Popen([BIN / "ordivyr-board", "up", "--home", home, "--port", str(api), "--lease-port", str(lease)], env=env, stdout=open(W / f"up{api}.out", "w"), stderr=open(W / f"up{api}.err", "w"))
    for _ in range(60):
        try: urllib.request.urlopen(f"http://127.0.0.1:{api}/healthz", timeout=1); return p
        except Exception: time.sleep(0.5)
    raise SystemExit("server did not start: " + (W / f"up{api}.err").read_text()[-800:])
def call(api, m, path, tok, body=None):
    r = urllib.request.Request(f"http://127.0.0.1:{api}{path}", json.dumps(body).encode() if body is not None else None, {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}, method=m)
    try:
        with urllib.request.urlopen(r, timeout=15) as x: return x.status, json.loads(x.read() or b"{}")
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")
H1 = str(W / "home"); API, LEASE = 18871, 18872
ini = subprocess.run([BIN / "ordivyr-board", "init", "--home", H1, "--model", "m", "--base-url", murl], capture_output=True, text=True); print("init rc", ini.returncode)   # the documented quickstart: init, then plain `up`
ak = (Path(H1) / "admin.token").read_text().strip(); p = up(H1, API, LEASE); P = "main"
print("memory put", call(API, "PUT", "/v1/projects/main/memory/project/k1", ak, {"value": "persist-me"}))
s, j = call(API, "POST", "/v1/projects/main/jobs", ak, {"prompt": "hello", "agent_id": "coder"}); jid = j["job_id"]; print("submit", s, jid)
for _ in range(40):
    st = call(API, "GET", f"/v1/projects/main/jobs/{jid}", ak)[1]
    if st.get("status") == "running": break
    time.sleep(0.25)
print("status before kill:", st.get("status"), "attempt", st.get("attempt"))
os.kill(p.pid, signal.SIGKILL); p.wait(); print("SIGKILLed board+worker mid-job")
time.sleep(1)
p = up(H1, API, LEASE); print("restarted")
t0 = time.time()
while time.time() - t0 < 120:
    st = call(API, "GET", f"/v1/projects/main/jobs/{jid}", ak)[1]
    if st.get("status") in ("completed", "failed", "cancelled", "held"): break
    time.sleep(1)
print("after recovery:", st.get("status"), "attempt", st.get("attempt"), "in", round(time.time() - t0, 1), "s")
out = call(API, "GET", f"/v1/projects/main/jobs/{jid}/outputs", ak); print("outputs", json.dumps(out)[:200])
print("memory get", call(API, "GET", "/v1/projects/main/memory/project/k1", ak))
os.kill(p.pid, signal.SIGTERM); p.wait(30)
bk = subprocess.run([BIN / "ordivyr-board", "backup", "--include-personal", "--home", H1, "--out", str(W / "b.bak")], capture_output=True, text=True); print("backup rc", bk.returncode, bk.stdout[-300:], bk.stderr[-300:])
bv = subprocess.run([BIN / "ordivyr-board", "backup-verify", "--from", str(W / "b.bak")], capture_output=True, text=True); print("verify rc", bv.returncode, bv.stdout[-300:], bv.stderr[-300:])
H2 = str(W / "restored")
rs = subprocess.run([BIN / "ordivyr-board", "restore", "--from", str(W / "b.bak"), "--home", H2], capture_output=True, text=True); print("restore rc", rs.returncode, rs.stdout[-300:], rs.stderr[-300:])
p2 = up(H2, 18873, 18874)
ak = (Path(H2) / "admin.token").read_text().strip()          # credentials came back from the backup
print("restored job:", call(18873, "GET", f"/v1/projects/main/jobs/{jid}", ak)[1].get("status"))
print("restored memory:", call(18873, "GET", "/v1/projects/main/memory/project/k1", ak))
s, j2 = call(18873, "POST", "/v1/projects/main/jobs", ak, {"prompt": "again", "agent_id": "coder"})
for _ in range(60):
    st2 = call(18873, "GET", f"/v1/projects/main/jobs/{j2['job_id']}", ak)[1]
    if st2.get("status") in ("completed", "failed", "cancelled", "held"): break
    time.sleep(1)
print("new job on restored install:", st2.get("status"))
os.kill(p2.pid, signal.SIGTERM); p2.wait(30)
