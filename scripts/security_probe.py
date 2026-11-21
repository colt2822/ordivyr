import json, subprocess, sys, time, urllib.request, urllib.error, shutil, socket
from pathlib import Path
BIN = Path(sys.argv[1]); W = Path(sys.argv[2]); shutil.rmtree(W, ignore_errors=True); W.mkdir(parents=True); H = str(W/"h"); API = 18891
subprocess.run([BIN/"ordivyr-board","init","--home",H,"--model","m","--base-url","http://127.0.0.1:9/v1"],capture_output=True)
p = subprocess.Popen([BIN/"ordivyr-board","up","--home",H,"--port",str(API),"--lease-port","18892"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(60):
    try: urllib.request.urlopen(f"http://127.0.0.1:{API}/healthz",timeout=1); break
    except Exception: time.sleep(.5)
ak=(Path(H)/"admin.token").read_text().strip(); pt=(Path(H)/"platform.token").read_text().strip()
def c(m,path,tok=None,body=None,raw=None,hdr=None):
    d = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    q=urllib.request.Request(f"http://127.0.0.1:{API}{path}",d,{**({"Authorization":"Bearer "+tok} if tok else {}),"Content-Type":"application/json",**(hdr or {})},method=m)
    try:
        with urllib.request.urlopen(q,timeout=10) as x: return x.status,x.read()[:4000]
    except urllib.error.HTTPError as e: return e.code,e.read()[:4000]
    except Exception as e: return type(e).__name__,b""
R=[]
def t(name,res,ok): R.append((name,res[0],"PASS" if ok(res[0]) else "FAIL"))
t("no token",c("GET","/v1/projects/main/jobs"),lambda s:s==401)
t("bad token",c("GET","/v1/projects/main/jobs","ords_x"),lambda s:s==401)
t("sql-ish token",c("GET","/v1/projects/main/jobs","' OR 1=1--"),lambda s:s==401)
t("traversal project id",c("GET","/v1/projects/..%2f..%2fetc/jobs",ak),lambda s:s in (400,404))
t("traversal agent id",c("PUT","/v1/projects/main/agents/..%2fx",ak,{"model_ref":{"endpoint":"local","model":"m"}}),lambda s:s in (400,404,422))
s,o=c("POST","/v1/admin/orgs",pt,{"id":"evil","plan":"free"}); ek=json.loads(o).get("admin_key") if s==200 else None
sj,oj=c("POST","/v1/projects/main/jobs",ak,{"agent_id":"coder","prompt":"x"}); jid=json.loads(oj)["job_id"] if sj==200 else "j-none"
if ek:
    c("POST","/v1/projects",ek,{"id":"main"})
    t("cross-tenant job read",c("GET",f"/v1/projects/main/jobs/{jid}",ek),lambda s:s==404)
    t("cross-tenant cancel",c("POST",f"/v1/projects/main/jobs/{jid}/cancel",ek,{}),lambda s:s==404)
    t("cross-tenant memory",c("GET","/v1/projects/main/memory/project/k",ek),lambda s:s in (200,404) )
t("org admin cannot make orgs",c("POST","/v1/admin/orgs",ak,{"id":"x2"}),lambda s:s==403)
t("org admin cannot read admin kill/workers",c("GET","/v1/admin/workers",ak),lambda s:s==403)
t("platform cannot read tenant jobs",c("GET",f"/v1/projects/main/jobs/{jid}",pt),lambda s:s in (403,404))
t("malformed json",c("POST","/v1/projects/main/jobs",ak,raw=b"{not json"),lambda s:s in (400,422))
t("array body",c("POST","/v1/projects/main/jobs",ak,raw=b"[1]"),lambda s:s==422)
t("huge body 20MB",c("POST","/v1/projects/main/jobs",ak,raw=b'{"prompt":"'+b"A"*20_000_000+b'"}'),lambda s:s in (413,400,422,"BrokenPipeError","ConnectionResetError","URLError"))
t("huge header",c("GET","/healthz",hdr={"X-A":"B"*70000}),lambda s:s!=500)
t("bad content-length",c("POST","/v1/projects/main/jobs",ak,raw=b"{}",hdr={"Content-Length":"-5"}),lambda s:s!=500)
t("unknown route",c("GET","/etc/passwd"),lambda s:s in (404,401))
t("static traversal",c("GET","/static/..%2f..%2f..%2fselfhost.json"),lambda s:s in (400,404,401))
t("static traversal2",c("GET","/../../../../etc/passwd"),lambda s:s in (400,404,401))
t("job id traversal",c("GET","/v1/projects/main/jobs/..%2f..%2fx/outputs",ak),lambda s:s in (400,404))
s=socket.create_connection(("127.0.0.1",API)); s.sendall(b"GET /v1/health HTTP/1.1\r\nHost: evil.example\r\n\r\n"); R.append(("Host: evil.example no token",s.recv(30).split(b"\r\n")[0].decode(),"INFO"))
for r in R: print(*r)
# brute force throttle
codes=[c("GET","/v1/projects/main/jobs","wrong%d"%i)[0] for i in range(40)]; print("brute-force statuses:",sorted(set(codes)))
p.terminate(); p.wait(20)
