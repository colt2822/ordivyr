"""Multi-MACHINE validation: coordinators run on THIS host; worker nodes run on other physical machines over the LAN (ssh-started, isolated dir, unique ports, hard lifetime cap).

Topology: M coordinators (one SQLite shard each, tenant -> shard by stable hash) listening on 0.0.0.0 with a random bearer token. Every host (including this one) runs one
`ordivyr.durable_worker` NodeAgent per shard. Scenarios inject real failures: kill -9 of a remote node's processes, SIGKILL + restart of a coordinator, a TCP blackhole on the
path of ONE remote host (network interruption), tenant flood, and cross-tenant/credential probes sent FROM a remote machine. Verification reads every shard DB directly:
each task completed once, digest correct, exactly one commit event, audit() empty, tasks only on their tenant's shard, per-host attribution.
SIMULATION MODE (--simulate N, names sim1..simN): every "host" is a set of local processes on loopback. That exercises coordinators, sharding, lease/fence recovery, kill -9 and a TCP blackhole
across separate PROCESSES, but proves NOTHING about multiple machines (no real NIC, no clock skew, no independent failure domains) and must never be reported as multi-machine success.
Honest scope: LAN hosts on one switch; not WAN, not different data centres, not a high-latency or lossy link. Usage: python -m ordivyr.hosting.distributed --hosts n1,n2,n3 --scenario all --out R.json"""
import argparse, shlex, hashlib, json, os, secrets, signal, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path
from .. import durable as D
from .chaos import Proxy, free_port, killpg, wait, PY
from .workbench import expect
from .shard import stable_hash

REPO = Path(__file__).resolve().parents[2]
BASE = "ordtest-dist"                                  # isolated directory in the remote HOME; removed at the end
MAXLIFE = 1500                                        # seconds: remote workers kill themselves even if this driver dies

def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("203.0.113.1", 9)); ip = s.getsockname()[0]; s.close(); return ip

def ssh(host, cmd, timeout=60):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, cmd], capture_output=True, text=True, timeout=timeout)

def is_sim(name): return name.startswith("sim")

class Host:
    def __init__(self, name, local=False): self.name, self.local, self.pgids = name, local, []
    def sync(self, token):
        if self.local: return
        r = ssh(self.name, f"rm -rf ~/{BASE} && mkdir -p ~/{BASE}/ws && echo '{token}' > ~/{BASE}/tok && chmod 600 ~/{BASE}/tok"); assert r.returncode == 0, r.stderr
        t = subprocess.run(f"tar -C {REPO} --exclude=__pycache__ --exclude=tests -cf - ordivyr | ssh -o BatchMode=yes {self.name} 'tar -C ~/{BASE} -xf -'", shell=True, capture_output=True); assert t.returncode == 0, t.stderr
    def start(self, name, url, ttl, slots, tokfile):
        cmd = [PY if self.local else "python3", "-B", "-m", "ordivyr.durable_worker", "--url", url, "--token-file", tokfile, "--name", name, "--node", self.name, "--ws", (tempfile.mkdtemp(prefix="ordw-") if self.local else f"$HOME/{BASE}/ws/{name}"), "--ttl", str(ttl), "--slots", str(slots), "--longpoll", "1.0"]
        if self.local:
            p = subprocess.Popen(["timeout", str(MAXLIFE), *cmd], cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True); self.pgids.append(p); return p
        r = ssh(self.name, f"cd ~/{BASE} || exit 1; setsid nohup nice -n 10 timeout {MAXLIFE} {' '.join(cmd)} > ws/{name}.log 2>&1 < /dev/null & echo $!"); self.pgids.append(int(r.stdout.split()[-1])); return None
    def kill_all(self, sig=9):
        for p in self.pgids:
            if self.local: killpg(p)
            else: ssh(self.name, f"kill -{sig} -- -{p} 2>/dev/null; pkill -{sig} -f '{BASE}.*durable_worker' 2>/dev/null; true")
        self.pgids = []
    def cleanup(self):
        self.kill_all()
        if not self.local: ssh(self.name, f"pkill -9 -f 'durable_worker.*{BASE}' ; rm -rf ~/{BASE}; true")

class Cluster:
    def __init__(self, hosts, shards=2, tenants=("t1", "t2", "t3", "t4", "t5", "t6"), per_tenant=100, think=1.0, rounds=2000, ttl=3.0, slots=6, flood=None, principals=None):
        self.sim = bool(hosts) and all(is_sim(h) for h in hosts); self.bind = "127.0.0.1" if self.sim else "0.0.0.0"
        self.ip, self.M, self.ttl, self.slots, self.think, self.rounds = "127.0.0.1" if self.sim else lan_ip(), shards, ttl, slots, think, rounds
        self.token = secrets.token_hex(16); self.d = Path(tempfile.mkdtemp(prefix="orddist-")); (self.d / "tok").write_text(self.token)
        self.hosts = [Host("main", local=True)] + [Host(h, local=is_sim(h)) for h in hosts]; self.ports = [free_port() for _ in range(shards)]; self.dbs = [self.d / f"s{i}.db" for i in range(shards)]
        self.stores = [D.Store(p) for p in self.dbs]; self.seeds = {}; self.coords = [None] * shards; self.principals = principals or {}; self.proxies = {}; self.tenants = tenants
        for t in tenants:
            for i in range(per_tenant if not flood or t not in flood else flood[t]): self.submit(t, i)
    def shard_of(self, tenant): return stable_hash(tenant, self.M)
    def submit(self, tenant, i):
        s = self.shard_of(tenant); tid = self.stores[s].submit("compute", {"seed": f"{tenant}-{i}", "rounds": self.rounds, "think_s": self.think}, f"{tenant}-{i}", tenant=tenant); self.seeds[(s, tid)] = (f"{tenant}-{i}", tenant)
    def start_coordinator(self, i):
        code = (f"from ordivyr import durable as D; from ordivyr.durable_net import Coordinator; import time; "
                f"Coordinator(D.Store({str(self.dbs[i])!r}), {self.token!r}, host={self.bind!r}, port={self.ports[i]}, principals={self.principals!r}, reap_every=0.5).start(); time.sleep(10**6)")
        self.coords[i] = subprocess.Popen([PY, "-c", code], cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        assert wait(lambda: _up(self.ports[i]), 20), "coordinator did not start"
    def start(self):
        for i in range(self.M): self.start_coordinator(i)
        with_threads = [threading.Thread(target=h.sync, args=(self.token,)) for h in self.hosts]; [t.start() for t in with_threads]; [t.join() for t in with_threads]
        for h in self.hosts: self.attach(h)
    def attach(self, h, via_proxy=False):
        for i in range(self.M):
            port = self.proxies[(h.name, i)].port if via_proxy else self.ports[i]
            h.start(f"{h.name}-s{i}", f"http://{self.ip}:{port}", self.ttl, self.slots, str(self.d / "tok") if h.local else f"$HOME/{BASE}/tok")
    def done(self): return sum(s._conn().execute("SELECT COUNT(*) FROM tasks WHERE state='completed'").fetchone()[0] for s in self.stores)
    def done_for(self, tenants): return sum(s._conn().execute(f"SELECT COUNT(*) FROM tasks WHERE state='completed' AND tenant IN ({','.join('?' * len(tenants))})", list(tenants)).fetchone()[0] for s in self.stores)
    def verify(self):
        valid = dup = viol = misrouted = stale = 0; per_host = {}; attempts = 0
        for si, st in enumerate(self.stores):
            c = st._conn(); rows = {r["id"]: dict(r) for r in c.execute("SELECT id, state, result, tenant, attempt FROM tasks")}; commits = {r[0]: r[1] for r in c.execute("SELECT task_id, COUNT(*) FROM events WHERE kind='commit' GROUP BY task_id")}
            for (s, tid), (seed, tenant) in self.seeds.items():
                if s != si: continue
                r = rows.get(tid); attempts += r["attempt"] if r else 0
                if r and r["state"] == "completed" and json.loads(r["result"]).get("digest") == expect(seed, self.rounds) and commits.get(tid) == 1:
                    valid += 1; n = c.execute("SELECT node FROM events WHERE task_id=? AND kind='claimed' ORDER BY id DESC LIMIT 1", (tid,)).fetchone(); per_host[n[0] if n else "?"] = per_host.get(n[0] if n else "?", 0) + 1
            dup += sum(1 for v in commits.values() if v > 1); viol += len(st.audit())
            misrouted += sum(1 for (t,) in c.execute("SELECT DISTINCT tenant FROM tasks") if self.shard_of(t) != si)
            stale += c.execute("SELECT COUNT(*) FROM events WHERE kind IN ('lease_expired','attempt_failed')").fetchone()[0]
        return {"tasks": len(self.seeds), "validated": valid, "duplicate_commits": dup, "audit_violations": viol, "misrouted_tenants": misrouted, "lease_expiries_or_failures": stale, "attempts_total": attempts, "completed_by_host": dict(sorted(per_host.items()))}
    def close(self):
        for h in self.hosts: h.cleanup()
        for c in self.coords:
            if c: killpg(c)
        for p in self.proxies.values(): p.close()

def _up(port):
    try: socket.create_connection(("127.0.0.1", port), timeout=0.3).close(); return True
    except OSError: return False

def finish(name, c, t0, ok, **extra):
    v = c.verify(); passed = bool(ok) and v["validated"] == v["tasks"] and not v["duplicate_commits"] and not v["audit_violations"] and not v["misrouted_tenants"]
    return {"scenario": ("sim_" if c.sim else "") + name, "passed": passed, "wall_s": round(time.time() - t0, 1), "hosts": [h.name for h in c.hosts], "simulated_single_host": c.sim, **v, **extra}

def run(name, hosts, inject=None, finalize=None, **kw):
    c = Cluster(hosts, **kw); t0 = time.time()
    try:
        c.start(); n = len(c.seeds); extra = {}
        if inject: extra = inject(c) or {}
        ok = wait(lambda: c.done() == n, 400, 0.5); extra.update(finalize(c) if finalize else {})
        return finish(name, c, t0, ok, **extra)
    finally: c.close()

def baseline(hosts, **kw): return run("baseline_multi_host", hosts, lambda c: (wait(lambda: c.done() >= 1, 60) and {"first_completion_s": round(time.time() - _T0[0], 1)}) if False else {}, **kw)

def node_loss(hosts, **kw):
    victim = hosts[0]
    def inj(c):
        wait(lambda: c.done() >= 40, 90); h = next(h for h in c.hosts if h.name == victim)
        held = sum(s._conn().execute("SELECT COUNT(*) FROM tasks WHERE lease_node=? AND state IN ('claimed','running','validating')", (victim,)).fetchone()[0] for s in c.stores)
        h.kill_all(9); tk = time.time(); freed = wait(lambda: sum(s._conn().execute("SELECT COUNT(*) FROM tasks WHERE lease_node=? AND state IN ('claimed','running','validating')", (victim,)).fetchone()[0] for s in c.stores) == 0, 40)
        return {"killed_host": victim, "leases_held_at_kill": held, "seconds_until_dead_hosts_leases_requeued": round(time.time() - tk, 1) if freed else None}
    return run("remote_node_kill9", hosts, inj, **kw)

def coordinator_restart(hosts, **kw):
    def inj(c):
        wait(lambda: c.done() >= 40, 90); before = c.done(); killpg(c.coords[0]); tk = time.time(); time.sleep(4.0); c.start_coordinator(0)
        rec = wait(lambda: c.done() > before + 2, 60) and round(time.time() - tk, 1); return {"killed_shard": 0, "downtime_s": 4.0, "seconds_from_kill_to_progress": rec}
    return run("coordinator_sigkill_restart", hosts, inj, **kw)

def partition(hosts, **kw):
    far = hosts[-1]
    class C2(Cluster):
        def start(self):
            for i in range(self.M): self.start_coordinator(i)
            ts = [threading.Thread(target=h.sync, args=(self.token,)) for h in self.hosts]; [t.start() for t in ts]; [t.join() for t in ts]
            for h in self.hosts:
                if h.name == far:
                    for i in range(self.M): self.proxies[(far, i)] = Proxy(self.ports[i], bind=self.bind, target_host="127.0.0.1")
                self.attach(h, via_proxy=(h.name == far))
    def inj(c):
        wait(lambda: c.done() >= 40, 90)
        for i in range(c.M): c.proxies[(far, i)].partition(True)
        tp = time.time(); time.sleep(c.ttl * 3 + 2); expired = sum(s._conn().execute("SELECT COUNT(*) FROM events WHERE kind='lease_expired'").fetchone()[0] for s in c.stores)
        for i in range(c.M): c.proxies[(far, i)].partition(False)
        return {"partitioned_host": far, "partition_s": round(time.time() - tp, 1), "lease_expiries_during_partition": expired}
    c = C2(hosts, **kw); t0 = time.time()
    try:
        c.start(); n = len(c.seeds); extra = inj(c); ok = wait(lambda: c.done() == n, 400, 0.5); return finish("network_partition_one_host", c, t0, ok, **extra)
    finally: c.close()

def fairness(hosts, **kw):
    small = ("t1", "t2", "t3", "t4")
    def inj(c):
        for st in c.stores:
            st.tenant_set("flood", weight=1.0, max_active=int(len(c.hosts) * c.slots * c.M * 0.5))
        t0 = time.time(); fin = wait(lambda: c.done_for(small) == 4 * 25, 300, 0.25); ts = round(time.time() - t0, 1); fl = c.done_for(("flood",))
        return {"small_tenants_all_done_s": ts if fin else None, "flood_tasks_done_when_small_finished": fl, "flood_total": 400}
    return run("tenant_fairness_flood", hosts, inj, tenants=small + ("flood",), per_tenant=25, flood={"flood": 400}, **kw)

def access(hosts, **kw):
    """Credential / tenant boundary probes sent FROM a remote machine to a LAN coordinator."""
    ptok = {"tokA": {"role": "tenant", "tenant": "tA"}, "tokB": {"role": "tenant", "tenant": "tB"}, "wrk": {"role": "worker", "tenants": ["tA"]}}
    c = Cluster(hosts, shards=1, tenants=("tA", "tB"), per_tenant=3, think=0.01, principals=ptok); t0 = time.time()
    try:
        for i in range(c.M): c.start_coordinator(i)               # coordinators only: no cluster workers, so the probe worker below is the only claimant
        if not c.sim:
            c.hosts[1].sync(c.token)
        ida = [tid for (s, tid), (_, t) in c.seeds.items() if t == "tA"][0]; idb = [tid for (s, tid), (_, t) in c.seeds.items() if t == "tB"][0]
        probe = f"""
import json, sys
sys.path.insert(0, '.')
from ordivyr.durable_net import RemoteStore, RemoteError
U = 'http://{c.ip}:{c.ports[0]}'
def t(label, f):
    try: return label, repr(f())[:90]
    except Exception as e: return label, type(e).__name__ + ': ' + str(e)[:90]
A, B, W, BAD = RemoteStore(U, 'tokA'), RemoteStore(U, 'tokB'), RemoteStore(U, 'wrk'), RemoteStore(U, 'nope')
out = dict([t('bad_token_counts', lambda: BAD.counts()), t('A_get_own', lambda: (A.get({ida}) or {{}}).get('tenant')), t('A_get_B_task', lambda: A.get({idb})), t('B_get_A_task', lambda: B.get({ida})),
            t('A_claim_forbidden', lambda: A.claim('w')), t('A_cancel_B_task', lambda: A.cancel({idb})), t('A_reap_forbidden', lambda: A.reap()),
            t('A_submit_as_B', lambda: A.submit('compute', {{'seed':'x','rounds':1}}, 'probe', tenant='tB')),
            t('worker_claims_only_tA', lambda: sorted({{x['tenant'] for x in W.claim_many('wk', limit=10)}})),
            t('worker_touch_B_task', lambda: W.heartbeat({idb}, 1))])
print(json.dumps(out))
"""
        r = subprocess.run([PY, "-B", "-c", probe], cwd=REPO, capture_output=True, text=True, timeout=60) if c.sim else ssh(hosts[0], f"cd ~/{BASE} && python3 -B -c {shlex.quote(probe)}", 60); res = json.loads(r.stdout.strip().splitlines()[-1]) if r.returncode == 0 else {"error": r.stderr[-300:]}
        sub = c.stores[0]._conn().execute("SELECT tenant FROM tasks WHERE idem_key LIKE '%probe'").fetchone()
        ok = (res.get("bad_token_counts", "").startswith("RemoteError") or "auth" in res.get("bad_token_counts", "") or "401" in res.get("bad_token_counts", "")) and res.get("A_get_B_task") == "None" and res.get("B_get_A_task") == "None" \
             and "PermissionError" in res.get("A_claim_forbidden", "") and "PermissionError" in res.get("A_reap_forbidden", "") and res.get("worker_claims_only_tA") == "['tA']" and "PermissionError" in res.get("worker_touch_B_task", "") and (sub is None or sub[0] == "tA")
        return {"scenario": ("sim_" if c.sim else "") + "access_boundaries_probe_host", "passed": bool(ok), "probe_results": res, "submit_as_B_landed_in_tenant": sub[0] if sub else None, "wall_s": round(time.time() - t0, 1), "hosts": [h.name for h in c.hosts], "simulated_single_host": c.sim}
    finally: c.close()

_T0 = [0]
SCEN = {"baseline": baseline, "node_loss": node_loss, "coordinator_restart": coordinator_restart, "partition": partition, "fairness": fairness, "access": access}

def main(argv=None):
    a = argparse.ArgumentParser(); a.add_argument("--hosts", required=True, help="comma-separated ssh aliases of REMOTE machines, or sim1,sim2,... for the single-host simulation"); a.add_argument("--scenario", default="all"); a.add_argument("--out"); a.add_argument("--think", type=float, default=1.0); a.add_argument("--per-tenant", type=int, default=100); a.add_argument("--slots", type=int, default=6)
    a = a.parse_args(argv); hosts = a.hosts.split(","); out = []; kw = {"think": a.think, "per_tenant": a.per_tenant, "slots": a.slots}
    for k, f in SCEN.items():
        if a.scenario in ("all", k):
            r = f(hosts, **({} if k in ("access", "fairness") else kw)) if k not in ("fairness",) else f(hosts, think=min(a.think, 0.5), slots=a.slots)
            out.append(r); print(json.dumps(r), flush=True)
    res = {"driver_host": socket.gethostname(), "lan_ip": lan_ip(), "remote_hosts": hosts, "all_passed": all(r["passed"] for r in out), "results": out}
    if a.out: Path(a.out).write_text(json.dumps(res, indent=1))
    return 0 if res["all_passed"] else 1

if __name__ == "__main__": sys.exit(main())
