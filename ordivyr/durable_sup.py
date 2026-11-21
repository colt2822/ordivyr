"""Durable supervisor: owns the store + lease API, keeps workers / model servers / node tunnels alive, reaps dead leases, adapts concurrency to host pressure.

  python -m ordivyr.durable_sup CONFIG.json

config: {"db","ws","run","tag","token_file","max_concurrency","ttl","workers":N,"port":0,"services":[{"name","health","cmd":[...],"env":{}}],
         "nodes":[{"name","ssh","dir","workers":N}]}
Everything is recoverable from the database alone: start the supervisor against an existing db after a crash/reboot and unfinished tasks re-enter the queue.
"""
from __future__ import annotations
import json, os, signal, subprocess, sys, threading, time, urllib.request
from pathlib import Path
from . import durable as D
from .durable_net import Coordinator
from .durable_worker import _pdeathsig

def read_pressure():
    """Host pressure sample (same signals the 4-hour torture governor used): MemAvailable MB, swap used MB, memory PSI some/avg10."""
    mi = {}
    for line in open("/proc/meminfo"):
        k, _, v = line.partition(":"); mi[k] = int(v.split()[0])
    psi = 0.0
    try: psi = float(open("/proc/pressure/memory").readline().split("avg10=")[1].split()[0])
    except (OSError, IndexError, ValueError): pass
    return {"mem_avail_mb": mi.get("MemAvailable", 0) // 1024, "swap_used_mb": (mi.get("SwapTotal", 0) - mi.get("SwapFree", 0)) // 1024, "psi_mem": psi}

class Governor:
    """Back off first, stop only when critical: returns the fraction (0..1) of max concurrency the host can take right now."""
    def __init__(self, low_mb=3000, psi_hi=30.0, swap_step=400): self.low, self.psi_hi, self.swap_step, self.hist, self.notes = low_mb, psi_hi, swap_step, [], []
    def scale(self, r, now=None):
        now = now or time.time(); sc = 1.0; self.notes = []
        if r["mem_avail_mb"] < self.low: sc = min(sc, 0.5); self.notes.append(f"mem<{self.low}")
        if r["mem_avail_mb"] < self.low / 2: sc = 0.0; self.notes.append("mem-critical")
        if r["psi_mem"] > self.psi_hi: sc = min(sc, 0.5); self.notes.append(f"psi{r['psi_mem']}")
        self.hist = [x for x in self.hist if x[0] > now - 300] + [(now, r["swap_used_mb"])]
        if r["swap_used_mb"] - self.hist[0][1] > self.swap_step: sc = min(sc, 0.5); self.notes.append("swap-growth")
        return sc

class Supervisor:
    def __init__(self, cfg, sample=read_pressure):
        self.cfg = cfg; self.tag = cfg.get("tag", "ordp01"); self.run = Path(cfg["run"]); self.run.mkdir(parents=True, exist_ok=True); self.ws = cfg["ws"]; self.ttl = cfg.get("ttl", 6.0)
        self.store = D.Store(cfg["db"]); self.stop_ev = threading.Event(); self.procs = {}; self.svc = {}; self.tun = {}; self.blocked = set(); self.sample = sample; self.gov = Governor()
        self.maxc = cfg.get("max_concurrency", 4); self.lock = threading.Lock(); self.log_f = open(self.run / "supervisor.jsonl", "a", buffering=1); self.bad = {}
        tf = Path(cfg.get("token_file") or self.run / "token"); 
        if not tf.exists(): tf.write_text(os.urandom(16).hex()); tf.chmod(0o600)
        self.token_file = tf; self.coord = Coordinator(self.store, tf.read_text().strip(), port=cfg.get("port", 0))
    def ev(self, kind, **kw):
        with self.lock: self.log_f.write(json.dumps(dict(ts=time.time(), kind=kind, **kw), default=str) + "\n")

    # ---------------------------------------------------------------- lifecycle
    def start(self):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip() if Path("/proc/sys/kernel/random/boot_id").exists() else ""
        old = self.store.meta("boot_id", boot)
        if old and old != boot: self.ev("host_rebooted", expired=self.store.expire_node("main", "boot_id changed"))
        rec = self.store.reap(); self.ev("recover", requeued=rec, counts=self.store.counts())            # restart / reboot recovery: nothing is lost, dead leases go back to the queue
        self.coord.start(); self.ev("coordinator", port=self.coord.port)
        for s in self.cfg.get("services", []): self.svc[s["name"]] = {"cfg": s, "proc": None, "bad": 0}; self._start_service(s["name"])
        for i in range(self.cfg.get("workers", 2)): self._start_worker(f"{self.tag}-m{i}")
        for n in self.cfg.get("nodes", []): self._start_node(n)
        self.thread = threading.Thread(target=self.loop, daemon=True, name="ordivyr-supervisor"); self.thread.start(); return self

    def _spawn(self, argv, name, env=None):
        e = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]), **(env or {})); lf = open(self.run / f"{name}.log", "a")
        return subprocess.Popen(argv, stdout=lf, stderr=subprocess.STDOUT, start_new_session=True, env=e, preexec_fn=_pdeathsig)      # a SIGKILLed supervisor takes its workers/services with it (no orphans); leases simply expire
    def _start_worker(self, name):
        self.procs[name] = self._spawn([sys.executable, "-m", "ordivyr.durable_worker", "--db", self.cfg["db"], "--name", name, "--node", "main", "--ws", self.ws, "--ttl", str(self.ttl)], name); self.ev("worker_start", name=name, pid=self.procs[name].pid)
    def _start_service(self, name):
        s = self.svc[name]; c = s["cfg"]; s["proc"] = self._spawn(c["cmd"], "svc-" + name, c.get("env")); s["bad"] = 0; self.ev("service_start", name=name, pid=s["proc"].pid)
    def _tunnel(self, n):
        self.tun[n["name"]] = subprocess.Popen(["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
                                               + sum([["-R", f"127.0.0.1:{p}:127.0.0.1:{p}"] for p in [self.coord.port] + n.get("forward", [])], []) + [n["ssh"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.ev("tunnel_up", node=n["name"], pid=self.tun[n["name"]].pid)
    def _remote_workers(self, n):
        cmd = ""
        for i in range(n.get("workers", 1)):
            w = f"{self.tag}-{n['name']}{i}"
            cmd += (f"cd {n['dir']} && (setsid nohup env PYTHONPATH={n['dir']} python3 -m ordivyr.durable_worker --url http://127.0.0.1:{self.coord.port} --token-file {n['dir']}/token --name {w} --node {n['name']} "
                    f"--ws {n['dir']}/ws --ttl {self.ttl} {n.get('extra', '')} >> {n['dir']}/{w}.log 2>&1 < /dev/null &) ; ")
        subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", n["ssh"], cmd + "true"], timeout=40, capture_output=True); self.ev("remote_workers_start", node=n["name"])
    def _deploy(self, n):
        """Copy this ordivyr package + the lease token to the node's isolated test directory (idempotent)."""
        pkg = Path(__file__).resolve().parent
        cmd = f"mkdir -p {n['dir']} && cd {n['dir']} && rm -rf ordivyr && tar xzf - && umask 077 && cat > token <<< {self.token_file.read_text().strip()}"
        tar = subprocess.Popen(["tar", "czf", "-", "--exclude=__pycache__", "--exclude=tests", "-C", str(pkg.parent), "ordivyr"], stdout=subprocess.PIPE)
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", n["ssh"], cmd], stdin=tar.stdout, capture_output=True, timeout=120); tar.wait()
        self.ev("deploy", node=n["name"], rc=r.returncode, err=r.stderr.decode()[-200:])
    def _start_node(self, n):
        self._deploy(n); self._tunnel(n); time.sleep(1.0); self._remote_workers(n)

    def block_node(self, name):
        """Fault injection: sever the tunnel to a node and keep it severed (the node's workers can no longer reach the lease API)."""
        self.blocked.add(name); p = self.tun.get(name)
        if p and p.poll() is None:
            try: os.killpg(p.pid, 9)
            except OSError: pass
        self.ev("node_blocked", node=name)
    def unblock_node(self, name): self.blocked.discard(name); self.ev("node_unblocked", node=name)

    # ---------------------------------------------------------------- loop
    def loop(self):
        t_gov = 0.0
        while not self.stop_ev.is_set():
            try:
                for tid, st in self.store.reap(): self.ev("lease_reaped", task=tid, state=st)
                for name, p in list(self.procs.items()):
                    if p.poll() is not None and not self.stop_ev.is_set(): self.ev("worker_died", name=name, rc=p.returncode); self._start_worker(name)
                for name, s in self.svc.items():
                    ok = self._healthy(s["cfg"]["health"])
                    if ok: s["bad"] = 0
                    else:
                        s["bad"] += 1
                        if s["bad"] >= 3 or (s["proc"] and s["proc"].poll() is not None):
                            self.ev("service_down", name=name); self._kill(s["proc"]); self._start_service(name)
                for n in self.cfg.get("nodes", []):
                    p = self.tun.get(n["name"])
                    if n["name"] not in self.blocked and (p is None or p.poll() is not None): self.ev("tunnel_down", node=n["name"]); self._tunnel(n); time.sleep(1.0); self._remote_workers(n)   # reconnect, re-ensure workers
                ctl = self.run / "control"
                if ctl.exists():                                                                   # operator / test fault injection: {"action":"block|unblock","node":name}
                    try: c = json.loads(ctl.read_text()); ctl.unlink(); (self.block_node if c["action"] == "block" else self.unblock_node)(c["node"])
                    except (ValueError, KeyError, OSError) as ex: self.ev("control_error", error=str(ex))
                if time.time() - t_gov > 5:
                    t_gov = time.time(); r = self.sample(); sc = self.gov.scale(r); cap = int(self.maxc * sc); 
                    if cap != self.store.cap(): self.store.set_cap(cap); self.ev("governor", cap=cap, notes=self.gov.notes, sample=r)
            except Exception as e: self.ev("supervisor_error", error=f"{type(e).__name__}: {e}")
            self.stop_ev.wait(0.5)

    @staticmethod
    def _healthy(url):
        try:
            with urllib.request.urlopen(url, timeout=2) as r: return r.status < 500
        except Exception: return False
    @staticmethod
    def _kill(p, sig=9):
        if p and p.poll() is None:
            try: os.killpg(p.pid, sig)
            except OSError: pass
            try: p.wait(5)
            except subprocess.TimeoutExpired: pass

    def shutdown(self):
        """Clean stop: workers get SIGTERM then SIGKILL, services/tunnels/remote workers are stopped; nothing tagged with this run survives."""
        self.stop_ev.set(); self.thread.join(5)
        for p in self.procs.values():
            if p.poll() is None:
                try: os.killpg(p.pid, signal.SIGTERM)
                except OSError: pass
        for p in self.procs.values():
            try: p.wait(8)
            except subprocess.TimeoutExpired: self._kill(p)
        for n in self.cfg.get("nodes", []):
            subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", n["ssh"], f"pkill -f '[{self.tag[0]}]{self.tag[1:]}-' ; true"], timeout=30, capture_output=True)
        for p in self.tun.values(): self._kill(p)
        for s in self.svc.values(): self._kill(s["proc"], signal.SIGTERM); self._kill(s["proc"])
        self.coord.stop(); self.ev("shutdown")

def main(argv=None):
    cfg = json.loads(Path((argv or sys.argv[1:])[0]).read_text()); sup = Supervisor(cfg).start(); done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set()); signal.signal(signal.SIGINT, lambda *_: done.set())
    print(json.dumps({"coordinator_port": sup.coord.port, "token_file": str(sup.token_file)}), flush=True); done.wait(); sup.shutdown()

if __name__ == "__main__": main()
