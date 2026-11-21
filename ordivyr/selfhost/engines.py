"""Inference Engine Manager: one interface over llama.cpp, Ollama, vLLM, SGLang and any existing OpenAI-compatible server.

What is real here vs. declared:
  llama.cpp  - REAL lifecycle: spawn `llama-server` in its own process group, GPU pinned by UUID, loopback only, per-instance API key file (0600), health probe, graceful stop (SIGTERM -> SIGKILL on the group),
               RSS watchdog, crash recovery with bounded restarts, VRAM reservation ledger reading LIVE free memory (so other workers' VRAM is respected), refusal of incompatible launches.
  Ollama     - delegated to the existing `ordivyr.llm.OllamaBackend` (list/load/unload); the daemon itself is the owner's system service and is never started or stopped here.
  vLLM/SGLang- detection + compatibility verdict + argv builder only. They are NOT started by this module in this release and are reported `launch: "adapter-only"`; compute-capability minimums are the
               documented ones and are used to REFUSE, never to claim support.
  external   - registered OpenAI-compatible endpoints: health + model list only.
Nothing is pip-installed or downloaded by the manager. Instance state is persisted so a restarted manager can adopt or reap what it started (no orphans).
"""
from __future__ import annotations
import json, os, re, secrets, shutil, signal, socket, subprocess, sys, threading, time, urllib.error, urllib.request
from pathlib import Path
from .. import hw as HW

DENY_PORTS = {11434, 11582, 18434, 18435, 18440, 8090, 8811, 8840, 8830}           # other workers' / owner services: never bind, never probe-kill
PORT_RANGE = range(18500, 18600)
MIN_SM = {"llama.cpp": 0, "ollama": 0, "vllm": 70, "sglang": 75}                     # documented minimum compute capability x10 (0 = CPU/any supported by the build)

class EngineError(RuntimeError):
    def __init__(self, code, msg, **ctx): super().__init__(msg); self.code = code; self.ctx = ctx
    def to_dict(self): return {"error": self.code, "message": str(self), **self.ctx}

def _free_port(deny=DENY_PORTS):
    for p in PORT_RANGE:
        if p in deny: continue
        with socket.socket() as s:
            try: s.bind(("127.0.0.1", p)); return p
            except OSError: continue
    raise EngineError("no_port", "no free port in the ORDIVYR range")

def cuda_runtime_of(lib_dir):
    """Which CUDA runtime a llama.cpp build links (12 or 13) - decides Pascal/Volta support. None for CPU-only builds."""
    for so in sorted(Path(lib_dir).glob("libggml-cuda.so*")):
        try: out = subprocess.run(["ldd", str(so)], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError): continue
        m = re.search(r"libcudart\.so\.(\d+)", out)
        if m: return int(m.group(1))
    return None

def compat(engine, gpu, fmt, cuda_runtime=None):
    """Verdict for running `fmt` on `gpu` (hw.GPU or None=CPU) with `engine`. -> {'ok':bool,'reasons':[...]}"""
    why = []
    if engine == "llama.cpp" and fmt != "gguf": why.append(f"llama.cpp runs GGUF only (got {fmt})")
    if engine in ("vllm", "sglang") and fmt not in ("safetensors",): why.append(f"{engine} needs safetensors/HF-format weights (got {fmt})")
    if engine == "ollama" and fmt not in ("gguf", "safetensors"): why.append(f"ollama imports GGUF/safetensors (got {fmt})")
    if gpu is not None:
        if gpu.sm and gpu.sm < MIN_SM.get(engine, 0): why.append(f"{engine} requires compute capability >= {MIN_SM[engine] / 10:.1f}; {gpu.name} is {gpu.compute_cap}")
        if engine == "llama.cpp" and cuda_runtime and cuda_runtime >= 13 and gpu.sm and gpu.sm < 75: why.append(f"this llama.cpp build links CUDA {cuda_runtime}, which dropped Pascal/Volta (sm_{gpu.sm}); use a CUDA 12 build")
    elif engine in ("vllm", "sglang"): why.append(f"{engine} has no supported CPU mode here")
    return {"ok": not why, "reasons": why}

class Manager:
    def __init__(self, state_dir, llama_server=None, deny_gpus=(), allow_gpus=None, hw_detect=None, deny_ports=DENY_PORTS, max_restarts=2, health_timeout=120):
        self.dir = Path(state_dir); self.dir.mkdir(parents=True, exist_ok=True); os.chmod(self.dir, 0o700); (self.dir / "keys").mkdir(exist_ok=True, mode=0o700); (self.dir / "logs").mkdir(exist_ok=True)
        self.bin = llama_server or os.environ.get("ORDIVYR_LLAMA_SERVER") or next((c for c in (str(Path.home() / "llama.cpp/build/bin/llama-server"), shutil.which("llama-server")) if c and os.access(c, os.X_OK)), None)
        self.deny_gpus = set(deny_gpus); self.allow_gpus = None if allow_gpus is None else set(allow_gpus); self.detect = hw_detect or (lambda: HW.detect(disk_path=str(self.dir))); self.deny_ports = set(deny_ports)
        self.max_restarts = max_restarts; self.health_timeout = health_timeout; self.inst = {}; self._lock = threading.RLock(); self._seq = 0; self.events = []; self._stop = threading.Event()
        self.pending = {}                                                                   # instance id -> (gpu index, mb) reserved but not yet visible in live VRAM
        self._reconcile()

    # ---------------------------------------------------------------- inventory
    def engines(self):
        lib = Path(self.bin).parent if self.bin else None; cu = cuda_runtime_of(lib) if lib else None
        return {"llama.cpp": {"installed": bool(self.bin), "binary": self.bin, "cuda_runtime": cu, "launch": "managed"},
                "ollama": {"installed": bool(shutil.which("ollama")), "launch": "delegated (system service; never started/stopped here)"},
                "vllm": {"installed": self._py_has("vllm"), "launch": "adapter-only", "min_sm": MIN_SM["vllm"]}, "sglang": {"installed": self._py_has("sglang"), "launch": "adapter-only", "min_sm": MIN_SM["sglang"]}}
    @staticmethod
    def _py_has(mod):
        try: return subprocess.run([sys.executable, "-c", f"import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('{mod}') else 1)"], timeout=15).returncode == 0
        except (OSError, subprocess.SubprocessError): return False
    def usable_gpus(self, hw=None):
        hw = hw or self.detect()
        return [g for g in hw.gpus if g.index not in self.deny_gpus and g.uuid not in self.deny_gpus and (self.allow_gpus is None or g.index in self.allow_gpus or g.uuid in self.allow_gpus)]      # policy entries are GPU UUIDs (stable) or indexes
    def vram(self):
        """Live per-GPU free memory minus reservations still in flight. Other workers' usage is already in `used_mb`."""
        hw = self.detect(); pend = {}
        for g, mb in self.pending.values(): pend[g] = pend.get(g, 0) + mb
        return [{"index": g.index, "name": g.name, "total_mb": g.vram_mb, "used_mb": g.used_mb, "reserved_pending_mb": pend.get(g.index, 0), "free_mb": max(0, g.free_mb - pend.get(g.index, 0)),
                 "allowed": g in self.usable_gpus(hw)} for g in hw.gpus]

    # ---------------------------------------------------------------- start / stop
    def start(self, model_path, engine="llama.cpp", gpu=None, ctx=4096, parallel=1, mmproj=None, alias=None, threads=None, nice=5, max_rss_mb=None, port=None, need_mb=None, fmt="gguf", env_extra=None):
        """Start a managed instance. `gpu` = GPU index or None for CPU. Refuses (EngineError) rather than launching something that cannot work."""
        if engine != "llama.cpp": raise EngineError("not_managed", f"{engine} is {self.engines()[engine]['launch']}; this release only starts llama.cpp instances", engine=engine)
        if not self.bin: raise EngineError("engine_missing", "llama-server not found (set ORDIVYR_LLAMA_SERVER or install llama.cpp)")
        mp = Path(model_path)
        if not mp.is_file(): raise EngineError("model_missing", f"{mp} does not exist")
        with open(mp, "rb") as _f: magic = _f.read(4)
        if mp.suffix.lower() != ".gguf" or magic != b"GGUF": raise EngineError("unsupported_format", f"{mp.name} is not a GGUF file (magic check failed)", format=fmt)
        hw = self.detect(); g = None
        if gpu is not None:
            g = next((x for x in hw.gpus if x.index == gpu), None)
            if g is None: raise EngineError("no_such_gpu", f"GPU {gpu} not present")
            if g not in self.usable_gpus(hw): raise EngineError("gpu_denied", f"GPU {gpu} ({g.name}) is reserved by policy (deny list/allow list)", gpu=gpu)
            c = compat(engine, g, fmt, cuda_runtime_of(Path(self.bin).parent))
            if not c["ok"]: raise EngineError("gpu_incompatible", "; ".join(c["reasons"]), gpu=gpu)
        else:
            c = compat(engine, None, fmt)
            if not c["ok"]: raise EngineError("incompatible", "; ".join(c["reasons"]))
        need = need_mb or int(mp.stat().st_size / 1048576 * 1.05 + (ctx / 1024) * 64 * max(1, parallel) + 300) + (int(mmproj_size(mmproj)) if mmproj else 0)
        with self._lock:
            if g is not None:
                free = next(v["free_mb"] for v in self.vram() if v["index"] == gpu)
                if free < need: raise EngineError("no_fit", f"needs ~{need} MiB on GPU {gpu}, {free} MiB free (other processes and pending loads included)", need_mb=need, free_mb=free, gpu=gpu)
            else:
                avail = _mem_available_mb()
                if avail and avail < need * 1.2: raise EngineError("no_fit", f"needs ~{need} MiB RAM, {avail} MiB available", need_mb=need, free_mb=avail)
            port = port or _free_port(self.deny_ports)
            if port in self.deny_ports: raise EngineError("port_denied", f"port {port} belongs to another service")
            self._seq += 1; iid = f"i{int(time.time())}-{self._seq}"; keyf = self.dir / "keys" / f"{iid}.key"; keyf.write_text(secrets.token_hex(24)); os.chmod(keyf, 0o600)
            argv = [self.bin, "-m", str(mp), "--alias", alias or mp.stem, "--host", "127.0.0.1", "--port", str(port), "--ctx-size", str(ctx), "--parallel", str(parallel), "--api-key-file", str(keyf), "--jinja", "--no-webui"]
            argv += ["--n-gpu-layers", "99", "--flash-attn", "on"] if g is not None else ["--n-gpu-layers", "0"]
            if mmproj: argv += ["--mmproj", str(mmproj)]
            if threads: argv += ["--threads", str(threads)]
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/"), "LD_LIBRARY_PATH": str(Path(self.bin).parent), "CUDA_VISIBLE_DEVICES": g.uuid if g is not None else "", **{k: str(v) for k, v in (env_extra or {}).items()}}
            i = {"id": iid, "engine": engine, "model": str(mp), "alias": alias or mp.stem, "gpu": gpu, "gpu_uuid": g.uuid if g else None, "port": port, "key_file": str(keyf), "argv": argv, "env": env, "need_mb": need if g is not None else 0,
                 "ctx": ctx, "mmproj": str(mmproj) if mmproj else None, "state": "starting", "restarts": 0, "pid": None, "started": time.time(), "nice": nice, "max_rss_mb": max_rss_mb, "log": str(self.dir / "logs" / f"{iid}.log"), "last_error": None}
            if g is not None: self.pending[iid] = (gpu, need)
            self.inst[iid] = i
            try: self._spawn(i)
            except Exception: self.pending.pop(iid, None); self.inst.pop(iid, None); raise
            self._persist()
        threading.Thread(target=self._watch, args=(iid,), daemon=True, name="eng-" + iid).start()
        return iid

    def _spawn(self, i):
        log = open(i["log"], "ab"); p = subprocess.Popen(i["argv"], env=i["env"], stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=(lambda: os.nice(i["nice"])) if i["nice"] else None)
        i["pid"] = p.pid; i["proc"] = p; i["state"] = "starting"; i["pgid"] = os.getpgid(p.pid)

    def _auth(self, i): return {"Authorization": "Bearer " + Path(i["key_file"]).read_text().strip()}
    def health(self, iid):
        i = self.inst[iid]
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{i['port']}/health", headers=self._auth(i))
            with urllib.request.urlopen(req, timeout=3) as r: return r.status == 200
        except (urllib.error.URLError, OSError, ValueError): return False
    def wait_ready(self, iid, timeout=None):
        t0 = time.time(); timeout = timeout or self.health_timeout
        while time.time() - t0 < timeout:
            i = self.inst[iid]
            if i["state"] in ("failed", "stopped"): raise EngineError("start_failed", i.get("last_error") or "instance failed to start", log=i["log"])
            if i["state"] == "running": return self.info(iid)
            time.sleep(0.3)
        raise EngineError("start_timeout", f"{iid} not healthy after {timeout}s", log=self.inst[iid]["log"])

    def _watch(self, iid):
        """Health, RSS limit and crash recovery (bounded restarts)."""
        while not self._stop.is_set():
            i = self.inst.get(iid)
            if not i or i["state"] in ("stopped", "failed"): return
            proc = i["proc"]; rc = proc.poll()
            if rc is not None and i["state"] != "stopping":
                i["last_error"] = f"exited rc={rc}; log tail: " + _tail(i["log"]); self.events.append((time.time(), iid, "crashed", rc))
                if i["restarts"] >= self.max_restarts: i["state"] = "failed"; self.pending.pop(iid, None); self._persist(); return
                i["restarts"] += 1; i["state"] = "restarting"; time.sleep(min(5, 1.5 * i["restarts"]))
                with self._lock:
                    if i["state"] == "restarting": self._spawn(i); self._persist()
            elif i["state"] in ("starting", "restarting") and self.health(iid):
                i["state"] = "running"; self.pending.pop(iid, None); self._persist()
            elif i["state"] == "running":
                if i.get("max_rss_mb") and _rss_mb(i["pid"]) > i["max_rss_mb"]: i["last_error"] = f"RSS {_rss_mb(i['pid'])} MiB over limit {i['max_rss_mb']}"; self.events.append((time.time(), iid, "rss_limit", None)); self._kill(i)
            elif i["state"] == "starting" and time.time() - i["started"] > self.health_timeout: i["last_error"] = "health timeout"; self._kill(i)
            time.sleep(0.5)

    def _kill(self, i, grace=8):
        pg = i.get("pgid")
        if not pg: return
        for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 5)):
            try: os.killpg(pg, sig)
            except (ProcessLookupError, PermissionError): break
            t0 = time.time()
            while time.time() - t0 < wait and _group_alive(pg): time.sleep(0.1)
            if not _group_alive(pg): break
        proc = i.get("proc")
        if proc:
            try: proc.wait(2)
            except Exception: pass

    def stop(self, iid, wait_vram=True, timeout=30):
        i = self.inst.get(iid)
        if not i: raise EngineError("unknown_instance", iid)
        i["state"] = "stopping"; before = None
        if i["gpu"] is not None and wait_vram: before = next((v["used_mb"] for v in self.vram() if v["index"] == i["gpu"]), None)
        self._kill(i); i["state"] = "stopped"; self.pending.pop(iid, None)
        freed = None
        if i["gpu"] is not None and wait_vram and before is not None:        # prove no VRAM leak: our reservation must come back
            t0 = time.time()
            while time.time() - t0 < timeout:
                now = next((v["used_mb"] for v in self.vram() if v["index"] == i["gpu"]), before)
                if before - now >= max(50, int(i["need_mb"] * 0.6)): break
                time.sleep(0.5)
            freed = before - now
        try: Path(i["key_file"]).unlink()
        except OSError: pass
        self._persist(); return {"id": iid, "stopped": True, "vram_freed_mb": freed, "group_alive": _group_alive(i.get("pgid"))}

    def restart(self, iid):
        i = self.inst[iid]; self.stop(iid); return self.start(i["model"], gpu=i["gpu"], ctx=i["ctx"], mmproj=i.get("mmproj"), alias=i["alias"], nice=i["nice"], max_rss_mb=i["max_rss_mb"], need_mb=i["need_mb"] or None)

    def switch(self, iid, new_model, **kw):
        """Safe model switch: stop (and verify VRAM returned) BEFORE the new load's fit check; if the new model cannot start, the old one is NOT restored silently - the error says so."""
        i = self.inst[iid]; g = i["gpu"]; self.stop(iid)
        try: return self.start(new_model, gpu=kw.pop("gpu", g), ctx=kw.pop("ctx", i["ctx"]), **kw)
        except EngineError as e: e.ctx["previous_instance_stopped"] = iid; raise

    def info(self, iid):
        i = self.inst[iid]; return {k: i.get(k) for k in ("id", "engine", "alias", "model", "gpu", "port", "state", "restarts", "pid", "need_mb", "ctx", "last_error", "log", "started")} | {"base_url": f"http://127.0.0.1:{i['port']}/v1", "rss_mb": _rss_mb(i["pid"]) if i["state"] == "running" else 0}
    def list(self): return [self.info(k) for k in self.inst]
    def credentials(self, iid): i = self.inst[iid]; return {"base_url": f"http://127.0.0.1:{i['port']}/v1", "key": Path(i["key_file"]).read_text().strip()}     # for the gateway only - never handed to agents
    def shutdown(self):
        self._stop.set()
        for k in list(self.inst):
            if self.inst[k]["state"] not in ("stopped", "failed"): self.stop(k, wait_vram=False)

    # ---------------------------------------------------------------- persistence / orphan safety
    def _persist(self):
        s = {k: {x: v[x] for x in ("id", "pid", "pgid", "port", "model", "gpu", "state", "key_file", "alias") if x in v} | {"bin": os.path.basename(v["argv"][0])} for k, v in self.inst.items() if v["state"] not in ("stopped",)}
        t = self.dir / "instances.json.tmp"; t.write_text(json.dumps(s)); os.replace(t, self.dir / "instances.json")
    def _reconcile(self):
        """After a manager restart: anything we started that is still alive and matches its recorded cmdline is reaped (no orphan GPU processes), then the record is cleared."""
        try: s = json.loads((self.dir / "instances.json").read_text())
        except (OSError, ValueError): return
        for k, v in s.items():
            pid = v.get("pid")
            try: cmd = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="ignore")
            except (OSError, TypeError): continue
            if v.get("bin") and v["bin"] in cmd and str(v.get("port")) in cmd:
                try: os.killpg(v["pgid"], signal.SIGTERM); time.sleep(2); os.killpg(v["pgid"], signal.SIGKILL)
                except (ProcessLookupError, PermissionError, KeyError): pass
                self.events.append((time.time(), k, "reaped_orphan", pid))
        (self.dir / "instances.json").write_text("{}")

def mmproj_size(p):
    try: return os.path.getsize(p) / 1048576
    except OSError: return 0
def _group_alive(pg):
    """True if any NON-zombie process is in process group `pg` (a killed-but-unreaped child must not count as alive)."""
    if not pg: return False
    for d in Path("/proc").iterdir():
        if not d.name.isdigit(): continue
        try:
            st = (d / "stat").read_text(); rest = st[st.rindex(")") + 2:].split()
            if int(rest[2]) == pg and rest[0] != "Z": return True
        except (OSError, ValueError, IndexError): continue
    return False
def _rss_mb(pid):
    try: return int(re.search(r"VmRSS:\s+(\d+)", Path(f"/proc/{pid}/status").read_text()).group(1)) // 1024
    except (OSError, AttributeError): return 0
def _mem_available_mb():
    try: return int(re.search(r"MemAvailable:\s+(\d+)", open("/proc/meminfo").read()).group(1)) // 1024
    except (OSError, AttributeError): return 0
def _tail(p, n=300):
    try: return Path(p).read_text(errors="ignore")[-n:]
    except OSError: return ""
