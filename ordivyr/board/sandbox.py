"""Namespace sandbox for tenant execution (bubblewrap) + the host-side broker.

Isolation level: `namespace` (user/pid/net/ipc/uts/mount namespaces, no capabilities, private /tmp /proc /dev, read-only system, ONE writable workspace). It is NOT a microVM: the kernel is
shared, there are no cgroups here and no seccomp filter, so a kernel exploit or a fork/CPU bomb limited only by timeouts is out of scope of what this provides (see docs/board/SECURITY_MODEL.md).

What the sandboxed job can see: /usr (ro), the ordivyr package (ro), ITS workspace (rw), a private tmpfs, and one unix socket to the broker. What it cannot: the host filesystem, other tenants'
workspaces, the gateway home (provider keys), Board/queue databases, the network (including host loopback), host processes, host environment.
All credentials stay with the trusted worker (broker side): model calls, Board calls (delegate/memory) and lease heartbeats are brokered; the broker pins endpoint/model to the job's own model_ref.
"""
from __future__ import annotations
import json, os, resource, secrets, shutil, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path
from .. import durable as D
from . import contract as C

PKG = Path(__file__).resolve().parents[1]
ISOLATION = "namespace"                                  # base level; `isolation_level()` reports what is actually applied
TMP_BYTES = 64 << 20
_probe = {}


def available():
    if "ok" not in _probe:
        exe = shutil.which("bwrap"); ok = False
        if exe:
            try: ok = subprocess.run([exe, "--unshare-all", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev", "/usr/bin/true"], capture_output=True, timeout=10).returncode == 0
            except (OSError, subprocess.TimeoutExpired): ok = False
        _probe["ok"] = ok
    return _probe["ok"]


_hard = {"cg": None, "n": 0}
_hlock = threading.Lock()
TASKS_PER_JOB = 128


def hardening():
    """-> {"seccomp": bool, "cgroups": bool, "why": str}: which extra layers this host can really apply (probed, not assumed)."""
    from . import isolate as I
    with _hlock:
        if _hard["cg"] is None: _hard["cg"] = I.Cgroups()
    return {"seccomp": I.seccomp_available(), "cgroups": _hard["cg"].ok, "why": _hard["cg"].why}


def isolation_level():
    h = hardening(); return "+".join(["namespace"] + (["seccomp"] if h["seccomp"] else []) + (["cgroup"] if h["cgroups"] else []))


def strict():
    return os.environ.get("ORDIVYR_ISOLATION_STRICT") == "1"


def launch(cmd, *, name="job", mem_mb=1024, tasks=TASKS_PER_JOB, cpu_pct=None, rlimits=None, **popen_kw):
    """Popen a bwrap command with the extra layers: seccomp deny-list (`--seccomp`), a per-workload cgroup (memory/pids/cpu, cgroup.kill on cleanup). Under ORDIVYR_ISOLATION_STRICT=1 a missing layer REFUSES
    (D.NeedsApproval) instead of silently running with less. -> (Popen, finish) ; finish() destroys the cgroup and returns its stats ({} without cgroups)."""
    from . import isolate as I
    h = hardening()
    if strict() and not (h["seccomp"] and h["cgroups"]): raise D.NeedsApproval(f"needs_owner: isolation layers unavailable on this worker (seccomp={h['seccomp']} cgroups={h['cgroups']} {h['why']}); refusing to run tenant code with less than configured")
    fd = None; cg = None; pre = [rlimits] if rlimits else []
    try:
        if h["seccomp"]:
            fd = I.bpf_fd(); cmd = [cmd[0], "--seccomp", str(fd)] + list(cmd[1:]); popen_kw["pass_fds"] = tuple(popen_kw.get("pass_fds", ())) + (fd,)
        if h["cgroups"]:
            with _hlock: _hard["n"] += 1; n = _hard["n"]
            cg = _hard["cg"].make(f"{name}-{os.getpid()}-{n}", mem_mb=mem_mb, tasks=tasks, cpu_pct=cpu_pct); pre.insert(0, I.Cgroups.enter(cg))       # FIRST: the rlimits below cap RLIMIT_NOFILE at 256 and the parent may hold more fds than that, so any open() after them fails with EMFILE (found by the full regression run)
        popen_kw["preexec_fn"] = (lambda: [f() for f in pre]) if pre else None
        p = subprocess.Popen(cmd, **popen_kw)
    except BaseException:
        if cg: I.Cgroups.destroy(cg)
        raise
    finally:
        if fd is not None: os.close(fd)
    def finish():
        st = I.Cgroups.stats(cg) if cg else {}
        if cg: I.Cgroups.destroy(cg)
        return st
    return p, finish


def _limits(mem_mb, cpu_s, fsize_mb):
    def f():
        if mem_mb: resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20))
        if cpu_s: resource.setrlimit(resource.RLIMIT_CPU, (int(cpu_s), int(cpu_s) + 5))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_mb << 20, fsize_mb << 20)); resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return f


def command(argv, workdir, bind_rw=(), bind_ro=(), env=None, net=False, chdir="/work"):
    """The bwrap argv for running `argv` with `workdir` mounted read-write at /work. Exposed for tests."""
    c = [shutil.which("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
         "--ro-bind", "/usr", "/usr", "--tmpfs", "/usr/share", "--tmpfs", "/usr/local/share", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin", "--proc", "/proc", "--dev", "/dev",
         "--size", str(TMP_BYTES), "--tmpfs", "/tmp", "--ro-bind", str(PKG), "/opt/code/ordivyr", "--bind", str(workdir), "/work"]
    # Hide large host-only runtimes and their package trees. Tenant code gets the
    # interpreter and system libraries needed to execute, not firmware, kernels,
    # office suites, language package caches, or desktop application payloads.
    for path in ("/usr/lib/firmware", "/usr/lib/modules", "/usr/lib/node_modules", "/usr/lib/claude-desktop", "/usr/lib/jvm", "/usr/lib/llvm-18", "/usr/lib/libreoffice", "/usr/lib/i386-linux-gnu/wine", "/usr/lib/x86_64-linux-gnu/wine"):
        if os.path.isdir(path): c += ["--tmpfs", path]
    if not net: c.append("--unshare-net")
    for src, dst in bind_rw: c += ["--bind", str(src), str(dst)]
    for src, dst in bind_ro: c += ["--ro-bind", str(src), str(dst)]
    c += ["--remount-ro", "/", "--chdir", chdir, "--clearenv"]          # the root tmpfs is read-only: the only writable places are /work (bounded by RLIMIT_FSIZE) and the SIZE-CAPPED /tmp
    for k, v in {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/opt/code", **(env or {})}.items(): c += ["--setenv", k, str(v)]
    return c + ["--"] + list(argv)


def run(argv, workdir, timeout=60, mem_mb=1024, fsize_mb=64, env=None, net=False, input=None):
    """Run one command in a fresh sandbox. -> (rc, combined output tail). rc 124 on timeout (the whole pid namespace dies with the sandbox's init).
    Output goes to a size-limited temp file, never to host memory: a job that floods stdout is stopped by RLIMIT_FSIZE, not by the host running out of RAM."""
    Path(workdir).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile() as out:
        p, fin = launch(command(argv, workdir, env=env, net=net), name="run", mem_mb=mem_mb + 256, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, rlimits=_limits(mem_mb, timeout + 5, fsize_mb), start_new_session=True)
        try: p.communicate(input, timeout=timeout); rc = p.returncode
        except subprocess.TimeoutExpired: _kill(p); p.communicate(); rc = 124
        finally: fin()
        out.seek(0, 2); n = out.tell(); out.seek(max(0, n - 8000)); tail = out.read().decode("utf-8", "replace")
    return rc, tail + ("\n[sandbox: timed out]" if rc == 124 else "")


def _kill(p):
    try: os.killpg(p.pid, 9)
    except (ProcessLookupError, PermissionError): pass
    try: p.kill()
    except OSError: pass


# ------------------------------------------------------------------ broker (host side)
MAX_MSG = 4_000_000


class Broker:
    """Serves one job's sandbox over a unix socket (JSON lines). Pins endpoint/model to the job's model_ref; whitelists Board calls; records steps through the lease."""
    def __init__(self, ctx, job, gateway, sockpath):
        self.ctx, self.job, self.gw = ctx, job, gateway; self.sock = socket.socket(socket.AF_UNIX); self.sock.bind(str(sockpath)); os.chmod(sockpath, 0o600); self.sock.listen(4); self.sock.settimeout(0.3)
        self._slots = threading.BoundedSemaphore(8)
        self._spend_lock = threading.Lock(); self._usage = {"prompt_tokens": 0, "completion_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0, "cost_usd": 0.0}; self.started = time.time(); self._has_paid = False
        self.final = None; self.err = None; self.stop = False; self.thread = threading.Thread(target=self._serve, daemon=True); self.thread.start()
    def _serve(self):
        while not self.stop:
            try: c, _ = self.sock.accept()
            except socket.timeout: continue
            except OSError: return
            if not self._slots.acquire(blocking=False):
                c.close(); continue
            c.settimeout(30)
            threading.Thread(target=self._bounded_conn, args=(c,), daemon=True).start()
    def _bounded_conn(self, c):
        try: self._conn(c)
        finally: self._slots.release()
    def _conn(self, c):
        f = c.makefile("rwb")
        try:
            while True:
                line = f.readline(MAX_MSG + 1)
                if not line: break
                if len(line) > MAX_MSG:
                    f.write(b'{"err":{"code":"too_large"}}\n'); f.flush(); break
                try: m = json.loads(line); r = self.handle(m)
                except Exception as e: r = {"err": {"code": type(e).__name__, "msg": str(e)[:500]}}
                f.write(json.dumps(r, default=str).encode() + b"\n"); f.flush()
        except OSError: pass
        finally:
            try: f.close()
            except OSError: pass             # a peer may close while a buffered response is being flushed
            try: c.close()
            except OSError: pass
    def handle(self, m):
        from ..selfhost.gateway import GatewayError
        op = m.get("op"); ctx = self.ctx; ctx.check()
        if op == "chat":
            a = m["args"]; mr = self.job["model_ref"]
            limits = self.job.get("limits") or {}; budget = limits.get("budget_usd")
            max_out = min(int(a.get("max_tokens") or 1024), int(limits.get("max_output_tokens") or 65536), 65536)
            request_id = None; estimate = 0.0
            try:
                with self._spend_lock:
                    ep = self.gw._ep(mr["endpoint"])
                    if ep["paid"] and (budget is None or limits.get("tenant_budget_usd") is None):
                        raise GatewayError("cap_exceeded", "paid calls require both a Board job budget and a tenant gateway budget", mr["endpoint"])
                    request_id = secrets.token_urlsafe(24) if ep["paid"] else None
                    if ep["paid"]:
                        estimate = self.gw._estimate(ep, mr["model"], a["messages"], max_out, tools=a.get('tools'))
                        try: ctx.store.board_gateway_spend(ctx.tid, ctx.fence, "reserve", request_id, estimate)
                        except Exception as e: raise GatewayError("cap_exceeded", f"Board refused the durable spending reservation: {str(e)[:180]}", mr["endpoint"])
                        self._has_paid = True
                    r = self.gw.chat(f"{self.job['org']}.{self.job['project']}.{self.job['agent']['id']}", mr["endpoint"], mr["model"], a["messages"], tools=a.get("tools"), max_tokens=max_out, timeout=min(float(a.get("timeout") or 60), 300), spend_scope=self.job["job_id"], spend_limit_usd=budget)
                    usage = r.usage or {}
                    if not all(isinstance(usage.get(k, 0), int) and usage.get(k, 0) >= 0 for k in ("prompt_tokens", "completion_tokens", "cache_read_tokens", "cache_write_tokens")) or not isinstance(r.cost_usd, (int, float)) or not 0 <= r.cost_usd < float("inf"):
                        if ep["paid"]:
                            try: ctx.store.board_gateway_spend(ctx.tid, ctx.fence, "uncertain", request_id, estimate)
                            except Exception: pass
                        raise GatewayError("server", "gateway returned invalid authoritative usage", mr["endpoint"])
                    if ep["paid"]:
                        try: ctx.store.board_gateway_spend(ctx.tid, ctx.fence, "settle", request_id, float(r.cost_usd), usage)
                        except Exception as e:
                            self.err = ("uncertain", f"provider replied but Board could not commit usage: {str(e)[:180]}")
                            raise GatewayError("server", "provider replied but authoritative usage settlement is uncertain", mr["endpoint"], True)
                    for k in ("prompt_tokens", "completion_tokens", "cache_read_tokens", "cache_write_tokens"): self._usage[k] += usage.get(k, 0)
                    self._usage["cost_usd"] += r.cost_usd
            except GatewayError as e:
                if request_id and self.err is None:
                    op = "uncertain" if e.code in ("network", "timeout", "server") else "failed"
                    try: ctx.store.board_gateway_spend(ctx.tid, ctx.fence, op, request_id, estimate)
                    except Exception: self.err = ("uncertain", "provider outcome or durable reservation could not be reconciled")
                return {"gwerr": {"code": e.code, "msg": str(e), "retryable": e.retryable, "endpoint": e.endpoint}}
            return {"ok": {"text": r.text, "tool_calls": r.tool_calls, "usage": r.usage, "cost_usd": r.cost_usd, "model": r.model, "endpoint": r.endpoint, "latency_s": r.latency_s, "finish": r.finish}}
        if op == "step": ctx.write({"op": "output", "tool": str(m["name"])[:60], "args": m.get("args"), "output": str(m.get("out"))[:2000]}); return {"ok": True}
        if op == "board":
            name = m["name"]
            if not C.tool_allowed(self.job, name): return {"err": {"code": "tool_not_granted", "msg": name}}
            a = m.get("args") or {}; s = ctx.store
            try:
                if name == "delegate": r = s.board_delegate(ctx.tid, ctx.fence, {k: a.get(k) for k in ("agent", "prompt", "engine", "key") if a.get(k)})
                elif name == "child_results":
                    end = time.time() + max(0.0, min(float(a.get("wait_s") or 0), 60.0))
                    while True:
                        r = s.board_children(ctx.tid, ctx.fence)
                        if r["all_done"] or time.time() >= end: break
                        ctx.check(); time.sleep(0.4)
                elif name in ("memory_get", "memory_list", "memory_put"):
                    r = s.board_memory(ctx.tid, ctx.fence, name[7:], a.get("ns") or "project", a.get("key"), a.get("value"))
                else: return {"err": {"code": "unknown_tool", "msg": name}}
            except PermissionError as e: return {"err": {"code": "refused", "msg": str(e)}}
            return {"ok": r}
        if op == "done":
            self.final = dict(m["result"])
            claimed = self.final.get("usage") or {}
            if self._has_paid:
                try: summary = ctx.store.board_gateway_spend(ctx.tid, ctx.fence, "summary")
                except Exception as e:
                    self.final = None; self.err = ("uncertain", f"Board usage summary unavailable: {str(e)[:180]}"); return {"err": {"code": "usage_uncertain"}}
                if summary["uncertain_usd"] > 0 or summary["cost_usd"] > float((self.job.get("limits") or {}).get("budget_usd") or 0) + 1e-9:
                    self.final = None; self.err = ("uncertain", f"unresolved or over-budget provider cost ({summary['uncertain_usd']:.6f} uncertain)"); return {"err": {"code": "usage_uncertain"}}
                self._usage.update({k: summary[k] for k in ("prompt_tokens", "completion_tokens", "cache_read_tokens", "cache_write_tokens", "cost_usd")})
            self.final["usage"] = {**claimed, **self._usage, "turns": claimed.get("turns", 0), "tool_calls": claimed.get("tool_calls", 0), "wall_seconds": max(0.0, time.time() - self.started)}
            return {"ok": True}
        if op == "fatal": self.err = ("fatal", m.get("msg")); return {"ok": True}
        if op == "gwfail": self.err = ("gw", m); return {"ok": True}
        raise ValueError("unknown op")
    def close(self):
        self.stop = True
        try: self.sock.close()
        except OSError: pass


def board_handler_sandboxed(ctx, mem_mb=1024):
    """Durable handler for Board jobs on SHARED workers: the whole agent loop (tools, validators) runs inside the namespace sandbox."""
    from ..selfhost.gateway import Gateway
    from . import runtime_adapter as RA
    from .. import durable_worker as W
    job = ctx.payload; ctx.check(); RA.check_job(job)
    if not available(): raise D.NeedsApproval("needs_owner: sandbox unavailable on this worker (bwrap); refusing to run tenant code unsandboxed")
    home = os.environ.get("ORDIVYR_GATEWAY_HOME")
    if not home: raise D.NeedsApproval("needs_owner: this worker has no ORDIVYR_GATEWAY_HOME")
    wsn = (job.get("workspace") or {}).get("name"); wd = (ctx.ws / "board" / job["org"] / job["project"] / wsn) if wsn else ctx.dir; wd.mkdir(parents=True, exist_ok=True, mode=0o700)
    bd = Path(tempfile.mkdtemp(prefix="bjob-")); os.chmod(bd, 0o700); (bd / "job.json").write_text(json.dumps(job)); broker = Broker(ctx, job, Gateway(home), bd / "b.sock"); lim = job.get("limits") or {}
    wall = float(lim.get("max_seconds") or 1800) + 30
    p, fin = launch(command([sys.executable if sys.executable.startswith("/usr/") else "/usr/bin/python3", "-S", "-m", "ordivyr.board.jobrunner"], wd, bind_rw=[(bd, "/run/b")], env={"BOARD_SOCK": "/run/b/b.sock"}), name="job", mem_mb=mem_mb + 256,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=open(bd / "stderr", "wb"), rlimits=_limits(mem_mb, wall, 256), start_new_session=True)
    t0 = time.time()
    try:
        while p.poll() is None:
            try: ctx.check()
            except BaseException: _kill(p); raise
            if time.time() - t0 > wall: _kill(p); raise D.Transient("timeout: sandbox exceeded its wall-clock limit")
            time.sleep(0.15)
        time.sleep(0.05); ctx.check()                      # cancellation / lost lease take precedence over "the sandbox exited"
        if broker.final is None and broker.err is None:
            st = fin(); fin = lambda: {}
            if st.get("oom_kill"): raise D.Fatal(f"memory_limit: sandbox exceeded {mem_mb + 256} MiB (cgroup oom kill, peak {st.get('memory.peak', 0) >> 20} MiB)")
            tail = (bd / "stderr").read_text("utf-8", "replace")[-600:]; raise D.Transient(f"runtime_unavailable: sandbox exited rc={p.returncode} without a result: {tail}")
        if broker.err:
            kind, e = broker.err
            if kind == "fatal": raise D.Fatal(str(e))
            if kind == "uncertain": raise D.NeedsApproval(f"cap_exceeded: unresolved provider spend requires operator reconciliation: {e}")
            raise RA.map_gateway_error(e["code"], e["msg"], e["retryable"])
        ctx.check(); r = broker.final
        bad = C.validate_result(r)
        if bad: raise D.Fatal("invalid_result: " + "; ".join(bad)[:500])
        for e in r["evidence"]: ctx.store.add_evidence(ctx.tid, ctx.fence, e["name"], e["ok"], e["detail"])
        if r["completion"]["tests_passed"] is False: raise W.ValidationFailed("validation_failed: " + "; ".join(e["name"] for e in r["evidence"] if not e["ok"]))
        st = fin(); fin = lambda: {}; r["runtime"] = {**r["runtime"], "isolation": isolation_level(), "peak_mem_mb": (st.get("memory.peak", 0) >> 20) or None}; return r, None
    finally:
        _kill(p); fin(); broker.close(); shutil.rmtree(bd, ignore_errors=True)
