"""Hardware detection and model-fit estimation (stdlib only, read-only).

`detect()` asks nvidia-smi (when present) for every GPU's name, VRAM, compute capability and driver, and reads CPU/RAM from /proc.
Nothing is loaded, started or changed. Every external call goes through an injectable `run` so tests use captured output.
Compute capability matters: a Pascal card (sm_6x, e.g. Tesla P40) is rejected by CUDA-13-only builds, so the planner flags it.
"""
from __future__ import annotations
import os, re, shutil, subprocess
from dataclasses import dataclass, field, asdict

QUERY = "index,name,memory.total,memory.used,compute_cap,driver_version,uuid"
# approximate bytes per weight for common GGUF quantisations
QUANT_BYTES = {"f16": 2.0, "fp16": 2.0, "bf16": 2.0, "q8_0": 1.07, "q8": 1.07, "q6_k": 0.82, "q5_k_m": 0.71, "q5_k_s": 0.69, "q4_k_m": 0.60, "q4_k_s": 0.57,
               "q4_0": 0.56, "q4": 0.60, "q3_k_m": 0.49, "q3": 0.49, "q2_k": 0.35, "iq4_xs": 0.55}


@dataclass
class GPU:
    index: int; name: str; vram_mb: int; used_mb: int = 0; compute_cap: str = ""; driver: str = ""; uuid: str = ""
    @property
    def free_mb(self): return max(0, self.vram_mb - self.used_mb)
    @property
    def sm(self):
        try: return int(float(self.compute_cap) * 10)
        except ValueError: return 0
    @property
    def notes(self):
        n = []
        if self.sm and self.sm < 70: n.append(f"compute capability {self.compute_cap} (Pascal or older): no tensor cores; builds that only target CUDA 13 will not run on it - use a CUDA 12.x llama.cpp/Ollama build")
        if self.vram_mb and self.vram_mb < 6000: n.append("under 6 GB VRAM: small models only")
        return n


@dataclass
class Hardware:
    gpus: list = field(default_factory=list); cpu_threads: int = 1; ram_mb: int = 0; os: str = ""; disk_free_mb: int = 0; disk_path: str = ""
    @property
    def total_vram_mb(self): return sum(g.vram_mb for g in self.gpus)
    @property
    def largest_gpu_mb(self): return max((g.vram_mb for g in self.gpus), default=0)
    @property
    def tier(self):
        """cpu | small (<=8 GB) | mid (<=16 GB) | large (>=20 GB on one card) | multi (several GPUs, combined >= 24 GB)."""
        if not self.gpus: return "cpu"
        if len(self.gpus) > 1 and self.total_vram_mb >= 24000 and self.largest_gpu_mb < 40000: return "multi"
        m = self.largest_gpu_mb
        return "small" if m <= 8300 else "mid" if m <= 16500 else "large"
    def to_dict(self):
        return {"tier": self.tier, "gpus": [{**asdict(g), "free_mb": g.free_mb, "notes": g.notes} for g in self.gpus], "total_vram_mb": self.total_vram_mb,
                "cpu_threads": self.cpu_threads, "ram_mb": self.ram_mb, "os": self.os, "disk_free_mb": self.disk_free_mb, "disk_path": self.disk_path}


def _run(cmd, timeout=10):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False).stdout


def parse_nvidia_smi(text):
    gpus = []
    for line in (text or "").strip().splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) < 7 or not p[0].isdigit(): continue
        gpus.append(GPU(int(p[0]), p[1], int(float(p[2])), int(float(p[3])), p[4], p[5], p[6]))
    return gpus


def detect(run=None, meminfo_path="/proc/meminfo", disk_path=None):
    run = run or _run; gpus = []
    if run is not _run or shutil.which("nvidia-smi"):
        try: gpus = parse_nvidia_smi(run(["nvidia-smi", f"--query-gpu={QUERY}", "--format=csv,noheader,nounits"]))
        except (OSError, subprocess.SubprocessError): gpus = []
    ram = 0
    try:
        m = re.search(r"MemTotal:\s+(\d+) kB", open(meminfo_path).read()); ram = int(m.group(1)) // 1024 if m else 0
    except OSError: pass
    dp = str(disk_path or os.path.expanduser("~")); free = 0
    try:
        while dp and not os.path.exists(dp): dp = os.path.dirname(dp)
        free = shutil.disk_usage(dp).free // (1024 * 1024)
    except OSError: pass
    return Hardware(gpus, os.cpu_count() or 1, ram, os.uname().sysname if hasattr(os, "uname") else os.name, free, dp)


def params_from_name(name):
    """'qwen3-coder:30b-a3b-q4_K_M' -> (30.0 total params in billions, 'q4_k_m'); (None, None) when unknown. For MoE the total (not active) size is what must fit."""
    n = (name or "").lower(); m = re.findall(r"(?<![a-z0-9.])(\d+(?:\.\d+)?)b(?![a-z])", n)
    q = re.search(r"(q\d(?:_[a-z0-9]+)*|iq\d_[a-z]+|f16|fp16|bf16)", n)
    return (float(m[0]) if m else None), (q.group(1) if q else None)


def model_vram_mb(params_b, quant="q4_k_m", ctx=8192, kv_per_1k_mb=64):
    """Rough weights + KV cache + runtime overhead in MB. An estimate for planning, never a guarantee."""
    bpw = QUANT_BYTES.get((quant or "q4_k_m").lower(), 0.60)
    return int(params_b * 1000 * bpw + (ctx / 1024) * kv_per_1k_mb + 600)


def fits(hw, need_mb):
    """Where does a model of need_mb fit? -> {'where': [gpu indexes] | 'cpu' | None, 'split': bool}. Prefers the single best-fitting GPU, then a split across GPUs."""
    single = sorted((g for g in hw.gpus if g.free_mb >= need_mb), key=lambda g: g.free_mb)
    if single: return {"where": [single[0].index], "split": False}
    if len(hw.gpus) > 1 and sum(g.free_mb for g in hw.gpus) >= need_mb * 1.1:
        return {"where": [g.index for g in sorted(hw.gpus, key=lambda g: -g.free_mb)], "split": True}
    if hw.ram_mb and hw.ram_mb >= need_mb * 1.5: return {"where": "cpu", "split": False}
    return {"where": None, "split": False}
