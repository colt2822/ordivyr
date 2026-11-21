"""Small-sample statistics for the Arena (stdlib only). Every comparison reports an interval, never a bare point estimate.

  wilson(k, n)            95% Wilson score interval for a pass rate
  mcnemar_exact(b, c)     exact two-sided binomial test on discordant pairs (paired pass/fail, same tasks)
  bootstrap_ci(xs, f)     percentile bootstrap interval for any statistic (deterministic: seeded)
  percentile(xs, q)       linear-interpolation percentile (q in 0..100)
  verdict(...)            'A better' / 'B better' / 'no significant difference' / 'insufficient data' under a fixed rule
"""
from __future__ import annotations
import math, random


def wilson(k, n, z=1.959964):
    if n <= 0: return (0.0, 1.0)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); w = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - w) / d), min(1.0, (c + w) / d))


def percentile(xs, q):
    xs = sorted(x for x in xs if x is not None)
    if not xs: return None
    if len(xs) == 1: return xs[0]
    k = (len(xs) - 1) * q / 100.0; f = math.floor(k); c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def bootstrap_ci(xs, f=mean, n=2000, alpha=0.05, seed=12345):
    xs = [x for x in xs if x is not None]
    if len(xs) < 2: return (None, None)
    r = random.Random(seed); vals = sorted(f([xs[r.randrange(len(xs))] for _ in xs]) for _ in range(n))
    return (vals[int(alpha / 2 * n)], vals[min(n - 1, int((1 - alpha / 2) * n))])


def mcnemar_exact(b, c):
    """b = tasks only A passed, c = tasks only B passed. Two-sided exact p under H0: P(A-only) = P(B-only) = 0.5."""
    n = b + c
    if n == 0: return 1.0
    k = min(b, c); p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def paired(a_pass, b_pass):
    """a_pass / b_pass: {task_id: bool} over the SAME tasks. -> dict with counts, difference and exact p-value."""
    ids = sorted(set(a_pass) & set(b_pass)); bb = sum(1 for i in ids if a_pass[i] and not b_pass[i]); cc = sum(1 for i in ids if b_pass[i] and not a_pass[i])
    ka, kb = sum(a_pass[i] for i in ids), sum(b_pass[i] for i in ids)
    return {"n": len(ids), "a_pass": ka, "b_pass": kb, "a_only": bb, "b_only": cc, "diff": (ka - kb) / len(ids) if ids else None, "p": mcnemar_exact(bb, cc),
            "a_ci": wilson(ka, len(ids)), "b_ci": wilson(kb, len(ids))}


def verdict(pr, alpha=0.05, min_n=20):
    """Fixed, pre-declared rule. Never claims superiority from a small or non-significant sample."""
    if pr["n"] < min_n: return "insufficient data (n=%d < %d)" % (pr["n"], min_n)
    if pr["p"] < alpha: return "A better" if pr["a_pass"] > pr["b_pass"] else "B better"
    return "no significant difference (p=%.3f)" % pr["p"]


def ratio_ci(a, b, n=2000, seed=7):
    """Bootstrap interval for mean(a)/mean(b) (e.g. tokens per validated task): None when either side has < 3 samples."""
    a = [x for x in a if x is not None]; b = [x for x in b if x is not None]
    if len(a) < 3 or len(b) < 3 or not mean(b): return (None, None, None)
    r = random.Random(seed); vals = []
    for _ in range(n):
        ma = mean([a[r.randrange(len(a))] for _ in a]); mb = mean([b[r.randrange(len(b))] for _ in b])
        if mb: vals.append(ma / mb)
    vals.sort(); return (mean(a) / mean(b), vals[int(0.025 * len(vals))], vals[min(len(vals) - 1, int(0.975 * len(vals)))])
