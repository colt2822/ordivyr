# ORDIVYR Board — Security & Reliability Report (2026-11-13)

Sprint V, commits through `7cc9545`. Baseline 75 tests → **95 passed, 0 failed**.

## 1. Failure-injection (ordivyr/tests/test_failure_injection.py, 6 tests)
Scenarios injected into the Runner with real exceptions on the model/tool path:
- **Provider timeout (total)**: all-local board with an always-timing-out backend → run `failed`, every agent `failed`/`blocked`, `failures == 1` (contained; no retry storm), error type + message recorded in the persisted transcript.
- **Provider error (partial)**: one broken model among deterministic agents → run `partial`; healthy agents complete, failed agent records `TimeoutError` with 0 tokens.
- **Failed dependency → downstream blocked**: dependent agent is `blocked` with "a dependency failed" note; it never executes on missing input.
- **Transient failure → retry**: documented recovery path is a fresh run; attempt 1 `failed`, attempt 2 `done`, distinct run ids, no cross-contamination.
- **No side effects on failure**: the tool-executing agent that fails on its model call has zero tokens and no partial writes — the ToolBox is only constructed after the model responds.
- **Event-log evidence**: failures now also land in the run event log (`self._note` on the failure branch — fixed this sprint; previously only agent state carried it).

Residual gaps (documented, not hidden): no mid-run crash resume (a kill between agents restarts the whole run — safe because tool effects are file-scoped to the workdir); no automatic retry-with-backoff inside a run (bounded single-attempt by design).

## 2. Adversarial sandbox (ordivyr/tests/test_sandbox_adversarial.py, 14 tests)
Against `agentloop.ToolBox` — the boundary an influenced/attacked agent faces:
- **Path escapes**: absolute paths, `..` traversal, symlink escape, NUL bytes → all rejected (`use a relative path` / `path escapes` / `symlinks are not followed`).
- **Write containment**: write outside root rejected and verified absent on disk; `.git` (root and nested) write-blocked; >400 KB content rejected.
- **Permission gates**: `write_file` without write permission and `fetch_url` without web permission are refused and have no effect.
- **SSRF guard**: DNS resolving to loopback / link-local (169.254.169.254 metadata) → blocked; mixed global+private answer sets → blocked (all addresses must be global); ftp/file schemes and user:pass@ URLs rejected.
- Result: **all 14 held with no code changes needed** — defenses were already present and are now pinned by tests.

## 3. Real multi-agent execution evidence
- Board: Planner → Coder (ollama `gemma3:4b`, resident on P40, placement verified by GPU uuid before the run).
- Mission: "Design a retry policy for a webhook dispatcher…" → both agents `done` (343/681 tokens), transcript persisted: `~/.local/state/ordivyr/runs/run-4687f1cf.json` (also `/tmp/ordivyr-demo/state/runs/`).
- Deterministic (offline) handoff coverage exists in the suite; gemma3:4b runs prove the local-inference path.

## 4. Packaging
- `python -m build --sdist` → `dist/ordivyr-0.4.0a0.tar.gz` + `SHA256SUMS`; installs into a clean venv; `ordivyr doctor` reports tier/GPUs/backends and the Pascal/CUDA-12 guidance.
- New test files ship inside the sdist (package `ordivyr*` find includes `ordivyr/tests`).

## 5. Open-source release blockers (remaining, honest)
1. README quickstart still references a local tarball name; publish flow (PyPI account, trusted publishing or manual upload) is not set up — needs an owner decision.
2. No CI workflow in-repo (GitHub Actions for pytest on 3.10–3.12) — recommended before first public tag.
3. Sandbox is process-level (path/web/permission gates in-process); stronger isolation (bwrap per-plugin) is optional-dep documented, not enforced — README should keep saying so plainly.
4. Transcripts grow unboundedly under `runs/` — add a retention/rotate note or command.

None of the above block tagging a source release; 1–2 block a polished PyPI launch.
