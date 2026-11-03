# ORDIVYR

**Genesis Protocol** - open multi-agent orchestration core (Apache-2.0, Python >= 3.10, standard library only).

* **Boards** of agents with **License trees** (what each agent may do, with department policy inheritance) and **Gambits** (deterministic IF -> THEN rules).
* **BYOK** providers (Anthropic, OpenAI-compatible, Gemini, Ollama, LM Studio, ...) with a bounded tool loop; paid runs are denied unless explicitly allowed *and* approved.
* **Local LLM / GPU management**: hardware detection (VRAM, compute capability), Ollama / OpenAI-compatible backends, read-only placement planning.
* **Specialised model roles** (router, planner, coder, reviewer, summariser, embedder, vision) assigned from the models you actually have.
* **Hardware-aware templates** that say whether *this machine* can run a team, and with which local models.
* **Scoped memory** (none / mock / local SQLite) enforced by namespace.
* **Plugins**: MCP, A2A, n8n, LangGraph, Hermes/OpenClaw/Claude-style skills, OpenCode configs, native extensions - with permissions, sandboxing and audit. See `ordivyr/docs/PLUGINS.md`.
* **Bridges**: DREX (bounded-decision model, off until you configure it) and JEV Fleet Command (task/approval register).

```
pip install .            # or run from a checkout: ./bin/ordivyr
ordivyr doctor
ordivyr hw
ordivyr templates        # which teams can this machine run?
ordivyr new local-dev-duo -o board.json
ordivyr run board.json --mission "add input validation to the signup form"
python -m pytest         # 70+ tests, no network, no model, no spend
```

Status: **alpha**. See "Limitations" in `ordivyr/docs/PLUGINS.md` and `CHANGELOG.md`. Nothing in ORDIVYR phones home; every network or model call is something you configured.

## Docs
`INSTALL.md` (install and first run), `SECURITY.md` (threat model, reporting), `CHANGELOG.md`, `ordivyr/docs/PLUGINS.md`, `LICENSE` (Apache-2.0), `NOTICE` (Copyright 2026 ELYREON).
