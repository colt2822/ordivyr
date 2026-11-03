# Changelog

## 0.4.0a0 - Genesis Protocol / Plugin Ecosystem
* Security: stdio plugins fail closed when no working bubblewrap is available (override: ORDIVYR_ALLOW_UNCONFINED=1).
* Added SECURITY.md and INSTALL.md; Apache-2.0 licensing and copyright notice finalised.

### Contents (includes the 0.1 Genesis core)
* Open-source core split from the commercial layer; module-aliased compatibility shims keep the commercial product on the same code.
* Hardware detection, local LLM backends, placement planner, model roles, hardware-aware templates (3 local teams added).
* In-process runner (dependency order, License gates, Gambits, memory, BYOK, local models, DREX routing, JEV mirroring).
* Plugin ecosystem: manifest + permissions + hash-pinned store + audit; MCP (stdio/http), A2A client/server, n8n, LangGraph, native, SKILL.md/OpenCode/.mcp.json importers, discovery, pinned catalog; bubblewrap confinement.
* Known gaps: see ordivyr/docs/PLUGINS.md "Limitations". DREX wire contract is tested with an injected transport only (not live-verified).
