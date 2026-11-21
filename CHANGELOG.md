# Changelog

## 0.5.0 - Full Board (open source)
* The full self-hosted Board is now open source under Apache-2.0: durable queue with fenced worker leases, multi-tenant Board service (projects, agents, schedules, hosted workers, secrets vault, audit chain, backup/restore), model gateway, persistent memory.
* New `ordivyr-board` entry point.
* BYO-key spending controls kept: tenant gateway budget, job budgets, atomic in-flight reservations. Subscriptions, invoices, refunds, payment webhooks and commercial entitlement are NOT part of the open-source Board; the admission-gate hook (`Board._gates`) lets an external layer add policy.
* Performance: tool step records (output + checkpoint) commit in one fenced transaction; durable lifecycle 14.0 -> 11.0 commits (fsyncs) per 3-step task, +19% tasks/s in `python -m ordivyr.bench_durable`; synchronous=FULL unchanged.
* Requires Python >= 3.11 and `cryptography` >= 50.0.2 (secrets vault, auth). Optional: `psycopg` for PostgreSQL; the separate `ordivyr-lite` package (install its wheel from its GitHub Release) enables `ordivyr-board init --engine lite`.

## 0.4.0a0 - Genesis Protocol / Plugin Ecosystem
* Security: stdio plugins fail closed when no working bubblewrap is available (override: ORDIVYR_ALLOW_UNCONFINED=1).
* Added SECURITY.md and INSTALL.md; Apache-2.0 licensing and copyright notice finalised.

### Contents (includes the 0.1 Genesis core)
* Open-source core split from the commercial layer; module-aliased compatibility shims keep the commercial product on the same code.
* Hardware detection, local LLM backends, placement planner, model roles, hardware-aware templates (3 local teams added).
* In-process runner (dependency order, License gates, Gambits, memory, BYOK, local models, DREX routing, JEV mirroring).
* Plugin ecosystem: manifest + permissions + hash-pinned store + audit; MCP (stdio/http), A2A client/server, n8n, LangGraph, native, SKILL.md/OpenCode/.mcp.json importers, discovery, pinned catalog; bubblewrap confinement.
* Known gaps: see ordivyr/docs/PLUGINS.md "Limitations". DREX wire contract is tested with an injected transport only (not live-verified).
