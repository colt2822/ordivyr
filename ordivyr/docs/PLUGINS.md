# ORDIVYR plugins (v0.4)

One manifest (`ordivyr-plugin.json`, schema `ordivyr-plugin/1`), one permission model, adapters for the ecosystems people already use.

| You have | How it plugs in | Runs where | Isolation |
|---|---|---|---|
| **MCP server** (stdio or Streamable HTTP) | `runtime: mcp` | stdio: child process; http: remote | stdio under **bubblewrap** (home hidden, root read-only, no network unless `net:` granted); http: host allowlist |
| **A2A agent** (Agent2Agent) | `runtime: a2a` - tool `ask`; also serve a board as an A2A agent (`card_for_board`, `handle_rpc`) | remote | host allowlist |
| **n8n workflow** | `runtime: n8n` - one tool per Webhook node; `plugin import n8n workflow.json` | your n8n | host allowlist |
| **LangGraph server** | `runtime: langgraph` - tool `run`, plus assistant discovery | your LangGraph server | host allowlist; API key only if `env:` granted |
| **Hermes / OpenClaw / Claude-style skills** (`SKILL.md`) | `plugin import skills DIR --origin hermes\|openclaw` -> `declarative` | never executed | text only; bundled scripts are not copied |
| **OpenCode** config / agents, **`.mcp.json`** | `plugin import opencode\|mcp\|agents PATH` | as MCP / declarative | secret values are never imported; env *names* become requested permissions |
| **Native Python extension** | `runtime: native`, `register(api)` | in-process | **none**; loaded only after `plugin trust ID HASH` pinned to the exact current content |

## Quick start
```
ordivyr plugin discover                       # read-only scan of this machine; lists what could be imported
ordivyr plugin import skills ~/.hermes/skills/devops --origin hermes
ordivyr plugin install ./my-plugin            # folder, .zip or .tar(.gz); runs NOTHING
ordivyr plugin inspect my-plugin              # manifest, requested permissions, content hash
ordivyr plugin grant my-plugin net:api.example.com env:API_TOKEN
ordivyr plugin enable my-plugin
ordivyr plugin tools my-plugin ; ordivyr plugin call my-plugin ask '{"message": "hi"}'
ordivyr plugin audit
```
An agent may use a plugin only if its License lists the plugin id under `mcp` (the same grant MCP tools already use); department policy still applies.

## Permissions
`net:<host[:port]|local>`, `env:<NAME>`, `exec:<program>`, `fs.read:<abs path>`, `fs.write:<abs path>`, `memory:<ns>`, `tool.write`, `paid`.
Nothing is granted automatically; a grant must be one the manifest requested; widening a plugin's permissions on upgrade clears its grants. Tools not marked read-only
need `tool.write`. Every call is audited (secrets redacted) in `plugin-audit.jsonl`; a per-run call cap and result size cap apply.

## Install safety
Folder/zip/tar install rejects symlinks, absolute or `..` paths, special files, and oversized archives; strips executable bits; records a content hash; refuses to enable or call a
plugin whose files changed since install. Catalog installs require a sha256 pin and verify it before extracting. No default catalog is shipped.

## Limitations (read these)
* **Native plugins are not sandboxed.** Trust = running their code with your privileges.
* Without `bwrap`, stdio MCP plugins get a scrubbed environment but no filesystem/network confinement (`ordivyr doctor` / the UI report which).
* Granting any `net:` to a stdio plugin gives it the whole network (the host cannot filter traffic it does not make).
* HTTP adapters block redirects rather than follow them; servers that require redirects/OAuth flows are not supported yet.
* A2A: client `message/send` + `tasks/get` polling only (no streaming, push notifications, or authenticated cards); server side answers `message/send` only.
* OpenClaw TypeScript plugins and Hermes Python plugins execute inside their own runtimes and cannot be loaded here; only their skills / MCP servers can be used.
* Hermes `config.yaml` MCP sections are not imported (no YAML parser is bundled); export them to `.mcp.json` first.
* n8n: webhook-triggered workflows only; no REST-API workflow management.
* MCP: tools only (no resources, prompts, sampling, roots); the stdio client reuses the core's simple line protocol.
