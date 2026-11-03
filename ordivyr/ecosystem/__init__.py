"""ORDIVYR plugin ecosystem (v0.4): one manifest, one permission model, adapters for MCP, A2A, n8n, LangGraph, native extensions,
and importers for Hermes / OpenClaw / OpenCode skills, agents and MCP configs.

Trust tiers (strongest isolation first):
  declarative  skills / agent definitions: text only, never executed (still untrusted prompt text)
  external     out-of-process: MCP (stdio under bubblewrap when available, or http), A2A, n8n, LangGraph - permissions enforced at the host boundary
  native       in-process Python: NOT sandboxed; loaded only after an explicit, hash-pinned trust decision
Nothing runs at install time. Nothing is enabled, granted or trusted implicitly.
"""
