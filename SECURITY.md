# Security Policy

ORDIVYR is alpha software that can launch plugins and call models you configure. Please read the threat model before trusting it with anything valuable.

## Reporting a vulnerability
Do not open a public issue for security problems. Report privately to the maintainers (ELYREON) through the private vulnerability-reporting
channel of the repository that distributes this package (GitHub "Report a vulnerability"). Include version (`ordivyr version`), steps to reproduce, and impact.
We aim to acknowledge within 7 days. Alpha releases receive fixes in the next alpha; there is no backport policy yet.

## Supported versions
Only the latest 0.x alpha.

## Threat model (what is enforced)
* Installing a plugin never executes it. Archives are extracted with path/symlink/size guards; content is hash-pinned and re-checked before every call (tamper = refusal).
* Native (in-process Python) plugins run only after an explicit `ordivyr plugin trust <id> <tree-hash>`. They are NOT sandboxed: trust equals running your own code.
* Stdio MCP plugins run under bubblewrap (HOME hidden, root read-only, network unshared unless `net:` granted). If no working `bwrap` exists the plugin is
  REFUSED (fail closed). `ORDIVYR_ALLOW_UNCONFINED=1` overrides this and runs plugins with only a scrubbed environment - at your own risk.
* HTTP-based adapters (A2A, n8n, LangGraph, MCP-http) are checked against the plugin's `net:` allowlist by the host before each request.
* Paid model calls are denied unless explicitly allowed and approved. Nothing phones home.

## Known limits
* A `net:` grant to a stdio plugin opens the whole network for that process (no per-host filtering inside the sandbox).
* bubblewrap does not restrict CPU/memory use or the kernel attack surface; it is not a hardened multi-tenant boundary.
* Linux only is tested. macOS/Windows have no confinement backend (stdio plugins are refused there unless you override).
* Model output is untrusted: tool use is bounded by License trees, but prompt injection through fetched content remains possible.
