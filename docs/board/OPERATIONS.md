# Board operations

For a personal install start with INSTALL.md. This guide covers running, protecting and recovering a Board.

## Layout of a home

`ordivyr-board init --home H` creates (all inside a 0700 directory):

| File | What it is | Secret? |
|---|---|---|
| `board.db`, `queue.db` | Board registry and the durable job queue (SQLite) | holds hashed keys, sealed values |
| `master.key` | seals secrets, MFA seeds, hosted-worker tokens | **yes** |
| `platform.token` | platform operator key (create orgs, kill switch, metrics) | **yes** |
| `admin.token` | admin key of the personal org `local` | **yes** |
| `worker.token` | token of the built-in personal worker | **yes** |
| `gateway/gateway.json`, `gateway/gateway-secrets.json` | model endpoint and its API key (secrets file is 0600) | **yes** |
| `selfhost.json` | install state (engine, model, slots) | no |
| `ws/` | job workspaces | job content |

`board.db`, `queue.db` and `gateway/gateway.json` are not individually mode 0600; the 0700 home is what protects them. Do not loosen the home's permissions or place it on a shared mount.

## Running

```
ordivyr-board up --home H                      # personal install: also runs the built-in worker
ordivyr-board up --home H --port 8870 --lease-port 8871
```

- API and lease API bind to loopback. A non-loopback `--host` needs `--allow-public-bind`, and **Board does not terminate TLS by default**: either pass `--tls-cert/--tls-key` or put a TLS proxy in front. Without TLS, bearer tokens cross the network in clear text.
- `GET /healthz` (liveness), `GET /readyz` (readiness, includes `killed`), `GET /metrics` (Prometheus; needs the platform key; aggregates only, no tenant data). `GET /v1/health` is the authenticated health report.
- Logs: one JSON access line per request (to stderr, or `--access-log FILE`). Each carries a trace id (`X-Trace-Id`); `GET /v1/traces/{id}` follows it through a job and its children.
- Stop with SIGTERM or SIGINT. Shutdown runs a final metering pass. A hard kill (`kill -9`) is safe: leased jobs are re-leased to a worker and finished jobs are metered at the next start. Verified with the release drill below.

## Model endpoints and spend

- `init` registers one endpoint named `local` in `<home>/gateway`. A loopback endpoint is free.
- A remote HTTPS endpoint is **paid** and is refused until the owner sets spend caps: `init ... --authorize-daily-usd N --authorize-total-usd M` (both required, finite and positive). `doctor` reports not-ok until then.
- Spend is enforced twice: the gateway ledger (`gateway/spend.db`) checks each call against the endpoint caps, and Board checks metered cost plus in-flight reservations against tenant budgets before admitting a job (`/v1/spending`, `/v1/spending/limits`). Metering is exactly-once per job and includes every attempt of a recovered job.
- Keep API keys in key files (`--key-file`), never on a command line.

## Backups

```
ordivyr-board backup --home H --out DIR [--include-personal]
ordivyr-board backup-verify --from DIR
ordivyr-board restore --from DIR --home NEW_HOME
```

- A backup is a directory: online SQLite snapshots plus `manifest.json` (sha256 of every file, schema version, audit-chain head, row counts). It is safe to take while Board is serving. `OUT` must be empty.
- `restore` refuses a non-empty target, then proves the copy: integrity check, audit hash chain, schema version, row counts. The new home is created 0700.
- PostgreSQL: `BOARD_PG_DSN` (preferred over `--pg-dsn`, command lines are visible in `ps`) uses `pg_dump` / `pg_restore` (`--pg-bin` if they are not on PATH); restore needs an empty database. `--include-personal` applies to SQLite homes only. Only SQLite is exercised by the release drill.
- **Default backups contain no credentials.** After a plain restore you have the data but no tokens: use the platform key to create fresh keys, and re-register workers.
- **`--include-personal`** also saves `admin.token`, `worker.token`, `selfhost.json` and the `gateway/` directory including the model API key, so a personal install runs again after restore, at a new path. That archive is as sensitive as those secrets: encrypt it, restrict it, do not put it in shared storage.
- Test restores. A backup you have never restored is a hope. `scripts/release_drill.py` does a complete init, crash, backup, restore, new-job cycle against an installed wheel with a stub model.

## master.key

`<home>/master.key` seals secrets, MFA seeds and hosted-worker tokens. It is never in a backup, on purpose: a stolen backup alone reveals no sealed value.

- **Back it up separately** from the archive (password manager, encrypted removable media, secrets store). Both in one place defeats the separation.
- **Without it, sealed values are unrecoverable**: a restore without it runs, but vault secrets, MFA seeds and hosted tokens cannot be read and must be re-entered.
- **Restore:** run `restore`, then place the saved `master.key` into the new home, mode 0600, before `up`. If no key file is present Board will create a new one, which cannot open the old sealed values.
- **Container secrets:** set `ORDIVYR_BOARD_MASTER_KEY` instead of a file.
- **Rotation is supported:** `POST /v1/admin/vault/rotate` with the platform key adds a new key and re-encrypts every sealed value under it. The key file then holds several `kid base64` lines (newest last); **re-copy the whole file to your off-site store after every rotation**, since the older copy cannot open values sealed under the new key.

## Kill switch, retention, hosted workers

- `POST /v1/admin/kill {"on": true}` (platform key) refuses all submits, claims and schedule fires and cancels every unfinished job; `{"on": false}` reverses it. Audited.
- `PUT /v1/retention {"job_days": N}` (org admin, 1 to 3650) deletes old finished jobs; money and audit records are kept. Live work is never touched.
- Shared pool workers (`up --local-worker`) refuse to start without bubblewrap (`bwrap`) unless `--unsafe-unsandboxed-pool`, which is development only. A personal install's own worker is not a shared pool: it runs your own code with your own credentials, without a sandbox.
- Hosted-worker hardening: `BOARD_ISOLATION_STRICT=1` makes workers refuse tenant code unless seccomp and cgroups are really applied. `BOARD_ALLOW_LOCAL_ENDPOINTS=1` is development only. `BOARD_WORKER_LAUNCHER` is a JSON command prefix for per-tenant OS users on root deployments.

## Mail and public URL

Outbound mail (invites, password reset) is off unless configured, by environment (not command line): `BOARD_MAIL_DIR` writes `.eml` files; or `BOARD_SMTP_HOST`, `BOARD_SMTP_PORT`, `BOARD_SMTP_USER`, `BOARD_SMTP_PASSWORD_FILE`, `BOARD_SMTP_FROM`, `BOARD_SMTP_MODE` (`starttls` or `tls`). `BOARD_PUBLIC_URL` sets the base for links in mail.

## Upgrades

Schema migrations run at start and are checksummed. Back up (and verify) first, stop Board, install the new version, run `ordivyr-board doctor --home H`, then `up`. Do not edit the database by hand. The schema still carries unused legacy tables (subscriptions, invoices, refunds); they are empty and harmless.

## Verifying a release candidate

From a source checkout, using the built wheel in a fresh virtualenv:

```
python scripts/release_drill.py  VENV/bin WORKDIR        # stub model: crash recovery, durable job, memory, backup/restore
python scripts/real_model_drill.py VENV/bin WORKDIR BASE_URL MODEL KEY_FILE   # a model endpoint YOU authorise
python scripts/security_probe.py VENV/bin WORKDIR        # adversarial API probes
```

## Known limits

- Linux only is tested. Python 3.11 is the declared minimum but has been verified by syntax check only, not by running the suite on a 3.11 interpreter.
- bubblewrap is process isolation, not a hardened multi-tenant boundary.
- No external penetration test has been done.
- Tokens are bearer secrets stored in plain files (0600). Rotate by issuing new keys and deleting old ones (`/v1/keys`).
