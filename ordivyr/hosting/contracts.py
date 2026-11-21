"""Core execution contracts shared by all three deployment modes (self-hosted, managed orchestration, fully hosted).

Only the contracts live here. Every contract has (a) an embedded stdlib implementation in `local.py` that the self-hosted product uses, and (b) an executable
contract test in tests/test_hosting_contracts.py that ANY adapter must pass. Distributed backends (Postgres, Redis, S3, containers, cloud sandboxes) are
deliberately NOT shipped: they are added only when a concrete use case exists, by registering a factory (see registry.py) and passing the same contract tests.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

LOCAL_TENANT = "local"


@dataclass(frozen=True)
class Principal:
    id: str
    tenant: str = LOCAL_TENANT
    role: str = "admin"            # admin | worker | user
    def can(self, action): return self.role == "admin" or (self.role == "worker" and action in ("claim", "heartbeat", "complete", "report")) or (self.role == "user" and action in ("submit", "read"))


@dataclass(frozen=True)
class Endpoint:
    base: str
    key: str = ""                  # customer-owned credential (BYOK); never logged, never stored in task payloads
    kind: str = "openai"


@dataclass
class ExecSpec:
    argv: list
    cwd: str
    env: dict = field(default_factory=dict)
    timeout_s: float = 600.0
    max_memory_mb: int = 0         # 0 = unlimited
    max_cpu_s: int = 0
    max_procs: int = 0
    network: str = "inherit"       # inherit | none  (isolation backends must enforce; LocalProcessExecutor can only inherit)


@runtime_checkable
class TaskStore(Protocol):
    """Persistence + durable queue. The reference implementation is ordivyr.durable.Store; RemoteStore (HTTP lease API) satisfies the same surface."""
    def submit(self, kind, payload, idem_key=None, max_attempts=3, priority=0): ...
    def claim(self, worker, node="main", ttl=15.0, kinds=None): ...
    def heartbeat(self, tid, fence, ttl=15.0): ...
    def claim_many(self, worker, node="main", ttl=15.0, kinds=None, limit=16): ...
    def heartbeat_many(self, leases, ttl=15.0): ...
    def begin(self, tid, fence, phase="running"): ...
    def checkpoint(self, tid, fence, phase, data): ...
    def complete(self, tid, fence, result, promote=None): ...
    def fail(self, tid, fence, reason, retry=True, backoff=1.0): ...
    def get(self, tid): ...
    def counts(self): ...


@runtime_checkable
class ExecHandle(Protocol):
    def wait(self, timeout=None): ...
    def kill(self): ...
    def usage(self): ...


@runtime_checkable
class Executor(Protocol):
    isolation: str                 # 'process' | 'container' | 'microvm' - UNTRUSTED customer code needs more than 'process'
    def start(self, spec: ExecSpec) -> ExecHandle: ...


@runtime_checkable
class ArtifactStorage(Protocol):
    def put(self, tenant, key, data: bytes) -> str: ...
    def get(self, tenant, key) -> bytes: ...
    def list(self, tenant, prefix="") -> list: ...
    def delete(self, tenant, key) -> bool: ...
    def expire(self, tenant, older_than_s) -> int: ...


@runtime_checkable
class ModelProvider(Protocol):
    def resolve(self, tenant, name) -> Endpoint: ...


@runtime_checkable
class Authenticator(Protocol):
    def authenticate(self, token) -> "Principal | None": ...


@runtime_checkable
class Meter(Protocol):
    def record(self, tenant, kind, qty, ref=""): ...
    def usage(self, tenant, since=0.0) -> dict: ...


class QuotaExceeded(Exception): pass


@runtime_checkable
class QuotaPolicy(Protocol):
    def check(self, tenant, kind, active, requested=1): ...     # raises QuotaExceeded
