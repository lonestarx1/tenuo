---
title: Temporal Integration
description: Warrant-based authorization for durable workflows
---

# Tenuo Temporal Integration

> **Status**: Implemented (Activity authorization + PoP + Delegation)

## Overview

Tenuo integrates with [Temporal](https://temporal.io) to bring warrant-based authorization to durable workflows. Activities are transparently authorized against the workflow's warrant without code changes to your activity definitions.

**Key Features:**
- **Activity-level authorization**: Each activity execution is authorized against warrant constraints
- **Proof-of-Possession (PoP)**: Ed25519 signature verification when `trusted_roots` is configured
- **Warrant propagation**: Warrants flow through workflow headers automatically
- **Child workflow delegation**: Attenuate warrants when spawning child workflows
- **Fail-closed**: Missing or invalid warrants block execution by default
- **Enterprise key management**: VaultKeyResolver, KMSKeyResolver, CompositeKeyResolver

---

## Installation

```bash
uv pip install "tenuo[temporal]"
```

Requires Temporal server running locally or in production.

---

## Quick Start

### Basic Workflow Protection

```python
from datetime import timedelta
from pathlib import Path
from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy
from temporalio.worker import Worker

from tenuo import SigningKey, Warrant
from tenuo_core import Subpath
from tenuo.temporal import (
    AuthorizedWorkflow,
    TenuoInterceptor,
    TenuoInterceptorConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    tenuo_headers,
    tenuo_execute_activity,
)

# Define protected activities (no Tenuo-specific code needed)
@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()

@activity.defn
async def write_file(path: str, content: str) -> str:
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes"

# Define workflow — use AuthorizedWorkflow for automatic PoP calculation
@workflow.defn
class DataProcessingWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, input_path: str, output_path: str) -> str:
        # Automatic PoP signature generation via self.execute_authorized_activity
        data = await self.execute_authorized_activity(
            read_file,
            args=[input_path],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )

        processed = data.upper()
        
        await self.execute_authorized_activity(
            write_file,
            args=[output_path, processed],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )

        return f"Processed {len(data)} bytes"

# Setup
async def main():
    # Client interceptor injects warrant headers into workflow start
    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect("localhost:7233",
                                  interceptors=[client_interceptor])

    # Generate keys
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # Issue warrant using the builder API
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/data/input"))
        .capability("write_file", path=Subpath("/data/output"))
        .ttl(3600)
        .mint(control_key)
    )

    # Configure worker interceptor with full PoP verification
    interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            trusted_roots=[control_key.public_key],  # enables Authorizer + PoP
        )
    )

    # Start worker with interceptor
    async with Worker(
        client,
        task_queue="data-processing",
        workflows=[DataProcessingWorkflow],
        activities=[read_file, write_file],
        interceptors=[interceptor],
    ):
        # Set warrant headers, then execute workflow
        client_interceptor.set_headers(
            tenuo_headers(warrant, "agent-key-1", agent_key)
        )
        result = await client.execute_workflow(
            DataProcessingWorkflow.run,
            args=["/data/input/report.txt", "/data/output/report.txt"],
            id="process-001",
            task_queue="data-processing",
        )
```

**What happens:**
1. `TenuoClientInterceptor` injects warrant + signing key into workflow headers
2. Each `tenuo_execute_activity()` call computes a PoP signature via `warrant.sign()`
3. `TenuoActivityInboundInterceptor` extracts the warrant and PoP from module-level stores
4. `Authorizer.authorize()` verifies chain, expiry, capabilities, constraints, and PoP
5. Activity executes only if all checks pass

---

## Configuration

### Interceptor Config

```python
from tenuo.temporal import TenuoInterceptorConfig

config = TenuoInterceptorConfig(
    key_resolver=EnvKeyResolver(),        # Required: key resolution strategy
    on_denial="raise",                    # "raise" | "log" | "skip"
    trusted_roots=[control_key.public_key],  # Enables Authorizer + PoP verification
    require_warrant=True,                 # Fail-closed: deny if no warrant
    block_local_activities=True,          # Prevent local activity bypass
    redact_args_in_logs=True,             # Prevent secret leaks in logs
    max_chain_depth=10,                   # Max delegation depth
    audit_callback=on_audit,              # Optional audit event handler
    metrics=TenuoMetrics(),               # Optional Prometheus metrics
)
```

### Key Resolvers

**Development: EnvKeyResolver**
```python
from tenuo.temporal import EnvKeyResolver
import os
import base64

# Set environment variable
os.environ["TENUO_KEY_agent1"] = base64.b64encode(
    agent_key.secret_key_bytes()
).decode()

resolver = EnvKeyResolver()  # Reads from TENUO_KEY_{key_id}
```

**Production: VaultKeyResolver**
```python
from tenuo.temporal import VaultKeyResolver

resolver = VaultKeyResolver(
    url="https://vault.company.com:8200",
    mount="secret",
    path_template="tenuo/keys/{key_id}",
    cache_ttl=300,  # 5 minute cache
)
```

**Fallback Chain: CompositeKeyResolver**
```python
from tenuo.temporal import CompositeKeyResolver

resolver = CompositeKeyResolver([
    VaultKeyResolver(url="https://vault.prod"),  # Try Vault first
    EnvKeyResolver(),                            # Fallback to env vars
])
```

---

## Proof-of-Possession

When `trusted_roots` is configured, Tenuo enforces PoP verification for all activity executions. The challenge is a CBOR-serialized tuple of `(warrant_id, tool, sorted_args, window_ts)` signed with the holder's Ed25519 key.

### Automatic PoP with tenuo_execute_activity

```python
from tenuo.temporal import tenuo_execute_activity

@workflow.defn
class MyWorkflow:
    @workflow.run
    async def run(self) -> str:
        # Automatically signs PoP challenge
        result = await tenuo_execute_activity(
            read_file,
            args=["/data/report.txt"],
            start_to_close_timeout=timedelta(seconds=30),
        )
        return result
```

## Manual Activity Execution

For advanced use cases (e.g., multi-warrant workflows or delegation) where `AuthorizedWorkflow` is too restrictive, use the `tenuo_execute_activity` helper directly:

```python
from tenuo.temporal import tenuo_execute_activity

@workflow.defn
class PipelineWorkflow:
    @workflow.run
    async def run(self, path: str) -> str:
        # Manually specify timeouts and retry policy
        return await tenuo_execute_activity(
            read_file,
            args=[path],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
```

### PoP Challenge Format

The PoP signature is computed deterministically by the Rust core:

```
domain_context = b"tenuo-pop-v1"
window_ts      = (unix_now // 30) * 30          # 30-second bucket
challenge_data = CBOR( (warrant_id, tool, sorted_args, window_ts) )
preimage       = domain_context || challenge_data
signature      = Ed25519.sign(signing_key, preimage)   # 64 bytes
```

In Python, this is a single call:

```python
pop_signature = warrant.sign(signing_key, "read_file", {"path": "/data/file.txt"})
# Returns 64 raw bytes; valid for 4 windows (2 minutes)
```

`tenuo_execute_activity()` handles this automatically. You only need `warrant.sign()` directly if building custom tooling outside of Temporal.

---

## Child Workflow Delegation

Attenuate warrants when spawning child workflows:

```python
from tenuo.temporal import attenuated_headers

@workflow.defn
class ParentWorkflow:
    @workflow.run
    async def run(self) -> str:
        # Parent has: read_file + write_file

        # Child gets only read_file with reduced TTL
        result = await workflow.execute_child_workflow(
            ChildWorkflow.run,
            args=["/data/input"],
            headers=attenuated_headers(
                tools=["read_file"],  # Subset of parent tools
                ttl_seconds=60,       # Shorter than parent
            ),
        )
        return result
```

---

## Decorators

### @tool() - Activity-to-Tool Mapping

Map activity names to different tool names in warrants:

```python
from tenuo.temporal import tool

@activity.defn
@tool("read_file")
async def fetch_document(doc_id: str) -> str:
    """Activity name is 'fetch_document', warrant checks 'read_file'."""
    return await storage.get(doc_id)
```

### @unprotected - Local Activities

Mark activities as safe for local execution (bypass interceptor):

```python
from tenuo.temporal import unprotected

@activity.defn
@unprotected
async def get_config_value(key: str) -> str:
    """Internal config lookup - no warrant needed."""
    return config[key]

# Can be used as local activity
await workflow.execute_local_activity(
    get_config_value,
    args=["database_url"],
)
```

---

## Audit Events

Subscribe to authorization decisions:

```python
from tenuo.temporal import TemporalAuditEvent

def on_audit(event: TemporalAuditEvent):
    if event.decision == "ALLOW":
        logger.info(
            f"Allowed: {event.tool} in {event.workflow_type} "
            f"(warrant: {event.warrant_id})"
        )
    else:
        logger.warning(
            f"Denied: {event.tool} in {event.workflow_type} - "
            f"{event.denial_reason}"
        )

config = TenuoInterceptorConfig(
    key_resolver=resolver,
    audit_callback=on_audit,
    audit_allow=True,   # Log allowed actions
    audit_deny=True,    # Log denied actions
)
```

---

## Observability

### Prometheus Metrics

```python
from tenuo.temporal import TenuoMetrics

metrics = TenuoMetrics(prefix="tenuo_temporal")

config = TenuoInterceptorConfig(
    key_resolver=resolver,
    metrics=metrics,
)

# Exposes metrics at /metrics:
# - tenuo_temporal_activities_authorized_total{tool, workflow_type}
# - tenuo_temporal_activities_denied_total{tool, reason, workflow_type}
# - tenuo_temporal_authorization_latency_seconds_bucket{tool}
```

---

## Security Model

### Fail-Closed by Default

All security checks default to deny:

| Check | Missing/Invalid | Behavior |
|-------|----------------|----------|
| Warrant header | Missing | Denied (require_warrant=True) |
| Warrant expired | Expired | Raises WarrantExpired |
| Tool not in warrant | Not allowed | Raises ConstraintViolation |
| Constraint violated | Args don't match | Raises ConstraintViolation |
| PoP signature | Missing/invalid | Raises PopVerificationError |
| Local activity | Protected function | Raises LocalActivityError |

### Replay Safety

PoP challenges use 30-second time-window bucketing (`floor(unix_now / 30) * 30`) for replay tolerance. Signatures remain valid for 4 windows (2 minutes). The `tenuo_execute_activity()` helper handles PoP signing inside the workflow sandbox via module-level stores, avoiding issues with Temporal's deterministic replay.

---

## Exceptions

All exceptions include `error_code` for wire format compatibility:

```python
from tenuo.temporal import (
    ConstraintViolation,      # error_code: "CONSTRAINT_VIOLATED"
    WarrantExpired,           # error_code: "WARRANT_EXPIRED"
    ChainValidationError,     # error_code: "CHAIN_INVALID"
    PopVerificationError,     # error_code: "POP_VERIFICATION_FAILED"
    LocalActivityError,       # error_code: "LOCAL_ACTIVITY_BLOCKED"
    KeyResolutionError,       # error_code: "KEY_NOT_FOUND"
)
```

---

## Best Practices

1. **Use tenuo_execute_activity()** for automatic PoP signing
2. **Set up VaultKeyResolver** for production key management
3. **Enable audit logging** to track authorization decisions
4. **Use @unprotected** sparingly - only for truly internal operations
5. **Attenuate warrants** for child workflows to enforce least privilege
6. **Configure metrics** for observability in production
7. **Keep TTLs short** for sensitive operations (minutes, not hours)

---

## Examples

| Example | Description |
|---------|-------------|
| [`demo.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/demo.py) | Basic warrant enforcement with authorized / unauthorized access |
| [`multi_warrant.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/multi_warrant.py) | Multi-tenant isolation: separate warrants per workflow |
| [`delegation.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/delegation.py) | Per-stage pipeline authorization with least-privilege warrants |

### Per-Stage Pipeline (from delegation.py)

Each pipeline stage gets its own tightly-scoped warrant:

```python
# Ingest warrant: read-only
ingest_warrant = (
    Warrant.mint_builder()
    .holder(ingest_key.public_key)
    .capability("read_file", path=Subpath("/data/source"))
    .capability("list_directory", path=Subpath("/data/source"))
    .ttl(600)
    .mint(control_key)
)

# Transform warrant: write-only
transform_warrant = (
    Warrant.mint_builder()
    .holder(transform_key.public_key)
    .capability("write_file", path=Subpath("/data/output"), content=Pattern("*"))
    .ttl(600)
    .mint(control_key)
)

# Switch warrant between stages
client_interceptor.set_headers(tenuo_headers(ingest_warrant, "ingest", ingest_key))
data = await client.execute_workflow(IngestWorkflow.run, ...)

client_interceptor.set_headers(tenuo_headers(transform_warrant, "transform", transform_key))
await client.execute_workflow(TransformWorkflow.run, ...)
```

---

## Comparison with Other Integrations

| Integration | Use Case | Durable | PoP | Delegation |
|-------------|----------|---------|-----|------------|
| **OpenAI** | Streaming agents | No | Optional | No |
| **LangChain** | Tool chains | No | Optional | Via context |
| **CrewAI** | Multi-agent crews | No | Yes (Tier 2) | Yes |
| **Temporal** | Long-running workflows | Yes | Mandatory | Yes |

Temporal integration is designed for workflows that may run for hours or days, with full replay support and durable state.

---

## More Information

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Core Concepts](./concepts.md)
- [Security Model](./security.md)
- [Example Code](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal)
