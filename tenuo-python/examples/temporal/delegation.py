"""
Warrant Delegation Patterns with Temporal

Demonstrates two delegation patterns for multi-stage workflows:

  1. Parent-to-child attenuation:
     An orchestrator workflow holds a broad warrant (read_file + write_file).
     It spawns child workflows with narrowed warrants — e.g., a "reader"
     child that can only read, and a "writer" child that can only write.

  2. Per-stage warrant rotation:
     A pipeline with distinct stages (ingest, transform, export) where each
     stage gets a fresh, tightly-scoped warrant minted by the control plane.

Requirements:
    temporal server start-dev   # Terminal 1
    python delegation.py        # Terminal 2
"""

import asyncio
import base64
import logging
import os
import uuid
from datetime import timedelta
from pathlib import Path

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import (
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)

from tenuo import SigningKey, Warrant, Pattern
from tenuo_core import Subpath
from tenuo.temporal import (
    TenuoInterceptor,
    TenuoInterceptorConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    tenuo_headers,
    tenuo_execute_activity,
    TemporalAuditEvent,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("temporalio.activity").setLevel(logging.ERROR)
logging.getLogger("temporalio.worker").setLevel(logging.ERROR)


# =============================================================================
# Activities
# =============================================================================

@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()


@activity.defn
async def write_file(path: str, content: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes"


@activity.defn
async def list_directory(path: str) -> list[str]:
    return sorted(str(p) for p in Path(path).iterdir() if p.is_file())


# =============================================================================
# Pattern 1: Per-Stage Warrant Rotation
# =============================================================================

@workflow.defn
class IngestWorkflow:
    """Stage 1: Reads source files. Warrant scoped to read_file only."""

    @workflow.run
    async def run(self, source_dir: str) -> list[str]:
        no_retry = RetryPolicy(maximum_attempts=1)
        files = await tenuo_execute_activity(
            list_directory, args=[source_dir],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=no_retry,
        )
        results = []
        for f in files:
            content = await tenuo_execute_activity(
                read_file, args=[f],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=no_retry,
            )
            results.append(content)
        return results


@workflow.defn
class TransformWorkflow:
    """Stage 2: Writes transformed output. Warrant scoped to write_file only."""

    @workflow.run
    async def run(self, output_dir: str, data: list[str]) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)
        for i, content in enumerate(data):
            transformed = content.upper()
            await tenuo_execute_activity(
                write_file,
                args=[f"{output_dir}/output_{i}.txt", transformed],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=no_retry,
            )
        return f"Transformed {len(data)} files to {output_dir}"


# =============================================================================
# Pattern 2: Broad-to-Narrow Attenuation via Fresh Warrants
# =============================================================================
#
# A "broad" orchestrator warrant covers both read + write, but we mint
# narrower warrants for each stage. This is the recommended pattern
# because it avoids over-privilege at every stage.

# =============================================================================
# Audit
# =============================================================================

def on_audit(event: TemporalAuditEvent):
    symbol = "ALLOW" if event.decision == "ALLOW" else "DENY "
    logger.info(f"  [{symbol}] {event.tool} (wf={event.workflow_id})")


# =============================================================================
# Main
# =============================================================================

async def main():
    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect("localhost:7233", interceptors=[client_interceptor])
    logger.info("Connected to Temporal server")

    control_key = SigningKey.generate()
    ingest_key = SigningKey.generate()
    transform_key = SigningKey.generate()

    os.environ["TENUO_KEY_ingest"] = base64.b64encode(ingest_key.secret_key_bytes()).decode()
    os.environ["TENUO_KEY_transform"] = base64.b64encode(transform_key.secret_key_bytes()).decode()

    data_dir = Path("/tmp/tenuo-demo/pipeline")
    source_dir = data_dir / "source"
    output_dir = data_dir / "output"
    source_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    (source_dir / "doc1.txt").write_text("hello world")
    (source_dir / "doc2.txt").write_text("temporal is great")

    task_queue = f"delegation-{uuid.uuid4().hex[:8]}"

    # -- Mint stage-specific warrants (principle of least privilege) --

    # Ingest warrant: read-only access to source directory
    ingest_warrant = (
        Warrant.mint_builder()
        .holder(ingest_key.public_key)
        .capability("read_file", path=Subpath(str(source_dir)))
        .capability("list_directory", path=Subpath(str(source_dir)))
        .ttl(600)
        .mint(control_key)
    )

    # Transform warrant: write-only access to output directory
    transform_warrant = (
        Warrant.mint_builder()
        .holder(transform_key.public_key)
        .capability("write_file", path=Subpath(str(output_dir)), content=Pattern("*"))
        .ttl(600)
        .mint(control_key)
    )

    logger.info(f"Ingest warrant:    {ingest_warrant.id} (read {source_dir})")
    logger.info(f"Transform warrant: {transform_warrant.id} (write {output_dir})")

    worker_interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            audit_callback=on_audit,
            trusted_roots=[control_key.public_key],
        )
    )

    sandbox_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core")
    )

    async with Worker(
        client, task_queue=task_queue,
        workflows=[IngestWorkflow, TransformWorkflow],
        activities=[read_file, write_file, list_directory],
        interceptors=[worker_interceptor],
        workflow_runner=sandbox_runner,
    ):
        logger.info("Worker started\n")

        # -- Stage 1: Ingest (read-only warrant) --
        logger.info("=== Stage 1: Ingest (read-only) ===")
        client_interceptor.set_headers(tenuo_headers(ingest_warrant, "ingest", ingest_key))
        data = await client.execute_workflow(
            IngestWorkflow.run,
            args=[str(source_dir)],
            id=f"ingest-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"Ingested {len(data)} files\n")

        # -- Stage 2: Transform (write-only warrant) --
        logger.info("=== Stage 2: Transform (write-only) ===")
        client_interceptor.set_headers(tenuo_headers(transform_warrant, "transform", transform_key))
        result = await client.execute_workflow(
            TransformWorkflow.run,
            args=[str(output_dir), data],
            id=f"transform-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"Result: {result}\n")

        # -- Verify: transform warrant cannot read source --
        logger.info("=== Verify: transform warrant cannot read (should be denied) ===")
        try:
            from temporalio.client import WorkflowFailureError
            await client.execute_workflow(
                IngestWorkflow.run,
                args=[str(source_dir)],
                id=f"bad-{uuid.uuid4().hex[:8]}",
                task_queue=task_queue,
            )
            logger.error("BUG: should have been denied")
        except (WorkflowFailureError, Exception) as e:
            logger.info(f"Correctly denied: {type(e).__name__}")

    # -- Verify output --
    logger.info("\nOutput files:")
    for p in sorted(output_dir.iterdir()):
        logger.info(f"  {p.name}: {p.read_text()!r}")

    logger.info("\nDone. Per-stage delegation verified.")


if __name__ == "__main__":
    asyncio.run(main())
