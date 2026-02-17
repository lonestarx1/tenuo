"""
AuthorizedWorkflow Demo — The "easy mode" for Tenuo + Temporal

Shows how to use AuthorizedWorkflow as a base class instead of calling
tenuo_execute_activity() manually.  AuthorizedWorkflow gives you:

  - Fail-fast validation: workflow aborts immediately if started without
    Tenuo headers (no cryptic errors mid-execution).
  - self.execute_authorized_activity(): single method with automatic PoP.
  - Works with asyncio.gather for parallel activities.

Compare with demo.py which uses the lower-level tenuo_execute_activity()
directly — both approaches are correct, but AuthorizedWorkflow is less
boilerplate for the common case.

Requirements:
    pip install temporalio tenuo

Usage:
    temporal server start-dev   # Terminal 1
    python authorized_workflow_demo.py   # Terminal 2
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

from tenuo import SigningKey, Warrant
from tenuo_core import Subpath
from tenuo.temporal import (
    AuthorizedWorkflow,
    TenuoInterceptor,
    TenuoInterceptorConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    tenuo_headers,
    TemporalAuditEvent,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("temporalio.activity").setLevel(logging.ERROR)
logging.getLogger("temporalio.worker").setLevel(logging.ERROR)


# =============================================================================
# Activities — plain functions, no Tenuo boilerplate needed
# =============================================================================

@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()


@activity.defn
async def list_directory(path: str) -> list[str]:
    return sorted(str(p) for p in Path(path).iterdir())


# =============================================================================
# Workflow — inherits AuthorizedWorkflow for automatic authorization
# =============================================================================

@workflow.defn
class FileAnalysisWorkflow(AuthorizedWorkflow):
    """Analyze files in a directory.

    AuthorizedWorkflow validates Tenuo headers at workflow start and
    provides self.execute_authorized_activity() with automatic PoP.
    """

    @workflow.run
    async def run(self, data_dir: str) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)
        timeout = timedelta(seconds=30)

        # List directory
        files = await self.execute_authorized_activity(
            list_directory,
            args=[data_dir],
            start_to_close_timeout=timeout,
            retry_policy=no_retry,
        )

        txt_files = [f for f in files if f.endswith(".txt")]

        # Read all text files in parallel — each gets its own PoP
        contents = await asyncio.gather(*(
            self.execute_authorized_activity(
                read_file,
                args=[f],
                start_to_close_timeout=timeout,
                retry_policy=no_retry,
            )
            for f in txt_files
        ))

        total = sum(len(c) for c in contents)
        return f"Analyzed {len(txt_files)} files ({total} chars total)"


# =============================================================================
# Main
# =============================================================================

def on_audit(event: TemporalAuditEvent):
    tag = "ALLOW" if event.decision == "ALLOW" else "DENY"
    logger.info(f"  [{tag:5s}] {event.tool} (warrant: {event.warrant_id})")


async def main():
    # --- Client with TenuoClientInterceptor ---
    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect(
        "localhost:7233", interceptors=[client_interceptor],
    )
    logger.info("Connected to Temporal server")

    # --- Keys (in production: Vault / KMS) ---
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()
    os.environ["TENUO_KEY_agent1"] = base64.b64encode(
        agent_key.secret_key_bytes()
    ).decode()

    # --- Warrant scoped to /tmp/tenuo-demo ---
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/tmp/tenuo-demo"))
        .capability("list_directory", path=Subpath("/tmp/tenuo-demo"))
        .ttl(3600)
        .mint(control_key)
    )
    logger.info(f"Minted warrant {warrant.id}")

    task_queue = f"tenuo-auth-wf-{uuid.uuid4().hex[:8]}"

    # --- Demo data ---
    demo_dir = Path("/tmp/tenuo-demo")
    demo_dir.mkdir(exist_ok=True)
    (demo_dir / "report.txt").write_text("Quarterly revenue report")
    (demo_dir / "metrics.txt").write_text("Uptime: 99.97%")
    (demo_dir / "notes.txt").write_text("Action items from standup")

    # --- Worker with passthrough modules (required for PoP) ---
    worker_interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            audit_callback=on_audit,
            trusted_roots=[control_key.public_key],
        )
    )
    sandbox_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo", "tenuo_core",  # Required for PoP
        )
    )

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[FileAnalysisWorkflow],
        activities=[read_file, list_directory],
        interceptors=[worker_interceptor],
        workflow_runner=sandbox_runner,
    ):
        logger.info("Worker started\n")

        # ── Authorized workflow (parallel reads) ─────────────────
        logger.info("=== AuthorizedWorkflow with parallel reads ===")
        client_interceptor.set_headers(
            tenuo_headers(warrant, "agent1", agent_key)
        )
        result = await client.execute_workflow(
            FileAnalysisWorkflow.run,
            args=[str(demo_dir)],
            id=f"analysis-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"Result: {result}\n")

        # ── Missing headers → fail-fast ──────────────────────────
        logger.info("=== Missing Tenuo headers → fail-fast ===")
        client_interceptor.clear_headers()
        try:
            from temporalio.client import WorkflowFailureError
            await client.execute_workflow(
                FileAnalysisWorkflow.run,
                args=[str(demo_dir)],
                id=f"no-headers-{uuid.uuid4().hex[:8]}",
                task_queue=task_queue,
                execution_timeout=timedelta(seconds=10),
            )
            logger.error("BUG: should have failed at init")
        except WorkflowFailureError:
            logger.info("Correctly rejected: AuthorizedWorkflow requires Tenuo headers\n")

        # ── Out-of-scope path → denied ───────────────────────────
        logger.info("=== Out-of-scope path → denied ===")
        client_interceptor.set_headers(
            tenuo_headers(warrant, "agent1", agent_key)
        )
        try:
            await client.execute_workflow(
                FileAnalysisWorkflow.run,
                args=["/etc"],
                id=f"denied-{uuid.uuid4().hex[:8]}",
                task_queue=task_queue,
            )
            logger.error("BUG: should have been denied")
        except WorkflowFailureError as e:
            logger.info(f"Correctly denied: {e.cause}")


if __name__ == "__main__":
    asyncio.run(main())
