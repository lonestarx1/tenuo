"""
tenuo[a2a] - Inter-agent delegation with warrant-based authorization.

A2A handles agent-to-agent communication. This package adds warrant-based
authorization to that communication.

Server usage (builder pattern):
    from tenuo.a2a import A2AServerBuilder
    from tenuo.constraints import Subpath

    server = (A2AServerBuilder()
        .name("Research Agent")
        .url("https://research-agent.example.com")
        .key(my_signing_key)
        .trust(orchestrator_key)
        .build())

    @server.skill("read_file", constraints={"path": Subpath})
    async def read_file(path: str) -> str:
        with open(path) as f:
            return f.read()

    uvicorn.run(server.app, port=8000)

Server usage (direct):
    from tenuo.a2a import A2AServer

    server = A2AServer(
        name="Research Agent",
        url="https://research-agent.example.com",
        public_key=my_public_key,
        trusted_issuers=[orchestrator_key],
    )

Client usage (builder pattern):
    from tenuo.a2a import A2AClientBuilder

    client = (A2AClientBuilder()
        .url("https://research-agent.example.com")
        .pin_key(expected_key)
        .warrant(my_warrant, my_key)
        .build())

    result = await client.send_task(
        message="Read the config",
        skill="read_file",
    )

Client usage (direct):
    from tenuo.a2a import A2AClient

    client = A2AClient("https://research-agent.example.com")
    result = await client.send_task(
        message="Read the config",
        warrant=my_warrant,
        skill="read_file",
    )
"""

from .types import (
    # Core types
    Grant,
    AgentCard,
    SkillInfo,
    Message,
    TaskResult,
    TaskUpdate,
    TaskUpdateType,
    # Audit
    AuditEvent,
    AuditEventType,
    # Context
    current_task_warrant,
)

from .errors import (
    # Base
    A2AError,
    A2AErrorCode,
    # Warrant validation
    MissingWarrantError,
    InvalidSignatureError,
    UntrustedIssuerError,
    WarrantExpiredError,
    AudienceMismatchError,
    ReplayDetectedError,
    # Authorization
    SkillNotFoundError,
    SkillNotGrantedError,
    ConstraintViolationError,
    UnknownConstraintError,
    RevokedError,
    # Chain
    ChainInvalidError,
    ChainMissingError,
    ChainValidationError,
    ChainReason,
    # PoP (Proof-of-Possession)
    PopRequiredError,
    PopVerificationError,
    MissingSigningKeyError,
    # Client
    KeyMismatchError,
    # Configuration
    ConstraintBindingError,
)

from .server import A2AServer, A2AServerBuilder
from .client import A2AClient, A2AClientBuilder, delegate
from .helpers import explain, explain_str, visualize_chain, dry_run, simulate, SimulationTrace

__all__ = [
    # Server
    "A2AServer",
    "A2AServerBuilder",
    # Client
    "A2AClient",
    "A2AClientBuilder",
    "delegate",
    # DX Helpers
    "explain",
    "explain_str",
    "visualize_chain",
    "dry_run",
    "simulate",
    "SimulationTrace",
    # Types
    "Grant",
    "AgentCard",
    "SkillInfo",
    "Message",
    "TaskResult",
    "TaskUpdate",
    "TaskUpdateType",
    # Audit
    "AuditEvent",
    "AuditEventType",
    # Context
    "current_task_warrant",
    # Errors
    "A2AError",
    "A2AErrorCode",
    "MissingWarrantError",
    "InvalidSignatureError",
    "UntrustedIssuerError",
    "WarrantExpiredError",
    "AudienceMismatchError",
    "ReplayDetectedError",
    "SkillNotFoundError",
    "SkillNotGrantedError",
    "ConstraintViolationError",
    "UnknownConstraintError",
    "RevokedError",
    "ChainInvalidError",
    "ChainMissingError",
    "ChainValidationError",
    "ChainReason",
    "PopRequiredError",
    "PopVerificationError",
    "MissingSigningKeyError",
    "KeyMismatchError",
    "ConstraintBindingError",
]
