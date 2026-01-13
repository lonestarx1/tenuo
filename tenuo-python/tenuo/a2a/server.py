"""
A2A Adapter - Server implementation.

Provides A2AServer with @skill decorator for warrant-enforced skill execution.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from .types import (
    AgentCard,
    AuditEvent,
    AuditEventType,
    SkillInfo,
    TenuoExtension,
    current_task_warrant,
)
from .errors import (
    A2AError,
    A2AErrorCode,
    AudienceMismatchError,
    ChainValidationError,
    ConstraintBindingError,
    ConstraintViolationError,
    InvalidSignatureError,
    MissingWarrantError,
    ReplayDetectedError,
    SkillNotFoundError,
    SkillNotGrantedError,
    UnknownConstraintError,
    UntrustedIssuerError,
    WarrantExpiredError,
)

if TYPE_CHECKING:
    from starlette.requests import Request

    from .types import Warrant

__all__ = [
    "A2AServer",
    "ReplayCache",
    "SkillDefinition",
]

logger = logging.getLogger("tenuo.a2a.server")


# =============================================================================
# Replay Cache (in-memory for MVP)
# =============================================================================


class ReplayCache:
    """
    Simple in-memory replay cache with TTL.

    NOTE on time.time() usage:
    We use wall clock time (time.time()) rather than monotonic time because:
    1. JWT 'exp' claims are Unix timestamps (wall clock)
    2. We need to compare against those timestamps for consistency
    3. Ensure your server's NTP is synced to prevent clock drift issues

    For production deployments, consider using Redis or similar for:
    - Multi-instance coordination
    - Persistence across restarts
    - Better memory management
    """

    def __init__(self):
        self._cache: Dict[str, float] = {}  # jti -> expiry_time (wall clock)
        self._lock: Optional[asyncio.Lock] = None  # Lazy init to avoid event loop issues

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the lock (lazy initialization)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def check_and_add(self, jti: str, ttl_seconds: int) -> bool:
        """
        Check if jti exists, add if not.

        Returns:
            True if jti is new (not a replay)
            False if jti already exists (replay detected)
        """
        async with self._get_lock():
            now = time.time()

            # Cleanup expired entries (simple GC)
            expired = [k for k, v in self._cache.items() if v < now]
            for k in expired:
                del self._cache[k]

            # Check for replay
            if jti in self._cache:
                return False

            # Add to cache
            self._cache[jti] = now + ttl_seconds
            return True

    async def clear(self):
        """Clear all entries (for testing). Async to prevent race with check_and_add."""
        async with self._get_lock():
            self._cache.clear()


# =============================================================================
# Skill Registration
# =============================================================================


class SkillDefinition:
    """Internal representation of a registered skill."""

    def __init__(
        self,
        skill_id: str,
        func: Callable,
        constraints: Dict[str, Any],
        name: Optional[str] = None,
    ):
        self.skill_id = skill_id
        self.func = func
        self.constraints = constraints
        self.name = name or skill_id

        # Get function signature for validation
        sig = inspect.signature(func)
        self.param_names = list(sig.parameters.keys())

        # Validate constraint keys match parameters
        for key in constraints:
            if key not in self.param_names:
                raise ConstraintBindingError(skill_id, key, self.param_names)

    def to_skill_info(self) -> SkillInfo:
        """Convert to SkillInfo for AgentCard."""
        from .types import ConstraintInfo

        constraint_infos = {}
        for key, constraint in self.constraints.items():
            type_name = type(constraint).__name__
            constraint_infos[key] = ConstraintInfo(type=type_name, required=True)

        return SkillInfo(
            id=self.skill_id,
            name=self.name,
            constraints=constraint_infos,
        )


# =============================================================================
# A2A Server
# =============================================================================


class A2AServer:
    """
    A2A server with warrant-based authorization.

    Example:
        server = A2AServer(
            name="Research Agent",
            url="https://research-agent.example.com",
            public_key=my_public_key,
            trusted_issuers=[orchestrator_key],
        )

        @server.skill("search", constraints={"query": str})
        async def search(query: str) -> list[dict]:
            return await do_search(query)

        # Run with uvicorn
        uvicorn.run(server.app, port=8000)
    """

    def __init__(
        self,
        name: str,
        url: str,
        public_key: str,
        trusted_issuers: List[str],
        *,
        trust_delegated: bool = True,
        require_warrant: Optional[bool] = None,
        require_audience: Optional[bool] = None,
        check_replay: Optional[bool] = None,
        replay_window: Optional[int] = None,
        max_chain_depth: Optional[int] = None,
        audit_log: Any = None,
        audit_format: str = "json",
        previous_keys: Optional[List[str]] = None,
    ):
        """
        Initialize A2A server.

        Args:
            name: Display name of this agent
            url: Public URL of this agent (used for audience validation)
            public_key: This agent's public key (multibase or DID)
            trusted_issuers: List of public keys/DIDs to trust as warrant issuers
            trust_delegated: Accept warrants attenuated from trusted issuers
            require_warrant: Reject tasks without warrant (env: TENUO_A2A_REQUIRE_WARRANT)
            require_audience: Require aud claim matches our URL (env: TENUO_A2A_REQUIRE_AUDIENCE)
            check_replay: Enforce jti uniqueness (env: TENUO_A2A_CHECK_REPLAY)
            replay_window: Seconds to remember jti values (env: TENUO_A2A_REPLAY_WINDOW)
            max_chain_depth: Maximum delegation chain depth (env: TENUO_A2A_MAX_CHAIN_DEPTH)
            audit_log: Destination for audit events (env: TENUO_A2A_AUDIT_LOG for path)
            audit_format: "json" or "text"
            previous_keys: List of previous public keys for key rotation
        """
        self.name = name
        self.url = url.rstrip("/")
        self.public_key = public_key
        self.trusted_issuers = set(trusted_issuers)
        self.trust_delegated = trust_delegated

        # Apply environment variable defaults
        # Explicit args take precedence over env vars
        self.require_warrant = self._get_bool_config(require_warrant, "TENUO_A2A_REQUIRE_WARRANT", default=True)
        self.require_audience = self._get_bool_config(require_audience, "TENUO_A2A_REQUIRE_AUDIENCE", default=True)
        self.check_replay = self._get_bool_config(check_replay, "TENUO_A2A_CHECK_REPLAY", default=True)
        self.replay_window = self._get_int_config(replay_window, "TENUO_A2A_REPLAY_WINDOW", default=3600)
        self.max_chain_depth = self._get_int_config(max_chain_depth, "TENUO_A2A_MAX_CHAIN_DEPTH", default=10)

        # Audit log: handle env var for file path
        if audit_log is None:
            env_log = os.environ.get("TENUO_A2A_AUDIT_LOG", "").strip()
            if env_log and env_log.lower() != "stderr":
                self.audit_log = open(env_log, "a")  # noqa: SIM115
            else:
                self.audit_log = sys.stderr
        else:
            self.audit_log = audit_log
        self.audit_format = audit_format
        self.previous_keys = previous_keys or []

        # Skill registry
        self._skills: Dict[str, SkillDefinition] = {}

        # Replay cache
        self._replay_cache = ReplayCache()

        # ASGI app (lazy init)
        self._app = None

    # -------------------------------------------------------------------------
    # Configuration Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _get_bool_config(explicit: Optional[bool], env_var: str, default: bool) -> bool:
        """Get boolean config value from explicit arg or env var."""
        if explicit is not None:
            return explicit
        env_val = os.environ.get(env_var, "").strip().lower()
        if env_val in ("true", "1", "yes", "on"):
            return True
        elif env_val in ("false", "0", "no", "off"):
            return False
        return default

    @staticmethod
    def _get_int_config(explicit: Optional[int], env_var: str, default: int) -> int:
        """Get integer config value from explicit arg or env var."""
        if explicit is not None:
            return explicit
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            try:
                return int(env_val)
            except ValueError:
                logger.warning(f"Invalid int for {env_var}: {env_val!r}, using default {default}")
        return default

    # -------------------------------------------------------------------------
    # Skill Decorator
    # -------------------------------------------------------------------------

    def skill(
        self,
        skill_id: str,
        *,
        constraints: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
    ) -> Callable:
        """
        Register a skill with optional constraints.

        Args:
            skill_id: Unique identifier for this skill
            constraints: Map of parameter names to constraint types
            name: Display name (defaults to skill_id)

        Example:
            @server.skill("read_file", constraints={"path": Subpath})
            async def read_file(path: str) -> str:
                ...
        """
        constraints = constraints or {}

        def decorator(func: Callable) -> Callable:
            # Register skill
            skill_def = SkillDefinition(
                skill_id=skill_id,
                func=func,
                constraints=constraints,
                name=name,
            )
            self._skills[skill_id] = skill_def

            # Return original function - constraint enforcement happens in validate_warrant()
            # which is called before skill execution in _handle_task_send()
            return func

        return decorator

    # -------------------------------------------------------------------------
    # Warrant Property Access
    # -------------------------------------------------------------------------

    @staticmethod
    def _get_warrant_prop(warrant: Any, *names: str, default: Any = None) -> Any:
        """
        Get a property from a warrant object, trying multiple attribute names.

        This exists because Warrant objects may use either JWT-style names (iss, aud, jti)
        or descriptive names (issuer, audience, id). The Rust Warrant type exposes both,
        but we want to handle any warrant-like object consistently.

        Args:
            warrant: Warrant object
            *names: Attribute names to try in order
            default: Value to return if no attribute found

        Returns:
            First found attribute value, or default
        """
        for name in names:
            value = getattr(warrant, name, None)
            if value is not None:
                return value
        return default

    # -------------------------------------------------------------------------
    # Warrant Validation
    # -------------------------------------------------------------------------

    async def validate_warrant(
        self,
        warrant_token: str,
        skill_id: str,
        arguments: Dict[str, Any],
        *,
        warrant_chain: Optional[str] = None,
    ) -> "Warrant":
        """
        Validate a warrant for a skill invocation.

        Args:
            warrant_token: JWT warrant token
            skill_id: Requested skill
            arguments: Skill arguments to check against constraints
            warrant_chain: Optional semicolon-separated chain of parent warrants

        Returns:
            Validated Warrant object

        Raises:
            Various A2AErrors for validation failures
        """
        start_time = time.time()

        try:
            from tenuo_core import Warrant
        except ImportError as e:
            raise RuntimeError("tenuo_core not available") from e

        # Decode and verify warrant signature
        # Note: Warrant.from_base64() / from_jwt() performs cryptographic verification
        # against the embedded public key. The issuer trust check below ensures we
        # only accept warrants signed by keys we trust.
        try:
            warrant = Warrant.from_base64(warrant_token)
        except Exception as e:
            raise InvalidSignatureError(f"Failed to decode/verify warrant: {e}")

        # Check expiry
        # Use is_expired if available, otherwise check exp claim manually
        is_expired = getattr(warrant, "is_expired", None)
        if is_expired is True:
            raise WarrantExpiredError()
        elif is_expired is None:
            # Fallback: check exp claim manually
            now = int(time.time())
            exp = getattr(warrant, "exp", None)
            if exp is not None and exp < now:
                raise WarrantExpiredError()

        # Check issuer trust (direct or via chain)
        issuer = self._get_warrant_prop(warrant, "iss", "issuer")

        if issuer and issuer not in self.trusted_issuers:
            if self.trust_delegated and warrant_chain:
                # Validate delegation chain
                await self._validate_chain(warrant, warrant_chain)
            else:
                raise UntrustedIssuerError(issuer)

        # Check audience
        if self.require_audience:
            aud = self._get_warrant_prop(warrant, "aud", "audience")
            if aud and aud != self.url:
                raise AudienceMismatchError(expected=self.url, actual=aud)

        # Check replay
        if self.check_replay:
            jti = self._get_warrant_prop(warrant, "jti", "id")
            if jti:
                is_new = await self._replay_cache.check_and_add(jti, self.replay_window)
                if not is_new:
                    raise ReplayDetectedError(jti)

        # Check skill is granted in warrant
        grants = getattr(warrant, "grants", [])
        if not grants:
            # Try to get grants from tools/capabilities
            tools = getattr(warrant, "tools", None)
            if tools:
                grants = [{"skill": t} for t in tools]

        granted_skills = [g.get("skill", g) if isinstance(g, dict) else g for g in grants]
        if skill_id not in granted_skills:
            raise SkillNotGrantedError(skill_id, granted_skills)

        # Get warrant constraints for this skill (if any)
        warrant_constraints = {}
        for grant in grants:
            if isinstance(grant, dict):
                grant_skill = grant.get("skill")
                if grant_skill == skill_id:
                    warrant_constraints = grant.get("constraints", {})
                    break

        # Check constraints - warrant constraints take precedence over server constraints
        # Server constraints define what the skill CAN check
        # Warrant constraints define what this invocation IS LIMITED TO
        # Both must pass, but warrant may be more restrictive
        skill_def = self._skills.get(skill_id)
        if skill_def:
            for param, server_constraint in skill_def.constraints.items():
                if param in arguments:
                    value = arguments[param]

                    # First check server constraint (the skill's declared requirement)
                    if not self._check_constraint(server_constraint, value, param):
                        raise ConstraintViolationError(
                            param=param,
                            constraint_type=type(server_constraint).__name__,
                            value=value,
                            reason="Value does not satisfy server constraint",
                        )

                    # Then check warrant constraint if present (may be more restrictive)
                    if param in warrant_constraints:
                        warrant_constraint = warrant_constraints[param]
                        if not self._check_constraint(warrant_constraint, value, param):
                            raise ConstraintViolationError(
                                param=param,
                                constraint_type=type(warrant_constraint).__name__,
                                value=value,
                                reason="Value does not satisfy warrant constraint",
                            )

        # Log audit event
        latency_ms = int((time.time() - start_time) * 1000)
        await self._audit(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                event=AuditEventType.WARRANT_VALIDATED,
                task_id="",
                skill=skill_id,
                warrant_jti=self._get_warrant_prop(warrant, "jti", "id", default=""),
                warrant_iss=issuer or "",
                warrant_sub=self._get_warrant_prop(warrant, "sub", "subject", default=""),
                outcome="allowed",
                latency_ms=latency_ms,
            )
        )

        return warrant

    async def _validate_chain(
        self,
        leaf_warrant: Any,
        chain_header: str,
    ) -> None:
        """
        Validate a delegation chain.

        The chain header contains semicolon-separated JWTs ordered parent-first:
            root_warrant;middle_warrant;leaf_warrant

        Validation rules:
            1. Root warrant must be from a trusted issuer
            2. Each warrant must have valid signature
            3. Each child's issuer must match parent's subject/holder
            4. Chain depth must not exceed max_chain_depth
            5. All warrants in chain must not be expired
            6. Grants must narrow (monotonicity)

        Args:
            leaf_warrant: The final warrant being validated
            chain_header: Semicolon-separated JWT chain

        Raises:
            A2AError on validation failure
        """

        try:
            from tenuo_core import Warrant
        except ImportError as e:
            raise RuntimeError("tenuo_core not available") from e

        # Parse chain (parent-first order)
        chain_tokens = [t.strip() for t in chain_header.split(";") if t.strip()]

        if not chain_tokens:
            raise ChainValidationError("Empty warrant chain")

        if len(chain_tokens) > self.max_chain_depth:
            raise ChainValidationError(f"Chain depth {len(chain_tokens)} exceeds maximum {self.max_chain_depth}")

        # Decode all warrants in chain
        chain_warrants = []
        for i, token in enumerate(chain_tokens):
            try:
                w = Warrant.from_jwt(token)
                chain_warrants.append(w)
            except Exception as e:
                raise ChainValidationError(f"Invalid warrant at position {i}: {e}")

        # Validate root warrant is from trusted issuer
        root = chain_warrants[0]
        root_issuer = getattr(root, "iss", None) or getattr(root, "issuer", None)

        if root_issuer not in self.trusted_issuers:
            raise UntrustedIssuerError(root_issuer, reason=f"Root warrant issuer '{root_issuer}' is not trusted")

        # Validate chain linkage
        now = int(time.time())

        for i in range(len(chain_warrants)):
            current = chain_warrants[i]

            # Check expiry
            exp = getattr(current, "exp", None)
            if exp and exp < now:
                raise WarrantExpiredError(f"Warrant at position {i} has expired")

            # Check chain linkage (child's issuer should be parent's holder)
            if i > 0:
                parent = chain_warrants[i - 1]

                # Get parent's authorized holder (the one who can delegate)
                parent_holder = (
                    getattr(parent, "sub", None)
                    or getattr(parent, "subject", None)
                    or getattr(parent, "authorized_holder", None)
                )

                # Get current warrant's issuer
                current_issuer = getattr(current, "iss", None) or getattr(current, "issuer", None)

                if parent_holder and current_issuer and parent_holder != current_issuer:
                    raise ChainValidationError(
                        f"Chain broken at position {i}: "
                        f"parent holder '{parent_holder}' != child issuer '{current_issuer}'"
                    )

                # Monotonicity check: child grants must be subset of parent grants
                if not self._grants_are_subset(current, parent):
                    raise ChainValidationError(
                        f"Monotonicity violation at position {i}: child grants exceed parent grants",
                        depth=i,
                    )

        # Verify leaf warrant in chain matches the leaf_warrant being validated
        leaf_jti = getattr(leaf_warrant, "jti", None) or getattr(leaf_warrant, "id", None)
        chain_leaf = chain_warrants[-1] if chain_warrants else None
        chain_leaf_jti = getattr(chain_leaf, "jti", None) or getattr(chain_leaf, "id", None) if chain_leaf else None

        if leaf_jti and chain_leaf_jti and leaf_jti != chain_leaf_jti:
            raise ChainValidationError(
                f"Leaf warrant mismatch: warrant jti '{leaf_jti}' != chain tail '{chain_leaf_jti}'"
            )

        logger.debug(f"Chain validated: {len(chain_warrants)} warrants, root issuer: {root_issuer}")

    def _grants_are_subset(self, child: Any, parent: Any) -> bool:
        """
        Check if child's grants are a valid attenuation (subset) of parent's grants.

        Returns True if:
        - Child has fewer or equal skills than parent
        - Each child skill exists in parent
        - (Constraint narrowing is NOT enforced here - would require deep comparison)
        """
        # Get grants from both warrants
        child_grants = getattr(child, "grants", []) or []
        parent_grants = getattr(parent, "grants", []) or []

        # Extract skill names
        def get_skills(grants):
            skills = set()
            for g in grants:
                if isinstance(g, dict):
                    skill = g.get("skill", "")
                    if skill:
                        skills.add(skill)
                elif isinstance(g, str):
                    skills.add(g)
            return skills

        child_skills = get_skills(child_grants)
        parent_skills = get_skills(parent_grants)

        # Also check tools field as fallback
        if not child_skills:
            child_tools = getattr(child, "tools", []) or []
            child_skills = set(child_tools)
        if not parent_skills:
            parent_tools = getattr(parent, "tools", []) or []
            parent_skills = set(parent_tools)

        # If parent has no grants/tools, allow any child (root warrant)
        if not parent_skills:
            return True

        # Child skills must be subset of parent skills
        return child_skills.issubset(parent_skills)

    def _check_constraint(self, constraint: Any, value: Any, param: str = "") -> bool:
        """
        Check if value satisfies constraint.

        Fails closed: unknown constraint types are denied for security.

        NOTE on duck typing:
        We use duck typing (hasattr checks) because:
        1. tenuo_core constraints are PyO3-compiled Rust types
        2. isinstance() doesn't work well across the FFI boundary
        3. The method names are part of the stable API contract:
           - Subpath: contains(path) -> bool
           - UrlSafe: is_safe(url) -> bool
           - Shlex: matches(value) -> bool

        Note: Simple constraints like Pattern, Exact, Range are typically
        evaluated within the Warrant itself during authorize(), not here.
        This method handles "active" constraints that need runtime checks.

        If tenuo_core changes these method names, tests in test_a2a.py will fail.
        See TestConstraintMethodNames for regression tests.

        Args:
            constraint: The constraint to check against
            value: The value to validate
            param: Parameter name (for error reporting)

        Returns:
            True if value satisfies constraint

        Raises:
            UnknownConstraintError: If constraint type is not recognized
        """
        # Handle Rust constraint types via duck typing
        # Method names are stable API - see docstring
        if hasattr(constraint, "contains"):
            # Subpath constraint
            return constraint.contains(str(value))
        elif hasattr(constraint, "is_safe"):
            # UrlSafe constraint
            if isinstance(value, list):
                return all(constraint.is_safe(str(v)) for v in value)
            return constraint.is_safe(str(value))
        elif hasattr(constraint, "matches"):
            # Shlex constraint
            return constraint.matches(str(value))
        elif isinstance(constraint, type):
            # Type constraint (e.g., str, int)
            return isinstance(value, constraint)
        elif hasattr(constraint, "pattern"):
            # Simple Pattern constraint - use fnmatch for glob matching
            import fnmatch

            return fnmatch.fnmatch(str(value), constraint.pattern)
        else:
            # SECURITY: Unknown constraint type - FAIL CLOSED
            # We don't recognize this constraint, so we cannot validate it.
            # Allowing by default would be a security hole.
            raise UnknownConstraintError(
                constraint_type=type(constraint).__name__,
                param=param,
            )

    # -------------------------------------------------------------------------
    # Audit Logging
    # -------------------------------------------------------------------------

    async def _audit(self, event: AuditEvent):
        """Write audit event."""
        if callable(self.audit_log):
            # Custom handler
            if asyncio.iscoroutinefunction(self.audit_log):
                await self.audit_log(event)
            else:
                self.audit_log(event)
        elif hasattr(self.audit_log, "write"):
            # File-like object
            if self.audit_format == "json":
                self.audit_log.write(json.dumps(event.to_dict()) + "\n")
            else:
                self.audit_log.write(f"[{event.event.value}] {event.skill}: {event.outcome}\n")
            self.audit_log.flush()

    # -------------------------------------------------------------------------
    # Agent Card
    # -------------------------------------------------------------------------

    def get_agent_card(self) -> AgentCard:
        """Generate AgentCard for discovery."""
        skills = [s.to_skill_info() for s in self._skills.values()]
        return AgentCard(
            name=self.name,
            url=self.url,
            skills=skills,
            tenuo_extension=TenuoExtension(
                version="0.1.0",
                required=self.require_warrant,
                public_key=self.public_key,
                previous_keys=self.previous_keys,
            ),
        )

    def get_agent_card_dict(self) -> Dict[str, Any]:
        """Generate AgentCard as dict for JSON response."""
        card = self.get_agent_card()
        skills = []
        for s in card.skills:
            skill_dict: Dict[str, Any] = {"id": s.id, "name": s.name}
            if s.constraints:
                skill_dict["x-tenuo-constraints"] = {
                    k: {"type": v.type, "required": v.required} for k, v in s.constraints.items()
                }
            skills.append(skill_dict)

        return {
            "name": card.name,
            "url": card.url,
            "skills": skills,
            "x-tenuo": {
                "version": card.tenuo_extension.version,
                "required": card.tenuo_extension.required,
                "public_key": card.tenuo_extension.public_key,
                "previous_keys": card.tenuo_extension.previous_keys,
            }
            if card.tenuo_extension
            else None,
        }

    # -------------------------------------------------------------------------
    # ASGI App
    # -------------------------------------------------------------------------

    @property
    def app(self):
        """Get ASGI application for uvicorn."""
        if self._app is None:
            self._app = self._create_app()
        return self._app

    def _create_app(self):
        """Create Starlette ASGI app."""
        try:
            from starlette.applications import Starlette
            from starlette.requests import Request  # noqa: F401 (used in handle_a2a below)
            from starlette.responses import JSONResponse
            from starlette.routing import Route
        except ImportError:
            raise ImportError("starlette is required for A2A server. Install with: pip install tenuo[a2a]")

        async def handle_a2a(request: Request) -> JSONResponse:
            """Handle JSON-RPC A2A requests."""
            try:
                body = await request.json()
            except Exception:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {"code": A2AErrorCode.PARSE_ERROR, "message": "Parse error"},
                        "id": None,
                    }
                )

            method = body.get("method", "")
            params = body.get("params", {})
            request_id = body.get("id")

            try:
                if method == "agent/discover":
                    result = self.get_agent_card_dict()
                elif method == "task/send":
                    result = await self._handle_task_send(request, params)
                elif method == "task/sendSubscribe":
                    # Streaming response
                    return await self._handle_task_send_subscribe(request, params, request_id)
                else:
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "error": {"code": A2AErrorCode.METHOD_NOT_FOUND, "message": "Method not found"},
                            "id": request_id,
                        }
                    )

                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": request_id,
                    }
                )

            except A2AError as e:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": e.to_jsonrpc_error(),
                        "id": request_id,
                    }
                )
            except Exception as e:
                logger.exception("Unexpected error in A2A handler")
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {"code": A2AErrorCode.INTERNAL_ERROR, "message": str(e)},
                        "id": request_id,
                    }
                )

        async def handle_discover(request: Request) -> JSONResponse:
            """Handle agent discovery requests."""
            return JSONResponse(self.get_agent_card_dict())

        routes = [
            Route("/a2a", handle_a2a, methods=["POST"]),
            Route("/.well-known/agent.json", handle_discover, methods=["GET"]),
        ]

        return Starlette(routes=routes)

    async def _handle_task_send(self, request: "Request", params: Dict) -> Dict[str, Any]:
        """Handle task/send method."""
        task = params.get("task", {})
        _message = task.get("message", "")  # Extracted for future use (logging, context)
        skill_id = task.get("skill", "")
        arguments = task.get("arguments", {})
        task_id = task.get("id") or str(uuid.uuid4())

        # Get warrant from header or params
        warrant_token = request.headers.get("X-Tenuo-Warrant")
        if not warrant_token:
            warrant_token = params.get("x-tenuo-warrant")

        # Get delegation chain (semicolon-separated, parent-first)
        warrant_chain = request.headers.get("X-Tenuo-Warrant-Chain")
        if not warrant_chain:
            warrant_chain = params.get("x-tenuo-warrant-chain")

        if self.require_warrant and not warrant_token:
            raise MissingWarrantError("Warrant required")

        # Validate warrant (with optional chain)
        warrant = None
        if warrant_token:
            warrant = await self.validate_warrant(
                warrant_token,
                skill_id,
                arguments,
                warrant_chain=warrant_chain,
            )

        # Set current warrant context
        token = current_task_warrant.set(warrant)

        try:
            # Get skill handler
            skill_def = self._skills.get(skill_id)
            if not skill_def:
                # Note: This is different from SkillNotGrantedError
                # - SkillNotFoundError: skill doesn't exist on this server
                # - SkillNotGrantedError: skill exists but not granted in warrant
                raise SkillNotFoundError(skill_id, list(self._skills.keys()))

            # Execute skill
            result = await skill_def.func(**arguments)

            return {
                "task_id": task_id,
                "status": "complete",
                "output": result,
            }
        finally:
            current_task_warrant.reset(token)

    async def _handle_task_send_subscribe(self, request: "Request", params: Dict, request_id: Any) -> Any:
        """Handle task/sendSubscribe method with SSE streaming response."""
        try:
            from starlette.responses import StreamingResponse
        except ImportError:
            raise RuntimeError("starlette is required for streaming")

        task = params.get("task", {})
        _message = task.get("message", "")
        skill_id = task.get("skill", "")
        arguments = task.get("arguments", {})
        task_id = task.get("id") or str(uuid.uuid4())

        # Get warrant from header or params
        warrant_token = request.headers.get("X-Tenuo-Warrant") or params.get("x-tenuo-warrant")
        warrant_chain = request.headers.get("X-Tenuo-Warrant-Chain") or params.get("x-tenuo-warrant-chain")

        # Validate warrant (same as task/send)
        warrant = None
        if self.require_warrant and not warrant_token:
            raise MissingWarrantError("Warrant required for streaming")

        if warrant_token:
            warrant = await self.validate_warrant(
                warrant_token,
                skill_id,
                arguments,
                warrant_chain=warrant_chain,
            )

        # Get warrant expiry for mid-stream checks
        warrant_exp = getattr(warrant, "exp", None) if warrant else None

        async def event_generator():
            """Generate SSE events."""
            import json

            # Set current warrant context
            token = current_task_warrant.set(warrant)

            try:
                # Get skill handler
                skill_def = self._skills.get(skill_id)
                if not skill_def:
                    error_event = {
                        "type": "error",
                        "task_id": task_id,
                        "code": A2AErrorCode.SKILL_NOT_FOUND,
                        "message": f"Skill '{skill_id}' not found",
                    }
                    yield f"data: {json.dumps(error_event)}\n\n"
                    return

                # Emit status event
                status_event = {
                    "type": "status",
                    "task_id": task_id,
                    "status": "running",
                }
                yield f"data: {json.dumps(status_event)}\n\n"

                # Execute skill - check for generator/streaming skill
                result = skill_def.func(**arguments)

                # Check if result is async generator (streaming skill)
                if hasattr(result, "__anext__"):
                    async for chunk in result:
                        # Mid-stream expiry check
                        if warrant_exp and time.time() > warrant_exp:
                            error_event = {
                                "type": "error",
                                "task_id": task_id,
                                "code": A2AErrorCode.EXPIRED,
                                "message": "Warrant expired",
                                "data": {"mid_stream": True},
                            }
                            yield f"data: {json.dumps(error_event)}\n\n"
                            return

                        # Emit chunk
                        chunk_event = {
                            "type": "message",
                            "task_id": task_id,
                            "content": str(chunk),
                        }
                        yield f"data: {json.dumps(chunk_event)}\n\n"
                else:
                    # Await if coroutine
                    if hasattr(result, "__await__"):
                        result = await result

                # Emit completion
                complete_event = {
                    "type": "complete",
                    "task_id": task_id,
                    "output": result if not hasattr(result, "__anext__") else None,
                }
                yield f"data: {json.dumps(complete_event)}\n\n"

            except A2AError as e:
                error_event = {
                    "type": "error",
                    "task_id": task_id,
                    "code": e.code.value if hasattr(e.code, "value") else e.code,
                    "message": str(e),
                }
                yield f"data: {json.dumps(error_event)}\n\n"
            except Exception as e:
                error_event = {
                    "type": "error",
                    "task_id": task_id,
                    "code": A2AErrorCode.INTERNAL_ERROR,
                    "message": str(e),
                }
                yield f"data: {json.dumps(error_event)}\n\n"
            finally:
                current_task_warrant.reset(token)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
