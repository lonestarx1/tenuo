"""
Tenuo Approval Policy - Human-in-the-loop authorization for tool calls.

The approval layer sits between warrant authorization and tool execution.
Warrants define *what* an agent can do. Approval policies define *when*
a human must confirm before execution proceeds.

    warrant: "You can transfer up to $100K"
    policy:  "Amounts over $10K need human approval"

The policy is an orchestration concern, not a capability. It can be changed
at runtime without reissuing warrants.

Architecture:
    enforce_tool_call()  ->  warrant says OK  ->  check approval policy
                                                        |
                                    no rule matches: proceed
                                    rule matches: call approval handler
                                        |
                                handler approves: proceed
                                handler denies/times out: raise ApprovalDenied

Usage:
    from tenuo.approval import ApprovalPolicy, require_approval, cli_prompt

    policy = ApprovalPolicy(
        require_approval("transfer_funds", when=lambda args: args["amount"] > 10_000),
        require_approval("delete_user"),  # always requires approval
    )

    # In a GuardBuilder:
    guard = (GuardBuilder(client)
        .allow("transfer_funds", amount=Range(0, 100_000))
        .approval_policy(policy)
        .on_approval(cli_prompt())
        .build())
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Union

logger = logging.getLogger("tenuo.approval")


# =============================================================================
# Approval Request / Response
# =============================================================================


@dataclass(frozen=True)
class ApprovalRequest:
    """Context passed to an approval handler when a rule triggers.

    Attributes:
        tool: Name of the tool requiring approval.
        arguments: Arguments the agent wants to pass.
        warrant_id: ID of the warrant authorizing this call (if available).
        rule: The ApprovalRule that triggered this request.
    """

    tool: str
    arguments: Dict[str, Any]
    warrant_id: Optional[str] = None
    rule: Optional[ApprovalRule] = None


@dataclass(frozen=True)
class ApprovalResponse:
    """Result returned by an approval handler.

    Attributes:
        approved: Whether the human approved the call.
        approver: Identifier of the approver (email, key ID, etc.).
        reason: Optional reason for approval or denial.
    """

    approved: bool
    approver: Optional[str] = None
    reason: Optional[str] = None


# =============================================================================
# Exceptions
# =============================================================================


class ApprovalRequired(Exception):
    """Raised when a tool call requires human approval.

    This is not an authorization failure — the warrant permits the call.
    The approval policy requires a human to confirm before execution.

    Attributes:
        request: The ApprovalRequest with full context.
    """

    def __init__(self, request: ApprovalRequest):
        self.request = request
        super().__init__(
            f"Approval required for '{request.tool}' "
            f"(warrant: {request.warrant_id or 'unknown'})"
        )


class ApprovalDenied(Exception):
    """Raised when a human denies an approval request.

    Attributes:
        request: The original ApprovalRequest.
        response: The denial ApprovalResponse.
    """

    def __init__(self, request: ApprovalRequest, response: ApprovalResponse):
        self.request = request
        self.response = response
        reason = response.reason or "denied by approver"
        super().__init__(
            f"Approval denied for '{request.tool}': {reason}"
        )


class ApprovalTimeout(ApprovalDenied):
    """Raised when an approval request times out."""

    def __init__(self, request: ApprovalRequest, timeout_seconds: float):
        self.timeout_seconds = timeout_seconds
        response = ApprovalResponse(
            approved=False,
            reason=f"timed out after {timeout_seconds}s",
        )
        super().__init__(request, response)


# =============================================================================
# Approval Rules
# =============================================================================


@dataclass(frozen=True)
class ApprovalRule:
    """A single rule that triggers an approval request.

    Attributes:
        tool: Tool name this rule applies to.
        when: Predicate on args. If None, always requires approval.
        description: Human-readable description shown to the approver.
    """

    tool: str
    when: Optional[Callable[[Dict[str, Any]], bool]] = None
    description: Optional[str] = None

    def matches(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """Check if this rule triggers for the given call."""
        if tool_name != self.tool:
            return False
        if self.when is None:
            return True
        try:
            return bool(self.when(args))
        except Exception:
            logger.warning(
                f"Approval rule predicate failed for '{tool_name}', "
                "requiring approval as a safety default",
                exc_info=True,
            )
            return True


def require_approval(
    tool: str,
    *,
    when: Optional[Callable[[Dict[str, Any]], bool]] = None,
    description: Optional[str] = None,
) -> ApprovalRule:
    """Create an approval rule.

    Args:
        tool: Tool name that requires approval.
        when: Optional predicate — if provided, approval is only required
            when the predicate returns True. If omitted, approval is
            always required for this tool.
        description: Human-readable description shown to the approver.

    Examples:
        require_approval("delete_user")
        require_approval("transfer_funds", when=lambda args: args["amount"] > 10_000)
        require_approval("send_email",
            when=lambda args: not args["to"].endswith("@company.com"),
            description="External emails require approval")
    """
    return ApprovalRule(tool=tool, when=when, description=description)


# =============================================================================
# Approval Policy
# =============================================================================


class ApprovalPolicy:
    """Collection of approval rules checked after warrant authorization.

    The policy does not affect what an agent *can* do (that's the warrant).
    It gates *when* a human must confirm before execution proceeds.

    Args:
        *rules: One or more ApprovalRule instances.

    Example:
        policy = ApprovalPolicy(
            require_approval("transfer_funds", when=lambda a: a["amount"] > 10_000),
            require_approval("delete_user"),
        )
    """

    def __init__(self, *rules: ApprovalRule) -> None:
        self._rules: List[ApprovalRule] = list(rules)

    def check(
        self,
        tool_name: str,
        args: Dict[str, Any],
        warrant_id: Optional[str] = None,
    ) -> Optional[ApprovalRequest]:
        """Check if a tool call requires approval.

        Returns:
            ApprovalRequest if approval is needed, None otherwise.
        """
        for rule in self._rules:
            if rule.matches(tool_name, args):
                return ApprovalRequest(
                    tool=tool_name,
                    arguments=args,
                    warrant_id=warrant_id,
                    rule=rule,
                )
        return None

    @property
    def rules(self) -> List[ApprovalRule]:
        return list(self._rules)

    def __len__(self) -> int:
        return len(self._rules)


# =============================================================================
# Approval Handlers
# =============================================================================


class ApprovalHandler(Protocol):
    """Protocol for approval handlers.

    Handlers receive an ApprovalRequest and return an ApprovalResponse.
    They can be sync or async — the enforcement layer handles both.
    """

    def __call__(self, request: ApprovalRequest) -> Union[
        ApprovalResponse, Awaitable[ApprovalResponse]
    ]: ...


def cli_prompt(
    *,
    show_args: bool = True,
) -> ApprovalHandler:
    """Create a CLI-based approval handler for local development.

    Displays the tool call details in the terminal and waits for
    the user to type 'y' or 'n'.

    Args:
        show_args: Whether to display tool arguments (may contain PII).

    Returns:
        An ApprovalHandler that prompts in the terminal.
    """

    def _handle(request: ApprovalRequest) -> ApprovalResponse:
        print(f"\n{'=' * 60}", file=sys.stderr)
        print("  APPROVAL REQUIRED", file=sys.stderr)
        print(f"{'=' * 60}", file=sys.stderr)
        print(f"  Tool:    {request.tool}", file=sys.stderr)
        if show_args and request.arguments:
            for k, v in request.arguments.items():
                print(f"  {k:>8s}: {v}", file=sys.stderr)
        if request.rule and request.rule.description:
            print(f"  Reason:  {request.rule.description}", file=sys.stderr)
        if request.warrant_id:
            print(f"  Warrant: {request.warrant_id}", file=sys.stderr)
        print(f"{'=' * 60}", file=sys.stderr)

        try:
            answer = input("  Approve? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        approved = answer in ("y", "yes")
        return ApprovalResponse(
            approved=approved,
            approver="cli",
            reason="approved via CLI" if approved else "denied via CLI",
        )

    return _handle


def auto_approve() -> ApprovalHandler:
    """Create a handler that auto-approves everything. For testing only."""

    def _handle(request: ApprovalRequest) -> ApprovalResponse:
        logger.info(f"Auto-approving '{request.tool}' (testing mode)")
        return ApprovalResponse(approved=True, approver="auto", reason="auto-approved")

    return _handle


def auto_deny(*, reason: str = "auto-denied by policy") -> ApprovalHandler:
    """Create a handler that auto-denies everything. For dry-run / audit mode."""

    def _handle(request: ApprovalRequest) -> ApprovalResponse:
        logger.info(f"Auto-denying '{request.tool}' (dry-run mode)")
        return ApprovalResponse(approved=False, approver="auto", reason=reason)

    return _handle


def webhook(
    url: str,
    *,
    timeout: float = 300,
    headers: Optional[Dict[str, str]] = None,
) -> ApprovalHandler:
    """Create a webhook-based approval handler.

    Posts the approval request to a URL and polls for a response.
    This is a placeholder — full implementation requires async polling
    or a callback endpoint.

    Args:
        url: Webhook URL to POST the approval request to.
        timeout: Timeout in seconds waiting for approval.
        headers: Optional HTTP headers (e.g., auth tokens).

    Returns:
        An ApprovalHandler that sends requests via webhook.
    """

    def _handle(request: ApprovalRequest) -> ApprovalResponse:
        raise NotImplementedError(
            "Webhook approval handler is a placeholder. "
            "Use tenuo.cloud or implement a custom handler."
        )

    return _handle


__all__ = [
    "ApprovalPolicy",
    "ApprovalRequest",
    "ApprovalResponse",
    "ApprovalRequired",
    "ApprovalDenied",
    "ApprovalTimeout",
    "ApprovalRule",
    "ApprovalHandler",
    "require_approval",
    "cli_prompt",
    "auto_approve",
    "auto_deny",
    "webhook",
]
