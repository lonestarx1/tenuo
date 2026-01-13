"""
A2A Adapter - Client implementation.

Provides A2AClient for sending tasks with warrants to A2A agents.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import TYPE_CHECKING, Any, AsyncIterator, Dict, Optional, Union

from .types import (
    AgentCard,
    Message,
    TaskResult,
    TaskUpdate,
)
from .errors import A2AError, KeyMismatchError, WarrantExpiredError

if TYPE_CHECKING:
    from .types import Warrant

__all__ = [
    "A2AClient",
    "delegate",
]

logger = logging.getLogger("tenuo.a2a.client")


# =============================================================================
# A2A Client
# =============================================================================


class A2AClient:
    """
    Client for sending tasks to A2A agents with warrants.

    Example:
        client = A2AClient("https://research-agent.example.com")

        # Discover agent capabilities
        card = await client.discover()
        print(f"Agent requires warrant: {card.requires_warrant}")

        # Send task with warrant
        result = await client.send_task(
            message="Find papers on security",
            warrant=my_warrant,
        )
    """

    def __init__(
        self,
        url: str,
        *,
        auth: Optional[Any] = None,
        pin_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize A2A client.

        Args:
            url: Base URL of the A2A agent
            auth: Optional authentication config
            pin_key: Expected public key (raises KeyMismatchError if different)
            timeout: Request timeout in seconds
        """
        self.url = url.rstrip("/")
        self.auth = auth
        self.pin_key = pin_key
        self.timeout = timeout

        # Cached agent card
        self._agent_card: Optional[AgentCard] = None

        # HTTP client (lazy init)
        self._client = None

    async def _get_client(self):
        """Get or create httpx client."""
        if self._client is None:
            try:
                import httpx
            except ImportError:
                raise ImportError("httpx is required for A2A client. Install with: pip install tenuo[a2a]")
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    # -------------------------------------------------------------------------
    # Discovery
    # -------------------------------------------------------------------------

    async def discover(self) -> AgentCard:
        """
        Fetch agent card from the server.

        If pin_key was provided, raises KeyMismatchError if the agent's
        public key doesn't match. This prevents TOFU attacks where a
        compromised server swaps its key.

        Returns:
            AgentCard with agent capabilities and Tenuo config
        """
        client = await self._get_client()

        # Try well-known endpoint first
        response = await client.get(f"{self.url}/.well-known/agent.json")

        if response.status_code != 200:
            # Try JSON-RPC discovery
            response = await client.post(
                f"{self.url}/a2a",
                json={
                    "jsonrpc": "2.0",
                    "method": "agent/discover",
                    "params": {},
                    "id": 1,
                },
            )
            data = response.json()
            if "error" in data:
                raise RuntimeError(f"Discovery failed: {data['error']}")
            card_data = data.get("result", {})
        else:
            card_data = response.json()

        card = AgentCard.from_dict(card_data)

        # Validate pinned key if provided
        if self.pin_key and card.public_key:
            if card.public_key != self.pin_key:
                raise KeyMismatchError(self.pin_key, card.public_key)

        self._agent_card = card
        return card

    # -------------------------------------------------------------------------
    # Task Sending
    # -------------------------------------------------------------------------

    async def send_task(
        self,
        message: Union[str, Message],
        warrant: "Warrant",
        *,
        skill: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> TaskResult:
        """
        Send a task to the agent with a warrant.

        Args:
            message: Task message (string or Message object)
            warrant: Tenuo warrant for authorization
            skill: Skill to invoke (inferred from warrant if not provided)
            arguments: Arguments for the skill
            task_id: Optional task ID (generated if not provided)

        Returns:
            TaskResult with output
        """
        import uuid

        client = await self._get_client()

        # Build message content
        if isinstance(message, str):
            message_content = message
        else:
            message_content = message.content

        # Skill is required - no implicit inference from warrant
        if skill is None:
            raise ValueError(
                "skill is required. Specify the skill to invoke explicitly. "
                "Example: client.send_task(message='...', warrant=w, skill='search_papers')"
            )

        # Serialize warrant using to_base64() - the canonical method
        # Warrant must be a tenuo Warrant object with to_base64()
        if not hasattr(warrant, "to_base64"):
            raise TypeError(f"warrant must be a Warrant object with to_base64() method, got {type(warrant).__name__}")
        warrant_token = warrant.to_base64()

        # Build request with known task_id for response validation
        expected_task_id = task_id or str(uuid.uuid4())
        task_data = {
            "id": expected_task_id,
            "message": message_content,
            "skill": skill,
            "arguments": arguments or {},
        }

        # Send request
        response = await client.post(
            f"{self.url}/a2a",
            headers={"X-Tenuo-Warrant": warrant_token},
            json={
                "jsonrpc": "2.0",
                "method": "task/send",
                "params": {"task": task_data},
                "id": 1,
            },
        )

        data = response.json()

        # Validate JSON-RPC response structure
        if not isinstance(data, dict):
            raise ValueError(f"Invalid JSON-RPC response: expected dict, got {type(data).__name__}")

        if "error" in data:
            error = data["error"]
            from .errors import A2AError

            # Create appropriate error
            message = error.get("message", "Unknown error")
            error_data = error.get("data", {})

            raise A2AError(message, error_data)

        result_data = data.get("result", {})
        if not isinstance(result_data, dict):
            raise ValueError(f"Invalid result: expected dict, got {type(result_data).__name__}")

        # Validate task_id matches to prevent response spoofing
        response_task_id = result_data.get("task_id")
        if response_task_id and response_task_id != expected_task_id:
            raise ValueError(
                f"Response task_id mismatch: expected {expected_task_id!r}, "
                f"got {response_task_id!r}. Possible response spoofing."
            )

        return TaskResult.from_dict(result_data)

    async def send_task_streaming(
        self,
        message: Union[str, Message],
        warrant: "Warrant",
        *,
        skill: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> AsyncIterator[TaskUpdate]:
        """
        Send a streaming task to the agent.

        Uses Server-Sent Events (SSE) for streaming responses.
        Yields TaskUpdate objects for each event.

        Args:
            message: Task message (string or Message object)
            warrant: Tenuo warrant for authorization
            skill: Skill to invoke (required)
            arguments: Arguments for the skill
            task_id: Optional task ID (generated if not provided)

        Yields:
            TaskUpdate objects for status, artifacts, messages, and completion

        Raises:
            A2AError: If server returns an error (including mid-stream expiry)
        """
        client = await self._get_client()

        # Build message content
        if isinstance(message, str):
            message_content = message
        else:
            message_content = message.content

        # Skill is required
        if skill is None:
            raise ValueError(
                "skill is required. Specify the skill to invoke explicitly. "
                "Example: client.send_task_streaming(message='...', warrant=w, skill='search_papers')"
            )

        # Serialize warrant
        if not hasattr(warrant, "to_base64"):
            raise TypeError(f"warrant must be a Warrant object with to_base64() method, got {type(warrant).__name__}")
        warrant_token = warrant.to_base64()

        # Build request
        expected_task_id = task_id or str(uuid.uuid4())
        task_data = {
            "id": expected_task_id,
            "message": message_content,
            "skill": skill,
            "arguments": arguments or {},
        }

        # Send streaming request
        async with client.stream(
            "POST",
            f"{self.url}/a2a",
            headers={
                "X-Tenuo-Warrant": warrant_token,
                "Accept": "text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "method": "task/sendSubscribe",
                "params": {"task": task_data},
                "id": 1,
            },
        ) as response:
            # Check for non-streaming error response
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                # Non-streaming JSON error
                data = json.loads(await response.aread())
                if "error" in data:
                    error = data["error"]
                    raise A2AError(error.get("message", "Unknown error"), error.get("data", {}))

            # Parse SSE events
            data_buffer = ""
            async for line in response.aiter_lines():
                line = line.strip()

                if line.startswith("data:"):
                    data_buffer = line[5:].strip()
                elif line == "" and data_buffer:
                    # End of event
                    try:
                        event_data = json.loads(data_buffer)
                        update = TaskUpdate.from_dict(event_data)

                        # Validate task_id to prevent response spoofing
                        response_task_id = event_data.get("task_id")
                        if response_task_id and response_task_id != expected_task_id:
                            logger.warning(
                                f"Task ID mismatch in stream: expected {expected_task_id!r}, "
                                f"got {response_task_id!r}. Possible response spoofing."
                            )

                        # Check for error events
                        if update.type.value == "error":
                            error_code = event_data.get("code")
                            error_message = event_data.get("message", "Error during streaming")

                            # Check for mid-stream expiry
                            if error_code == -32004 and event_data.get("data", {}).get("mid_stream"):
                                raise WarrantExpiredError()

                            raise A2AError(error_message, event_data.get("data", {}))

                        yield update

                        # Stop on complete
                        if update.type.value == "complete":
                            return

                    except json.JSONDecodeError:
                        logger.warning(f"Invalid SSE data: {data_buffer!r}")
                    finally:
                        data_buffer = ""


# =============================================================================
# Delegation Helper
# =============================================================================


async def delegate(
    to: str,
    warrant: "Warrant",
    message: Union[str, Message],
    *,
    skill: str,
    arguments: Optional[Dict[str, Any]] = None,
    pin_key: Optional[str] = None,
) -> TaskResult:
    """
    Convenience function to delegate a task to another agent.

    Example:
        result = await delegate(
            to="https://research-agent.example.com",
            warrant=attenuated_warrant,
            message="Find TOCTOU papers",
            skill="search_papers",
        )

    Args:
        to: Target agent URL
        warrant: Warrant for authorization (should be attenuated for target)
        message: Task message
        skill: Skill to invoke (required)
        arguments: Skill arguments
        pin_key: Expected public key of target

    Returns:
        TaskResult from the target agent
    """
    async with A2AClient(to, pin_key=pin_key) as client:
        return await client.send_task(
            message=message,
            warrant=warrant,
            skill=skill,
            arguments=arguments,
        )
