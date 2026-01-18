"""
Tenuo AutoGen (AgentChat) Integration

This module provides lightweight wrappers to enforce Tenuo authorization for
tools used with AutoGen AgentChat. It is intentionally dependency-light:

- AutoGen is an optional dependency; importing this module does NOT require it.
- Wrappers work for plain Python callables and "tool-like" objects (duck-typed).

Recommended usage (AgentChat, Python >= 3.10):
    from tenuo import SigningKey, Warrant, Pattern
    from tenuo.autogen import guard_tool

    key = SigningKey.generate()
    warrant = Warrant.mint_builder().tools(["search"]).constraint("query", Pattern("safe*")).mint(key)
    bound = warrant.bind(key)

    def search(query: str) -> str:
        return f"results for {query}"

    guarded_search = guard_tool(search, bound, tool_name="search")
"""

from __future__ import annotations

from dataclasses import dataclass
import functools
import inspect
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    overload,
)

from .exceptions import (
    AuthorizationDenied,
    ConstraintResult,
    ToolNotAuthorized,
)

# Optional AutoGen import (best-effort, for feature detection only)
try:
    import autogen_agentchat  # type: ignore

    AUTOGEN_AVAILABLE = True
except Exception:
    AUTOGEN_AVAILABLE = False

T = TypeVar("T")
ToolLike = Any


def _resolve_tool_name(tool: Any, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    name = getattr(tool, "name", None)
    if isinstance(name, str) and name:
        return name
    fn_name = getattr(tool, "__name__", None)
    if isinstance(fn_name, str) and fn_name:
        return fn_name
    return tool.__class__.__name__


def _extract_auth_args(
    fn: Any, args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Dict[str, Any]:
    # Prefer kwargs (most tool calls are keyword-based)
    if kwargs:
        return dict(kwargs)

    # Common pattern: single dict payload
    if len(args) == 1 and isinstance(args[0], dict):
        return dict(args[0])

    # Pydantic v2 models / dataclasses / objects with dict-like export
    if len(args) == 1:
        obj = args[0]
        if hasattr(obj, "model_dump") and callable(getattr(obj, "model_dump")):
            try:
                return dict(obj.model_dump())  # type: ignore[attr-defined]
            except Exception:
                pass
        if hasattr(obj, "__dict__"):
            # Best effort: only for simple payload objects
            try:
                return dict(obj.__dict__)
            except Exception:
                pass

    # Fallback: bind positional args to signature
    try:
        sig = inspect.signature(fn)
        bound = sig.bind_partial(*args, **kwargs)
        return {k: v for k, v in bound.arguments.items() if k != "self"}
    except Exception:
        # Last resort: positional args by index
        return {f"arg{i}": v for i, v in enumerate(args)}


def _raise_from_denial(
    bound: Any, tool_name: str, auth_args: Dict[str, Any]
) -> None:
    # Tool not in warrant.tools
    try:
        tools = getattr(bound, "tools", None)
        if isinstance(tools, list) and tool_name not in tools:
            raise ToolNotAuthorized(
                tool=tool_name,
                authorized_tools=tools,
                hint=f"Add Capability('{tool_name}', ...) to your mint() call",
            )
    except ToolNotAuthorized:
        raise
    except Exception:
        # If bound doesn't expose .tools, fall through to why_denied
        pass

    why = None
    try:
        why = bound.why_denied(tool_name, auth_args)
    except Exception:
        why = None

    constraint_results: list[ConstraintResult] = []
    if (
        why is not None
        and hasattr(why, "constraint_failures")
        and getattr(why, "constraint_failures")
    ):
        try:
            for field, info in why.constraint_failures.items():  # type: ignore[union-attr]
                constraint_results.append(
                    ConstraintResult(
                        name=field,
                        passed=False,
                        constraint_repr=str(info.get("expected", "?")),
                        value=auth_args.get(field, "<not provided>"),
                        explanation=str(
                            info.get("reason", "Constraint not satisfied")
                        ),
                    )
                )
        except Exception:
            constraint_results = []

    if not constraint_results:
        # Fallback: still provide something readable
        for k, v in auth_args.items():
            constraint_results.append(
                ConstraintResult(
                    name=k,
                    passed=False,
                    constraint_repr="<see warrant>",
                    value=v,
                    explanation="Value does not satisfy constraint",
                )
            )

    hint = getattr(why, "suggestion", None) if why is not None else None
    raise AuthorizationDenied(
        tool=tool_name,
        constraint_results=constraint_results,
        reason="Arguments do not satisfy warrant constraints",
        hint=hint,
    )


def _ensure_authorized(
    bound: Any, tool_name: str, auth_args: Dict[str, Any]
) -> None:
    # BoundWarrant.validate performs full PoP verification; it returns ValidationResult.
    try:
        result = bound.validate(tool_name, auth_args)
    except Exception:
        # If bound doesn't have validate or validate errored, treat as deny with diagnostics.
        _raise_from_denial(bound, tool_name, auth_args)

    if result:
        return

    _raise_from_denial(bound, tool_name, auth_args)


@dataclass
class _ToolProxy:
    wrapped: Any
    bound: Any
    tool_name: str

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        auth_args = _extract_auth_args(self.wrapped, args, kwargs)
        _ensure_authorized(self.bound, self.tool_name, auth_args)
        return self.wrapped(*args, **kwargs)

    def __getattr__(self, item: str) -> Any:
        return getattr(self.wrapped, item)


@overload
def guard_tool(
    fn_or_tool: Callable[..., T],
    bound: Any,
    *,
    tool_name: Optional[str] = None,
) -> Callable[..., T]: ...


@overload
def guard_tool(
    fn_or_tool: ToolLike, bound: Any, *, tool_name: Optional[str] = None
) -> ToolLike: ...


def guard_tool(
    fn_or_tool: Any, bound: Any, *, tool_name: Optional[str] = None
) -> Any:
    """
    Guard a single tool/callable with Tenuo authorization using an explicit BoundWarrant.

    Args:
        fn_or_tool: A callable or tool-like object (must be invokable).
        bound: Typically a `tenuo.BoundWarrant` (recommended; performs PoP verification).
        tool_name: Tool name used for authorization checks. Defaults to `tool.name` or `fn.__name__`.

    Returns:
        A guarded callable/tool-like object.
    """
    resolved = _resolve_tool_name(fn_or_tool, tool_name)

    # If it's a plain callable function, return a wrapped function (preserves signature/name where possible).
    if callable(fn_or_tool) and inspect.isfunction(fn_or_tool):

        @functools.wraps(fn_or_tool)
        def wrapper(*args: Any, **kwargs: Any):
            auth_args = _extract_auth_args(fn_or_tool, args, kwargs)
            _ensure_authorized(bound, resolved, auth_args)
            return fn_or_tool(*args, **kwargs)

        return wrapper

    # Otherwise, return a proxy that forwards attributes and intercepts calls
    if not callable(fn_or_tool):
        raise TypeError("guard_tool expects a callable or tool-like object")

    return _ToolProxy(wrapped=fn_or_tool, bound=bound, tool_name=resolved)


def guard_tools(
    tools: Union[Sequence[Any], Mapping[str, Any]],
    bound: Any,
    *,
    tool_name_fn: Optional[Callable[[Any], str]] = None,
) -> Union[list[Any], dict[str, Any]]:
    """
    Guard a collection of tools.

    Supports:
    - list/tuple of tools
    - dict mapping name -> tool
    """
    if isinstance(tools, Mapping):
        out: dict[str, Any] = {}
        for name, tool in tools.items():
            tn = tool_name_fn(tool) if tool_name_fn else name
            out[name] = guard_tool(tool, bound, tool_name=tn)
        return out

    if isinstance(tools, Sequence):
        out_list: list[Any] = []
        for tool in tools:
            tn = tool_name_fn(tool) if tool_name_fn else None
            out_list.append(guard_tool(tool, bound, tool_name=tn))
        return out_list

    raise TypeError(
        "guard_tools expects a list/tuple of tools or a dict of name->tool"
    )
