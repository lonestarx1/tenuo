# Tenuo Python SDK Integration Guide

**For**: Contributors building new Python framework integrations  
**Examples**: [OpenAI](../../docs/openai.md), [Google ADK](../../docs/google-adk.md), [A2A](../../docs/a2a.md)

This guide ensures new Python integrations align with Tenuo's security philosophy and provide consistent developer experience.

---

## Security Model

### What Tenuo Protects Against

- **Prompt injection**: Malicious prompts cannot expand tool access beyond what constraints allow
- **Privilege escalation**: Delegated warrants can only narrow authority, never expand it
- **SSRF/path traversal**: `UrlSafe` and `Subpath` constraints block common attack patterns
- **Replay attacks**: JTI + expiry prevent warrant reuse
- **Hallucinated tools**: Only explicitly allowed tools can be called
- **Argument manipulation**: Constraints validate every parameter value

### What Tenuo Does NOT Protect Against

- **Vulnerable tool implementations**: If `read_file()` has a bug, Tenuo cannot help
- **Side channels**: Timing attacks, covert channels, etc.
- **Compromised signing keys**: If an attacker has the private key, game over
- **Denial of service**: Rate limiting is a transport-layer concern
- **Social engineering**: Users granting overly broad warrants

---

## Philosophy: Fail-Closed, Two-Tier, Zero Trust

### 1. Fail-Closed

**Deny by default. Explicitly allow.**

```python
# Good: Explicit constraints on every parameter
client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data"))
    .allow("search", query=Pattern("safe*"))
    .build())

# Tool allowed, but unknown args still rejected:
client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data"))
    .build())
# {"path": "/data/f.txt"} -> OK
# {"path": "/data/f.txt", "mode": "r"} -> REJECTED (mode not listed)

# To allow ANY argument value, use Wildcard explicitly:
client = (GuardBuilder(openai.OpenAI())
    .allow("search", query=Wildcard())  # Explicit: any query allowed
    .build())

# Bad: No tools specified
client = GuardBuilder(openai.OpenAI()).build()  # What tools are allowed?
```

**Constraint violations must block execution**, not just log warnings.

### 2. Two-Tier Model

```
Which tier should I use?
│
├─ Is the tool caller in the same process as the guard?
│   └─ Yes: Tier 1 (guardrails) is sufficient
│   └─ No:  Tier 2 (PoP) required
│
├─ Is the warrant delegated from another agent?
│   └─ Yes: Tier 2 with chain validation
│   └─ No:  Tier 2 without chain
│
└─ Do I need cryptographic proof of authorization?
    └─ Yes: Tier 2 always
    └─ No:  Tier 1 for simplicity
```

**Tier 1**: Runtime guardrails (no crypto)
- Constraint checking via `constraint.satisfies(value)`
- Tool allowlisting
- Suitable for single-process, trusted environments
- Example: OpenAI client in a monolith

**Tier 2**: Cryptographic authorization (warrant + PoP)
- All of Tier 1, plus:
- Warrant signature validation via `warrant.authorize()`
- Proof-of-Possession per tool call
- Delegation chain verification
- Required for distributed systems
- Example: Agent-to-Agent communication, microservices

**Both tiers must be supported.** Users choose based on threat model.

### 3. Zero Trust for Arguments

**Every argument must be explicitly allowed. There is no implicit pass-through.**

```python
# Adding a constraint to ANY parameter enables closed-world for ALL parameters
client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data"))
    .build())

# Results:
{"path": "/data/file.txt"}              # OK: path satisfies Subpath
{"path": "/etc/passwd"}                 # REJECTED: path violates Subpath
{"path": "/data/file.txt", "mode": "r"} # REJECTED: 'mode' not in constraints
#                         ^^^^^ This argument was never listed, so it's denied
```

**To allow unconstrained arguments:**
```python
# Option 1: Explicit Wildcard (recommended)
.allow("search", query=Wildcard(), limit=Wildcard())

# Option 2: Escape hatch (use sparingly)
.allow("search", _allow_unknown=True)
```

---

## API Patterns

### Pattern 1: Builder (Recommended)

All integrations should provide a fluent builder pattern:

```python
from tenuo.openai import GuardBuilder
from tenuo import Subpath, UrlSafe, Pattern, Wildcard

# Tier 1: Constraints on specific parameters
client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data"))
    .allow("fetch_url", url=UrlSafe(allow_domains=["api.example.com"]))
    .allow("search", query=Wildcard())  # Any query allowed
    .on_denial("raise")  # "raise" | "log" | "skip"
    .build())

# Tier 2: Warrant with PoP
client = (GuardBuilder(openai.OpenAI())
    .with_warrant(warrant, signing_key)
    .build())
```

### Pattern 2: Zero-Config Entry Point

For quick starts, provide a `protect()` or `protect_agent()` function:

```python
from tenuo.openai import protect
from tenuo import Subpath, UrlSafe

# One-liner with constraint inference
client = protect(
    openai.OpenAI(),
    read_file=Subpath("/data"),
    fetch_url=UrlSafe(allow_domains=["*.example.com"]),
)
```

### Pattern 3: Specialized Builders (A2A)

For complex integrations, provide specialized builders:

```python
from tenuo.a2a import A2AServerBuilder, A2AClientBuilder

# Server
server = (A2AServerBuilder()
    .skill("analyze", description="Analyze data")
    .accept_warrants_from(control_plane_key)
    .on_success(audit_callback)
    .build())

# Client
client = (A2AClientBuilder()
    .server_url("http://agent:8080")
    .warrant(my_warrant)
    .signing_key(my_key)
    .timeout(30)
    .build())
```

### Pattern 4: Framework-Specific Callbacks (ADK)

When the framework uses callbacks, adapt to its patterns:

```python
from tenuo.google_adk import GuardBuilder, protect_agent

# Builder pattern
guard = (GuardBuilder()
    .with_warrant(warrant, signing_key)
    .map_skill("read_file_tool", "read_file", path="file_path")
    .build())

agent = Agent(
    tools=guard.filter_tools([read_file, search]),
    before_tool_callback=guard.before_tool,
)

# Zero-config alternative
agent = protect_agent(
    Agent(tools=[read_file, search]),
    warrant=warrant,
    signing_key=signing_key,
)
```

### Async Support

Many agent frameworks (LangChain, AutoGen) are async-first. Tenuo Core operations are thread-safe and release the GIL during cryptographic operations, so they work correctly in async contexts.

```python
# Direct usage in async code (GIL-friendly)
async def authorize_tool(warrant, tool_name, args):
    # Rust core releases GIL during crypto operations
    warrant.authorize(tool_name, args)

# For CPU-intensive constraint checks, use asyncio.to_thread:
async def check_large_constraint(constraint, large_value):
    return await asyncio.to_thread(constraint.satisfies, large_value)
```

Both sync and async clients should be supported:

```python
# Sync
client = protect(openai.OpenAI(), ...)

# Async
async_client = protect(openai.AsyncOpenAI(), ...)
```

---

## Constraint Checking

### Use `satisfies()` Method

All constraints expose a unified `satisfies(value) -> bool` method from Rust core:

```python
def check_constraint(constraint: Any, value: Any) -> bool:
    """Check if value satisfies constraint. Fail closed on unknown types."""
    if hasattr(constraint, "satisfies"):
        return constraint.satisfies(value)
    
    # Unknown constraint type: fail closed
    logger.error(f"Unknown constraint type: {type(constraint).__name__}")
    return False
```

Do not use legacy semantic methods (`contains()`, `is_safe()`, `matches()`) in new code.

### Core Constraint Types

**Use existing constraints.** Do not invent framework-specific ones.

```python
from tenuo import (
    Subpath,    # Filesystem paths: Subpath("/data")
    UrlSafe,    # Network URLs: UrlSafe(allow_domains=["api.example.com"])
    Shlex,      # Shell commands: Shlex(allow_binaries=["/usr/bin/ls"])
    Pattern,    # Glob patterns: Pattern("*.txt")
    Regex,      # Regular expressions: Regex(r"^[a-z]+$")
    Range,      # Numeric ranges: Range(min=0, max=100)
    OneOf,      # Enumeration: OneOf(["read", "write"])
    Cidr,       # IP ranges: Cidr("10.0.0.0/8")
    Wildcard,   # Allow anything: Wildcard()
)
```

**Why reuse**: Constraints are portable. A warrant with `Subpath("/data")` works across OpenAI, ADK, A2A, and LangChain.

### Serialization

When sending warrants over the wire (e.g., A2A, HTTP headers), use the built-in serialization:

```python
# Serialize warrant
token = warrant.to_base64()  # Safe for HTTP headers, JSON

# Deserialize
warrant = Warrant.from_base64(token)
```

**Do not manually construct JSON dicts for warrants.** The wire format includes signatures that must be preserved exactly.

For constraints within warrants, serialization is handled automatically by the warrant methods. If you need to inspect constraints for debugging:

```python
# Debug only - not for wire transmission
print(warrant.capabilities)  # View capabilities and constraints
```

---

## Wire Format Requirement

**All runtime authorization MUST go through the Rust core.**

### Correct: Use Core Authorization

```python
from tenuo_core import Warrant

# Parse warrant from wire format
warrant = Warrant.from_base64(warrant_token)

# Tier 2: Authorize through core (validates signature, expiry, constraints)
warrant.authorize(tool_name, arguments)

# Generate PoP signature
pop_signature = warrant.sign(signing_key, tool_name, arguments)
```

### Incorrect: Reimplementing Authorization

```python
# DON'T do this - bypasses core security
def my_authorize(warrant_dict, tool, args):
    if tool in warrant_dict["tools"]:
        return True
    return False
```

**Why this matters**:
- Core has canonical signature validation
- Constraint checking is audited in Rust
- Wire format ensures cross-integration compatibility
- Bypassing core = security vulnerabilities

**Exception: Debug/Pre-flight Checks**

Pre-flight validation is acceptable for DX, but not for enforcement:

```python
# OK: Startup validation (not runtime blocking)
def validate(self):
    if self.warrant.is_expired():
        raise ConfigurationError("Warrant already expired")

# OK: Debug helpers (human-readable, not enforcement)
def explain_denial(warrant, tool, args):
    return warrant.why_denied(tool, args)
```

**The rule**: If it blocks a runtime tool call, it MUST use `warrant.authorize()` or `constraint.satisfies()` from core.

---

## Developer Experience Requirements

### 1. Validation on Startup

**Fail fast.** Catch configuration errors before runtime:

```python
class GuardBuilder:
    def build(self):
        self._validate()
        return self._build_client()
    
    def _validate(self):
        if self._warrant and self._signing_key is None:
            raise MissingSigningKey(
                "Warrant requires signing_key for PoP. "
                "Add .signing_key(...) or remove .with_warrant()."
            )
        
        if self._warrant and self._signing_key:
            if self._signing_key.public_key != self._warrant.holder:
                raise ConfigurationError(
                    "signing_key must match warrant holder"
                )
```

Also expose `.validate()` for explicit pre-flight checks:

```python
builder = GuardBuilder(client).allow("read_file", path=Subpath("/data"))
builder.validate()  # Throws if invalid, before build()
```

### 2. Rich Error Messages

Error messages should include:
- What went wrong
- Why it was denied
- How to fix it

```python
class ToolDenied(TenuoError):
    def __init__(self, tool_name: str, allowed_tools: List[str]):
        similar = _suggest_similar(tool_name, allowed_tools)
        
        message = f"Tool '{tool_name}' not allowed."
        if similar:
            message += f"\n\nDid you mean: {similar}?"
        message += f"\n\nAllowed tools: {', '.join(sorted(allowed_tools))}"
        message += f"\n\nQuick fix: .allow('{tool_name}')"
        message += f"\nDocs: https://tenuo.dev/docs/openai#allow-tools"
        
        super().__init__(message)
```

### 3. Denial Explanation Helpers

Provide helpers to explain why a call was denied:

```python
from tenuo.openai import explain_denial

reason = explain_denial(warrant, "read_file", {"path": "/etc/passwd"})
# "path '/etc/passwd' is outside allowed scope Subpath('/data')"
```

### 4. Development vs Production Modes

Support both exploratory development and strict production:

```python
# Development: log denials but allow execution
client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data"))
    .on_denial("log")  # Logs warning, allows execution
    .build())

# Production: strict enforcement (default)
client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data"))
    .on_denial("raise")  # Raises exception
    .build())
```

---

## Critical Test Scenarios

### 1. Constraint Enforcement

```python
def test_constraint_blocks_violation():
    client = (GuardBuilder(openai.OpenAI())
        .allow("read_file", path=Subpath("/data"))
        .build())
    
    with pytest.raises(ConstraintViolation):
        call_tool("read_file", {"path": "/etc/passwd"})
```

### 2. Closed-World Arguments

```python
def test_unknown_args_rejected():
    client = (GuardBuilder(openai.OpenAI())
        .allow("read_file", path=Subpath("/data"))
        .build())
    
    # 'mode' not in constraints -> rejected
    with pytest.raises(ConstraintViolation):
        call_tool("read_file", {"path": "/data/file.txt", "mode": "r"})
```

### 3. Wildcard Allows Any Value

```python
def test_wildcard_allows_any():
    client = (GuardBuilder(openai.OpenAI())
        .allow("search", query=Wildcard())
        .build())
    
    # Any query value passes
    call_tool("search", {"query": "anything"})  # OK
    call_tool("search", {"query": ""})  # OK
    
    # But unknown args still rejected
    with pytest.raises(ConstraintViolation):
        call_tool("search", {"query": "x", "limit": 100})  # 'limit' not listed
```

### 4. Tool Allowlist

```python
def test_unlisted_tool_rejected():
    client = (GuardBuilder(openai.OpenAI())
        .allow("read_file", path=Subpath("/data"))
        .build())
    
    with pytest.raises(ToolDenied):
        call_tool("delete_file", {"path": "/data/file.txt"})
```

### 5. Missing Signing Key (Tier 2)

```python
def test_warrant_requires_signing_key():
    with pytest.raises(MissingSigningKey):
        (GuardBuilder(openai.OpenAI())
            .with_warrant(warrant)  # No signing_key
            .build())
```

### 6. Key Mismatch (Tier 2)

```python
def test_signing_key_must_match_holder():
    wrong_key = SigningKey.generate()
    
    with pytest.raises(ConfigurationError):
        (GuardBuilder(openai.OpenAI())
            .with_warrant(warrant, wrong_key)
            .build())
```

### 7. Expired Warrant

```python
def test_expired_warrant_rejected():
    expired = Warrant.mint_builder().ttl(-1).mint(key)
    
    client = (GuardBuilder(openai.OpenAI())
        .with_warrant(expired, key)
        .build())
    
    with pytest.raises(WarrantExpired):
        call_tool("read_file", {"path": "/data/file.txt"})
```

### 8. Streaming TOCTOU Protection

**The integration must buffer tool arguments internally until they are complete, validate constraints, and only then yield the tool call to the user.**

This prevents Time-of-Check to Time-of-Use attacks where partial arguments pass validation but the final complete arguments would fail.

```python
def test_streaming_verifies_final_args():
    """
    Tool args must be buffered completely before verification.
    
    Attack scenario:
    1. LLM streams: {"query": "safe...
    2. Integration validates partial: "safe" -> OK
    3. LLM completes: {"query": "safe_injection_payload"}
    4. Without buffering, malicious payload executes
    
    Defense:
    1. Buffer ALL argument tokens until tool call complete
    2. Parse complete JSON
    3. Validate complete arguments
    4. Only then yield to user
    """
    client = (GuardBuilder(openai.OpenAI())
        .allow("search", query=Pattern("safe*"))
        .build())
    
    # Mock: streaming response where partial args look safe but final args are not
    with mock_streaming_response(
        partial_args={"query": "safe"},
        final_args={"query": "unsafe_injection"}
    ):
        # Integration buffers internally, validates final args, rejects
        with pytest.raises(ConstraintViolation):
            list(client.stream("search"))
```

**Implementation guidance:**

```python
async def guarded_stream(self, response_stream):
    tool_args_buffer = []
    
    async for chunk in response_stream:
        if chunk.is_tool_call_delta:
            # Buffer, don't validate yet
            tool_args_buffer.append(chunk.args_delta)
        elif chunk.is_tool_call_complete:
            # NOW validate complete arguments
            complete_args = json.loads("".join(tool_args_buffer))
            self._validate_args(complete_args)  # Raises on violation
            yield ToolCall(args=complete_args)  # Safe to yield
            tool_args_buffer = []
        else:
            # Text chunks can pass through immediately
            yield chunk
```

---

## Invariant Testing

**All integrations must pass these invariant tests.**

### Invariant 1: Monotonic Attenuation

Authority can only decrease, never increase.

```python
def test_monotonic_attenuation():
    root = (Warrant.mint_builder()
        .capability("read", path=Subpath("/"))
        .capability("write", path=Subpath("/"))
        .mint(root_key))
    
    child = (root.grant_builder()
        .capability("read", path=Subpath("/data"))
        .grant(root_key))
    
    # Child can read /data/file.txt
    assert child.authorize("read", {"path": "/data/file.txt"})
    
    # Child cannot read outside /data
    with pytest.raises(AuthorizationError):
        child.authorize("read", {"path": "/etc/passwd"})
    
    # Child cannot write (not in child's capabilities)
    with pytest.raises(AuthorizationError):
        child.authorize("write", {"path": "/data/file.txt"})
```

### Invariant 2: Fail-Closed on Unknown

Any unlisted parameter is rejected.

```python
def test_fail_closed_unknown():
    warrant = (Warrant.mint_builder()
        .capability("read", path=Subpath("/data"))
        .mint(key))
    
    # 'mode' not in warrant constraints
    with pytest.raises(ConstraintViolation):
        warrant.authorize("read", {"path": "/data/file.txt", "mode": "r"})
```

### Invariant 3: Expiry Enforced

Expired warrants rejected even with valid signature.

```python
def test_expiry_enforced():
    warrant = Warrant.mint_builder().capability("read").ttl(1).mint(key)
    
    time.sleep(2)
    
    with pytest.raises(WarrantExpired):
        warrant.authorize("read", {"path": "/data/file.txt"})
```

### Invariant 4: PoP Required (Tier 2)

Cannot use warrant without proving key possession.

```python
def test_pop_required():
    warrant = (Warrant.mint_builder()
        .capability("read")
        .holder(agent_key.public_key)
        .mint(control_key))
    
    # No signing_key: error at build time
    with pytest.raises(MissingSigningKey):
        GuardBuilder(client).with_warrant(warrant).build()
    
    # Wrong signing_key: error at build time
    with pytest.raises(ConfigurationError):
        GuardBuilder(client).with_warrant(warrant, wrong_key).build()
    
    # Correct signing_key: success
    GuardBuilder(client).with_warrant(warrant, agent_key).build()
```

### Invariant 5: Signature Verification

Modified warrants are rejected.

```python
def test_tampered_warrant_rejected():
    warrant = Warrant.mint_builder().capability("read").mint(key)
    
    warrant_bytes = warrant.to_bytes()
    tampered = bytearray(warrant_bytes)
    tampered[10] ^= 0xFF
    
    with pytest.raises(SignatureError):
        Warrant.from_bytes(bytes(tampered))
```

### Invariant 6: Chain Validation

Delegation chains must be valid from root to leaf.

```python
def test_chain_validation():
    root = Warrant.mint_builder().capability("read").mint(root_key)
    
    child = (root.grant_builder()
        .capability("read")
        .holder(child_key.public_key)
        .grant(root_key))
    
    assert child.validate_chain()
```

---

## Integration Checklist

### API Design

- [ ] Builder pattern with fluent API
- [ ] Zero-config entry point (`protect()` or similar)
- [ ] Supports both Tier 1 and Tier 2
- [ ] `on_denial` modes: raise, log, skip
- [ ] `.validate()` method for pre-flight checks
- [ ] Uses `constraint.satisfies()` for checking

### Security

- [ ] Fail-closed (deny by default)
- [ ] Closed-world arguments (unlisted params rejected)
- [ ] `Wildcard()` required for explicit any-value
- [ ] Constraint violations block execution
- [ ] Tier 2 requires both warrant AND signing_key
- [ ] Verifies signing_key matches warrant holder
- [ ] Checks warrant expiry before tool calls
- [ ] Generates PoP signature per tool call (Tier 2)
- [ ] Streaming buffers and verifies before emitting

### Developer Experience

- [ ] Rich error messages with quick fixes
- [ ] `explain_denial()` helper
- [ ] Validation at build time (fail fast)
- [ ] Clear docs links in errors
- [ ] Development mode (log only)

### Observability

- [ ] Audit log hook for authorization decisions
- [ ] Structured logging for denials (tool, args, reason, constraint)
- [ ] Optional: metrics callback or endpoint

### Error Types

- [ ] `ToolDenied` for disallowed tools
- [ ] `ConstraintViolation` for parameter violations
- [ ] `MissingSigningKey` for warrant without key
- [ ] `ConfigurationError` for key/warrant mismatch
- [ ] `WarrantExpired` for expired warrants

Each error should include an `error_code` for structured logging:

```python
class ToolDenied(TenuoError):
    error_code = "TOOL_DENIED"
    
class ConstraintViolation(TenuoError):
    error_code = "CONSTRAINT_VIOLATION"

# Usage in logs/metrics:
logger.error("Authorization failed", extra={
    "error_code": e.error_code,
    "tool": tool_name,
    "constraint": constraint_type,
})
```

### Documentation

- [ ] Quick start with constraints (secure first)
- [ ] Zero-config alternative
- [ ] Tier 2 example with delegation
- [ ] Development vs production patterns
- [ ] Security model section

### Tests

- [ ] All critical test scenarios above
- [ ] All 6 invariant tests
- [ ] Constraint types: Subpath, UrlSafe, Shlex, Pattern, Wildcard
- [ ] Streaming TOCTOU protection
- [ ] Async support (if applicable)

**Parametrized constraint testing** (recommended pattern):

```python
@pytest.mark.parametrize("constraint,valid_value,invalid_value", [
    (Subpath("/data"), "/data/file.txt", "/etc/passwd"),
    (Subpath("/data"), "/data/sub/file.txt", "/data/../etc/passwd"),
    (UrlSafe(), "https://example.com/api", "http://169.254.169.254/"),
    (UrlSafe(allow_domains=["api.github.com"]), "https://api.github.com/", "https://evil.com/"),
    (Pattern("*.txt"), "report.txt", "report.exe"),
    (Shlex(allow_binaries=["/usr/bin/ls"]), "ls -la", "rm -rf /"),
    (Range(min=1, max=100), 50, 200),
    (OneOf(["read", "write"]), "read", "delete"),
    (Wildcard(), "anything", None),  # Wildcard allows all, no invalid case
])
def test_constraint_enforcement(constraint, valid_value, invalid_value):
    assert constraint.satisfies(valid_value)
    if invalid_value is not None:
        assert not constraint.satisfies(invalid_value)
```

---

## Compatibility

Integrations should specify minimum `tenuo_core` version:

```python
# In your integration's __init__.py
import tenuo_core

_MIN_VERSION = "0.1.0"

def _check_version():
    from packaging import version
    if version.parse(tenuo_core.__version__) < version.parse(_MIN_VERSION):
        raise ImportError(
            f"tenuo_core >= {_MIN_VERSION} required. "
            f"Found {tenuo_core.__version__}. "
            f"Run: pip install --upgrade tenuo"
        )

_check_version()
```

---

## Common Pitfalls

### 1. Don't invent new constraint types

**Wrong**:
```python
class MyFrameworkPathConstraint:
    ...
```

**Right**:
```python
from tenuo import Subpath
```

### 2. Don't bypass core for authorization

**Wrong**:
```python
# Python-only validation
if tool in allowed_tools:
    execute(tool, args)
```

**Right**:
```python
# Use core
warrant.authorize(tool, args)
# or
constraint.satisfies(value)
```

### 3. Don't allow unlisted arguments by default

**Wrong**:
```python
for arg_name, arg_value in args.items():
    if arg_name in constraints:
        check(constraints[arg_name], arg_value)
    # Missing: reject unknown args
```

**Right**:
```python
for arg_name, arg_value in args.items():
    if arg_name not in constraints:
        raise ConstraintViolation(f"Argument '{arg_name}' not allowed")
    check(constraints[arg_name], arg_value)
```

### 4. Don't leave argument constraints ambiguous

**Wrong**:
```python
.allow("search")  # Ambiguous: does search take args? Which ones?
```

**Why it's bad**: The tool might accept `query`, `limit`, `offset` parameters. Without explicit constraints, users don't know which arguments are allowed. If `search` is called with `{"query": "x"}`, it will be REJECTED because `query` isn't listed.

**Right**:
```python
.allow("search", query=Wildcard())  # Explicit: query allowed, any value
.allow("search", query=Pattern("safe*"), limit=Range(1, 100))  # Constrained
```

### 5. Don't make Tier 2 optional for warrant

**Wrong**:
```python
def with_warrant(self, warrant, signing_key=None):
    # Allows warrant without PoP
```

**Right**:
```python
def with_warrant(self, warrant, signing_key):
    # signing_key is required (no default)
    if not signing_key:
        raise MissingSigningKey(...)
```

### 6. Don't skip PoP signature

**Wrong**:
```python
if warrant:
    return allow()  # Just checks presence
```

**Right**:
```python
pop = warrant.sign(signing_key, tool_name, args)
# Include pop in authorization header
```

---

## Reference Implementations

Study these for patterns and best practices:

| Integration | File | Key Patterns |
|-------------|------|--------------|
| **OpenAI** | `tenuo/openai.py` | Builder, streaming TOCTOU, `protect()` |
| **Google ADK** | `tenuo/google_adk/guard.py` | Callbacks, tool filtering, `protect_agent()` |
| **A2A** | `tenuo/a2a/server.py` | `A2AServerBuilder`, delegation chains |
| **LangChain** | `tenuo/langchain.py` | Tool wrapping, async support |
| **LangGraph** | `tenuo/langgraph.py` | State management, `KeyRegistry` |

---

## Questions?

- Review [protocol spec](../../docs/spec/protocol-spec-v1.md) for wire format details
- Ask in [GitHub Discussions](https://github.com/tenuo-ai/tenuo/discussions)

