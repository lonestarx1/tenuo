# Protocol Extensibility & Compatibility Guide

This document outlines the strategies used in Tenuo v0.1 to ensure forward compatibility and define how the protocol evolves.

## "Core is Frozen, SDKs Adapt" Philosophy

Tenuo v0.1 adheres to a **Frozen Core** philosophy. This means:
1.  **Strict Validation**: The core protocol (serialization, signature verification, warrant typing) is strict.
2.  **Fail-Closed by Design**: If an SDK encounters a protocol element it does not understand (e.g., a new Warrant Type or Core Field), it MUST reject the warrant. It cannot safely process "known unknowns" in the authorization path.
3.  **SDK Upgrades Required**: New protocol features require SDK upgrades. We prioritize security correctness over partial interoperability.

## Extensibility Mechanisms

Despite the frozen core, Tenuo provides specific hooks for extensibility without breaking changes.

### 1. `extensions` Field (Metadata)

The `WarrantPayload` includes an `extensions` field (Key 10) of type `Map<String, Bytes>`.
*   **Purpose**: Use this for **all** optional metadata, context, or non-critical data.
*   **Behavior**: SDKs preserve extensions they don't understand (pass-through).
*   **Examples**:
    *   Trace IDs (`tenuo.trace_id`)
    *   OIDC binding tokens
    *   Agent session labels
*   **Rule**: NEVER put authorization-critical logic in `extensions` if older SDKs ignoring it would cause a security bypass.

### 2. `Constraint` Variants

The `Constraint` enum reserves IDs 1-16 (currently used up to 15 for CEL).
*   **Unknown Variants**: The protocol defines a fallback `Unknown { type_id, payload }` variant.
*   **Behavior**:
    *   **Deserialization**: Preservation is best-effort. Bytes payloads are preserved; complex structured payloads might fail deserialization (effectively fail-closed).
    *   **Authorization**: `Unknown` constraints ALWAYS fail `matches()`. This ensures older verifiers don't allow access they can't validate.
*   **Future IDs**: IDs 17-255 are available for future standard constraints.

### 3. Protocol Versioning

*   **`WIRE_VERSION` (0)**: The first byte of the CBOR envelope.
*   **Strategy**: If we need to change the fundamental envelope structure (e.g., switch from Ed25519 to Dilithium, or change the `WarrantPayload` map structure), we bump `WIRE_VERSION`.
*   **Behavior**: SDKs check version first. `version != 1` -> Reject immediately.

## Protocol Limits (Hard Bounds)

To ensure determinism and prevent DoS, the following hard limits are frozen:
*   **`MAX_DELEGATION_DEPTH` = 64**: Maximum chain length.
*   **`MAX_CONSTRAINT_DEPTH` = 32**: Maximum nesting of boolean logic (`All`/`Any`/`Not`).
*   **`POP_TIMESTAMP_WINDOW` = ±30s**: Clock skew tolerance.

## Adding New Features

| Feature Type | Strategy | Compatibility Impact |
|--------------|----------|----------------------|
| **New Metadata** | Add to `extensions` | **Non-Breaking** (Invisible to old SDKs) |
| **New Constraint** | Add new `Constraint` variant ID | **Breaking for Authz** (Old SDKs deny access, new SDKs allow) |
| **New Warrant Type** | Add new `WarrantType` variant | **Breaking** (Old SDKs fail to deserialize) |
| **New Core Field** | Add new integer key to `WarrantPayload` | **Breaking** (Old SDKs fail to deserialize) |
| **New Crypto** | Bump `WIRE_VERSION` | **Breaking** (Old SDKs reject version) |

## Implementation Notes

*   **Rust**: Uses `serde` with strict checks. Unknown fields cause deserialization errors.
*   **Python**: Wraps Rust core, inheriting strictness.
*   **Maintenance**: When introducing breaking changes, bump the library Major version (e.g., 0.1 -> 0.2) or support dual-stack parsing if strictly necessary (not planned for v0.x).
