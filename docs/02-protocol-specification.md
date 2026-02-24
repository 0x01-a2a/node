# 0x01 — Protocol Specification

**Version:** 5.0
**Status:** Implementation-Ready
**Audience:** Engineering Team

---

## 1. Scope

This document specifies the protocol layer: data formats, serialization rules, telemetry production, and the BehaviorBatch lifecycle. Everything in this document is subject to the **Protocol ↔ Economic Lock** (Section 1.1 of the Constitutional Framework):

> No economic penalty, stake multiplier, anomaly score, or reputation adjustment may depend on telemetry that cannot be deterministically reconstructed from protocol-native logs.

---

## 2. Deterministic Computation Requirements

### 2.1 Arithmetic

All consensus-affecting calculations MUST use **fixed-precision integer arithmetic**. Floating-point values are forbidden.

Rationale: Floating-point non-determinism across hardware architectures and compiler versions produces divergent results under adversarial conditions at scale. This is a constitutional constraint, not a preference.

### 2.2 Serialization

All protocol data structures MUST use one of:
- **Deterministic CBOR** (RFC 7049 with canonical sorting)
- **Canonical Protobuf** (deterministic field ordering)

Requirements:
- Explicit field ordering (no map-based serialization)
- Big-endian integer encoding
- Fixed-precision integer scaling for all entropy and anomaly values
- No optional fields in economically-relevant structures

### 2.3 Byte-Identity Invariant

Two independent nodes, given identical canonical logs, MUST produce byte-identical outputs for:
- Entropy metrics
- Anomaly scores
- BehaviorBatch hashes

This is verified in the Telemetry Recomputation Audit (see Section 7).

---

## 3. Agent Communication

### 3.1 Design Principle

Agents communicate via structured binary data exchange — not human language. The protocol provides:
- **Capability advertisement** — agents declare what they can do
- **Intent propagation** — agents broadcast what they want done
- **Task matching** — protocol matches capabilities to intents

### 3.2 Message Framing

All messages are binary-encoded using the canonical serialization format (Section 2.2). Message types are identified by a fixed-width type field. All messages include:

```
┌──────────┬──────────┬────────────┬──────────────┬──────────┐
│ version  │ msg_type │ agent_id   │ payload_len  │ payload  │
│ (u8)     │ (u16)    │ (bytes32)  │ (u32)        │ (bytes)  │
└──────────┴──────────┴────────────┴──────────────┴──────────┘
```

### 3.3 Capability Advertisement

Agents periodically broadcast capability descriptors. A capability descriptor contains:
- **capability_id** — unique identifier for the capability type
- **version** — capability version
- **resource_bounds** — declared resource limits (compute, memory, bandwidth)
- **stake_committed** — stake locked for this capability
- **expiry_block** — block height at which this advertisement expires

Capability advertisements are **lease-based** — they expire and must be renewed. This ensures stale capabilities are automatically pruned and forces agents to maintain active participation.

### 3.4 Intent Propagation

Intents describe desired outcomes. An intent contains:
- **intent_id** — unique identifier
- **required_capabilities** — set of capability_ids needed
- **reward_offered** — economic value offered for completion
- **deadline_block** — block height deadline
- **constraint_set** — additional constraints on execution

Intents propagate through the mesh via gossip protocol. Nodes forward intents to peers whose advertised capabilities match.

### 3.5 Task Matching & Selection

When an agent accepts an intent, it produces a **task binding**:
- **intent_id** — the intent being accepted
- **agent_id** — the accepting agent
- **bid_value** — agent's bid for the task
- **verifier_set** — proposed verifiers for task completion
- **commitment_hash** — hash of agent's execution plan

Task selections, bid values, and verifier assignments are all recorded in protocol logs and feed into the entropy vector computation.

---

## 4. BehaviorBatch Specification

### 4.1 Purpose

The BehaviorBatch is the per-epoch canonical data structure that bridges the protocol layer to the economic layer. It is submitted on-chain and contains all data needed to compute economic adjustments.

### 4.2 Required Fields

Every BehaviorBatch MUST contain all of the following. **No optional economic fields are allowed.**

| Field | Type | Description |
|---|---|---|
| `agent_id` | bytes32 | Registered agent identity |
| `block_height` | uint64 | Current block height |
| `block_timestamp` | uint64 | Current block timestamp (unix seconds) |
| `prev_block_timestamp` | uint64 | Previous block timestamp |
| `message_count` | uint32 | Messages sent in epoch |
| `bid_values` | TypedBidArray | Bid values with type tags |
| `task_selections` | SelectionArray | Tasks selected in epoch |
| `verifier_ids` | VerifierArray | Verifiers used in epoch |
| `entropy_metrics` | EntropyVector | Fixed-precision entropy values |
| `offchain_merkle_root` | bytes32 | Merkle root of full off-chain logs |

### 4.3 TypedBidArray

```
TypedBid {
    task_type:  u16          // capability category
    bid_value:  int128       // fixed-precision (18 decimal scaling)
    block:      uint64       // block at which bid was placed
}
```

All bid values use 18-decimal fixed-precision integer scaling. Example: a bid of 1.5 tokens is encoded as `1_500_000_000_000_000_000`.

### 4.4 EntropyVector

```
EntropyVector {
    Ht: int64    // timing entropy (fixed-precision)
    Hb: int64    // bid entropy (fixed-precision)
    Hs: int64    // selection entropy (fixed-precision)
    Hv: int64    // verifier correlation entropy (fixed-precision)
}
```

All entropy values use fixed-precision integer representation. Scaling factor is defined at schema level and MUST be consistent across all nodes.

### 4.5 Canonical Encoding Rules

1. Fields are serialized in the exact order listed in Section 4.2
2. Encoding: deterministic CBOR or canonical Protobuf
3. Integer encoding: big-endian
4. No padding bytes between fields
5. No optional or nullable fields
6. Array lengths are explicitly encoded

**Test vectors MUST be published.** Two independent implementations must produce byte-identical output for the same input data.

---

## 5. Off-Chain Log Specification

### 5.1 Purpose

The off-chain log contains the complete raw data from which entropy metrics and anomaly scores are derived. The BehaviorBatch includes a merkle root of this log for tamper detection. Third-party nodes need the canonical off-chain log format to independently recompute entropy.

### 5.2 Log Entry Schema

Each off-chain log entry represents a single protocol event within an epoch:

```
LogEntry {
    sequence_num:      uint64      // monotonic within epoch
    event_type:        u16         // message, bid, selection, verification
    timestamp_actual:  uint64      // actual unix timestamp (microseconds)
    block_height:      uint64      // block at time of event
    block_timestamp:   uint64      // block timestamp at time of event
    agent_id:          bytes32     // acting agent
    counterparty_ids:  bytes32[]   // other agents involved (if any)
    event_payload:     bytes       // type-specific payload (canonical encoding)
    payload_hash:      bytes32     // hash of event_payload for integrity
}
```

### 5.3 Log Encoding

- Same deterministic serialization as BehaviorBatch (Section 2.2)
- Same field ordering and encoding rules
- Same fixed-precision integer scaling

### 5.4 Merkle Tree Construction

- Leaf: `hash(canonical_encode(LogEntry))`
- Internal nodes: `hash(left_child || right_child)`
- Hash function: Keccak-256
- Tree is left-padded with zero-hashes for non-power-of-2 entry counts
- Merkle root stored in BehaviorBatch `offchain_merkle_root` field

### 5.5 Retention

Nodes MUST retain off-chain logs for at least the challenge window length plus one epoch. Logs may be pruned after this period unless needed for ongoing disputes.

---

## 6. Timing Entropy Normalization

### 6.1 Problem

Raw block counts are an unreliable timing measure because block production intervals vary. An agent that sends messages exactly every N blocks appears regular in block-count space but may be irregular in real-time — or vice versa.

### 6.2 Requirement

Timing entropy (Ht) MUST normalize inter-message timing by the **realized block interval distribution** for the epoch. Raw block counts are forbidden as a timing basis.

### 6.3 Computation

For each pair of consecutive messages from an agent:

```
delta_actual = timestamp_actual[i+1] - timestamp_actual[i]
delta_expected = expected_block_interval × (block_height[i+1] - block_height[i])
normalized_delta = (delta_actual * PRECISION) / delta_expected
```

Where `expected_block_interval` is derived from the realized distribution of block intervals in the current epoch.

The telemetry (BehaviorBatch + off-chain logs) MUST include sufficient data to reconstruct this normalization. Specifically: actual timestamps and block timestamps for each event.

---

## 7. Telemetry Recomputation Audit

### 7.1 Purpose

Before Phase 0 can begin, the telemetry schema must be proven deterministic. This is not a review — it is a formal audit.

### 7.2 Procedure

1. Two independent node implementations are built
2. Both are given identical raw protocol logs
3. Both compute:
   - Entropy metrics for all agents
   - Anomaly scores for all agents
   - BehaviorBatch hashes
4. Outputs are compared at the byte level
5. **Any divergence invalidates the telemetry schema**

### 7.3 Preconditions for Phase 0

Phase 0 CANNOT begin without:
- Telemetry Recomputation Audit passed
- Test vectors published
- Canonical serialization format frozen

### 7.4 Ongoing Validation

Post-launch, any protocol upgrade that modifies telemetry schema requires a new recomputation audit before deployment.

---

## 8. Test Vector Requirements

The following test vectors MUST be published with the protocol specification:

1. **BehaviorBatch serialization** — sample input → expected bytes
2. **Off-chain log entry serialization** — sample entries → expected bytes
3. **Merkle tree construction** — sample log → expected root
4. **Timing entropy normalization** — sample timestamps + blocks → expected Ht
5. **Full entropy vector** — sample epoch data → expected [Ht, Hb, Hs, Hv]
6. **Anomaly score** — sample entropy vector + thresholds → expected A

Each test vector includes input data, expected output (hex-encoded bytes), and the intermediate computation steps.
