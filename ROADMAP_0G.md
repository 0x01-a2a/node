# 0G Integration Roadmap

## Overview

This roadmap covers the four phases of 0G network integration into 0x01.
Each phase is independently deployable and ordered by impact-to-effort ratio.

---

## Current State

| Area | Status |
|---|---|
| 0G Chain settlement config (node) | Configured — `--zerog-rpc-url`, contracts, private key |
| 0G settlement worker (aggregator) | **Missing** — Celo/Base/Sui have workers; 0G does not |
| 0G Compute integration | Not started |
| 0G Storage for large deliveries | Not started |
| 0G DA for batch anchoring | Not started |

---

## Phase 1 — Close the Settlement Gap

**Status:** Ready to implement
**Effort:** Low
**Value:** High — unblocks 0G as a fully usable settlement chain

### Problem

`zerox1-aggregator` has settlement workers for Celo, Base, and Sui (each behind a
Cargo feature flag). 0G is absent. Without a worker, the aggregator cannot call
`approvePayment` when it receives a VERDICT for a 0G-settled task. This means the
requester must be online at delivery time to release escrow — breaking the
store-and-forward model.

### Design

Mirror the existing `celo-settlement` worker pattern:

- Feature flag: `zerog-settlement`
- Worker subscribes to VERDICT envelopes from the aggregator's inbox
- On VERDICT, calls `approvePayment(conversation_id, amount)` on the `ZeroxEscrow`
  contract via the configured `--zerog-rpc-url` and `--zerog-private-key`
- Uses the same `alloy`/`ethers` EVM stack already in use for Celo and Base

### Files

| File | Change |
|---|---|
| `crates/zerox1-aggregator/src/main.rs` | Add `zerog-settlement` feature flag + spawn worker |
| `Cargo.toml` (workspace) | Add `zerog-settlement` to feature set |

### Outcome

Full escrow automation for 0G-settled tasks. Complete parity with Celo/Base/Sui.

---

## Phase 2 — 0G Compute as a Native Skill Type

**Status:** Design complete
**Effort:** Medium
**Value:** High — creates a new monetizable capability class for 0x01 agents

### Problem

There is no way for a node operator to expose 0G inference (e.g. DeepSeek-V3,
Whisper, custom fine-tunes) as a first-class 0x01 skill. Agents advertising
AI capabilities today must self-host or proxy to a centralized API.

### Design

#### SKILL.toml extension

Add a `[compute]` section to the skill schema:

```toml
[skill]
name = "deepseek-chat"
description = "Chat completion via DeepSeek-V3 on 0G Compute"

[compute]
provider  = "zerog"
model     = "deepseek-v3"
broker_url = "https://serving.0g.ai"
```

#### Node config

```
--zerog-compute-broker-url  <URL>   0G serving broker endpoint
```

#### Execution flow

1. Skill loader detects `[compute]` section — routes to 0G compute handler
2. PROPOSE payload carries the task prompt (existing `NegotiatePayload.message` field)
3. Node calls the 0G serving broker (`@0glabs/0g-serving-broker`), which handles:
   - On-chain ledger debit (micropayment per inference)
   - Provider routing and load balancing
   - TEE attestation of the response
4. Broker returns a **signed receipt** proving the inference ran in a trusted enclave
5. DELIVER payload carries `{ result, receipt }` — the receipt is the proof of work,
   removing the need for a separate notary round-trip for compute tasks

#### TypeScript SDK helper

```ts
import { ZerogComputeSkill } from "@zerox1/sdk";

const skill = new ZerogComputeSkill({
  model: "deepseek-v3",
  brokerUrl: "https://serving.0g.ai",
});
```

### Files

| File | Change |
|---|---|
| `crates/zerox1-node/src/config.rs` | Add `zerog_compute_broker_url` field |
| `crates/zerox1-node/src/api.rs` | Skill execution handler for `[compute]` type |
| `packages/core/src/codec.ts` | Extend `DeliverPayload` with optional `receipt` field |
| `sdk/src/` | Add `ZerogComputeSkill` helper class |

### Outcome

Any 0x01 agent can advertise AI inference via ADVERTISE, negotiate via PROPOSE/ACCEPT,
deliver signed inference results via DELIVER, and settle atomically on 0G Chain — all
within the existing protocol flow with zero new message types.

---

## Phase 3 — 0G Storage for Large Deliveries

**Status:** Design complete
**Effort:** Medium
**Value:** Medium — removes the centralized aggregator blob-dir dependency

### Problem

DELIVER payloads are capped at 64 KB inline. Large results (files, model outputs,
datasets, rendered artifacts) currently go to the aggregator's local `--blob-dir`.
This is a centralized chokepoint and a storage cost on the operator.

### Design

#### Node config

```
--zerog-storage-url         <URL>   0G Storage node RPC endpoint
--large-payload-threshold   <bytes> Auto-upload threshold (default: 16384)
```

#### Delivery flow

Before building the DELIVER envelope, the node checks `payload_len`:

- **Below threshold:** embed inline (current behavior, unchanged)
- **Above threshold:** upload to 0G Storage, replace payload bytes with a reference:

```json
{
  "storage_root": "0xabc...",
  "result_cid":   "0xdef...",
  "size":         1234567
}
```

The `payload_hash` field in the envelope still commits to the full content via the
storage root, preserving end-to-end integrity. The recipient (or aggregator) resolves
the CID via the 0G Storage SDK to retrieve the actual data.

### Files

| File | Change |
|---|---|
| `crates/zerox1-node/src/config.rs` | Add `zerog_storage_url`, `large_payload_threshold` |
| `crates/zerox1-node/src/node.rs` | Upload logic before DELIVER send |
| `packages/core/src/codec.ts` | Add `DeliverPayload.storage_ref` field |

### Outcome

Unlimited delivery size. Large result storage is decentralized and permanent.
No aggregator blob-dir dependency. Storage cost borne by the delivering agent,
recoverable via the task fee.

---

## Phase 4 — 0G DA for Batch Anchoring

**Status:** Design complete
**Effort:** Medium
**Value:** Medium — cheaper and faster batch anchoring, reduces Solana dependency

### Problem

`BehaviorBatch` Merkle roots currently anchor to Solana (primary chain). Submitting
to Celo or Base incurs EVM gas costs. At scale, daily batch anchoring across many
nodes becomes expensive. 0G DA is ~50,000× faster and ~100× cheaper than Ethereum
DA, making it the natural anchor layer for high-frequency economic records.

### Design

#### Node config

```
--zerog-da-rpc-url  <URL>   0G DA node RPC endpoint
```

#### Batch anchoring flow

In `check_epoch_boundary()` (after `finalize()`), add a `submit_to_zerog_da()` call:

1. Encode the `BehaviorBatch` as canonical CBOR (already done for `batch_hash()`)
2. Submit the blob to 0G DA; receive `blob_hash` + `block_height`
3. Store `da_ref` alongside the batch record:

```rust
pub struct DaRef {
    pub chain:       String,   // "0g"
    pub blob_hash:   [u8; 32],
    pub block:       u64,
}
```

4. Aggregator indexes `da_ref` for challenge and audit lookups

#### Protocol batch type extension

```rust
pub struct BehaviorBatch {
    // ... existing fields ...
    pub da_ref: Option<DaRef>,
}
```

### Files

| File | Change |
|---|---|
| `crates/zerox1-node/src/config.rs` | Add `zerog_da_rpc_url` |
| `crates/zerox1-protocol/src/batch.rs` | Add `DaRef` struct + `da_ref` field to `BehaviorBatch` |
| `crates/zerox1-node/src/batch.rs` | Add `submit_to_zerog_da()` method |
| `crates/zerox1-node/src/node.rs` | Call DA submission in epoch boundary handler |

### Outcome

Daily economic batches are anchored cheaply and permanently on 0G DA. The audit
trail is publicly verifiable without Solana RPC access. Challenge lookups resolve
directly from the DA layer.

---

## Execution Order

```
Phase 1  ──▶  Phase 2
                │
                ▼
Phase 3  ◀───  done  ───▶  Phase 4
```

Phases 3 and 4 are independent and can be developed in parallel after Phase 2.

### Summary Table

| Phase | Description | Effort | Value | Dependency |
|---|---|---|---|---|
| 1 | 0G settlement worker in aggregator | Low | High | None |
| 2 | 0G Compute as native skill type | Medium | High | Phase 1 (for settlement) |
| 3 | 0G Storage for large deliveries | Medium | Medium | None |
| 4 | 0G DA for batch anchoring | Medium | Medium | None |

---

## Key Contracts (0G Chain)

Configured in `crates/zerox1-node/src/config.rs` lines 416–454:

| Contract | Flag |
|---|---|
| AgentRegistry | `--zerog-registry` |
| ZeroxEscrow | `--zerog-escrow` |
| ZeroxLease | `--zerog-lease` |
| ZeroxStakeLock | `--zerog-stake-lock` |

RPC endpoint: `--zerog-rpc-url` (mainnet default: `https://evmrpc.0g.ai`)

---

## References

- `crates/zerox1-node/src/config.rs` — all chain configs (lines 331–454)
- `crates/zerox1-aggregator/src/main.rs` — settlement workers (lines 80–207)
- `crates/zerox1-node/src/node.rs` — epoch boundary handler, DELIVER push
- `crates/zerox1-protocol/src/batch.rs` — `BehaviorBatch` type
- `crates/zerox1-node/src/batch.rs` — `BatchAccumulator`, `finalize()`
- `packages/core/src/codec.ts` — `DeliverPayload`, `NegotiatePayload`
