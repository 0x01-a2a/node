# 0x01 — Architecture Overview

**Version:** 5.0
**Status:** Implementation-Ready
**Audience:** Engineering Team

---

## 1. System Purpose

0x01 is a machine-native agentic mesh network with an integrated economic layer and constitutional human sovereignty controls. Agents coordinate via structured binary protocols — not human language. The system provides:

- **P2P mesh communication** — capability advertisement, intent propagation, task matching
- **Crypto-economic enforcement** — stake, reputation, anomaly detection, slashing
- **Constitutional guarantees** — deterministic reproducibility, adversarial robustness, governance constraints

---

## 2. Architectural Principles

Every design choice in this system answers two questions:

> Does this make truth mechanically downhill?
> Does this make fraud require continuous energy input?

Honest behavior requires no coordination. Fraudulent behavior requires continuous coordination. The architecture composes lease expiration, reputation decay, challenge windows, and temporal rotation detection so that a cartel cannot set a strategy and coast — it must actively manage fraud, and continuous management is continuously detectable.

---

## 3. High-Level Component Map

```
┌─────────────────────────────────────────────────────────────┐
│                      GOVERNANCE LAYER                       │
│  Constitutional invariants · Governance epochs · Proposals  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                     ECONOMIC LAYER                          │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │   Staking   │  │  Reputation  │  │ Anomaly Detection │  │
│  │   Engine    │  │    System    │  │   (Entropy Vec)   │  │
│  └──────┬──────┘  └──────┬───────┘  └────────┬──────────┘  │
│         │                │                    │             │
│  ┌──────▼────────────────▼────────────────────▼──────────┐  │
│  │              Dynamic Stake Multiplier                  │  │
│  │    Sv_dynamic = Sv_base × (1 + β₁A + β₂R + β₃C + β₄S)│  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                  │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │  Capital Velocity Anomaly (CVA) · Circuit Breakers    │  │
│  │  Systemic Risk Index (SRI) · Probation Engine         │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                     PROTOCOL LAYER                          │
│                                                             │
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │  BehaviorBatch│  │  Timing Norm  │  │  Telemetry Log  │  │
│  │  (canonical)  │  │  (block var)  │  │  (off-chain)    │  │
│  └──────┬───────┘  └───────┬───────┘  └────────┬────────┘  │
│         │                  │                    │           │
│  ┌──────▼──────────────────▼────────────────────▼────────┐  │
│  │          Deterministic Serialization (CBOR/Proto)      │  │
│  │          Fixed-precision integer arithmetic only        │  │
│  └────────────────────────┬──────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                     IDENTITY LAYER                          │
│                                                             │
│  ┌─────────────────┐  ┌──────────────────┐                  │
│  │  ERC8004 (ETH)  │  │  SATI (Solana)   │                  │
│  └────────┬────────┘  └────────┬─────────┘                  │
│           │                    │                             │
│  ┌────────▼────────────────────▼─────────────────────────┐  │
│  │        Wallet Binding · Minimum Stake Lock (Sv)        │  │
│  │        Ownership Clustering · Capital Flow Analysis    │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Component Descriptions

### 4.1 Identity Layer

On-chain identity is mandatory for economic participation. Every agent registers via ERC8004 (Ethereum) or SATI (Solana), binds a wallet, and locks minimum stake. No anonymous participation in the economic layer.

Ownership clustering heuristics detect Sybil structures:
- Shared funding source
- Shared withdrawal endpoints
- Behavioral similarity
- Capital flow correlation

These clusters feed into Capital Velocity monitoring and cartel detection.

### 4.2 Protocol Layer

The protocol layer handles data production and serialization. Its core artifact is the **BehaviorBatch** — a per-epoch canonical data structure containing all economically relevant telemetry.

Key constraints:
- **Deterministic CBOR or canonical Protobuf** — explicit field ordering, big-endian integers
- **Fixed-precision integer arithmetic only** — floating-point is forbidden in all consensus-affecting calculations
- **Byte-identical outputs** across independent nodes
- **Timing entropy normalization** against realized block interval distribution (raw block counts forbidden)

### 4.3 Economic Layer

The economic layer consumes protocol telemetry and produces enforcement actions. Its components are:

| Component | Input | Output |
|---|---|---|
| **Entropy Vector** | Protocol logs | Anomaly score (A) per agent |
| **Reputation System** | Historical behavior | Reputation decay (R) per agent |
| **CVA Monitor** | Balance + task volume | Audit probability adjustments |
| **SRI Oracle** | Exposure graph | Systemic risk multiplier (S) |
| **Stake Engine** | A, R, C, S | Dynamic stake requirement |
| **Circuit Breakers** | SRI, anomaly clusters, CVA surge | Throttling, suspension, stake increase |
| **Probation Engine** | Violation history | Dual-exit probation (time + clean audits) |

### 4.4 Governance Layer

The governance layer enforces constitutional invariants. No governance proposal may:
- Introduce non-reconstructible telemetry
- Introduce proprietary anomaly inputs
- Modify α_min outside a governance epoch

Constitutional invariant violations invalidate a proposal automatically.

---

## 5. Data Flow

```
Agent Activity
    │
    ▼
Protocol Logs (off-chain, canonical format, merkle-committed)
    │
    ├──▶ BehaviorBatch (on-chain, per epoch)
    │        │
    │        ▼
    │    Entropy Vector Computation ──▶ Anomaly Score (A)
    │                                       │
    │    Reputation Decay ──────────────▶ R  │
    │    Coordination Risk ─────────────▶ C  │
    │    SRI Oracle ────────────────────▶ S  │
    │                                       │
    │                              ┌────────▼────────┐
    │                              │  Sv_dynamic =    │
    │                              │  Sv_base × (1 +  │
    │                              │  β₁A+β₂R+β₃C+β₄S)│
    │                              └────────┬────────┘
    │                                       │
    │                                       ▼
    │                              Stake Enforcement
    │
    ├──▶ CVA Computation ──▶ Audit Probability / Cluster Review
    │
    └──▶ Third-party Recomputation (Constitutional Audit)
```

---

## 6. Adversarial Model

The system assumes agents have **full knowledge** of:
- Entropy thresholds
- Stake formula and all coefficients
- Anomaly scoring algorithms
- Other agents' public behavior

Additionally, agents **can**:
- Coordinate with other agents
- Optimize behavior adaptively over time
- Attempt rotational evasion across entropy dimensions

**Security derives from economic topology, not obscurity.** The architecture must remain sound even when the adversary knows every parameter. This is a constitutional assumption — any component that relies on secrecy for security is invalid.

---

## 7. External Dependencies

| Dependency | Role | Chain |
|---|---|---|
| ERC8004 registry | Agent identity (Ethereum) | Ethereum |
| SATI registry | Agent identity (Solana) | Solana |
| SRI Oracle | Systemic risk computation | Off-chain → on-chain commit |
| Cartel Simulator | α_min / β derivation | Off-chain (pre-launch) |

---

## 8. Relationship to Prior Systems

0x01 builds on capabilities from:
- **Bastion** — Agent security proxy patterns
- **MoltMind** — Behavioral monitoring primitives
- **KYA Registry** — Agent identity framework

These systems inform design decisions but are not runtime dependencies.

---

## 9. Implementation Sequence

The implementation sequence is **strictly ordered** — no inversion between steps 3–4:

1. Build adversarial cartel simulator
2. Derive α_min (+ β coefficients, SRI threshold)
3. Design canonical telemetry schema (including off-chain log format)
4. Execute Telemetry Recomputation Audit
5. Implement Phase 0 (observation, no penalties)
6. Publish entropy distributions (anti-seeding)
7. Activate Phase 1 (enforcement)
8. Deploy economic contracts

**Critical path:** The simulator is the single most important artifact. Every constitutional parameter (α_min, β₁–β₄, SRI threshold, entropy thresholds) derives from it. The simulator must be independently audited before α_min publication.
