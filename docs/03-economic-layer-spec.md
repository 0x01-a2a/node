# 0x01 — Economic Layer Specification

**Version:** 5.0
**Status:** Implementation-Ready
**Audience:** Engineering Team

---

## 1. Scope

This document specifies the economic enforcement layer: staking, reputation, anomaly detection, capital velocity monitoring, systemic risk measurement, and the probation mechanism. All economic calculations are subject to the constitutional Protocol ↔ Economic Lock — every input must be derivable from protocol-native logs.

---

## 2. Agent Identity & Registration

### 2.1 On-Chain Identity

Every agent participating in the economic layer MUST:
1. Register via **ERC8004** (Ethereum) or **SATI** (Solana) compatible identity
2. Bind a wallet to the protocol identity
3. Lock minimum stake `Sv`

No anonymous participation is permitted. Identity is the anchor for all economic operations.

### 2.2 Ownership Clustering

The system maintains ownership cluster heuristics to detect Sybil structures and coordinated agent groups:

| Heuristic | Signal |
|---|---|
| Shared funding source | Agents funded from the same wallet or funding chain |
| Shared withdrawal endpoints | Agents withdrawing to common destinations |
| Behavioral similarity | Statistically correlated action patterns |
| Capital flow correlation | Synchronized capital movements |

Clusters are inputs to:
- Capital Velocity Anomaly monitoring
- Cartel detection
- Coordination risk scoring (C in the stake formula)

---

## 3. Stake Floor (α_min)

### 3.1 Constitutional Status

`α_min` is the minimum viable stake ratio. It is **constitutionally protected** — once set at launch, it cannot change without a governance epoch review.

`α_min` is derived **exclusively** from adversarial simulation. It is not set by intuition, committee decision, or market observation.

### 3.2 Simulation Requirements

The simulation MUST model the following parameter space:

| Parameter | Range |
|---|---|
| `n_agents` | 10–500 |
| `n_cartel` | 2–30% of population |
| Reward distributions | Uniform + power-law |
| Detection accuracy `p_detect` | 0.5–0.99 |
| Reputation decay `d` | System-defined range |
| Challenge window length | System-defined range |

### 3.3 Cartel Behavioral Models

The simulation MUST include at minimum:

**Type C-1: Static threshold hugging** — Cartel members maintain behavior just below detection thresholds across all entropy dimensions simultaneously.

**Type C-2: Rotational evasion** — Cartel members cycle which entropy dimension they exploit, staying below threshold in any single measurement window while extracting value across dimensions over time.

### 3.4 Success Criterion

`α_min` must satisfy:

```
P(cartel_EV > 0 persists for > T epochs) < ε
```

across **all tested coalition sizes and behaviors**.

If any tested cartel configuration achieves positive expected value for longer than T epochs, `α_min` is insufficient.

### 3.5 Simulation Audit

Simulation code MUST be:
- Open-source
- Reproducible (deterministic seeding, version-pinned dependencies)
- **Independently audited** by parties with no economic stake in the outcome

The audit report is a **precondition for Phase 0**. A buggy simulation that underestimates cartel profitability produces a wrong `α_min`, and a wrong `α_min` is constitutional — requiring a governance epoch to fix. This is the most dangerous failure state at launch.

---

## 4. Dynamic Stake Multiplier

### 4.1 Formula

```
Sv_dynamic = Sv_base × (1 + β₁A + β₂R + β₃C + β₄S)
```

Where:

| Symbol | Component | Source |
|---|---|---|
| `A` | Anomaly score | Entropy vector computation |
| `R` | Reputation decay | Historical behavior tracking |
| `C` | Coordination risk | Ownership clustering + behavioral correlation |
| `S` | Systemic risk multiplier | SRI oracle |

### 4.2 Component Independence

Each component (A, R, C, S) MUST be independently auditable. An observer with access to protocol logs can verify any single component without needing to verify the others.

### 4.3 β Coefficient Derivation

β₁ through β₄ are **derived from the same adversarial simulation as α_min**. They are not set by intuition.

Derivation target: no single component can dominate stake calculation under realistic parameter ranges. Specifically, for all simulated scenarios:

```
max(β_i × component_i) / Σ(β_j × component_j) < dominance_threshold
```

β coefficients are published alongside α_min and are subject to the same governance epoch requirement for modification.

---

## 5. Entropy Vector

### 5.1 Dimensions

The entropy vector measures behavioral regularity across four dimensions:

| Dimension | Symbol | What It Measures |
|---|---|---|
| Timing entropy | `Ht` | Regularity of message timing (normalized to block intervals) |
| Bid entropy | `Hb` | Regularity of bid values |
| Selection entropy | `Hs` | Regularity of task selection patterns |
| Verifier correlation | `Hv` | Regularity of verifier-agent pairings |

Each dimension is computed exclusively from protocol-native logs.

### 5.2 Anomaly Score Aggregation

```
A = Σ w_i × max(0, (H_i − H_i_threshold))
```

Key rules:
- **Only positive deviations above threshold contribute.** An agent that is unusually *random* in one dimension does NOT get credit to offset unusually *regular* behavior in another.
- **No negative deviation offsets allowed.** This is not a net score — it is a strictly additive penalty.
- Weights `w_i` are published and governance-controlled.

### 5.3 Temporal Rotation Detection

**Threat model (Type C-2):** A cartel rotates which entropy dimension it exploits per epoch, staying below threshold in any single measurement window.

**Defense:** Sequence-aware anomaly detection.

1. Maintain a rolling window `W` of epoch-level per-dimension anomaly flags
2. Compute rotation frequency:
   ```
   F = count(dimension-specific anomalies within W) / |W|
   ```
3. Compare `F` against baseline stochastic expectation under honest traffic
4. If rotation frequency exceeds honest baseline, apply **temporal anomaly multiplier** to the anomaly score

Sequence-aware anomaly detection is **mandatory**. Without it, the entropy vector is only statistically sound under honest behavior — not adversarially robust.

### 5.4 Entropy Thresholds

Thresholds for each dimension are derived from Phase 0 observation data. Before thresholds are finalized:
- Full entropy distributions are published publicly
- Threshold selection is performed transparently

This neutralizes information asymmetry — thresholds cannot be exploited by insiders who know them before others.

---

## 6. Capital Velocity Anomaly (CVA)

### 6.1 Purpose

CVA detects **valley hardening** — agents accumulating capital stock without proportional task activity. This is a stock measurement, distinct from the entropy vector which is a flow measurement.

### 6.2 Metric

```
CVA_i = (Δ idle_balance over W epochs) / (task_volume over W epochs)
```

### 6.3 Effects

If `CVA_i` exceeds the baseline percentile threshold:
- Increase audit probability for agent `i`
- Trigger ownership cluster review
- Increase coordination scrutiny weight (`C` component)

### 6.4 Separation Principle

**CVA does NOT directly modify the entropy vector.** This is an explicit architectural decision. CVA is a stock measurement; entropy is a flow measurement. Keeping them separate prevents either from masking the other and prevents gaming CVA to offset entropy anomalies.

---

## 7. Systemic Risk Index (SRI)

### 7.1 Definition

```
SRI = spectral_radius(exposure_graph)
```

SRI measures cascade propagation potential — how far a single-agent failure could ripple through the network.

### 7.2 Computation

The primary computation method is off-chain oracle using power iteration:

1. Oracle constructs the exposure matrix from on-chain data
2. Oracle computes spectral radius via power iteration
3. Oracle publishes:
   - Exposure matrix hash
   - Computed SRI value
   - Proof of computation

Anyone may independently recompute SRI from the published exposure matrix hash and on-chain data.

### 7.3 SRI Threshold Derivation

The SRI circuit breaker threshold is set at the spectral radius value at which a simulated single-agent failure produces cascade losses exceeding `X%` of total staked capital.

This threshold is derived from the adversarial simulation alongside α_min and β coefficients. It provides a principled basis for the trigger rather than an arbitrary cutoff.

### 7.4 Oracle Governance

- **Launch:** Council-operated oracle
- **Transition path:** Decentralized oracle (required, timeline TBD)
- Circuit breaker triggers from the committed SRI value

---

## 8. Reputation System

### 8.1 Decay

Reputation decays over time. An agent that stops participating sees its reputation decrease toward baseline. This ensures:
- Reputation cannot be stockpiled and spent
- Historical good behavior has diminishing returns
- Agents must continuously maintain reputation through active honest participation

### 8.2 Interaction with Stake

Reputation decay (`R`) is a component of the dynamic stake multiplier. As reputation decays, the agent's required stake increases — creating economic pressure to maintain good standing.

---

## 9. Probation Mechanism

### 9.1 Trigger

Agents enter probation after violations detected through anomaly scoring, challenge resolution, or circuit breaker events.

### 9.2 Dual Exit Condition

An agent exits probation only when BOTH conditions are met:
1. **Minimum block duration satisfied** — cannot exit early regardless of behavior
2. **Minimum clean audit count achieved** — must demonstrate sustained honest behavior

This dual condition prevents "wait-it-out" abuse where an agent simply idles through the probation period without demonstrating behavioral correction.

---

## 10. Circuit Breakers

### 10.1 Triggers

| Trigger | Source |
|---|---|
| SRI threshold breach | SRI oracle |
| Extreme anomaly clustering | Entropy vector analysis |
| Capital velocity systemic surge | CVA monitoring |

### 10.2 Effects

Circuit breakers may impose:
- Stake increase (temporary or permanent)
- Task throttling (reduced task acceptance rate)
- Temporary suspension (agent cannot participate)

### 10.3 Reproducibility Requirement

**All circuit breaker triggers MUST be reproducible from protocol logs.** A circuit breaker that fires on non-reproducible data violates the constitutional Protocol ↔ Economic Lock.

---

## 11. Economic Contract Deployment

Economic contracts are deployed in Step 8 of the implementation sequence — after Phase 0 observation, entropy distribution publication, and Phase 1 activation. Contracts encode:

- Stake locking and release logic
- Dynamic stake multiplier computation (on-chain verification)
- Probation state machine
- Circuit breaker trigger conditions
- Governance epoch rules
- α_min and β coefficient storage (governance-controlled)

All contract logic must be verifiable against the published specification and simulation results.
