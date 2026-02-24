# 0x01 — Constitutional Framework

**Version:** 5.0
**Status:** Implementation-Ready
**Audience:** Engineering Team

---

## 1. What "Constitutional" Means in This System

A constitutional rule in 0x01 is one that **cannot be changed by normal governance**. Constitutional rules require governance epoch review, and any proposal that violates a constitutional invariant is automatically invalid — regardless of vote count or stakeholder support.

The constitutional layer exists because certain properties, if broken even temporarily, compromise the entire system's trust model. These properties are identified below.

---

## 2. Foundational Invariants

### 2.1 Protocol ↔ Economic Lock (CONSTITUTIONAL)

> No economic penalty, stake multiplier, anomaly score, or reputation adjustment may depend on telemetry that cannot be deterministically reconstructed from protocol-native logs.

If a telemetry dimension cannot be independently recomputed by a third-party node from canonical logs, it is **invalid for economic use**.

**Why this matters:** Without this invariant, whoever controls telemetry production controls economic outcomes. The Lock ensures that enforcement is verifiable by any participant — not just by the parties producing the data.

### 2.2 Deterministic Reproducibility (CONSTITUTIONAL)

All entropy metrics, anomaly scores, and BehaviorBatch hashes must be:
- Byte-identical across independent nodes
- Computed using canonical serialization
- Derived from fixed-precision integer arithmetic

**Floating-point values are forbidden in consensus-affecting calculations.**

**Why this matters:** Floating-point non-determinism across hardware architectures and compiler versions has broken more distributed systems than logic errors. Constitutionalizing integer-only consensus math prevents an entire class of subtle divergence bugs that would only surface under adversarial conditions at scale.

### 2.3 Adversarial Model Assumption (CONSTITUTIONAL)

The system assumes agents have full knowledge of:
- Entropy thresholds
- Stake formula
- Anomaly scoring algorithms
- All protocol parameters

And that agents can:
- Coordinate with each other
- Optimize behavior adaptively
- Attempt evasion strategies

**Security derives from economic topology, not obscurity.**

**Why this matters:** Any component that relies on parameter secrecy for security is a ticking time bomb. Parameters will leak, be reverse-engineered, or be discovered through adversarial probing. The system must be secure with all parameters public.

---

## 3. Governance Constraints

### 3.1 Proposal Validity

No governance proposal may:

1. **Introduce non-reconstructible telemetry** — any new data input to the economic layer must be derivable from protocol-native logs
2. **Introduce proprietary anomaly inputs** — all anomaly detection must use open, published algorithms
3. **Modify α_min outside a governance epoch** — the stake floor can only change during scheduled governance reviews

A proposal that violates any of these constraints is **automatically invalid**.

### 3.2 Governance Epochs

α_min, β coefficients, and SRI thresholds are **governance-epoch-protected**. They can only be modified during designated review periods with:
- Published justification
- New simulation results (if parameter change involves simulation-derived values)
- Community review period
- Constitutional compliance verification

### 3.3 The Hidden-Measurement Prohibition

No governance action may create a situation where economic enforcement depends on measurements that are not visible to all participants. This is a direct consequence of Invariant 2.1 but is stated separately because of its importance:

**Whoever controls measurement controls outcome. Therefore, measurement must be universally verifiable.**

---

## 4. Simulation as Constitutional Ground Truth

### 4.1 Status of the Simulator

The adversarial cartel simulator is not supporting work — it is the **ground truth** that the constitution references. The following parameters are all simulation-derived:

| Parameter | Constitutional Protection |
|---|---|
| α_min (stake floor) | Cannot change outside governance epoch |
| β₁–β₄ (stake component weights) | Cannot change outside governance epoch |
| SRI threshold | Cannot change outside governance epoch |
| Entropy thresholds | Finalized before Phase 1, published before enforcement |

### 4.2 Simulation Audit Requirement

The simulation MUST be independently audited before α_min publication.

- **Not reviewed — audited.** By parties with no economic stake in the outcome.
- The audit report is a **precondition for Phase 0**.

**Why this matters:** If the simulation has a bug that underestimates cartel profitability, α_min is wrong. A wrong α_min is constitutional — it requires a governance epoch to fix. A buggy constitutional parameter is the most dangerous state the system can be in at launch.

### 4.3 Simulation Transparency

Simulation code must be:
- Open-source
- Reproducible (deterministic seeding, version-pinned dependencies)
- Published with full parameter sweeps and results

---

## 5. Anti-Cartel Architecture

### 5.1 Design Philosophy

The system does not try to prevent cartels from forming. It makes cartels **economically unprofitable** and **operationally expensive** to maintain.

A cartel that must work hard to stay hidden is already losing.

### 5.2 Layered Defense

**Layer 1 — Entropy Vector:** Detects behavioral regularity across four dimensions (timing, bid, selection, verifier correlation). Only positive deviations above threshold contribute — no offsetting allowed.

**Layer 2 — Temporal Rotation Detection:** Prevents the rotational evasion strategy (Type C-2) where cartels cycle which dimension they exploit. Rolling window analysis detects dimension-cycling patterns that exceed honest baseline frequency.

**Layer 3 — Capital Velocity Anomaly:** Detects capital stock accumulation without proportional activity. Separated from entropy vector to prevent cross-metric gaming.

**Layer 4 — Ownership Clustering:** Identifies Sybil structures and coordinated agent groups through funding, withdrawal, behavioral, and capital flow analysis.

**Layer 5 — Dynamic Stake Multiplier:** Translates detected anomalies into economic cost. As detection signals increase, the agent's required stake increases — making fraud progressively more capital-intensive.

**Layer 6 — Probation:** Dual-exit condition (time + clean audits) prevents "wait-it-out" strategies.

**Layer 7 — Circuit Breakers:** System-level emergency response when aggregate risk indicators breach thresholds.

### 5.3 The Gradient Principle

The entire anti-cartel architecture is designed around a single principle:

> Honest behavior should require no coordination.
> Fraudulent behavior should require continuous coordination.

Lease expiration, reputation decay, challenge windows, and temporal rotation detection compose together to ensure that a cartel cannot set its strategy once and coast. It must actively manage its fraud, and continuous management is continuously detectable.

---

## 6. Phase 0 Bootstrap Protocol

### 6.1 Purpose

Phase 0 is the observation period before economic enforcement begins. Its purpose is to:
1. Collect real behavioral data
2. Derive entropy thresholds from empirical distributions
3. Validate the telemetry pipeline

### 6.2 Rules During Phase 0

- Anomaly scoring IS computed (to validate the pipeline)
- **No economic penalties are applied**
- Controlled cohort participation
- Full data collection and publication

### 6.3 Anti-Seeding Protection

Before enforcement thresholds are finalized:
1. Full entropy distributions are published publicly
2. Threshold selection is performed transparently
3. All participants can observe and verify the process

This neutralizes the **insider timing attack** — where parties who know thresholds before others can position themselves advantageously. Information asymmetry is eliminated before it becomes actionable.

### 6.4 Transition to Phase 1

Phase 1 (enforcement) begins ONLY after all three preconditions are met:
1. Entropy thresholds finalized and published
2. Telemetry Recomputation Audit passed
3. α_min derived from audited simulation and published

---

## 7. Circuit Breaker Constitutional Status

### 7.1 Trigger Reproducibility

All circuit breaker triggers MUST be reproducible from protocol logs. A circuit breaker that fires on non-reproducible data violates Invariant 2.1 and is constitutionally invalid.

### 7.2 Trigger Sources

| Source | Metric | Constitutional Basis |
|---|---|---|
| SRI oracle | Spectral radius of exposure graph | Published computation, independently verifiable |
| Anomaly clustering | Aggregate entropy vector analysis | Computed from protocol logs |
| CVA systemic surge | Aggregate capital velocity | Computed from on-chain balance + task data |

### 7.3 Effects

Circuit breakers may impose stake increases, task throttling, or temporary suspension. The specific effects for each trigger type are governance-controlled but must not violate constitutional invariants.

---

## 8. SRI Oracle Governance Path

### 8.1 Launch Configuration

At launch, the SRI oracle is council-operated. This is a pragmatic concession — spectral radius computation is expensive and the infrastructure for decentralized computation is not yet available.

### 8.2 Decentralization Requirement

A transition path to decentralized oracle operation is **required**. The council-operated oracle is explicitly temporary. The transition plan must be published before Phase 1 activation.

### 8.3 Mitigation During Council Operation

While the oracle is centralized:
- The exposure matrix hash is published
- The SRI value is published
- Proof of computation is published
- Anyone may independently recompute and challenge

---

## 9. Implementation Sequence (Constitutional Ordering)

The following sequence is strictly ordered. **No inversion is allowed between steps 3–4.**

| Step | Action | Precondition |
|---|---|---|
| 1 | Build adversarial cartel simulator | — |
| 2 | Derive α_min, β coefficients, SRI threshold | Simulation audit passed |
| 3 | Design canonical telemetry schema | α_min published |
| 4 | Execute Telemetry Recomputation Audit | Schema frozen |
| 5 | Implement Phase 0 | Audit passed |
| 6 | Publish entropy distributions | Phase 0 data collected |
| 7 | Activate Phase 1 | Thresholds finalized, α_min published |
| 8 | Deploy economic contracts | Phase 1 active |

**The simulator is the critical path.** Everything downstream depends on numbers it produces. Treat it accordingly.

---

## 10. Amendment Process

### 10.1 Non-Constitutional Changes

Standard governance process. Proposals submitted, reviewed, voted on.

### 10.2 Constitutional Changes

Constitutional amendments require:
1. Governance epoch scheduling
2. Published rationale with formal analysis
3. New simulation results (if affecting simulation-derived parameters)
4. Extended review period
5. Constitutional compliance verification by independent parties
6. Supermajority approval (threshold TBD at launch)

### 10.3 Emergency Provisions

In the event of a critical vulnerability:
- Circuit breakers can activate without governance (by design)
- But no constitutional parameter can be modified outside governance epoch, even in emergency
- The correct response to a constitutional-level emergency is to activate circuit breakers and schedule an emergency governance epoch

---

## 11. Summary of Constitutional Rules

For quick reference, these are the rules that cannot be changed by normal governance:

1. **Protocol ↔ Economic Lock** — No economic action on non-reconstructible telemetry
2. **Deterministic Reproducibility** — Integer-only consensus math, byte-identical outputs
3. **Adversarial Model** — Security from topology, not obscurity
4. **α_min Protection** — Simulation-derived only, governance-epoch-locked
5. **β Coefficient Protection** — Same derivation and protection as α_min
6. **Hidden-Measurement Prohibition** — All measurements universally verifiable
7. **Simulation Audit Precondition** — Audited simulation before Phase 0
8. **Anti-Seeding** — Public distributions before threshold enforcement
9. **Implementation Ordering** — Steps 3–4 cannot be inverted
10. **Circuit Breaker Reproducibility** — All triggers from protocol logs
