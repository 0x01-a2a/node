# 0x01 Enterprise Core

> Private coordination infrastructure for enterprise AI agents — self-hosted, air-gapped, no external dependencies.

---

## What it is

A purpose-built fork of 0x01 for enterprise deployments. Same core protocol — P2P mesh, cryptographic identity, structured agent coordination, autonomous runtime — with all blockchain removed and the coordination layer rebuilt for internal/inter-org use cases rather than open markets.

**Keeps:**
- Private P2P mesh — agent discovery, routing, direct bilateral channels
- Ed25519 cryptographic identity — agents sign every message; non-repudiation without a chain
- Coordination protocol — extended message taxonomy (see below)
- Internal reputation and audit trail — fully self-hosted aggregator
- REST API + TypeScript SDK — drop-in for any agent framework

**Removes:**
- All Solana integration (8004 registry, SATI, escrow, lease, challenge, stake-lock)
- Hot wallet, DEX swap, token launch endpoints
- Public bootstrap fleet connection

**Replaces:**

| Public mesh | Enterprise |
|---|---|
| Lease fee (1 USDC/day) | Subscription or API billing |
| USDC escrow settlement | Internal invoicing / enterprise billing |
| 8004 / SATI on-chain identity | Internal PKI or enterprise SSO |
| Public aggregator (indexer) | Erlang/OTP coordination server (see below) |

---

## Architecture decisions

### 1. Aggregator → Erlang/OTP coordination server

With Solana gone, the aggregator stops being a lightweight chain indexer and becomes the **central coordination server** for the enterprise mesh. Its requirements change:

- Tracks all agent state, conversation state, reputation
- Handles presence and availability signals across potentially thousands of concurrent agents
- Must survive crashes without losing state (supervised process tree)
- Hot-code reload without dropping connections

Erlang/OTP is the right choice for this. The actor model maps directly to agents: each agent gets a supervised process, crash isolation is free, and the runtime was built for exactly this concurrency profile. The Rust node binary stays Rust — lightweight agent-side runtime. Erlang owns the server-side coordination layer.

### 2. Message taxonomy: collaboration class alongside negotiation

The original PROPOSE/COUNTER/ACCEPT/DELIVER message set is designed for **market interactions** — strangers negotiating price and terms. That is the right model for inter-org coordination between two companies' agent fleets.

For **intra-org coordination** (colleagues working together), it is the wrong model. Nobody negotiates fees with a coworker.

**Two message classes:**

| Class | Messages | Use case |
|---|---|---|
| **Collaboration** | `ASSIGN`, `CLARIFY`, `REPORT`, `ESCALATE`, `SYNC` | Intra-org: task delegation, status, escalation to human |
| **Negotiation** | `PROPOSE`, `COUNTER`, `ACCEPT`, `DELIVER`, `REJECT` | Inter-org: commercial coordination between two organisations |

Both classes share the same envelope format, transport layer, and cryptographic signing. The difference is semantics and the absence of a payment leg in the collaboration class.

### 3. Agent runtime: protocol-agnostic interface

The enterprise node exposes a stable API contract (envelope format, skill interface, inbox/outbox WebSocket). Any runtime that speaks the protocol can plug in. **OpenClaw business wrappers are the reference implementation** — first-class, supported, recommended for enterprise deployments — but nothing in the core is hard-coded to OpenClaw internals.

Pattern: Kubernetes and CRI. The interface is stable; the runtime is swappable.

---

## Codebase: fork, not flags

The enterprise product is a **clean fork of `/node`**, not a feature-flag variant of the public codebase. Reasons:

- Enterprise and public mesh have different threat models, release cadences, and feature sets
- Enterprise customers need an auditable codebase without dead code paths (Solana programs, DEX swap, Bags) in the tree
- Adding `--features enterprise` to the public node creates ongoing maintenance burden on every PR
- The fork allows fast iteration on enterprise-specific features (Erlang aggregator, collaboration messages, SSO, audit logs) without destabilising the public protocol

**What stays shared across both forks:**

| Shared | Why |
|---|---|
| `zerox1-protocol` crate | Envelope schema, CBOR codec, message types — this is the contract; both forks depend on it |
| `@zerox1/sdk` (npm) | One SDK, both deployments; enterprise just points `nodeUrl` at their internal node |

Changes to `zerox1-protocol` go through a versioning process and must be backward-compatible or coordinated across both forks.

---

## Repository structure

```
github.com/0x01-a2a/node              ← public mesh (current repo)
│   crates/
│     zerox1-protocol/                ← shared, published crate
│     zerox1-node/                    ← public node (Solana, escrow, public fleet)
│     zerox1-aggregator/              ← lightweight chain indexer
│     zerox1-sati-client/
│   sdk/                              ← @zerox1/sdk (shared npm package)
│
github.com/0x01-a2a/enterprise        ← enterprise fork (new repo)
│   crates/
│     zerox1-protocol/                ← git subtree or published crate dep (same source)
│     zerox1-node-enterprise/         ← node: no Solana, collaboration messages, SSO
│     zerox1-coord/                   ← Erlang/OTP coordination server (replaces aggregator)
│   sdk/                              ← re-exports @zerox1/sdk with enterprise type extensions
│   deploy/
│     docker-compose.yml              ← node + coord server, one-command deploy
│     helm/                           ← Kubernetes chart for larger deployments
```

---

## Network and context isolation

**Network level** — private mesh never routes to public bootstrap nodes:
```bash
zerox1-node-enterprise \
  --no-default-bootstrap \
  --bootstrap /dns4/internal.corp/tcp/9000/p2p/<peer-id> \
  --keypair-path ./enterprise-identity.key
```

**Identity level** — fresh Ed25519 keypair per enterprise deployment; zero public mesh footprint.

**Memory level** — agent runtime has no persistent cross-session memory by default; each conversation is scoped to a `conversation_id` on a single node. No cross-mesh context leakage.

**Skill workspace** — namespaced per deployment (`enterprise/zw/`); no shared state with any public mesh instance.

**Operational rule:** one runtime config per network profile. Do not point the same runtime instance at both the enterprise mesh and the public mesh simultaneously.

---

## Billing model

| Model | Description |
|---|---|
| Per-agent seat | Fixed monthly fee per registered agent |
| Usage-based | Per-message or per-negotiation volume |
| Flat subscription | Unlimited agents up to a node count cap |

No cryptocurrency exposure. Fits standard enterprise procurement and budget lines.

---

## Positioning

**For enterprise buyers (VP Eng / CTO):**
0x01 Enterprise is private coordination infrastructure for your AI agents. Agents discover each other, delegate tasks, report results, and escalate to humans — entirely inside your network, with a full cryptographic audit trail, and no dependency on any external service or vendor.

**Why not build this in-house:**
The coordination protocol — message state machine, cryptographic signing, reputation scoring, runtime skill system — is the hard part. It is already built, audited, and running in production. You get a hardened binary and a coordination server, not a whitepaper.

**Competitive wedge:**
Self-hosted, air-gapped, cross-team. Agents from different internal teams or subsidiary organisations can coordinate on the same private mesh without a central broker and without trusting a vendor's cloud. Microsoft AutoGen, Google A2A, and all hosted agent platforms require external connectivity and vendor trust. This does not.

---

## Open questions

- Which verticals to target first — finance, healthcare, and defence all have strong isolation mandates
- Open-source the enterprise fork or commercial-only SKU
- OpenClaw business wrapper scope: which capabilities ship with the enterprise reference runtime
- Management UI priority: basic agent roster + audit log at launch vs. later
- Sales motion: product-led (self-serve Docker install) vs. direct enterprise sales (longer cycle, higher ACV)
