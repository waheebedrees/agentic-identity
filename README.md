# Agentic Identity

## The 4 Protocols and the Question They Don't Answer

The industry has converged on four well-understood protocols for establishing **agent identity** — proving *who* an agent claims to be at a single point in time:

### 1. API Keys / Bearer Tokens
- **What it proves:** "This request comes from a registered client."
- **Mechanism:** A static secret shared between the agent and the service.
- **Limitation:** Proves the *credential* is valid, not the *agent*. If the key is exfiltrated or the agent's code is swapped behind the same key, the token still works.

### 2. mTLS (Mutual TLS) / X.509 Certificates
- **What it proves:** "This workload holds a private key issued by a trusted CA."
- **Mechanism:** Both sides of a connection present certificates; a chain of trust back to a root CA validates each. SPIFFE/SPIRE is the dominant framework for workload-level mTLS in cloud-native systems.
- **Limitation:** Proves the *workload's cryptographic identity*, not what code is actually running inside that workload. A re-deployed container with a different model or different system prompt receives the same SVID.

### 3. OAuth 2.0 / OIDC (Delegated Authority)
- **What it proves:** "A human (or upstream service) authorized this agent to act on their behalf, with these scopes."
- **Mechanism:** Token exchange, consent flows, scoped permissions.
- **Limitation:** Proves *authorization was granted at time T*. Says nothing about whether the agent's behavior, model weights, or tool access have changed since the user clicked "Approve."

### 4. DID (Decentralized Identifiers) / Verifiable Credentials
- **What it proves:** "This entity controls a cryptographic identifier anchored to a decentralized registry, and may hold verifiable attestations from issuers."
- **Mechanism:** DID documents, DID resolution, Verifiable Presentations.
- **Limitation:** Proves *identifier ownership*. A DID is a stable pointer, but it says nothing about whether the *thing behind the pointer* — the model, the prompt, the tool set — is the same thing that was evaluated, audited, or approved.

---

## The Harder Question

> **"Is this still the agent I approved?"**

All four protocols answer a *static* question: **authentication** (who are you?) or **authorization** (what are you allowed to do?). None of them answer the *dynamic* question:

> Between the moment I approved this agent and the moment it is acting, has anything material changed?

This is the **agent continuity problem** — and it has no equivalent in human identity. When you grant a human colleague access to a system, their identity is biologically continuous. But an agent is a *composition* of mutable parts:

| Component | Can change silently? | Impact |
|---|---|---|
| Model weights / version | ✅ Provider-side update | Behavior, reasoning, safety profile |
| System prompt | ✅ Config change | Goals, persona, guardrails |
| Tool access / plugins | ✅ Deployment config | Capability surface, blast radius |
| Memory / context | ✅ Accumulates at runtime | Drift in behavior over time |
| Orchestration logic | ✅ Code deploy | Control flow, delegation patterns |
| Fine-tuning / RLHF | ✅ Training pipeline | Subtle behavioral shifts |

**An agent's identity is not a point — it is a trajectory.** The four protocols give you a snapshot. The hard question requires a *film*.

---

## What Would a Solution Look Like?

A protocol that answers "is it still the agent you approved?" needs to provide:

1. **Configuration Binding** — Cryptographically tie the agent's identity to a *specific* composition (model version + prompt hash + tool manifest + orchestration code hash).

2. **Continuity Attestation** — At any point in time, produce a verifiable statement: "the agent currently running under identity X is materially identical to the composition that was approved at time T."

3. **Drift Detection** — Continuously monitor for changes to any component and, upon detecting drift, either:
   - Re-attest (if the change is within policy), or
   - Revoke/suspend the identity (if the change violates approval conditions).

4. **Approval Scoping** — Let the approver specify *what they approved* with enough granularity: "I approved agent X *with GPT-4o, this system prompt, and these 3 tools*" — not just "I approved agent X."

---

## This Project

`agentic-identity` explores and prototypes solutions for the missing layer — specifically:

- Using **SPIRE** as the workload identity foundation (mTLS, SVIDs)
- Adding a **composition attestation layer** on top that hashes and signs the agent's configuration
- Building **drift detection** that can trigger re-attestation or revocation
- Defining an **approval policy format** that captures what was actually approved

The goal is not to replace the 4 protocols — they are necessary infrastructure. The goal is to build the layer *above* them that answers the question they can't.

---

## Getting Started

> 🚧 **Work in progress** — architecture and prototyping phase.


```

## License

TBD
