
# Agentic Identity

## The Four Approaches and the Question They Don't Answer

The industry has converged on four well-understood approaches for establishing
**agent identity** — proving *who* an agent claims to be at a single point in time:

### 1. API Keys / Bearer Tokens

- **What it proves:** "This request comes from a registered client."
- **Mechanism:** A static secret shared between the agent and the service.
- **Limitation:** Proves the *credential* is valid, not the *agent*. If the key is
  exfiltrated or the agent's code is swapped behind the same key, the token still works.

### 2. mTLS (Mutual TLS) / X.509 Certificates

- **What it proves:** "This workload holds a private key issued by a trusted CA."
- **Mechanism:** Both sides of a connection present certificates; a chain of trust back
  to a root CA validates each. SPIFFE/SPIRE is the dominant framework for workload-level
  mTLS in cloud-native systems.
- **Limitation:** Proves the *workload's cryptographic identity*, not what code is actually
  running inside that workload. A re-deployed container with a different model or different
  system prompt receives the same SVID.

### 3. OAuth 2.0 / OIDC (Delegated Authority)

- **What it proves:** "A human (or upstream service) authorized this agent to act on their
  behalf, with these scopes."
- **Mechanism:** Token exchange, consent flows, scoped permissions.
- **Limitation:** Proves *authorization was granted at time T*. Says nothing about whether
  the agent's behavior, model weights, or tool access have changed since the user clicked
  "Approve."

### 4. DID / Verifiable Credentials

- **What it proves:** "This entity controls a cryptographic identifier anchored to a
  decentralized registry, and may hold verifiable attestations from issuers."
- **Mechanism:** DID documents, DID resolution, Verifiable Presentations.
- **Limitation:** Proves *identifier ownership*. A DID is a stable pointer, but it says
  nothing about whether the *thing behind the pointer* — the model, the prompt, the tool
  set — is the same thing that was evaluated, audited, or approved.

---

## The Harder Question

> **"Is this still the agent I approved?"**

All four approaches answer a *static* question: **authentication** (who are you?) or
**authorization** (what are you allowed to do?). None of them answer the *dynamic* question:

> Between the moment I approved this agent and the moment it is acting, has anything
> material changed?

This is the **agent continuity problem**. It is not that human identity systems solve this
and agent systems don't — human identity systems *assume* a substrate that persists across
approvals. A human colleague's body, memories, and dispositions provide biological
continuity even as their skills and roles change. An agent has no such substrate. Between
two invocations, its weights can be swapped, its prompt rewritten, its tools reconfigured,
and its memory reset or expanded — all without any identity system noticing, because
nothing in the identity system is looking.

| Component | Can change silently? | Impact |
|---|---|---|
| Model weights / version | ✅ Provider-side update | Behavior, reasoning, safety profile |
| System prompt | ✅ Config change | Goals, persona, guardrails |
| Tool access / plugins | ✅ Deployment config | Capability surface, blast radius |
| Memory / context | ✅ Accumulates at runtime | Drift in behavior over time |
| Orchestration logic | ✅ Code deploy | Control flow, delegation patterns |
| Fine-tuning / RLHF | ✅ Training pipeline | Subtle behavioral shifts |

**An agent's identity is not a point — it is a trajectory.** The four approaches give you
a snapshot. The hard question requires a *film*.

---

## What Would a Solution Look Like?

A protocol that answers "is it still the agent you approved?" needs to provide:

1. **Configuration Binding** — Cryptographically tie the agent's identity to a *specific*
   composition (model version + prompt hash + tool manifest + orchestration code hash).

2. **Continuity Attestation** — At any point in time, produce a verifiable statement:
   "the agent currently running under identity X is materially identical to the composition
   that was approved at time T."

3. **Drift Detection** — Continuously monitor for changes to any component and, upon
   detecting drift, either:
   - Re-attest (if the change is within policy), or
   - Revoke/suspend the identity (if the change violates approval conditions).

4. **Approval Scoping** — Let the approver specify *what they approved* with enough
   granularity: "I approved agent X *with GPT-4o, this system prompt, and these 3 tools*" —
   not just "I approved agent X."

---

## This Project

`agentic-identity` explores and prototypes solutions for the missing layer — specifically:

- Using **SPIRE** as the workload identity foundation (mTLS, SVIDs)
- Adding a **composition attestation layer** on top that hashes and signs the agent's
  configuration
- Building **drift detection** that can trigger re-attestation or revocation
- Defining an **approval policy format** that captures what was actually approved

The goal is not to replace the four approaches — they are necessary infrastructure. The
goal is to build the layer *above* them that answers the question they can't.

### Status

- [x] SPIRE foundation — server, agent, Docker workload attestor, per-agent identities
- [x] mTLS peer transport with SVID verification
- [x] SVID rotation with live refresh in long-running processes
- [ ] Composition attestation — hash + sign model/prompt/tools/orchestration
- [ ] Drift detection and re-attestation
- [ ] Approval policy format

The foundation is runnable today (see Getting Started). The composition layer is
designed but not yet implemented.

---

## Architecture

    ┌──────────────────────────┐         ┌──────────────────────────┐
    │        manager           │         │         worker           │
    │  spiffe://acme.test/...  │◄──mTLS──►  spiffe://acme.test/...  │
    │  - SVID (auto-rotated)   │         │  - SVID (auto-rotated)   │
    │  - composition hash      │         │  - composition hash      │
    │  - tool manifest         │         │  - tool manifest         │
    └────────────┬─────────────┘         └────────────┬─────────────┘
                 │                                    │
                 └──────────────┬─────────────────────┘
                                │ Workload API
                                ▼
                      ┌────────────────────┐
                      │    spire-agent     │
                      │  docker attestor   │
                      └─────────┬──────────┘
                                │
                                ▼
                      ┌────────────────────┐
                      │    spire-server    │
                      │   entries + CA     │
                      └────────────────────┘

Two or more agents run as separate Docker containers. Each gets a distinct SVID
based on its `role` label. They talk to each other over mTLS, verifying each
other's SPIFFE ID. The agent and server handle attestation, issuance, and rotation.

The composition layer (in progress) will extend this with signed configuration
hashes on top of the SVID-based identity.

---

## Getting Started

> 🚧 **Work in progress** — architecture and prototyping phase.

Prerequisites: Docker, Docker Compose, Python 3.13, `uv`.

    # 1. Configure environment
    cp .env.example .env
    $EDITOR .env

    # 2. Generate compose and registration script from topology
    python scripts/gen.py

    # 3. Build per-agent images
    docker compose build

    # 4. Bring up SPIRE and register entries
    docker compose up -d spire-init spire-server spire-agent
    ./scripts/register-entries.sh

    # 5. Start the agents
    docker compose up -d manager worker

    # 6. Verify SVIDs
    docker compose exec manager python -c "
    from spiffe import WorkloadApiClient
    print(WorkloadApiClient().fetch_x509_svid().spiffe_id)
    "
    # spiffe://acme.test/manager

The topology is defined in `agents.yaml` — edit that and re-run `python scripts/gen.py`
to change who exists and who talks to whom.

See `Makefile` for shortcuts (`make up`, `make entries`, `make list`).

---

## License

Apache-2.0
