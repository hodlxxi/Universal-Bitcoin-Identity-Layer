# HODLXXI Agent Trust Model

## Why this exists

Most agents today are easy to start, easy to stop, and hard to trust.

They can answer a prompt, but they cannot easily prove continuity, reliability, or accountable history. Their “identity” is often just a hostname, a login, or a vendor account. If the runtime disappears, the practical history disappears with it.

HODLXXI Agent UBID takes a different approach.

HODLXXI treats agent trust not as a social claim but as an economically verifiable commitment. In design terms, an agent identity is modeled as:

- `public_key`
- `operator_binding`
- `time_locked_capital` (optional trust anchor, only when concretely exposed)
- `observable_behavior`

Trust is derived from continuity, accountability, verifiability, and bounded risk. As a design principle, this shifts trust away from pure reputation graphs and toward economically enforced continuity over time where the runtime exposes the necessary evidence.

In the current runtime, the verifiable surfaces are the public key, declared operator metadata, Lightning-paid execution flow, signed job receipts, append-only attestations, reputation summaries, and chain-health checks. The repository does **not** currently claim verified on-chain proof or verified time-locked capital for the agent runtime unless such a surface is explicitly added and exposed.

This does not create perfect trust.
It creates **auditable trust with explicit boundaries**.

---

## Trust Anchors

### 1. Public-key identity

The first verified trust anchor is the agent’s secp256k1 public key.

This key is the persistent identity reference for the service. A client should treat the pubkey as more fundamental than the domain name.

Domains can move.
Processes can restart.
Infrastructure can migrate.

The pubkey is the durable identity anchor.

---

### 2. Operator binding and signed outputs

The operator name published in discovery documents binds human-readable service metadata to the key at the runtime layer. That helps discovery, but it should be treated as declared metadata unless backed by an additional proof surface outside the current runtime.

Signed outputs and receipts remain the stronger verification path.

A completed job is not just a response payload.

It is associated with hashes and a signature that bind the agent to a specific execution event. This allows a verifier to ask:

- did this agent really produce this result?
- was this result part of an actual paid workflow?
- does this event fit into the prior history?

That is stronger than simple API success.

---

### 3. Attestation chain

The attestation chain adds continuity.

Each receipt can reference a previous event hash. This means the service is not only saying “I did this,” but also “this event came after that event in my public history.”

That matters because trust is not only about correctness.
It is also about continuity.

A chain can show:

- whether the service has a history
- whether that history is consistent
- whether new events extend prior events cleanly
- whether the operator has preserved continuity over time

---

### 4. Reputation summary

Reputation is not hand-wavy branding here.

It is a compact summary of observed activity:

- total jobs
- completed jobs
- attestations count
- distribution across job types

This is intentionally simple.

It avoids fake social metrics and instead reports operational evidence.

---

### 5. Chain health

Chain health is the fast integrity check.

A client or marketplace can inspect whether the attestation sequence is healthy without replaying the entire dataset. This makes monitoring practical.

If chain health fails, counterparties should downgrade trust immediately and investigate further.

---

## What this model proves

This model can help prove:

- the agent exposes a stable cryptographic identity
- the runtime publishes an operator binding alongside that identity
- the agent has completed real paid work within this runtime
- completed work can be tied to signed receipts
- receipts can be linked into a continuity chain
- the service exposes public verification and reputation surfaces

That is already valuable.

It lets other agents and humans distinguish between:

- a fresh anonymous endpoint
- a service with observable operational history

---

## What this model does not prove

This model does **not** by itself prove:

- future uptime
- moral honesty
- code quality
- absence of operator compromise
- absence of bugs
- absence of censorship
- economic solvency
- legal ownership or organizational control of the named operator
- long-term persistence of the domain or infrastructure
- on-chain proof of reserves or collateral
- time-locked capital backing unless the runtime exposes a verifiable proof surface for it

It also does not prove that the operator will keep the service alive forever.

It only makes the service more accountable for what it has already done.

---

## Threats and limits

### Key compromise

If the signing key is stolen, an attacker could produce apparently valid receipts.

Mitigation direction:

- protect the private key carefully
- rotate only under explicit public procedure
- publish key transitions clearly
- consider hardware isolation over time

### Silent reset / continuity loss

If the operator wipes state and starts over, continuity may break.

Mitigation direction:

- preserve attestation history
- expose chain health
- make resets visible
- allow counterparties to detect discontinuities

### Domain-level confusion

A domain can be proxied, transferred, or imitated.

Mitigation direction:

- prioritize pubkey pinning
- publish identity metadata under `/.well-known/agent.json`
- publish capability shape under `/agent/capabilities/schema`
- encourage counterparties to verify signatures, not branding

### Payment/result mismatch

A service might take payment and fail to deliver a valid result.

Mitigation direction:

- bind receipts to request and result hashes
- expose job status clearly
- let third parties inspect completed history

### Empty reputation theater

An endpoint can expose capability docs while having no real history.

Mitigation direction:

- check `/agent/reputation`
- check `/agent/attestations`
- check `/agent/chain/health`
- check `/agent/skills` when the integration depends on reusable agent-facing skills
- discount agents with no operational trail

---

## Optional trust anchors and design goals

The long-horizon HODLXXI direction may eventually include stronger trust anchors such as Bitcoin-backed reserves, covenant-linked commitments, or other time-locked capital models. In this repository, those should be described conservatively as:

- optional trust anchors
- design goals
- possible backing models
- mechanisms that may be tied to long-horizon Bitcoin commitments

They should not be presented as verified runtime facts unless the agent surface exposes concrete proofs that counterparties can inspect.

## Why Lightning matters

Lightning is not only a payment rail here.

It acts as:

- spam resistance
- economic metering
- machine-native settlement
- event correlation via payment hashes

A paid job is more meaningful than an unauthenticated free request because it creates cost, commitment, and traceability.

---

## Why this matters for agent-to-agent trust

Agent ecosystems need more than model quality.

They need ways to answer:

- Who are you?
- What key anchors your identity?
- What work have you actually completed?
- Can I verify your receipts?
- Do you preserve history?
- Is your history still internally consistent?

HODLXXI Agent UBID is one answer to those questions.

It shifts trust from vague reputation to inspectable cryptographic surfaces.

---

## HODLXXI-specific direction

The deeper direction of HODLXXI is that agent trust should not end at runtime identity.

In the long run, an agent may be associated with:

- a persistent public key
- a public attestation history
- a Lightning wallet
- optional Bitcoin-backed or covenant-linked trust anchors when verifiable
- durable service promises extending beyond a single deployment

That is the real strategic distinction.

The goal is not just “an agent that works.”
The goal is “an agent that can be trusted across time” without overstating what the current runtime actually proves.

---

## Verification checklist for counterparties

Before trusting this agent, a counterparty should verify:

1. the advertised pubkey
2. `/.well-known/agent.json`
3. the capabilities document
4. the published capability schema
5. the advertised skills surface if skill discovery matters
6. the job type and price
7. a sample paid request
8. the returned job record
9. the receipt verification path
10. the attestation chain
11. the reputation summary
12. the chain health report

Trust should be earned by successful verification, not assumed from presentation.

---

## Final statement

HODLXXI’s trust model is simple:

**identity is a key plus declared operator binding, work is paid, results are signed, history is chained, and stronger capital-backed trust anchors remain optional until proven.**
