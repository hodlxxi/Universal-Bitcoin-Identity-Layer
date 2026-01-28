# FAQ for Developers

This document addresses technical and architectural questions
commonly raised by developers evaluating HODLXXI.

It assumes familiarity with cryptography, distributed systems,
and adversarial threat models.

---

## What problem is HODLXXI actually trying to solve?

HODLXXI explores whether long-term commitments and reciprocity
can be made observable and durable without centralized authority.

It is not a general-purpose identity system.
It is not a governance framework.
It is not a consensus protocol.

It is a coordination layer focused on time, accountability,
and voluntary participation.

---

## Is this a protocol or a product?

It is a set of architectural constraints and primitives.

Specific deployments are implementations.
No single implementation is canonical.

Forking is expected.
Divergence is acceptable.

---

## Why use Bitcoin primitives instead of building a new chain?

Bitcoin provides:

- Extremely conservative design
- High cost of rule changes
- Long time horizons
- Cultural resistance to central control

These properties are difficult to replicate artificially.

HODLXXI does not require Bitcoin scripting extensions,
sidechains, or tokens.

---

## Does HODLXXI require on-chain transactions?

No.

On-chain interactions are optional and minimal.
Most logic exists off-chain.

Bitcoin is used primarily as:
- a time anchor,
- a settlement layer for commitments,
- and a credibility boundary.

---

## How is identity defined?

Identity is defined as control over a cryptographic key.

There are no accounts, usernames, or recovery flows enforced by the system.

Key rotation, aggregation, or abstraction
may be implemented at higher layers,
but are not assumed at the core.

---

## How does this differ from DID / Web3 identity standards?

Most DID systems optimize for:
- portability,
- interoperability,
- and institutional adoption.

HODLXXI optimizes for:
- exit,
- adversarial durability,
- and long-term commitments.

Interoperability is secondary to constraint integrity.

---

## What are the trust assumptions?

Minimal.

- Cryptography must hold.
- Time must progress.
- Agents may behave adversarially.

There is no assumption of honesty, alignment, or goodwill.

---

## What is the threat model?

The system assumes:

- Rational adversaries
- Long time horizons
- Partial information
- Strategic defection

It does not attempt to prevent all attacks.
It attempts to make sustained abuse costly.

---

## How is reputation modeled?

Reputation is not a scalar.

It is an observable history of commitments and outcomes.
Interpretation is delegated to agents and applications.

No global aggregation function is required or provided.

---

## How does the system handle Sybil attacks?

Sybil resistance is contextual.

HODLXXI does not attempt universal Sybil prevention.
Instead, it allows commitments to define their own cost structures.

Sybil identities become expensive only where they matter.

---

## Is there a consensus mechanism?

No.

There is no global state that requires agreement.
There is no leader election.
There is no final arbiter.

Local agreement and forkability are preferred.

---

## What happens when participants disagree?

They diverge.

Disagreement does not imply failure.
Forced agreement is considered a failure mode.

Forking and exit are first-class outcomes.

---

## How are upgrades handled?

Slowly and visibly.

Backward compatibility is preferred.
Breaking changes must be opt-in.

No automatic migration is assumed.

---

## Is this safe to deploy in production?

That depends on the scope.

HODLXXI is not a turnkey solution.
It is a research-driven framework.

Deployments should be:
- limited in scope,
- explicit in assumptions,
- and conservative in enforcement.

---

## What would constitute failure?

Examples include:

- Inability to exit
- Centralized control accumulation
- Metric collapse into a single score
- Hidden rule changes
- Dependence on founder presence

Any of these invalidate the system’s core claims.

---

## Can AI or autonomous agents participate?

Yes, in principle.

CRT is compatible with artificial agents
provided they operate under persistent identity
and repeated interaction.

However, safety and alignment considerations
are out of scope for the core system.

---

## How should developers approach this project?

With skepticism.

Read the invariants.
Read what the project explicitly is not.
Inspect the assumptions.

If your use case requires:
- speed,
- certainty,
- or centralized guarantees —

this framework is likely inappropriate.

---

## Summary

HODLXXI is not optimized for adoption.

It is optimized for constraint integrity.

Developers are encouraged to treat it as:
- a design space,
- a set of architectural warnings,
- and an invitation to critique.

Participation is optional.
Forking is expected.