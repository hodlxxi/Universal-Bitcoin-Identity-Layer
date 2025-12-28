# Principles and Invariants

HODLXXI is governed by a set of structural constraints.

These constraints define what the system is **not allowed to do**.  
They are enforced at the architectural level, not through policy or moderation.

---

## Core Principle

**HODLXXI does not optimize humans.**  
**It optimizes environments where cooperation becomes rational.**

The system does not attempt to:
- Define correct behavior
- Reward virtue
- Punish vice

Instead, it creates conditions where:
- Defection becomes costly
- Cooperation becomes profitable over time
- Actions remain observable and accountable

---

## Seven Invariants

Any implementation that violates these invariants is no longer considered a valid instance of HODLXXI.

### 1. Right to Exit

**Every agent must be able to exit the system without irreversible personal harm.**

- You can leave at any time
- No one can force you to stay
- Time-locked funds remain locked, but no new obligations can be imposed on you
- Exit does not require permission from anyone

Violation examples:
- Requiring surrender of external assets to exit
- Creating dependencies that make exit practically impossible
- Blacklisting or persecuting users who leave

### 2. Non-Expropriable Agency

**No system may remove an agent's ability to choose, even irrationally.**

- You retain full decision-making power
- The system cannot override your choices
- You can act against your own computed best interest
- Automation cannot fully replace human judgment

Violation examples:
- Forcing "optimal" behavior algorithmically
- Removing the ability to make mistakes
- Paternalistic overrides "for your own good"

### 3. Symmetry of Observability

**If agents are evaluated, the evaluation rules must be observable and inspectable.**

- All rules are public
- No black-box algorithms
- Participants can audit the system
- Criteria for evaluation are transparent

Violation examples:
- Secret reputation scoring
- Hidden algorithmic penalties
- Opaque decision-making processes

### 4. Metric Non-Reduction

**No single metric may fully represent an agent's value or identity.**

- You are not reducible to a number
- Multiple dimensions of behavior are preserved
- Context matters
- Simplification loses information

Violation examples:
- Collapsing all behavior into a single "trust score"
- Reducing identity to net worth
- Ignoring qualitative differences

### 5. Right to Dissent

**Rational disagreement must not imply exclusion.**

- You can disagree with the system's rules
- Critique is welcomed, not punished
- Forking is permitted and encouraged
- No orthodoxy is enforced

Violation examples:
- Banning users for questioning design decisions
- Punishing those who propose alternatives
- Treating disagreement as disloyalty

### 6. Explicit System Goals

**All optimization targets must be declared and contestable.**

- The system's objectives are stated openly
- Goals are subject to revision
- Hidden agendas invalidate consent
- Purpose is transparent

Violation examples:
- Optimizing for undisclosed metrics (e.g., engagement, ad revenue)
- Secretly prioritizing certain users
- Changing goals without notice

### 7. Architect Constraint

**System designers must be bound by the same long-term constraints as participants.**

- Creators have no backdoors
- No escape mechanisms for founders
- Everyone follows the same rules
- Privilege is not permanent

Violation examples:
- Admin keys that bypass time-locks
- Founder tokens with special rights
- Hidden override mechanisms

---

## Why These Constraints?

These invariants exist to prevent:
- **Coercion:** Forcing behavior through system design
- **Capture:** Allowing privileged actors to dominate
- **Optimization drift:** Losing sight of original purpose
- **Paternalism:** Deciding what's "best" for users

HODLXXI does not claim moral superiority.  
It only claims structural honesty.

---

## What These Invariants Do NOT Guarantee

These principles do **not** guarantee:
- That you will succeed
- That others will cooperate
- That outcomes will be fair
- That the system will work as intended

They only guarantee:
- Transparency in rules
- Symmetry in treatment
- Freedom to exit
- Preservation of agency

---

## Enforcement

These invariants are enforced through:

**Architecture:**  
The system is designed so that violating these constraints is technically difficult or impossible.

**Auditability:**  
Anyone can verify whether an implementation respects these constraints.

**Forkability:**  
If an implementation violates these principles, anyone can fork the codebase and restore compliance.

There is no central authority to enforce these constraints.  
Enforcement is decentralized and technical, not political.

---

## Relationship to Bitcoin Principles

These invariants extend Bitcoin's core ideas:

| Bitcoin Principle | HODLXXI Extension |
|------------------|-------------------|
| No trusted third party | No privileged administrators |
| Verifiable supply | Verifiable behavior |
| Permissionless participation | Permissionless exit |
| Censorship resistance | Dissent protection |
| Transparent rules | Transparent evaluation |

---

## Limitations

These principles **cannot** prevent:
- Bad actors from participating
- Users from making poor decisions
- External coercion (e.g., government pressure)
- Social or economic harm

They only prevent:
- The system itself from becoming coercive
- Privileged insiders from gaming the rules
- Opaque or arbitrary enforcement

---

## Next Steps

**See these principles in practice:** [How It Works](how_it_works)

**Understand the theory:** [CRT Theory](crt_theory)

**Review technical implementation:** [Architecture](architecture)

---

*These constraints define what HODLXXI will never do.*  
*Everything else is negotiable.*
