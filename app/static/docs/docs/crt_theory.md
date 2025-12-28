# Cryptographic Reciprocity Theory (CRT)

Cryptographic Reciprocity Theory (CRT) is a framework for constructing systems in which cooperation emerges from rational self-interest over extended time horizons.

This document describes the theory without philosophical interpretation.

---

## Core Premises

CRT does not assume altruism or moral alignment.  
It assumes that agents respond to:
- **Incentives** (what benefits them)
- **Observability** (what others can see)
- **Delayed consequences** (what happens later)

The theory is based on three premises:

### 1. Behavior is shaped by repeated interaction

Single encounters favor defection (betrayal).  
Repeated encounters favor cooperation (tit-for-tat).

When agents know they will interact again, cooperation becomes more valuable than immediate gain.

### 2. Trust is an emergent property, not a prerequisite

You don't need to trust someone before cooperating with them.  
Trust emerges from repeated, predictable behavior over time.

CRT systems make behavior observable so trust can develop naturally.

### 3. Long-term commitments require mechanisms that outlast individuals

Promises fade.  
Contracts can be breached.  
Institutions can be captured.

Cryptographic commitments persist regardless of:
- Who created them
- What authority enforces them
- Whether the creator is still alive

---

## Theoretical Foundation: Game Theory

CRT builds on the **Iterated Prisoner's Dilemma**.

In a single-round Prisoner's Dilemma:
- Defection (betrayal) is always optimal
- Cooperation is irrational

In repeated games:
- Defection in round N hurts you in round N+1
- Cooperation becomes rational over time
- Tit-for-tat strategies emerge as optimal

**CRT extends this by:**
- Making behavior observable (blockchain records)
- Making history persistent (immutable ledger)
- Extending time horizons (21-year cycles)

---

## Cryptographic Primitives Used

CRT uses these Bitcoin primitives:

### 1. Public Key Cryptography

- Identities are public keys
- Authentication is signature verification
- No passwords or accounts required

### 2. Time-Locked Transactions

- Commitments encoded as Bitcoin transactions
- Unlocking requires specific block height or timestamp
- Cannot be reversed once created

### 3. Partially Signed Bitcoin Transactions (PSBTs)

- Proof of funds without spending
- Multi-party coordination
- Verifiable commitments

### 4. Output Descriptors

- Complex spending conditions
- Multi-signature schemes
- Covenant-like structures

---

## How CRT Systems Work

### Step 1: Identity Creation

Participant generates a Bitcoin key pair.  
Public key becomes their identity.  
Private key remains secret.

No registration required.  
No email or phone number.  
Just cryptography.

### Step 2: Commitment Creation

Participant creates a time-locked transaction:
- Locks funds until block height X
- Signs transaction with private key
- Broadcasts to Bitcoin network

The commitment is now:
- Publicly verifiable
- Immutable
- Enforceable by consensus rules

### Step 3: Behavior Observation

Other participants can:
- See the commitment on blockchain
- Verify the signature
- Track the participant's history
- Update their assessment of reliability

This is reputation without a centralized database.

### Step 4: Consequence Propagation

If participant defects:
- Their history shows the defection
- Future partners see this
- Cost of cooperation with them increases

If participant cooperates:
- Their history shows reliability
- Future partners prefer them
- Access to valuable relationships improves

---

## Why Time-Locks Matter

Time-locks solve the **commitment problem**.

Without time-locks:
- Promises can be broken
- Commitments are cheap
- Signals are unreliable

With time-locks:
- Breaking commitment means losing funds
- Making commitment is costly
- Signals are expensive to fake

This creates **credible commitment**.

---

## Reputation Model

CRT reputation is not a score.  
It is an observable history.

Traditional reputation systems:
- Collapse identity to a number (5 stars, 1000 points)
- Hide context and nuance
- Can be gamed or manipulated

CRT reputation:
- Preserves full history of actions
- Maintains context (when, with whom, under what conditions)
- Cannot be erased or edited

Participants form their own judgments based on observable facts.

---

## Incentive Alignment

CRT aligns incentives through:

### 1. Delayed Consequences

Short-term defection creates long-term costs.  
Reputation damage compounds over time.

### 2. Observable History

Actions cannot be hidden or denied.  
Blockchain provides permanent record.

### 3. Symmetric Rules

No one has privileged access.  
Everyone faces the same incentives.

### 4. Costly Signaling

Time-locked commitments are expensive to fake.  
Only serious participants will make them.

---

## Mathematical Model (Simplified)

Let:
- **A** = set of agents with persistent identities
- **L** = public ledger of all actions
- **T** = time horizon (e.g., 21 years)

For each agent *i* at time *t*:
- **H<sub>i,t</sub>** = history of actions up to time *t*
- **R<sub>i,t</sub>** = reputation derived from **H<sub>i,t</sub>**

Agent *i* chooses strategy *s<sub>i</sub>* to maximize:
```
V_i = Σ (payoff_t × discount_factor^t)
```

Where:
- **payoff<sub>t</sub>** depends on actions and reputation
- **discount_factor** < 1 (future matters less than present)

In CRT systems:
- Defection at time *t* reduces **R<sub>i,t+1</sub>**
- Lower reputation reduces future payoffs
- Long time horizon T makes future losses significant

Thus, cooperation becomes rational.

---

## Comparison to Traditional Systems

| Traditional | CRT |
|------------|-----|
| Trust required upfront | Trust emerges from observation |
| Reputation controlled by platform | Reputation derived from blockchain |
| Commitments enforced by law | Commitments enforced by cryptography |
| Exit may be restricted | Exit always possible |
| Rules can be changed arbitrarily | Rules are transparent and symmetric |

---

## Limitations

CRT cannot:
- Force cooperation (agents can always defect)
- Eliminate all uncertainty (unknown unknowns remain)
- Work with fully anonymous participants (identity must be persistent)
- Prevent Sybil attacks without cost-of-entry (proof-of-funds or proof-of-work)
- Encode subjective judgments (only objective facts)

---

## Applications

CRT is suited for:
- Long-term business relationships
- Inheritance and intergenerational transfer
- Decentralized marketplaces
- Reputation-based access control
- Coordination without institutions

CRT is NOT suited for:
- Anonymous transactions (requires persistent identity)
- Instant finality (Bitcoin confirmations take time)
- Off-chain enforcement (only on-chain actions are observable)
- Complex subjective disputes (requires human judgment)

---

## Next Steps

**See CRT in practice:** [Architecture](architecture)

**Understand time-locks:** [Time-Locked Covenants](covenants)

**Learn about reputation:** [Reputation & Incentives](reputation)

---

*CRT is a framework, not a solution.*  
*It solves some problems by creating new constraints.*
