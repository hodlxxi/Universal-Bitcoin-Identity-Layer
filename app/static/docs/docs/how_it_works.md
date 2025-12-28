# How HODLXXI Works

HODLXXI combines several Bitcoin-native primitives into a single coordination framework.

This document provides a conceptual overview without diving into implementation details.

---

## Core Components

### 1. Cryptographic Identity

Instead of usernames and passwords, HODLXXI uses Bitcoin public keys as identities.

You authenticate by signing messages with your private key.  
No email, no phone number, no KYC required.

Your identity is your cryptographic signature.  
No one can impersonate you without your private key.

### 2. Time-Locked Commitments

Time-locks allow you to make commitments that are enforced by Bitcoin's consensus rules, not by promises or contracts.

Example: "These funds will unlock at block 820,000."

Once created, the time-lock cannot be:
- Revoked by you
- Overridden by administrators
- Changed by anyone

The commitment is cryptographically enforced.

### 3. Observable Actions

All actions in HODLXXI are recorded on Bitcoin's blockchain.

This means:
- Your history is public and auditable
- You cannot erase past actions
- Others can verify your behavior over time

This creates accountability without requiring a trusted authority.

### 4. Voluntary Participation

Nothing in HODLXXI is mandatory.

You choose:
- Whether to participate
- How much to commit
- When to exit

The system cannot force you to stay.  
Exit is always possible, though time-locked funds remain locked until their specified unlock time.

---

## How These Components Work Together

### Example: Making a Commitment

1. **You decide** to commit 0.1 BTC for 1 year
2. **You create** a time-locked transaction with your Bitcoin keys
3. **Bitcoin enforces** the lock - no one can spend the funds early
4. **Others can verify** that you made this commitment by checking the blockchain
5. **After 1 year** (at the specified block height), the funds unlock automatically

No administrator needed.  
No trust required.  
Just cryptography and time.

### Example: Building Reputation

1. You make commitments over time (time-locks, signed statements, etc.)
2. Others observe your behavior on the blockchain
3. Your history becomes your reputation
4. Future partners can verify your track record independently

Reputation is not a score assigned by the system.  
It is the observable record of your actions.

---

## What HODLXXI Does NOT Do

**HODLXXI does not:**
- Hold your keys (you always control your private keys)
- Custody your funds (everything is self-custodial)
- Enforce behavior (it only makes behavior observable)
- Guarantee outcomes (it only guarantees transparency)

The system provides tools for coordination.  
It does not force cooperation.

---

## Key Design Principles

### Verifiability Over Trust

Don't trust, verify.  
All commitments are cryptographically provable.

### Symmetry of Rules

No participant has privileged access.  
Everyone follows the same rules.

### Transparency by Default

Actions are public and auditable.  
Privacy is achieved through pseudonymity, not secrecy.

### Long Time Horizons

The system is designed for 21-year cycles.  
Short-term thinking is discouraged by design.

---

## Technical Stack (Overview)

- **Base Layer:** Bitcoin blockchain
- **Identity:** Bitcoin signatures (ECDSA/Schnorr)
- **Commitments:** Time-locked transactions (OP_CHECKLOCKTIMEVERIFY)
- **Proofs:** PSBTs (Partially Signed Bitcoin Transactions)
- **Authentication:** LNURL-auth, Nostr identity integration

For technical details, see [Architecture](architecture).

---

## Limitations

HODLXXI cannot:
- Reverse time-locks once created
- Protect you if you lose your private keys
- Enforce off-chain behavior
- Guarantee that others will cooperate
- Make Bitcoin transactions free or instant

The system works within Bitcoin's constraints.  
It does not promise magic.

---

## Use Cases

**Long-term agreements:**  
Business partnerships, inheritance planning, multi-year contracts

**Reputation building:**  
Demonstrate commitment over time, verifiable track record

**Decentralized coordination:**  
Cooperate with others without requiring trusted intermediaries

**Identity layer:**  
Use Bitcoin keys as persistent identity across applications

---

## Next Steps

**Understand the constraints:** [Principles & Invariants](principles)

**See the roadmap:** [21-Year Roadmap](roadmap_21y)

**Technical details:** [Architecture](architecture)

**Still confused?** [FAQ](faq)

---

*HODLXXI does not solve coordination by force.*  
*It solves coordination by making actions observable and costly to fake.*
