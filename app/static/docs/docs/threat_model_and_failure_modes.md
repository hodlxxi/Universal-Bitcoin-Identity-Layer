# Threat Model and Failure Modes

This document describes the threat model assumed by HODLXXI
and enumerates known failure modes.

It exists to make risks explicit rather than implicit.

---

## Design Philosophy

HODLXXI does not aim to eliminate all threats.

It assumes:
- adversarial participants,
- incomplete information,
- rational defection,
- and long time horizons.

The goal is not safety by prevention,
but resilience through constraints, visibility, and exit.

---

## Assumed Threat Actors

The system explicitly considers the following adversaries:

- Rational individuals seeking advantage
- Coordinated groups with shared incentives
- Long-term strategic actors
- Implementers with conflicting goals
- Founders with asymmetric influence
- External observers attempting capture or misuse

No assumption of goodwill is made.

---

## Out-of-Scope Threats

The following are explicitly out of scope:

- Total cryptographic failure
- Physical coercion
- Legal compulsion
- State-level censorship
- Global time manipulation

HODLXXI does not claim to defend against these.

---

## Threat Categories

### 1. Centralization Risk

**Description:**  
Accumulation of irreversible control by individuals, institutions, or implementations.

**Mitigation:**  
- No canonical implementation  
- Forkability over voting  
- Founder non-authority  
- Exit as a first-class outcome  

**Residual Risk:**  
High, if users mistake convenience for legitimacy.

---

### 2. Metric Collapse

**Description:**  
Reduction of complex identity or behavior into a single score or ranking.

**Mitigation:**  
- Explicit prohibition of scalar reputation  
- Contextual and historical representation  
- No global aggregation  

**Residual Risk:**  
Medium. Pressure toward simplification is persistent.

---

### 3. Soft Coercion

**Description:**  
Participation becomes “voluntary in theory” but mandatory in practice
due to economic, social, or institutional pressure.

**Mitigation:**  
- Explicit right to exit  
- Discouragement of monopoly deployments  
- Transparency of participation costs  

**Residual Risk:**  
High in institutional environments.

---

### 4. Founder Capture

**Description:**  
Original authors retain de facto authority through knowledge asymmetry,
infrastructure control, or social legitimacy.

**Mitigation:**  
- No privileged keys  
- No governance roles  
- Encouraged forks  
- Explicit decay of founder relevance  

**Residual Risk:**  
Medium to high, especially in early phases.

---

### 5. Misaligned Optimization

**Description:**  
Implementations optimize for engagement, profit, or control
rather than long-term reciprocity.

**Mitigation:**  
- Ethical use guidelines  
- Explicit limits documentation  
- Non-enforcement of outcomes  

**Residual Risk:**  
High. Optimization pressure is structural.

---

### 6. Surveillance Expansion

**Description:**  
Gradual extension of observability beyond voluntary actions.

**Mitigation:**  
- Visibility only through explicit commitments  
- No background data collection  
- No inference requirement  

**Residual Risk:**  
Medium. Depends on implementer integrity.

---

### 7. Sybil Amplification

**Description:**  
Low-cost identity creation undermines reciprocity mechanisms.

**Mitigation:**  
- Context-specific cost structures  
- Time-bound commitments  
- Optional external anchoring  

**Residual Risk:**  
Context-dependent. No universal solution is claimed.

---

### 8. False Legitimacy Claims

**Description:**  
Third parties claim endorsement, authority, or canonical status.

**Mitigation:**  
- License disclaimers  
- Governance non-authority  
- Explicit rejection of canon  

**Residual Risk:**  
Medium. Social attacks cannot be fully prevented.

---

## Failure Modes

The following outcomes are considered acceptable failures:

- Low adoption
- Fragmentation into incompatible forks
- Abandonment of implementations
- Partial misuse by bad actors
- Irrelevance to most users

These do not invalidate the research.

---

## Unacceptable Failures

The following invalidate the project’s core claims:

- Inability to exit
- Hidden rule changes
- Irreversible power accumulation
- Metric reduction to a single score
- Dependence on founder presence

Any implementation exhibiting these
should be considered non-compliant.

---

## Conclusion

HODLXXI does not promise safety, fairness, or success.

It offers a constrained design space
for experimenting with long-term coordination
under adversarial conditions.

Threats are expected.
Failure is allowed.
Opacity is not.