# Attestation interpretation boundaries

When reading `GET /agent/attestations`, keep these boundaries explicit:

- `issuer` — the party that signs or publishes the statement.
- `subject` — the entity, job, or artifact the statement refers to.
- `scope` — the narrow claim set covered by the attestation.
- `signed statement` — the exact payload that was signed or recorded.

An attestation can provide accountability and traceability without proving broader real-world facts.
