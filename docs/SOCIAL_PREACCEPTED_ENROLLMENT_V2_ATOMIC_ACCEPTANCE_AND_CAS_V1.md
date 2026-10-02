# Social preaccepted-enrollment V2 atomic acceptance and CAS V1

Status: **dormant pure reservation/finalization byte contract and state model;
no persistence, transaction adapter, route, runtime wiring, or activation**.

The implementation is
`app/services/social_preaccepted_enrollment_v2_atomic_acceptance_contract.py`.
`RUNTIME_ENABLED` is `false`. UBID is the sole future owner of deadline
reservation, final acceptance/CAS, the association effect, immutable receipt,
challenge consumption and commit decision. Social owns only the separate
strict verification and verification-statement signing process.

## Two caller-owned UBID transactions

Reservation and finalization are separate transactions because Social
verification occurs outside UBID database locks.

### Reservation transaction

The caller-owned PostgreSQL transaction must lock/recheck all four deadline
authorities plus the exact challenge and absent association state, construct
[`MessagingDeviceVerificationDeadlineEvidenceV1`](SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_EVIDENCE_V1.md)
only from those locked results, insert one immutable `pending` reservation,
sign/store the exact evidence as required by that future owner, and commit.
The pure pending-reservation constructor strictly verifies the exact compact
evidence against its dedicated public trust and exact V2 input; it does not
accept four raw deadline integers.

### Finalization transaction

After Social returns the exact authenticated V2 statement, a new caller-owned
UBID transaction must lock, in the globally established order:

1. the exact reservation ID/revision;
2. the exact Current-Full, phone child/parent and approver authorities;
3. the exact current X25519 binding;
4. the exact issued challenge ID/revision; and
5. the exact subject/device association chain and the expected absent state.

It must reconstruct the closed current-authority snapshot from those locked
rows. The pure comparison model requires byte-for-byte equality of every
identity, revision, effective deadline, proof/digest and V2 binding frozen in
the evidence. It also requires the exact input, evidence and statement
digests; one matching acceptance/association/challenge/attempt graph; current
exclusive time bounds; challenge state `issued`; and the association CAS
tuple `absent/null/version 0/authority epoch 0`.

Only after all comparisons succeed may the durable owner, in that same
transaction, create association version 1/authority epoch 1, record exactly
one effect, insert the immutable receipt, consume the challenge, transition
the reservation to `accepted`, and commit. Any mismatch, ambiguity, expiry,
revocation, rotation, replacement, reuse or concurrent change denies and the
caller rolls back. The pure model does none of those operations and its output
is `provisional_until_caller_commit`.

## Closed state and retry semantics

The reservation states and replay/device-ID rules are fixed:

| State | Exact same-request retry | Changed reuse | Device-ID rule |
|---|---|---|---|
| `pending` | Return the already stored evidence while unexpired; never re-sign. | Deny. | Reserved by that exact pending request. |
| `accepted` | Return the immutable receipt; execute no second effect. | Deny. | Denied because the association is committed. |
| `rejected` | Deny; no reopening or re-signing. | Deny. | A new reservation is possible only after locked proof of no effect, receipt or association, with a new request, challenge, input and reservation. |
| `expired` | Deny; no reopening or re-signing. | Deny. | Same guarded new-reservation rule. |
| `cancelled` | Deny; no reopening or re-signing. | Deny. | Same guarded new-reservation rule. |

An accepted lost response is reconciled from immutable history and never
reexecuted. A pending lost response returns the exact stored JWS. Changed-byte,
changed-digest and changed-identity attempts fail closed. There is no fallback
to a different key, authority row, evidence version, statement, reservation,
challenge or association.

Retry reconciliation strictly extracts the stored compact evidence only to
compare its canonical header, payload, token identity and every reservation
identity/digest frozen by that payload and the exact V2 input. This historical
extraction is explicitly non-authoritative: it does not current-verify an
expired accepted record under a newly rotated key. Pending evidence must still
be within its exact signed interval. Accepted history compares every canonical
receipt field, including `decidedAt`, with the accepted reservation and
derivable finalization request. The receipt ID intentionally remains
decision-time-independent, but matching that ID alone never makes mutated
receipt bytes immutable history.

## Canonical bytes and identities

Reservation, current-authority snapshot, finalization observation, effect and
receipt wires are compact lexically key-sorted printable-ASCII JSON with
closed member sets and bounded sizes. Parsers reject duplicate, missing or
unknown fields, alternate JSON, Unicode, booleans-as-integers, floats,
negative/unsafe integers and malformed identifiers/digests.

The reservation binds the evidence token and payload digests, exact input
domain digest and payload digest, request/operation IDs, acceptance,
challenge, association, subject/device, challenge revision and evidence
interval. The finalization request, authority snapshot, effect ID, effect
digest and receipt ID each use a different domain-separated SHA-256 preimage.
None is reinterpreted as a V1 effect, V1 receipt, row ID, request ID, challenge
ID, association ID or bearer credential.

All persisted timestamps are wall-clock UTC epoch milliseconds. Expiry is
exclusive with no skew. Any local processing timeout is monotonic and outside
all authority/evidence bytes.

Every failure is the same non-sensitive message:

```text
social preaccepted enrollment v2 atomic acceptance denied
```

The public failure has no chained cause or context; malformed values and
internal parser or serializer failures are not retained on the exception.

## Public vector

The deterministic public fixture is
`tests/fixtures/social_preaccepted_enrollment_v2_atomic_acceptance_v1.json`:

```text
bytes  = 9638
sha256 = 6bbbf4c94f3120dbad57def6bceed7d5a9b563723402afb7cf1ca1e3121db7e8
```

It links the exact frozen deadline-evidence and Social V2 statement fixtures
and freezes one pending reservation, final locked observation, effect and
immutable receipt. These are pure values: they do not prove locks,
persistence, key custody, acceptance, an effect, challenge consumption,
receipt publication, commit, or runtime activation.

## Explicitly deferred

This phase adds no model/table, migration, repository or durable adapter,
transaction implementation, route, BFF, HTTP/socket transport, network call,
background process, runtime/factory composition, signer, key loader,
provisioning/rotation command, configuration, feature flag, service restart or
deployment. The remaining prerequisite for Phase 1 is the Social-owned
`InfrastructureMessagingDeviceVerificationSignerProcessV1` custody and
lifecycle contract plus separately authorized durable UBID adapters and
schema/runtime phases.
