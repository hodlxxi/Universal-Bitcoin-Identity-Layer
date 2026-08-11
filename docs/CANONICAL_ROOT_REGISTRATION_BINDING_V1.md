# Canonical Root Registration Binding V1

This dormant contract gives the canonical root subject the same kind of exact
trusted-registration selection pointer that an effective admission edge gives
an ordinary participant. It is selection authority only.

The root identity is not configured by this contract. Both writes and reads
must obtain the graph's records from canonical Genesis storage and accept the
claimed x-only key only when the existing Genesis evaluator returns one
unambiguous `GENESIS_ACTIVE` result. No participant label, public key,
registration UUID, or Bitcoin outpoint is fixed by the binding policy.

An effective binding points to one exact trusted-registration UUID and its
canonical SHA-256. Resolution repeats exact-ID lookup and requires the
registration to be canonical, `ACTIVE`, digest-matched, and bound to the same
root x-only key. Absence, ambiguity, malformed storage, lifecycle changes, or
source disagreement makes the selection unavailable. Row ordering is never a
selection rule. Other active registrations for the subject remain valid but
do not control this pointer.

## Lifecycle and storage

The finite lifecycle is `PROPOSED`, `EFFECTIVE`, `DISPUTED`, `SUPERSEDED`, or
`REVOKED`. Canonical timestamp and successor-field rules follow the existing
Genesis and admission-edge conventions. The transition validator permits only
activation, dispute, supersession, and revocation paths and never permits a
transition to change the graph or root subject.

Storage applies those rules transactionally. Activation updates the retained
binding snapshot. Rotation changes the former effective snapshot to
`SUPERSEDED` and inserts its named replacement in the same transaction, so the
partial uniqueness constraint never admits two controlling bindings.
Dispute or revocation preserves the original `effective_at`; a proposal that
was never effective retains `effective_at = null`. Deactivation may proceed
after the referenced registration becomes inactive, while activation and
effective resolution still require the exact current digest and `ACTIVE`
registration.

The dedicated additive table retains canonical JSON and its digest. A partial
unique index permits at most one `EFFECTIVE` row for a graph/root pair while
allowing non-effective history. There is no seed or backfill. Application
rollback leaves dormant evidence preserved; destructive removal is a separate
reviewed database operation.

## Explicit non-claims

A binding does not grant Full, Limited, membership, Operator rights, or any
current entitlement. It neither writes entitlement evidence nor evaluates a
covenant relation. It performs no Bitcoin observation or RPC, invokes no
materializer, and changes no browser, login, OAuth, MCP, Social, endpoint,
background-job, or production behavior.
