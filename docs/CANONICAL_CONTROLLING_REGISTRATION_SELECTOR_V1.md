# Canonical Controlling Registration Selector V1

This internal, read-only selector resolves one controlling
`TrustedCovenantRegistration` for an explicit graph/protocol and canonical
x-only subject. It is a selection seam, not an authorization seam.

The caller supplies the graph identifier, subject, evaluation time, and the
existing Genesis, admission-edge, root-binding, and trusted-registration
repositories. The selector owns no engine, session factory, cache, clock, or
fallback database and does not commit or mutate state.

## Selection policy

The selector first evaluates the existing canonical Genesis contract for the
explicit graph. Missing, ambiguous, inactive, malformed, or unavailable
Genesis state fails closed.

When the requested subject exactly equals the evaluated root identity, only
the unique EFFECTIVE `CanonicalRootRegistrationBinding` path is permitted.
Failure on that path never falls back to an admission edge.

For every non-root subject, only the unique EFFECTIVE
`CanonicalAdmissionEdge` for the exact graph and child subject is permitted.
Root-binding storage is not consulted.

The chosen selector record supplies the exact `trusted_registration_id` and
`trusted_registration_sha256`. Selection never uses timestamps, UUID order,
amounts, database row order, newest/oldest, or first/last behavior. Other
ACTIVE registrations for the subject are ignored.

## Revalidation and result

The exact referenced registration is fetched by ID and independently required
to be canonically valid, ACTIVE, digest-equal to the pointer, and bound to the
requested subject. The immutable result preserves the graph, subject,
selection-source kind, selector-record ID and digest, and exact registration.

Malformed input or stored state, missing or mismatched records, ambiguity, and
storage failures produce only `controlling registration unavailable`. Internal
database exception details are not exposed.

## Non-claims

The result grants no Full, Limited, membership, entitlement, access level,
lineage authority, Operator authority, runtime administration, or special
identity rights. The
selector performs no entitlement write or materialization, covenant-relation
evaluation, Bitcoin or Lightning observation, browser/OAuth behavior, public
route, background job, MCP operation, or Social behavior.
