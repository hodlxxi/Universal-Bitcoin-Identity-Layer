# Canonical CRT Authorization Proof V1

**Status: PR6.14 `IMPLEMENTED_DORMANT`; PR6.15 adds a separate
`IMPLEMENTED_SOURCE_ONLY` read-only reference surface.**

Canonical CRT Authorization Proof V1 is a pure deterministic artifact explaining
why one exact PR6.13 authorization evaluation is `FULL` or `LIMITED`. Its only
input is the complete `CanonicalCrtAuthorizationEvaluation`. Before explanation,
the builder serializes and parses that source through the authoritative PR6.13
codec. It does not retrieve evidence or independently compute membership or
authorization.

The identifiers are:

- schema `hodlxxi.canonical_crt_authorization_proof.v1`
- builder `hodlxxi.canonical_crt_authorization_proof_builder.v1`
- verification rule `hodlxxi.canonical_crt_authorization_proof_verification.v1`

The conclusion distinguishes exact genesis FULL, exact ordinary-participant
FULL, and LIMITED caused by provisional, target-edge inactivity, lineage
inactivity, disputed, or unknown membership. The basis identifies the controlling
part of the nested PR6.12 result: `genesis_record`,
`complete_sponsor_lineage`, `genesis_control`, `target_edge`, `ancestor_edge`,
`target_evidence`, `lineage_structure`, or `source_binding`.

The canonical explanation is exactly:

```text
authorization_class=<value>; authorization_reason=<value>; membership_state=<value>; membership_reason=<value>; proof_basis=<value>
```

It contains enum values only, has a fixed order and separator, and is rejected if
altered. It is an explanation code, not a legal assertion or live-chain claim.

## Complete source binding

The proof embeds the complete canonical PR6.13 evaluation, which itself embeds
the complete canonical PR6.12 membership evaluation. Identity, keys, depth,
target references, exact `evaluated_at`, class, authorization reason, membership
state and reason are equal to PR6.13. Source kind/digest/state/reason, control
references, selected genesis references, and sorted relevant-record references
are equal to nested PR6.12. All flattened control references exactly equal the
nested PR6.12 membership evaluation. For ordinary non-active genesis
evaluations, PR6.12 uses `controlling_depth=0` and
`controlling_edge_id=None`; PR6.14 preserves those values without
reinterpretation. Their selected genesis references are normally `None`/`None`,
and PR6.14 never invents a record. Every `source_*` binding reason takes
precedence and uses `source_binding`, including for a genesis subject. Separate
proof fields bind both authoritative canonical SHA-256 digests, including
PR6.13's own nested membership digest.

The proof says only that these exact canonical PR6.13 bytes derive this exact
conclusion and explanation under V1. The `evaluated_at` instant is the complete
currency boundary; the proof makes no claim that its source remains current
afterward.

## Canonical bytes and digest boundary

Canonical proof JSON uses exact field sets at all three levels, recursively
sorted keys, compact ASCII, exact enum and boolean values, lowercase UUIDs and
SHA-256 digests, and whole-second UTC `Z`. Parsers reject duplicate keys, floats,
`NaN`, infinities, offsets, microseconds, missing or extra fields, noncanonical
nested sources, reordered or duplicate relevant records, mismatched bindings,
tuple or string subclasses supplied to the serializer, and any noncanonical byte
representation. Successful parsing must reproduce the exact bytes.

The proof digest identifies exact canonical proof bytes and detects byte changes.
SHA-256 is not a signature. It identifies no issuer, proves neither who generated
the proof nor private-key possession, and does not establish live Bitcoin state.
Authenticity requires a separately reviewed signature or attestation layer;
PR6.14 adds neither.

## Domain boundary

The builder is caller-injected and performs no storage, database, Bitcoin RPC,
LND, HTTP, or subprocess operation. It adds no action authorization, entitlement,
role, session, scope, administrator/operator, invite, or sponsor grant. It adds
no route, API, MCP tool, CLI, scheduler, model, migration, runtime wiring, or
public endpoint. Active wallet-ratio authorization remains separate and
`ACTIVE_LEGACY_NON_CANONICAL`.

PR6.15 adds source-implemented read-only publication of three deterministic
reference artifacts and stateless verification through this parser. It does not
alter the builder, activate live source composition, grant authorization, add
MCP support, or claim deployment. See
[Canonical CRT Authorization Proof Publication V1](CANONICAL_CRT_AUTHORIZATION_PROOF_PUBLICATION_V1.md).
