# Canonical Current CRT Authorization Proof Resolver V1

PR6.19 calls this existing public explicit-snapshot resolver after exact local
source/snapshot-to-evidence composition. The resulting proof remains unsigned,
local, profile-specific, dormant, and unrelated to runtime authorization.

## Status and boundary

PR6.16 is `IMPLEMENTED_DORMANT`,
`READ_ONLY_EXPLICIT_SNAPSHOT_COMPOSITION`, `NOT_DEPLOYED`,
`NOT_LIVE_SOURCE_LOOKUP`, and `NOT_RUNTIME_AUTHORIZATION`.

“Current” means only relative to the exact immutable evidence snapshot supplied
by the caller and at the one exact canonical `evaluated_at`. It does not assert
that the snapshot reflects a production database or the current Bitcoin chain,
and it makes no claim after `evaluated_at`.

## Public API

```python
def resolve_canonical_crt_authorization_proof_from_snapshot(
    *,
    participant_id: str,
    compressed_public_key: str,
    x_only_public_key: str,
    depth: int,
    evaluated_at: datetime,
    genesis_records: tuple[CanonicalGenesisRecord, ...],
    target_edge_id: str | None = None,
    edge_evidence: tuple[CanonicalSponsorLineageEdgeEvidence, ...] = (),
) -> CanonicalCrtAuthorizationProof:
```

The resolver validates the API request, then uses the same `evaluated_at` for
PR6.9 genesis evaluation, PR6.11 lineage evaluation for ordinary subjects, and
PR6.12 membership evaluation. It maps that membership through PR6.13, builds
the PR6.14 proof, and returns the value reconstructed by PR6.14's authoritative
serializer and parser. Evidence problems remain authoritative fail-closed
LIMITED results; invalid API shape raises
`InvalidCanonicalCrtAuthorizationProofResolution`.

PR6.14 builds a proof over one exact PR6.13 evaluation. PR6.15 publishes
source-controlled reference bytes and verifies submitted bytes statelessly.
PR6.16 instead composes lower-level evaluations internally from exact
caller-injected PR6.9/PR6.11 source evidence. It does not read PR6.15 artifacts.

## Resolver-native vectors

- E923 FULL: `1e7508f12641f32e8813ddea1dd4b8bc9f0d5e862512773f36a4f414e7db4945`
- Depth-3 ordinary FULL: `48f1d49935e2f5a580fab0c56d350cba036c859bdb726c38a259ef6011ec0b98`
- Missing-target ordinary LIMITED: `3b08da361c571121895f97a4c0f2f74995aa4a335b454066906dab044ed0823b`

The missing-target vector is PR6.11 UNKNOWN `missing_target_evidence`, PR6.12
UNKNOWN `missing_target_evidence`, PR6.13 LIMITED
`unknown_membership_limited`, and PR6.14
`limited_by_unknown_membership` with `target_evidence` basis.

## PR6.15 temporal-mismatch reference

The existing PR6.15 `unknown-ordinary-limited` artifact with digest
`cf8aff59d98a2c0ec7bf62253fcfb1d0cce264517476ddecb6297153080e401c`
remains valid and unchanged. Its canonical PR6.11 lineage source was evaluated
at `2026-07-26T12:00:00Z`, while its PR6.12 membership evaluation was evaluated
at `2027-07-26T12:00:00Z`. It therefore demonstrates PR6.12's canonical
`source_time_mismatch` fail-closed behavior over an externally supplied source.

PR6.16 creates PR6.11 and PR6.12 results internally with one time, so it
does not fabricate or naturally reproduce that mismatch. PR6.12 and PR6.14 continue
to validate such externally composed canonical objects.

## Explicit non-claims

- `no automatic production database lookup`
- `no automatic admission-registry lookup`
- `no automatic trusted-registration lookup`
- `no automatic Bitcoin RPC observation`
- `no LND call`
- `no external network request`
- `no claim that the supplied evidence is live`
- `no claim that the supplied evidence is complete beyond lower-layer validation`
- `no claim that the proof remains current after evaluated_at`
- `no proof of private-key possession`
- `no signature or issuer attestation`
- `no authenticity claim from SHA-256 alone`
- `no action authorization grant`
- `no scope grant`
- `no session mutation`
- `no user-role mutation`
- `no entitlement write`
- `no administrator or operator status grant`
- `no invite or sponsor permission grant`
- `no automatic mapping to runtime IdentityClass`
- `no action_authorization integration`
- `no replacement of active legacy wallet-ratio authorization`
- `no public HTTP route`
- `no MCP tool`
- `no paid job`
- `no CLI`
- `no scheduler`
- `no deployment or production-enforcement claim`

## Deferred work

Still missing are a trusted live source adapter, production DB composition,
automatic Bitcoin observation, participant-facing current-proof lookup, an
HTTP current-proof route, an MCP current-proof tool, signature or issuer
attestation, a human HTML verifier, shadow authorization comparison,
runtime enforcement, and production deployment.
