# Canonical E923 Genesis Record V1

Status: IMPLEMENTED_DORMANT

## Exact publication and identity

The exact source publication is
`docs/data/e923_canonical_genesis_record_v1.json`. Its canonical compact JSON
SHA-256 is
`df0445177ad8e913ef18dbf4670e8f8bc7a23f8adb14b9d87d4425dc3c5b1339`.
The schema is `hodlxxi.canonical_genesis_record.v1`, the service version is
`hodlxxi.canonical_genesis_record_service.v1`, and the graph ID is
`hodlxxi.crt_membership_graph.v1`. This graph ID is the stable runtime schema
choice for the Canon-named HODLXXI Membership Protocol V1 graph; there are no
aliases.

The sole participant is E923 at depth 0. Its authoritative compressed
secp256k1 identity anchor is
`023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923`;
the derived x-only key is
`3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923`.
The exact parameters are Bitcoin, `legacy_777`, middle height `1777777`, and
delta `777`.

The initial record timestamps are `2026-07-26T07:12:51Z`, the original
source commit's author instant normalized to canonical UTC seconds. This is
after the PR6.8 base commit instant `2026-07-26T06:33:21Z` and records the first
source-controlled implementation publication ordering. It is not proof of
signing, key possession, social legitimacy, or independent acceptance.

Evidence integrity has a finite basis. `content_sha256` means the digest of
exact referenced file bytes. The Canon Genesis Bootstrap bytes were retrieved
from the immutable raw GitHub URL at commit
`152c87522a7d89cd5c0e7014d7915a19bf074e1a` and verified with
`sha256sum /tmp/genesis-bootstrap-v1.md`, producing
`fea957f51ad9a8c1962afa56f1e3da07ed533cc80368f9fd720fa52bede78b46`.
`docs/OPERATOR_CONTINUITY_E923.md` hashes to
`1b22f6b4a3ba882d26efb7469e867bee8e12b52e74625ac318fd7f16c7c28488`.
The source-publication evidence instead uses
`self_canonical_digest_externally_pinned` with a null content digest: its
canonical digest is pinned here and in publication-contract tests. The
repository path is only a locator, and the evidence item does not pretend to
contain its own recursively impossible final content hash.

## Lifecycle and evaluation

Persisted lifecycle states are `proposed`, `effective`, `disputed`,
`superseded`, and `revoked`. The pure evaluator emits `genesis_active`,
`provisional`, `disputed`, `lineage_inactive`, or `unknown` under finite reason
codes. Only an evaluated set containing exactly one trusted, exact, valid
effective initial record, evaluated at or after its effective timestamp without
a controlling contradiction, produces `genesis_active`. Any additional
lifecycle record fails closed because PR6.9 defines no transition, revocation,
amendment, or succession policy. Unavailable, malformed, cross-graph,
future-effective, or untrusted evidence never activates genesis. succession authority is unavailable
in PR6.9; a purported successor is not silently activated.

Genesis has no sponsor, parent, reciprocal admission edge, self-edge, covenant,
transaction, wallet, descriptor, entitlement, or administrator field. Inventing
one would incorrectly turn the exceptional depth-0 declaration into ordinary
admission evidence.

`genesis_active` is a pure conclusion about this named graph. It is not FULL or
LIMITED authorization, runtime administration, sponsor power, ordinary
participant membership, lineage, or permission to bypass later admission
rules. Source publication is not runtime composition or database registration.
Repository validity is not legal identity, KYC, complete personhood, universal
legitimacy, independent reciprocal trust, current private-key possession,
ownership, custody, guardianship, moral authority, or permanent authority.

## Persistence and deployment boundary

The injected SQLAlchemy repository is append-only: `append`, `get`, and
`list_for_graph`. Reads reconstruct the nested immutable contract, revalidate
all constants, recompute the canonical digest, and compare duplicated indexed
columns. Multiple competing or historical records are preserved.

Migration `migrations/2026-07-26_canonical_e923_genesis_record_v1.sql` is
additive and has not been applied. It performs no seeding. No route, public API,
MCP tool, application-factory wiring, scheduler, startup loader, CLI, production
repository, or entitlement write was added. No production behavior changes.
