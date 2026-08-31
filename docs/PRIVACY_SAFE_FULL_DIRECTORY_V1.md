# Privacy-Safe Full Directory V1

## Purpose and status

`PrivacySafeFullDirectoryV1` is a backend-only core contract for asking one
question: for this canonical current-Full viewer, what is the complete current
Full population represented by viewer-specific opaque aliases? It is
implemented and unit-testable. A disabled-by-default internal Flask delivery
adapter now invokes it only after separate service and human OAuth
authentication. It remains absent from Social, browsers, agent surfaces,
deployment, and production activation. It performs no runtime mutation merely
by constructing a directory.

This contract consumes the existing authoritative
`hodlxxi.full_entitlement_snapshot.v1` primitive. It does not reconstruct the
population from users, legacy access levels, wallets, descriptors, keys, or
online state.

## Exact injected inputs

Construction requires all of the following explicit dependencies:

- `viewer_subject`: one canonical lowercase 64-hex UBID subject;
- `current_entitlement_resolver`: the canonical persisted current-entitlement
  resolver callback;
- `full_population_provider`: a zero-argument callback returning one complete
  current `hodlxxi.full_entitlement_snapshot.v1` object;
- `alias_secret`: dedicated pairwise-alias key material of at least 32 bytes;
- optionally, a positive alias namespace version and an aware clock.

The service does not read a secret or any other configuration from the
environment. The alias secret must be generated from a cryptographically secure
source and dedicated to this purpose. It must not be the Flask secret, an OAuth
client secret, a JWT or agent signing key, a covenant key, or an X25519 key.

## Viewer authorization

Authorization happens before the population provider is called. The viewer
subject must already be canonical. The canonical resolver must return a
well-formed `EntitlementDecision` for that same subject with persisted current
evidence, exact `identity_class == FULL`, and exact
`current_full_relation_satisfied == true`. The resolver owns the existing
current-evidence semantics, including active persisted-user, expiry, and
revocation evaluation.

Limited, non-current, unknown, expired, revoked, unavailable, malformed,
noncanonical, and legacy-only Full viewers receive no population access.
Unauthorized viewers raise the generic typed
`PrivacySafeFullDirectoryDenied`; unavailable or malformed trusted state raises
the generic typed `PrivacySafeFullDirectoryUnavailable`.

## Complete population and failure behavior

The population must have the exact existing Full snapshot schema, constants,
fields, deterministic digest, strict canonical subject order, `complete: true`,
current interval of no more than 300 seconds, and at most 4096 exact current-Full
records. Every record must refer to its enclosing snapshot and cover the
snapshot interval. The authorized Full viewer must occur in the complete Full
population; absence would contradict the per-subject decision.

Partial, incomplete, stale, future, expired, malformed, duplicated, unsorted,
digest-mismatched, contradictory, excessive, unavailable, or throwing sources
fail the whole request closed. No best-effort or partial directory is returned,
and the error contains no subject, count, provider, or storage detail.

## Exact output

The result has exactly this shape:

```json
{
  "schema": "hodlxxi.privacy_safe_full_directory.v1",
  "version": 1,
  "participants": [
    {
      "alias": "p_example_opaque_value",
      "identity_class": "full",
      "current_full_relation_satisfied": true
    }
  ]
}
```

The viewer is excluded. Entries are sorted by alias. An entry contains no
target subject or other target metadata. The output is a construction-time
view, not a cache authority; a later consumer must request a newly authorized
directory rather than extend snapshot freshness.

## Pairwise alias semantics

An alias is `p_` followed by unpadded URL-safe Base64 encoding of 128 bits from
HMAC-SHA-256. The HMAC input is unambiguously separated and includes the domain
`HODLXXI_PRIVACY_DIRECTORY_ALIAS_V1`, directory schema version, injected alias
namespace version, canonical viewer subject, and canonical target subject.

For a fixed secret and alias version, the same viewer/target pair is stable.
The same target has a different alias for another viewer, and different targets
have different aliases for one viewer. The alias neither embeds nor truncates a
subject or key. Without the server-held alias secret, it is not a reversible
encoding of the target. Changing the dedicated secret or alias namespace
version intentionally rotates the alias namespace; deterministic stability is
scoped only to that secret and version.

An alias is a directory-local opaque handle. It is not an identity key, because
it cannot authenticate, sign for, or canonically identify the target outside
this viewer-bound namespace. It is not a covenant proof or spending key. It is
not a payment identifier or authorization. It is not an X25519 recipient key
and supports no encryption or key agreement. It is not a Nostr identity, npub,
profile lookup key, or display-name source.

## Privacy and security invariants

- Limited viewers receive zero Full population data, and the population source
  is not called for them.
- Full membership comes only from canonical current entitlement evidence.
- A Full viewer receives opaque aliases, never other participants' raw subject
  keys.
- Aliases are viewer-specific and contain no subject/key prefix, suffix, tail,
  participant identifier, or wallet/encryption/Nostr material.
- Full does not imply a direct relationship, friendship, sponsor relationship,
  covenant counterparty, or graph position.
- Full membership grants no wallet, descriptor, XPUB, payment, encryption,
  covenant-disclosure, or covenant-spending access.
- No production secret or private key is committed, and directory construction
  performs no write, refresh, repair, network request, or runtime mutation.

## Explicit non-claims

This V1 provides no public endpoint, Social UI integration, online presence,
display-name registry, friendship claim, sponsor claim, graph-depth claim,
direct covenant relationship claim, wallet or XPUB disclosure, payment
authorization, covenant spending authority, admin or operator grant,
trust/reputation assertion, legal identity or KYC claim, X25519 key
distribution, or protected-content delivery.

It also provides no names, Nostr change or profile resolution, relationship
path, direct-peer disclosure, OAuth behavior change, access-token storage,
confidential service credential, agent alias exposure, database migration,
deployment, or production activation.

## Why there is no live or public HTTP route

The intended later consumer is the Social backend-for-frontend through a
separately reviewed, protected service boundary. Source-level internal routes
are now available only behind complete explicit configuration and two distinct
credentials; they are not publicly advertised or activated. A deployment-level
private-path rule remains mandatory before activation. Publishing a browser or
session endpoint would create a durable enumeration surface. A Social Full
Network list, viewer-filtered presence, and direct-relationship disclosure each
require separate review and authorization.
