# Full Recipient Directory Provider V1

## Status and boundary

This change implements only a source-only, offline builder for
`hodlxxi.full_recipient_directory.v1`. It combines two caller-injected complete
snapshots: authoritative current-Full entitlement evidence for the entire
eligible population and explicit X25519 public-key bindings for exactly that
population. A generic unavailable error replaces every invalid result.

The existing per-subject current-entitlement table, resolver, and public
assertion do not prove population completeness and are not read by this
provider. Live acquisition is therefore unavailable. No cache is presented as
a complete directory.

## Injected contracts

Both inputs are exact plain dictionaries with `version: 1`, `source:
hodlxxi-crt`, an `[A-Za-z0-9._:-]{1,128}` `snapshotId`, exact `complete: true`,
current integer-millisecond `issuedAt` and `expiresAt`, and one dense array of
at most 4096 records. Extra fields, custom objects, booleans used as integers,
partial snapshots, and unsupported constants are invalid.

The entitlement snapshot schema is `hodlxxi.full_entitlement_snapshot.v1`; its
`entitlements` records contain exactly `snapshotId`, `subject`, `status`,
`validFrom`, `expiresAt`, and `revoked`. Records must be strictly ordered by
canonical lowercase 64-hex subject, refer to the enclosing snapshot, be current
and cover the source interval, and have exact `status: full` and `revoked:
false`.

The binding snapshot schema is
`hodlxxi.recipient_key_binding_snapshot.v1`; its `bindings` records contain
exactly `snapshotId`, `subject`, `algorithm`, `version`, `publicKey`,
`validFrom`, `expiresAt`, and `revoked`. Records are strictly subject-ordered,
refer to the enclosing snapshot, and must match the entitlement subject set
exactly. A key has algorithm `x25519-v1`, a positive safe-integer version, a
unique canonical lowercase 64-hex public encoding different from the signing
subject, `revoked: false`, and a current window fully contained by the resulting
directory interval.
Known low-order/prohibited encodings and high-bit aliases are rejected; no
private key is accepted or retained.

The common directory interval begins at the later source issue time and ends at
the earliest source expiry or 300000 milliseconds after directory issue,
whichever comes first. It must contain the explicit integer-millisecond `now`.

## Determinism and output

After exact validation, the builder serializes newly allocated normalized
source snapshots plus the selected directory interval as UTF-8-compatible
ASCII JSON with sorted keys and compact separators. `snapshotId` is
`sha256:` followed by the lowercase SHA-256 digest of those bytes. SHA-256 is
used only as a deterministic evidence identifier; it is not a signature or an
authenticity proof. Randomness, UUIDs, ambient time, object representations,
and mapping insertion order do not affect it.

The output has exactly `schema`, `version`, `source`, `snapshotId`, `complete`,
`issuedAt`, `expiresAt`, and `recipients`. Each strictly subject-ordered
recipient has exactly `snapshotId`, `subject`, `encryptionKey`, and `authority`
with the fields and constants required by the V1 downstream contract. A
complete empty directory is available only when both complete sources are
empty. Missing or extra bindings, duplicates, ineligible evidence, mismatches,
invalid time, malformed keys, or any ambiguity make the whole result generically
unavailable without disclosing subjects, counts, lookup outcomes, or details.

## Explicit non-claims

This adds no HTTP route, authentication surface, public enumeration, database
query or migration, key registration, key custody, runtime wiring, encryption,
decryption, key agreement, protected transport, UI, dependency, or deployment.
It does not derive an encryption key from, or equate it with, a Nostr or other
authentication/signing subject. It does not log recipient data, call a network,
or access a live database.

## Smallest subsequent objective

The next separately reviewed objective is durable explicit X25519 public-key
registration with identity-authorized rotation and revocation, followed by a
Full-authenticated bounded directory-delivery boundary. Those controls must be
reviewed before any runtime wiring.
