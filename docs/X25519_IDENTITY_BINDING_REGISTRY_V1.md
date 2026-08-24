# X25519 Identity Binding Registry V1

## Boundary

V1.24a is a source-only durable registry for public X25519 recipient keys. It
does not expose a route, publish a directory, encrypt or decrypt data, hold key
material, or assign membership. The SQL migration creates an empty table and
is not applied by this change.

## Statement and authorization

`hodlxxi.x25519_identity_binding_statement.v1` is a closed JSON object with
`schema`, `version` (exactly `1`), `subject`, `algorithm`, `publicKey`, `bindingVersion`, `validFrom`,
`expiresAt`, `operation`, `priorBindingId`, `nonce`, `digest`,
`signatureFormat`, and `signature`. The external statement boundary accepts only
canonical JSON text, decodes with duplicate-pair detection, and rejects decoded
objects, duplicate names, noncanonical serialization, and unknown fields before
authorization.

The subject is the canonical lowercase 64-hex x-only secp256k1 public key from
an independently authenticated identity boundary. It must equal the statement
subject. An OAuth token or session is not an authorization proof.

The signing preimage is canonical ASCII JSON with sorted keys and compact
separators:

```text
{"domain":"HODLXXI_X25519_IDENTITY_BINDING_V1","statement":<unsigned statement>}
```

The unsigned statement contains every field through `nonce`, excluding
`digest`, `signatureFormat`, and `signature`. `digest` is its lowercase SHA-256
hex digest. `signatureFormat` is exactly `bip340_schnorr_sha256`; `signature`
is a lowercase 64-byte BIP-340 Schnorr signature verified by
`PublicKeyXOnly(subject)` over the 32-byte digest. This retains the established
action-step-up identity-key cryptographic meaning without treating step-up or
OAuth possession as the binding authorization itself.

`algorithm` is exactly `x25519-v1`. `publicKey` is public material only: a
canonical lowercase 32-byte encoding that passes the centralized V1.23 checks
for prohibited/low-order values, high-bit aliases, and values outside the
canonical field range. Private keys, seeds, signers, wallet material,
passwords, bearer credentials, and session secrets are outside the contract.

Externally supplied times are canonical UTC second-resolution RFC 3339 values;
fractional seconds are rejected. The trusted internal service clock is
normalized to whole UTC seconds by truncation before repository calls. Versions
are positive JSON-safe integers. Nonces and binding identifiers are lowercase
64-hex values; a binding identifier is the canonical statement digest.

## Lifecycle

- `register` creates version 1 and has no prior identifier. A subject with any
  registry history cannot register again.
- `rotate` names the exact current binding, uses its version plus one, inserts
  the new evidence with an X25519 public key different from that exact
  predecessor, and atomically retires the prior row.
- `revoke` names the exact current binding, uses its version plus one, repeats
  that binding's public key as audit evidence, retires the current row, and
  appends a non-current revocation row.

Only the same canonical revocation digest is an idempotent replay, and only
after transactionally confirming its exact predecessor is retired and no
conflicting current row exists. Register and rotate replays fail closed, as do a reused nonce, conflicting digest, stale
prior identifier, skipped version, duplicate active key, or lost concurrent
update. An operation's validity interval must contain transaction time.
Rotation and revocation validate the complete persisted authorizing chain at
that exact normalized transaction time before any mutation, flush, or commit;
an expired or not-yet-valid predecessor cannot authorize a lifecycle write. A
successor lifecycle statement that names a predecessor, including revocation
and idempotent revocation replay, must have `expiresAt` no later than the
earliest expiration in the complete validated predecessor chain; equality is
permitted. A rotation can never extend effective authority beyond any
predecessor. After that chain deadline, the expired chain must not be silently
extended by later rotation or revocation. Expired unretired rows are atomically
retired before lifecycle selection, releasing the active uniqueness indexes;
future rows are never current. History is append-only: retirement changes only
the explicit current-state marker and timestamp on the predecessor.

## Persistence invariants

The database constrains the fixed contract, algorithm, operation and signature
format; lengths and safe versions; validity ordering; register/prior semantics;
unique nonce, digest, and subject/version; and prior-row references. Partial
unique indexes permit at most one unretired binding per subject and at most one
unretired use of a public encryption key. Service transactions additionally
lock and compare current state, require the exact next version, and conditionally
retire one predecessor to detect concurrent rotation.

The additive migration contains no insert, seed, backfill, synthetic subject,
default key, operator binding, or live database action.

Strict persisted-chain validation repeats the lifecycle edge contract rather
than trusting earlier write paths. Every persisted rotate successor must point
to the exact predecessor, use the exact next version, keep `expiresAt` within
the complete predecessor-chain expiration, and change the X25519 public key
from that predecessor. Persisted revocation rows keep the required same-key
audit semantics. A same-key persisted rotate, an outliving successor, or any
later lifecycle statement authorized through such a chain fails closed with the
generic registry-unavailable result and no repair, omission, truncation, or
partial output.

## Authoritative read boundary

The reader begins one database transaction, captures the trusted snapshot time,
and first validates every active row and its complete predecessor chain at that
exact time. An expired active row, a not-yet-valid active row, an active
revocation row, or any temporally invalid predecessor in an active chain fails
the whole snapshot closed with the generic
`x25519 identity binding registry unavailable` error. Only after that strict
active-row validation does the reader select current non-revoked bindings in
subject order and request one row beyond the caller's bound. It returns each
current binding with the validated chain deadline to the service boundary. The
snapshot `expiresAt` is no later than the configured 300-second snapshot TTL,
every returned active head expiration, and every predecessor expiration required
by every returned chain. A missing, malformed, or already expired chain deadline
also fails the whole snapshot closed with the same generic error. It never
truncates or silently omits invalid active rows. An empty registry produces a
complete empty snapshot, and inactive revocation history is ignored. No private
or credential material is selected or returned.

## Non-claims and later work

A binding grants no Full, Limited, Operator, covenant, sponsorship, friendship,
Social, custody, signing, or release authority and never creates, extends, or
mutates entitlement. V1.24b must independently obtain authoritative current
entitlements and perform the fail-closed Full-population join. V1.24c may add
the separately reviewed delivery/publication boundary. Neither is implemented
here.
