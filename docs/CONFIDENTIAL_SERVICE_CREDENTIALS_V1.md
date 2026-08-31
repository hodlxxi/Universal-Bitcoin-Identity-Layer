# Confidential Service Credentials V1

This boundary implements the credential mechanics required before a future
Social backend can request Full-directory reads. A source-level Flask adapter
now exists, but it is disabled by default and is not registered unless every
explicit dependency validates. It is not configured, activated, or deployed by
this change.

## Standards and claim contract

Client authentication follows OAuth 2.0 Client Credentials (RFC 6749) and JWT
Bearer client authentication (`private_key_jwt`, RFC 7523). Both client
assertions and service access tokens use PyJWT's `RS256` implementation. Keys
are public RSA JWKs selected by one exact, unique `kid`; `alg`, `kty`, and `use`
must be exactly `RS256`, `RSA`, and `sig`.
The client assertion and service-token verification JWK sets are separated by
actual RSA public parameters, not by `kid`: any canonicalized modulus `n` and
exponent `e` pair that appears in both sets makes the configuration invalid.
Different `kid` values or alternate encodings of the same RSA integers do not
create separate authority.

An assertion has exact `iss` and `sub` equal to the registered confidential
`client_id`, exact token-endpoint `aud`, integer `iat` and `exp`, unique nonempty
`jti`, `token_use=client_assertion`, and `grant_type=client_credentials`.
It also requires the exact domain binding
`purpose=service_client_authentication`.

A service token has exact configured `iss`, resource `aud`, service-principal
`sub`, client `azp`, `scope=social:full-directory:read`,
`grant_type=client_credentials`, `token_use=service_access`,
`purpose=social_full_directory_read`, integer `iat` and `exp`, and nonempty
`jti`. Assertion and service-token lifetimes are at most 60 seconds; accepted
clock skew is configurable only from zero through five seconds.

Signatures are verified before claims become evidence. Exact comparisons reject
case changes, prefixes, substrings, wildcards, arrays, and multiple-principal
forms. `none`, symmetric substitution, algorithm confusion, missing or unknown
keys, ambiguous duplicate keys, malformed signatures, malformed claims, stale,
future, expired, and oversized credentials fail closed with generic denied or
unavailable errors. Credential material and internal validation reasons are not
logged or returned.

## Replay and operational prerequisites

Issuance requires a durable, shared, atomic consume-once store for each
client-assertion `jti`. The replay consumer is called as
`replay_consumer(jti, retention_deadline_exclusive)`. The second argument is not
the assertion `exp`; it is the earliest exclusive deadline at which the consumed
marker may be removed. Retention is based on the protocol maximum skew, not the
local process setting, so the final accepted integer second is
`exp + MAX_CLOCK_SKEW_SECONDS` and the earliest safe value is
`exp + MAX_CLOCK_SKEW_SECONDS + 1`. A store that honors this exclusive deadline
is safe across allowed rolling skew changes from zero through five seconds.
The generated service access token is encoded, checked against the configured
credential-size cap, and cryptographically self-verified against the configured
service JWK trust set before the client assertion is consumed. The supplied
signing key and `kid` are dependencies, not authority by themselves. An
untrusted signer, unknown signing `kid`, or unusably oversized generated token
therefore cannot burn a valid one-shot assertion.
Absence, failure, or a non-success replay-consumer result makes issuance
unavailable. The repository now supplies a dedicated, source-only PostgreSQL
adapter and forward migration for this dependency, documented in
`CONFIDENTIAL_SERVICE_ASSERTION_REPLAY_STORE_V1.md`. It stores only SHA-256
over the exact UTF-8 JTI and uses PostgreSQL uniqueness for shared atomic
consume-once behavior. The disabled internal-delivery runtime now injects this
adapter into issuance; the migration is not added or applied by that source
change. A service access token remains a bearer
credential: this implementation does not consume
its `jti` and therefore does not claim bearer-token replay resistance. Its short
lifetime limits, but does not eliminate, replay exposure.

Future activation must deliberately apply the existing migration where needed,
register the asymmetric confidential client and its public keys, provision
protected signing keys outside source, provision the dedicated alias secret,
and install private network enforcement. The source token and protected
directory routes are documented in
`PRIVACY_FULL_DIRECTORY_INTERNAL_DELIVERY_V1.md`; no production activation is
implemented here.

## Authority limits

Verified evidence authenticates only the configured service principal for a
future Full-directory read policy. It grants no Full status, participant or user
identity, browser session, Operator role, covenant authority, wallet access,
spending, signing, encryption, publication, or general UBID access. IP address,
loopback, Host and forwarded headers are not authentication. Caller-decoded
claims and unverified verifier results are not accepted.

V1.24b2 Social authorization and V1.24c delivery remain unavailable.
