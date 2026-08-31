# Privacy-Safe Full Directory Internal Delivery V1

## Status and authority model

This source-level UBID delivery path is disabled by default. It adds no Social
client, production credentials, secret material, deployment, or network
privacy rule. When deliberately configured later, it exposes two Flask routes:

- `POST /internal/v1/social/service-token`
- `GET /internal/v1/social/full-directory`

The routes are not included in agent capabilities, agent discovery,
`/.well-known/agent.json`, MCP, marketplace metadata, or public catalogs. An
internal path can still be reachable through a broad reverse proxy. A
deployment-specific nginx/private-path rule is therefore a mandatory activation
gate; application authentication does not establish network privacy.

The directory request requires two independent credentials. `Authorization`
contains the Social backend's confidential service access token. The separate
`X-HODLXXI-Viewer-Authorization` header contains the human viewer's canonical
UBID OAuth access token. Both use the exact `Bearer <token>` grammar. The service
credential is permission to ask; it does not identify the human and does not
grant Full membership. The viewer credential is independently verified by
`validate_canonical_access_token`, including its signature, persisted token
record, active user/subject binding, revocation, expiry, configured OAuth client
audience, token contract, and existing `openid` scope.

## Service-token HTTP contract

The token request is exactly `application/x-www-form-urlencoded` with one of
each of these fields and no others:

- `grant_type=client_credentials`
- the exact configured `client_id`
- `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- `client_assertion=<compact RS256 JWT>`
- `scope=social:full-directory:read`

Validation and issuance reuse `confidential_service_credentials.py` without a
second credential format. The client assertion has the exact issuer, subject,
audience, purpose, token-use, lifetime, key-selection, and clock rules defined
there. Before issuance, its JTI is consumed through
`PostgresConfidentialServiceAssertionReplayStore`; PostgreSQL uniqueness is the
shared atomic authority and only the SHA-256 digest of exact UTF-8 JTI bytes is
persisted. Storage failure or replay makes issuance unavailable. The response
contains only a 60-second RS256 service bearer, token type, exact scope, and
expiry. Assertions, bearer tokens, JTI values, claims, and keys are not logged.

## Directory authorization and privacy

The directory route applies this sequence without accepting a viewer subject
from JSON, a query, an identity header, an IP address, or forwarded metadata:

1. cryptographically verify the service access token and exact
   `social:full-directory:read` scope;
2. independently verify the human's canonical OAuth bearer;
3. resolve that bearer's canonical subject through current entitlement;
4. require exact current canonical Full evidence;
5. require one complete, fresh canonical Full snapshot; and
6. invoke `PrivacySafeFullDirectoryV1` with the dedicated alias secret.

Limited, unknown, revoked, stale, malformed, incomplete, contradictory, and
unavailable state fails closed. Denials disclose no population count, target
existence, or internal validation reason. Success returns only the established
viewer-pairwise alias projection and Full status booleans. Self is excluded.
No raw subject, covenant key, address, transaction, UTXO, descriptor, XPUB,
X25519 key, Nostr key, graph data, contact detail, balance, or trust evidence is
returned.

**VERIFY != REVEAL.** Verifying membership does not authorize identity
resolution. This endpoint is not a general identity-resolution API, and an
opaque alias cannot authenticate, sign, pay, or resolve a participant.

## Disabled-by-default configuration

`PRIVACY_FULL_DIRECTORY_INTERNAL_ENABLED` defaults to false. When false, the
runtime is not built and the blueprint is not registered. When true, startup
fails closed unless all of the following are explicit and valid:

- confidential client ID, service principal, issuer, token audience, resource
  audience, client public-JWKS directory, and separate service signing-material
  directory;
- the OAuth client ID to which human viewer access tokens must be bound;
- an absolute, non-symlink dedicated alias-secret file containing 32–4096 bytes
  and having no group/other permissions; and
- an allowed clock skew and positive bounded alias namespace version.

Client and service RSA authority must remain cryptographically separated. No
key or alias secret is generated at startup, and there is no secret default.

## Not activated by this change

Production credential registration, signing keys, alias-secret provisioning,
nginx private-path enforcement, environment activation, service restart,
deployment, and Social BFF wiring remain separate future work. This change adds
no migration, Social UI, browser alias rendering, presence, X25519 transport,
Nostr behavior, protected content, Checking/payment behavior, wallet authority,
or private-key custody.
