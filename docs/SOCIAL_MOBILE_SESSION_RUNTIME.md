# Explicit Social mobile/session runtime

This server composition is source only. It does not deploy, provision data or
credentials, apply migrations, change listeners, or mount browser UI. The
[OAuth lifecycle](OAUTH_SESSION_LIFECYCLE_V1.md),
[mobile ingress](SOCIAL_MOBILE_AUTHORIZATION_INGRESS_V1.md), and
[issuance contract](SOCIAL_SESSION_ISSUANCE_V1.md) remain authoritative.

## Future operator boundary

The ordinary `app.factory:create_app` never installs this composition. A future,
separately authorized operator must select `app.factory:create_social_mobile_app`
and supply **both** `SOCIAL_MOBILE_AUTHORIZATION_ENABLED=true` and
`SOCIAL_SESSION_ISSUANCE_ENABLED=true`. Both default false; the parser accepts
only `true`, `false`, empty or absent. A single enabled switch fails startup.
The opt-in factory uses the already initialized PostgreSQL `get_session` owner.
The lower-level `configure_social_mobile_session(app, config,
session_factory=...)` requires an explicit callable; it has no database fallback.

Complete trusted configuration is required:

| Name | Contract |
| --- | --- |
| `SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID` | Explicit existing Social OAuth client ID; no default |
| `SOCIAL_SESSION_ISSUANCE_BACKEND_ID` | Explicit existing issuance backend ID; no default |
| `SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL` | Explicit existing issuance principal; no default |
| `SOCIAL_SESSION_ISSUANCE_SCOPE` | `social:session-issuance:manage` |
| `SOCIAL_SESSION_ISSUANCE_PURPOSE` | `social_session_issuance_v1` |
| `SOCIAL_MOBILE_AUTHORIZATION_BACKEND_ID` | Existing explicitly provisioned mobile backend; no default identity |
| `SOCIAL_MOBILE_AUTHORIZATION_SERVICE_PRINCIPAL` | Existing explicitly provisioned mobile principal; no default identity |
| `JWT_ISSUER` | Exact HTTPS origin, equal to lifecycle browser and bearer-validation issuer |
| `JWKS_DIR` | Existing OAuth signing/verification directory |

Identity values must match `[A-Za-z0-9._:-]{1,255}`. They come only from trusted
server configuration and are shared exactly by the lifecycle, mobile service
and issuance ingress. No deployment environment is an authorization policy.
At actual issuance, the existing `SqlAlchemySocialSessionIssuance._issuer()`
requires the persisted `social_session_issuers` row for that exact OAuth client,
matching backend ID and service principal, with `is_active=true`. Composition
does not read, create or modify issuer rows. HTTP fields cannot select or
override these trusted identities.

Each prefix `SOCIAL_SESSION_ISSUANCE` and `SOCIAL_MOBILE_AUTHORIZATION` also
requires `_CLIENT_JWKS_DIR`, `_SERVICE_JWKS_DIR`, `_SERVICE_SIGNING_KEY_ID`, and
`_SERVICE_SIGNING_KEY_PATH`. These are paths and identifiers, never PEM strings.
Client documents are public-only. Public RSA key sets must be nonempty, have
unique key IDs and contain no private JWK parameters. The existing confidential
credential contract rejects shared RSA keys between client and service sides.
The exact service signing file must be a private regular file, opened without
following a final symlink, bounded to 16384 bytes, and contain RSA >=2048 matching
its selected public key. No keys are discovered, generated or rotated here.

Audiences are derived from the existing schema constants. In particular,
issuance uses `JWT_ISSUER + /internal/v1/social/session-issuance/service-token`
for assertions and `JWT_ISSUER + /internal/v1/social/session-issuance` for service
access. There are no environment overrides for these audiences or for a
separate issuance issuer. Direct mappings containing conflicting values fail.
Full-directory URN audiences must not be reused.

All state owners share the exact injected factory, lifecycle and mobile
instances. The builder constructs and validates both ingresses before either
installer runs. Reinstallation fails. With both flags absent/off, it reads no
new key files and registers no routes. Existing request generation, entitlement,
pairing expiry, device binding and logout checks remain in their original
services. The existing internal-only listener/proxy boundary must be preserved
by any separately authorized activation; this module changes neither.

## Shared signer and existing device route

`app.tokens.issue_rs256_jwt`, called by both lifecycle exchange and initial
session issuance, passes its existing RSA private-key object directly to PyJWT.
It does not serialize the key to PEM. Claims, key selection, key ID, RS256
signature bytes and existing error propagation remain unchanged.

The existing device-binding token route is
`/internal/v1/social/messaging/device-binding-authorization-service-token`.
This composition adds no alias at
`/internal/v1/social/device-binding-authorization/service-token` and does not
enable the independent device-binding authorization feature.

## Offline verification

Run `python scripts/test_social_mobile_session_wiring_offline.py` using the
existing project environment. It selects only the wiring, issuance schema,
shared signer and pure lifecycle construction tests. It skips the shared
infrastructure conftest, clears inherited environment,
and denies network connections and database engine creation. Synthetic
infrastructure keys exist only in test memory; only public JWKS test documents
are written to temporary directories. No operational credentials are accessed.
