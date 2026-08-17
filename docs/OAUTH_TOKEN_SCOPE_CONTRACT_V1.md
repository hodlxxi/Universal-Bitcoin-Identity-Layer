# OAuth Token and Scope Contract V1

The canonical scope registry contains `openid`, `profile`, `self:read`,
`job:create`, `job:read:self`, `job:receipt:read:self`,
`action:receipt:read:self`, `covenant:draft:create`, and
`covenant:draft:read:self`. Covenant scopes are reserved and cannot be issued.

Unauthenticated dynamic clients have trust class `public_dynamic` and may use
only `openid profile self:read`. Operator-provisioned clients with trust class
`operator_managed` may additionally use the four currently supported job and
receipt scopes. Scope strings are strictly parsed, deduplicated, sorted, and
space-delimited. An omitted authorization scope defaults to `openid profile`.

Authorization requires a valid session identity canonicalized to a 64-character
x-only public key. Issued scopes are capability ceilings, not proof of current
entitlement. Protected-resource validation and entitlement re-evaluation remain
PR 3 work.

Authorization codes bind client, exact redirect URI, canonical subject, canonical
scope, and an S256 PKCE challenge. Redemption atomically transitions a valid code
from unused to used after every binding has passed.

Access tokens are RS256 JWTs with `iss`, client audience, canonical subject,
`iat`, `exp`, `jti`, canonical `scope`, `token_use=access`, and
`token_contract=hodlxxi.oauth.access-token.v1`. Persistence stores the JTI and
SHA-256 digest, never the JWT. Introspection authenticates the client and requires
the verified JWT to agree exactly with its unrevoked issuance record.

No schema migration is required. Legacy opaque token lookup remains unchanged.
