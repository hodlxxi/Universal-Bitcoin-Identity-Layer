# Social OAuth SSO Preconditions V1

HODLXXI OAuth authorization admits browser identities established by successful
Legacy or Nostr signature verification only. Both methods must canonicalize the
verified key to its x-only subject and persist and re-read an active canonical
`User` before an authenticated browser session can receive an authorization
code.

Guest, PIN-guest, and anonymous sessions are not OAuth identities. LNURL and
Lightning are also excluded: wallet callback verification does not yet finalize
an authenticated browser session. A key supplied only by Social, browser
JavaScript, NIP-07, or another client is not a HODLXXI OAuth login.

OAuth authentication proves control of the admitted key at login time. The
browser session's `full` or `limited` value is an admission precondition, not a
canonical entitlement claim, and it is not Social authority. Social must obtain
current Full/Limited authority through the separate canonical read-only
authority contract.

The session-cookie code default is host-only. An explicitly configured,
non-empty `SESSION_COOKIE_DOMAIN` remains supported for compatibility.
Production must separately remove any broad `.hodlxxi.com` environment value
before `social.hodlxxi.com` is deployed. Secure, HttpOnly, and SameSite=Lax
cookie protections remain required.

A future Social application must use an asymmetrically authenticated
confidential backend. Its private key must never be exposed to browser
JavaScript. Future operation requires explicit confidential-client and public
key registration, a durable shared atomic consume-once store for client
assertion `jti` values, private transport, and deliberate token-endpoint and
protected-route wiring. Social deployment, live OAuth-client registration,
DNS, proxy, service, and environment changes are outside this change.

The source-only credential mechanics do not authorize Social and do not deliver
directory data. V1.24b2 Social authorization and V1.24c delivery remain
unavailable. Service access tokens are bearer credentials; their replay is not
prevented by the source boundary.
