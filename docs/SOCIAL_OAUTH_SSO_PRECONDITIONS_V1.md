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

A future Social application must use a confidential backend. Its OAuth client
secret must never be exposed to browser JavaScript. Social deployment, live
OAuth-client registration, DNS, proxy, service, and environment changes are
outside this change.
