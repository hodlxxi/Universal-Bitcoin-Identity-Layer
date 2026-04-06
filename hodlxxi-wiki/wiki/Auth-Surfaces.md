# Auth Surfaces

## Verified/implemented surfaces in repository
1. **Bitcoin signature login**
   - `POST /verify_signature`
   - Challenge + timestamp checks in session.
   - Pubkey format checks and RPC-backed signature verification path.
2. **Guest login**
   - `POST /guest_login`
   - Supports PIN-mapped and anonymous guest sessions.
3. **Session logout**
   - `GET /logout` clears session.
4. **LNURL-auth API**
   - `/api/lnurl-auth/create`, `/callback/<session_id>`, `/check/<session_id>`, `/params`.
5. **OAuth2/OIDC provider**
   - Dynamic client registration, authorization code flow, token issuance, introspection, discovery, JWKS.

## Partial / caveated
- LNURL-auth callback currently contains explicit code comments noting placeholder trust behavior for signature verification; treat as implemented with caveats.

## Mentioned but not confirmed as fully implemented in this pass
- Nostr-related identity/report surfaces exist, but a Nostr login flow is not confirmed as a complete auth method in the same sense as Bitcoin signature or OAuth session login.
