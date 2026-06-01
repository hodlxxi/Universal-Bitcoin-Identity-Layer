# NIP-59 Client Finalization Guardrails

## Current state

HODLXXI currently supports a local-only NIP-17/NIP-59 compose path:

- signer preflight
- recipient/message validation
- local rumor/seal/gift-wrap skeleton diagnostics
- no server POST
- no relay publishing
- no plaintext server path
- no server key custody

The current browser code does **not** produce a publishable NIP-59 gift-wrap event.

## Server accepted transport

The server accepts only finalized relay-visible kind-1059 gift-wrap envelopes with:

- `kind: 1059`
- 64-hex `id`
- 64-hex `pubkey`
- integer `created_at`
- non-empty opaque `content`
- 128-hex `sig`
- exactly one receiver `["p", receiver_pubkey]` tag

## Required client-side finalization

A production-compatible client-side finalization path must use a vetted Nostr/secp256k1 implementation for:

- ephemeral wrapper key generation
- Nostr event serialization
- SHA-256 event id calculation
- Schnorr signing
- hex byte conversion
- validation of finalized kind-1059 shape before POST

## Prohibited implementation paths

Do not hand-roll any of the following in `app/browser_routes.py`:

- secp256k1 scalar math
- Schnorr signing
- Nostr event id hashing
- private key derivation
- ad-hoc event finalization
- relay publishing

Do not sign the final gift-wrap with the user's long-term Nostr signer key.

## Acceptable implementation paths

One of these must be chosen before enabling POST:

1. Add a vetted frontend dependency pipeline, such as `nostr-tools` with its maintained cryptographic dependencies.
2. Vendor a reviewed, pinned browser bundle with reproducible provenance.
3. Keep finalization out of browser delivery and continue test-only fixture generation until dependency policy is decided.

## Safety invariant

Until finalized gift-wrap creation is implemented correctly:

- `Send sealed envelope` remains disabled.
- `/api/messages/nip17/envelopes` remains feature-flagged off in production.
- relay publishing remains disabled.
- plaintext is never sent to the server.
