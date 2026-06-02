# NIP-59 Client Dependency Decision

## Decision

HODLXXI will not hand-roll browser-side NIP-59 finalization.

The preferred path is to add a pinned, auditable frontend dependency path for Nostr event construction and secp256k1/Schnorr primitives, with `nostr-tools` as the first candidate and Noble-based cryptographic dependencies treated as part of the reviewed dependency surface.

No production send path may be enabled until this dependency path is implemented, pinned, reproducible, and covered by contract tests.

## Current state

The current browser compose flow supports:

- signer preflight
- recipient/message readiness
- local NIP-17/NIP-59 event-layer skeleton diagnostics
- local NIP-44 capability proof
- no POST
- no relay publishing
- no plaintext server path
- no server key custody

The current browser code does not create a publishable NIP-59 gift-wrap event.

## Why a dependency is required

A real NIP-59 gift-wrap finalization path requires:

- ephemeral wrapper key generation
- Nostr event serialization
- SHA-256 event id calculation
- Schnorr signing
- hex/byte conversion
- finalized kind-1059 validation before POST

These must not be implemented manually inside `app/browser_routes.py`.

## Rejected path

Do not hand-roll:

- secp256k1 scalar math
- Schnorr signing
- event id hashing
- private key derivation
- ad-hoc finalizeEvent logic
- relay publishing

Do not sign the final gift-wrap with the user's long-term Nostr signer key.

## Accepted implementation path

The next implementation PR should introduce a minimal frontend dependency pipeline that can produce a browser bundle for local-only finalization.

Requirements:

- pinned dependency versions
- lockfile committed
- documented build command
- generated browser bundle served from local static assets
- no CDN dependency for security-critical crypto
- no production send enablement
- no relay publishing
- no plaintext POST
- no server key custody

## Required gates before enabling POST

Before the browser can POST to `/api/messages/nip17/envelopes`, it must locally produce a finalized gift-wrap object with:

- `kind: 1059`
- 64-hex `id`
- 64-hex ephemeral wrapper `pubkey`
- integer `created_at`
- exactly one receiver `["p", receiver_pubkey]` tag
- non-empty opaque `content`
- 128-hex `sig`

The local object must pass the same shape expectations documented by the backend validator contract.

## Safety invariant

Until the dependency path and local finalization are implemented:

- `Send sealed envelope` remains disabled.
- production `NIP17_MESSAGES_ENABLED` remains absent/false.
- relay publishing remains disabled.
- plaintext is never sent to the server.
