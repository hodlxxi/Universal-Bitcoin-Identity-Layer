# NIP-59 Narrow Import Bundle Evidence

## Result

The P45 generated bundle experiment showed that top-level `nostr-tools` import is not acceptable for the HODLXXI browser bundle.

The top-level import generated a bundle that included relay and fetch-related surface.

The narrow import experiment passed using:

- `nostr-tools/pure`
- `nostr-tools/nip44`

## Bundle results

- Top-level import bundle size: `210664` bytes
- Narrow import bundle size: `118978` bytes
- Forbidden hard terms after narrow import: none observed
- Relay surface terms after narrow import: none observed
- Direct source forbidden hard terms after narrow import: none observed

## Smoke result

The generated narrow-import bundle exposed `window.HODLXXI_NIP59_CLIENT` with:

- `status=generated-experiment-no-send`
- `cryptoReady=false`
- `canFinalizeLocalProbe=true`
- `canFinalizeGiftWrap=false`
- `canPostEnvelope=false`
- `relayPublishing=false`
- `plaintextPost=false`
- `sendEnabled=false`

The local throwaway probe returned `eventVerified=true` without network post, relay publishing, or plaintext post.

## Boundary

This PR patches the source import path and records evidence only.

It does not commit:

- `package-lock.json`
- `node_modules`
- generated browser bundle
- Mac clone build files

It does not enable:

- send
- POST to `/api/messages/nip17/envelopes`
- intake
- relay publishing

## Decision

HODLXXI NIP-59 browser source must avoid top-level `nostr-tools` import and use reviewed narrow imports.
