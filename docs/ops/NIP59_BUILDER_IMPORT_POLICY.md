# NIP-59 Builder Import Policy

## Decision

Future NIP-59 browser finalization work must avoid the explicit wasm path.

This policy does not approve `nostr-tools` for production browser crypto. It only defines imports and identifiers that future builder/client code must not use.

## Forbidden import paths

Future builder/client source must not import:

- `@nostr/tools/wasm`
- `nostr-wasm`

## Forbidden identifiers

Future builder/client source must not use:

- `initNostrWasm`
- `setNostrWasm`
- `NostrWasm`
- `WebAssembly`

## Reason

Prior review showed `nostr-wasm@0.1.0` is tied to the explicit `@nostr/tools/wasm` path.

The intended path is to avoid wasm-specific crypto unless a later review explicitly approves it.

## Safety invariant

Until a later reviewed builder PR proves the bundle contents:

- no `package-lock.json` is committed
- no `node_modules` is committed
- production does not run `npm install`
- root `package.json` remains zero-dependency
- static bundle remains skeleton-only
- `cryptoReady` remains false
- `canFinalizeGiftWrap` remains false
- `canPostEnvelope` remains false
- send remains disabled
- production intake remains disabled
- relay publishing remains disabled

## Required before crypto can be enabled

Before `cryptoReady` can become true:

1. Future builder source must pass this import policy.
2. Future bundle inspection must prove `nostr-wasm` is absent.
3. Future bundle inspection must prove WebAssembly payload is absent.
4. Finalized gift-wrap construction must have independent tests.
5. Send must remain disabled until server-side policy explicitly allows intake.
