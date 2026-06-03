# NIP-59 Static Bundle Inspection

## Purpose

The static bundle inspection verifies the committed NIP-59 browser bundle remains a safe skeleton artifact.

It does not build the bundle. It only inspects the existing committed file.

## Command

Run from the repository root:

    python scripts/verify_nip59_static_bundle.py

Expected:

    ok: NIP-59 static bundle inspection holds

## Required skeleton markers

- `status: "skeleton"`
- `cryptoReady: false`
- `canFinalizeGiftWrap: false`
- `canPostEnvelope: false`
- `relayPublishing: false`
- `plaintextPost: false`

## Forbidden terms

- `@nostr/tools/wasm`
- `nostr-wasm`
- `initNostrWasm`
- `setNostrWasm`
- `NostrWasm`
- `WebAssembly`
- `finalizeEvent`
- `generateSecretKey`
- `privateKey`
- `private_key`
- `secretKey`
- `fetch(`
- `XMLHttpRequest`
- `/api/messages/nip17/envelopes`

## Safety invariant

This inspection does not:

- install npm
- add a lockfile
- add `node_modules`
- build a bundle
- approve browser crypto
- enable send
- enable production intake
- enable relay publishing
