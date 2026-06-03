# NIP-59 Builder Source Placeholder

## Purpose

This records the first placeholder source location for future NIP-59 browser-client work.

The placeholder is intentionally non-cryptographic and exists only so the import-policy scanner has a real future source directory to watch.

## Source path

- `frontend/nip59/src/client_placeholder.js`

## Safety invariant

This placeholder does not:

- import `nostr-tools`
- import `@nostr/tools/wasm`
- import `nostr-wasm`
- use `WebAssembly`
- install npm
- add a lockfile
- build a bundle
- enable crypto
- enable send
- enable production intake
- enable relay publishing

## Required before replacement

Before this placeholder is replaced with real browser-client source:

1. The import-policy scanner must keep passing.
2. Source must avoid the explicit wasm path.
3. Bundle inspection must prove wasm code is absent.
4. Send must remain disabled until server-side policy allows intake.
