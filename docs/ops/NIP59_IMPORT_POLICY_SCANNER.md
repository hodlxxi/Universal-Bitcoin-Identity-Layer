# NIP-59 Import Policy Scanner

## Purpose

The import policy scanner enforces the NIP-59 builder import policy before real browser crypto work begins.

It prevents future builder/client source from accidentally using the explicit wasm path.

## Forbidden terms

Future builder/client source must not contain:

- `@nostr/tools/wasm`
- `nostr-wasm`
- `initNostrWasm`
- `setNostrWasm`
- `NostrWasm`
- `WebAssembly`

## Scanner command

Run from the repository root:

    python scripts/verify_nip59_import_policy.py

Expected:

    ok: NIP-59 import policy holds

## Scope

The scanner checks source-like builder/client paths:

- `app/static/js/nip59_client_bundle.js`
- `scripts/build_nip59_client_bundle.mjs`
- `frontend/nip59/src`
- `frontend/nip59/client`
- `frontend/nip59/builder`

It intentionally does not scan docs, tests, JSON policy records, or the scanner source, because those files must mention forbidden terms to document and test the policy.

## Safety invariant

This scanner does not:

- install npm
- add a lockfile
- add `node_modules`
- build a bundle
- approve `nostr-tools` for production crypto
- approve `nostr-wasm`
- enable send
- enable production intake
- enable relay publishing
