# NIP-59 Minimal Source Module

## Purpose

P44 introduces the first real NIP-59 browser-client source module.

This is implementation source only. It does not replace the production static bundle and does not enable send.

## Source file

- `frontend/nip59/src/client.js`

## Dependency boundary

The source module imports from normal `nostr-tools` only.

It must not import:

- `@nostr/tools/wasm`
- `nostr-wasm`

It must not use:

- `WebAssembly`
- `fetch`
- `XMLHttpRequest`
- `/api/messages/nip17/envelopes`

## Current capability

The source module may expose local crypto capability and a local throwaway event probe.

It still reports:

- `networkPost=false`
- `relayPublishing=false`
- `plaintextPost=false`
- `sendEnabled=false`

## Production boundary

P44 does not:

- install npm on production
- commit `package-lock.json`
- commit `node_modules`
- build a browser bundle
- replace `app/static/js/nip59_client_bundle.js`
- set production `cryptoReady=true`
- enable send
- enable intake
- enable relay publishing
