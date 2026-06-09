# NIP-59 Browser Global Smoke — No Send

## Purpose

P48 verifies that the live NIP-59 browser bundle exposes the expected browser global surface while send, POST, intake, and relay publishing remain disabled.

This is not a messaging enablement step.

## Expected global surface

The live static bundle must expose the generated no-send browser surface:

- `HODLXXINip59Bundle`
- `status=generated-experiment-no-send`
- `cryptoReady=false`
- `canFinalizeGiftWrap=false`
- `canPostEnvelope=false`
- `relayPublishing=false`
- `plaintextPost=false`
- `sendEnabled=false`

## Forbidden delivery surface

The smoke must fail if the bundle contains:

- `fetch(`
- `XMLHttpRequest`
- `/api/messages/nip17/envelopes`
- `SimplePool`
- `relayInit`
- `publish(`
- `WebAssembly`
- `nostr-wasm`

## Commands

Local committed bundle:

`python scripts/smoke_nip59_browser_global_no_send.py`

Production public static bundle:

`python scripts/smoke_nip59_browser_global_no_send.py --source https://hodlxxi.com/static/js/nip59_client_bundle.js`

## Runtime boundary

The NIP-17/NIP-59 policy endpoint must remain disabled:

- `enabled=false`
- `intake_enabled=false`
- `relay_publishing=false`
