# NIP-59 Reviewed Generated Bundle Artifact

## Result

P46 commits the reviewed generated NIP-59 browser bundle artifact without replacing the live static bundle.

The live production bundle remains the skeleton artifact at:

- `app/static/js/nip59_client_bundle.js`

The reviewed generated artifact is committed at:

- `frontend/nip59/dist/nip59_client_bundle.generated.js`

## Safety boundary

The generated artifact remains no-send:

- `status=generated-experiment-no-send`
- `cryptoReady=false`
- `canFinalizeGiftWrap=false`
- `canPostEnvelope=false`
- `relayPublishing=false`
- `plaintextPost=false`
- `sendEnabled=false`

The generated artifact must not contain:

- `@nostr/tools/wasm`
- `nostr-wasm`
- `WebAssembly`
- `fetch(`
- `XMLHttpRequest`
- `/api/messages/nip17/envelopes`
- `SimplePool`
- `relayInit`
- `publish(`
- relay surface helpers such as `fetchRelayInformation` or `RelayList`

## Verification

Run:

```bash
python scripts/verify_nip59_generated_bundle.py
bash scripts/release_gate_smoke_check.sh
```

## Boundary

This PR does not:

- install npm on production
- commit `package-lock.json`
- commit `node_modules`
- replace the live static bundle
- enable send
- enable intake
- enable relay publishing
