# NIP-59 Live Static Bundle Rollout — No Send

## Result

P47 replaces the live static NIP-59 browser bundle with the reviewed generated no-send artifact.

Live bundle:

- `app/static/js/nip59_client_bundle.js`

Source artifact:

- `frontend/nip59/dist/nip59_client_bundle.generated.js`

## Safety boundary

The live browser bundle remains no-send:

- `status=generated-experiment-no-send`
- `cryptoReady=false`
- `canFinalizeGiftWrap=false`
- `canPostEnvelope=false`
- `relayPublishing=false`
- `plaintextPost=false`
- `sendEnabled=false`

The live bundle may expose local event/hash/probe helpers, but it must not enable delivery.

The live bundle must not contain:

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

## Runtime boundary

This rollout does not enable:

- message send
- envelope POST
- server intake
- relay publishing

The NIP-17/NIP-59 policy endpoint must remain disabled:

- `enabled=false`
- `intake_enabled=false`
- `relay_publishing=false`

## Verification

Run:

```bash
python scripts/verify_nip59_static_bundle.py
python scripts/verify_nip59_generated_bundle.py
python scripts/verify_nip59_builder_safety.py
bash scripts/release_gate_smoke_check.sh
pytest -q tests/unit/test_nip59_live_static_bundle_rollout_no_send_contract.py
```
