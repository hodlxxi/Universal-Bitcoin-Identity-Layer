# NIP-59 No-Send Operator Checklist

## Purpose

This checklist verifies the current NIP-59 browser/UI state without enabling NIP-17/NIP-59 sending, POST intake, or relay publishing.

The expected state is: bundle visible, UI visible, sending disabled.

## Manual browser check

1. Open `https://hodlxxi.com/login?next=/app`.
2. Log in with the normal operator/browser flow.
3. Confirm `/app` opens.
4. Find the hybrid messaging status panel.
5. Confirm the page shows:

- `NIP-59 bundle`
- `NIP-59 send: disabled`
- `NIP-59 POST: disabled`
- `NIP-59 relay: disabled`

## Expected runtime policy

The public NIP-17/NIP-59 policy must remain disabled:

- `enabled=false`
- `intake_enabled=false`
- `relay_publishing=false`

## Command checks

Run from production:

`python scripts/smoke_nip59_browser_global_no_send.py --source https://hodlxxi.com/static/js/nip59_client_bundle.js`

Policy check:

`curl -sS https://hodlxxi.com/.well-known/nostr-dm-policy.json | python -m json.tool | grep -E '"enabled"|"intake_enabled"|"relay_publishing"'`

Rendered app smoke:

`pytest -q tests/unit/test_nip59_app_rendered_no_send_smoke_contract.py`

## Unsafe findings

Stop the rollout if any of these appear:

- `sendEnabled=true`
- `canPostEnvelope=true`
- `relayPublishing=true`
- `/api/messages/nip17/envelopes` appears in rendered `/app` HTML
- relay publishing helpers appear in rendered `/app` HTML
- `node_modules` or lockfiles are created on production

## Current boundary

This phase proves visibility and operator observability only. It does not send NIP-59 gift-wraps, persist encrypted inbox messages from the browser, or publish to Nostr relays.
