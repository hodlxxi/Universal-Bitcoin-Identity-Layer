# NIP-17 Messaging Stack Staging Runbook

## Current state

HODLXXI has an additive NIP-17/NIP-59 messaging stack behind a disabled-by-default feature flag.

Implemented surfaces:

- /.well-known/nostr-dm-policy.json
- /agent/capabilities metadata under messaging.nip17
- /.well-known/agent.json metadata under messaging.nip17
- POST /api/messages/nip17/envelopes

The intake API accepts only NIP-59 gift-wrap kind 1059 envelopes when explicitly enabled.

## Target state

On staging only:

- apply migrations/2026-05-28_nip17_envelopes.sql
- deploy feature/nip17-messaging-stack
- verify NIP17_MESSAGES_ENABLED=false returns 404 for intake
- enable NIP17_MESSAGES_ENABLED=true only on staging
- verify valid kind 1059 stores as opaque ciphertext
- verify plaintext kind 14 is rejected
- keep production disabled until staging is verified

## Security invariants

HODLXXI must never require custody of user private keys.

The NIP-17 server path must not:

- decrypt message content
- accept plaintext kind 14 or kind 15 as server transport
- store plaintext DM bodies
- echo ciphertext or plaintext bodies in API responses
- publish to relays without a separate explicit rollout
- mutate browser chat, Socket.IO, or legacy /app behavior

The only accepted intake transport format is relay-visible NIP-59 gift-wrap kind 1059.

## Files

Code:

- app/services/nostr_dm.py
- app/services/nip17_storage.py
- app/blueprints/nip17_messages.py
- app/models.py
- app/factory.py

Migration:

- migrations/2026-05-28_nip17_envelopes.sql

Tests:

- tests/unit/test_nip17_envelope_contract.py
- tests/unit/test_nip17_message_api_contract.py
- tests/unit/test_nip17_storage_contract.py
- tests/unit/test_nip17_capability_surfaces.py
- tests/unit/test_nip17_runtime_contract.py

## Local preflight

Run Black against NIP-17 files and run these tests:

- pytest -q tests/unit/test_nip17_storage_contract.py
- pytest -q tests/unit/test_nip17_message_api_contract.py
- pytest -q tests/unit/test_nip17_envelope_contract.py
- pytest -q tests/unit/test_nip17_capability_surfaces.py
- pytest -q tests/unit/test_nip17_runtime_contract.py
- pytest -q tests/unit/test_release_gate_route_contract.py

Expected:

- Black green
- 5 passed storage
- 6 passed message API
- 7 passed envelope validation
- 3 passed capability surfaces
- 5 passed runtime contract
- 5 passed release gate

## Staging rollout

Use /srv/ubid-staging.

Steps:

1. Snapshot git state.
2. Pull feature/nip17-messaging-stack.
3. Verify no local dirty files.
4. Verify database target without printing secrets.
5. Apply migrations/2026-05-28_nip17_envelopes.sql.
6. Restart ubid-staging.
7. Smoke critical routes.
8. Keep NIP17_MESSAGES_ENABLED=false by default.
9. Enable NIP17_MESSAGES_ENABLED=true only after disabled-path smoke passes.

## Staging smoke: disabled

With NIP17_MESSAGES_ENABLED=false or unset:

- GET /.well-known/nostr-dm-policy.json should return JSON.
- GET /agent/capabilities should include messaging.nip17.
- POST /api/messages/nip17/envelopes should return 404 not_found.

## Staging smoke: enabled

With NIP17_MESSAGES_ENABLED=true on staging only:

- POST a synthetic kind 1059 gift-wrap envelope.
- Expect HTTP 202.
- Expect stored true.
- Expect published false.
- Expect plaintext_seen false.
- Response must not include the synthetic ciphertext content.

Then POST a synthetic kind 14 plaintext event.

- Expect HTTP 400.
- Expect invalid_nip59_gift_wrap.
- Expect kind_must_be_1059.
- Response must not include the plaintext content.

## DB verification

Verify recent rows without selecting envelope_json during normal smoke.

Required visible fields:

- event_id
- kind
- source
- status
- receiver_pubkey
- received_at

Expected:

- kind = 1059
- source = api
- status = received

## Rollback

First rollback is feature-flag rollback:

- set NIP17_MESSAGES_ENABLED=false
- restart ubid-staging
- verify intake returns 404

Code rollback:

- git switch main
- git pull --ff-only origin main
- restart ubid-staging

Database rollback is normally not required if the feature flag is off.

If table removal is explicitly required:

- take a DB backup first
- only then run DROP TABLE IF EXISTS nip17_envelopes

Do not drop the table on production without explicit backup and operator approval.

## Production rollout gate

Production rollout is allowed only after staging proves:

- migration applies cleanly
- feature flag disabled route returns 404
- enabled staging route accepts kind 1059
- enabled staging route rejects kind 14
- API responses do not echo ciphertext or plaintext
- /health/ready, /login, /app, /docs, /oidc, /.well-known/*, /agent/*, and /api/public/status remain healthy
