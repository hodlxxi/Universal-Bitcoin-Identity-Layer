# NIP-59 Pre-Build Readiness Checkpoint

## Decision

The NIP-59 browser-client work has completed the pre-build safety ladder.

This checkpoint does not approve browser crypto, npm installation, lockfile generation, bundle replacement, send, intake, or relay publishing.

## Current protected state

- `nostr-tools@2.23.5` is observed as a candidate only.
- The candidate is not approved for production crypto.
- Exact version selection is not complete.
- Production npm is not required.
- Production install is not allowed.
- Root package mutation is not allowed.
- Static bundle remains skeleton-only.
- NIP-17 intake remains disabled.
- Send remains disabled.

## Existing guardrails

The current release helper runs:

    bash scripts/release_gate_smoke_check.sh

The NIP-59 release gate runs:

    python scripts/verify_nip59_release_gate.py

That release gate runs:

- `python scripts/verify_nip59_builder_safety.py`
- `python scripts/verify_nip59_import_policy.py`
- `python scripts/verify_nip59_static_bundle.py`

## Forbidden before next approval

Do not:

- run `npm install` on production
- commit `node_modules`
- commit `package-lock.json` before a reviewed non-production build experiment
- import `@nostr/tools/wasm`
- import `nostr-wasm`
- use `WebAssembly`
- set `cryptoReady` to true
- enable send
- POST to `/api/messages/nip17/envelopes`
- enable production intake
- enable relay publishing

## Next allowed phase

The next phase may be a controlled build experiment outside production.

That future phase must still prove:

1. The exact package version is reviewed.
2. Any lockfile is generated outside production.
3. The generated bundle excludes wasm, private-key, send, and network-post terms.
4. The NIP-59 release gate passes before commit.
5. Production remains npm-free unless a later explicit production decision changes that.
