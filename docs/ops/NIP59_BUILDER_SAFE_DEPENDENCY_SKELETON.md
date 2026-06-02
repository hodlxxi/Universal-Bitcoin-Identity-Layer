# NIP-59 Builder-Safe Dependency Skeleton

## Decision

HODLXXI will introduce real NIP-59 browser dependencies only through a controlled builder workflow.

Do not install npm, mutate dependencies, or generate lockfiles on the production runtime host.

## Current production-safe state

The repo currently has:

- `package.json`
- zero runtime dependencies
- zero dev dependencies
- `scripts/build_nip59_client_bundle.mjs`
- `app/static/js/nip59_client_bundle.js`
- skeleton bundle only
- no real NIP-59 finalization
- no send enablement
- no POST to `/api/messages/nip17/envelopes`
- no relay publishing

## Future dependency candidate

The first dependency candidate remains:

- `nostr-tools`

Its maintained Noble/secp256k1/Schnorr dependency surface must be reviewed as part of the dependency decision.

## Builder-only future workflow

A future builder environment may run:

1. install pinned frontend dependencies
2. generate a committed lockfile
3. build a local static bundle
4. run contract tests
5. produce a reviewed artifact

The production runtime host must only receive reviewed source/static artifacts through git rollout.

## Required future files before real crypto

Before enabling real local NIP-59 finalization, a future PR must add:

- committed lockfile
- explicit pinned dependency versions
- documented build command
- dependency audit/provenance notes
- local static bundle generated from reviewed source
- tests proving no CDN crypto is used
- tests proving send remains disabled until final local validation passes

## Prohibited in production

Do not run on production:

- `npm install`
- `npm update`
- `npm audit fix`
- dependency lockfile generation
- ad-hoc bundle download from CDN
- unreviewed minified crypto replacement

## Safety invariant

Until a reviewed builder dependency workflow lands:

- `cryptoReady` remains false
- `canFinalizeGiftWrap` remains false
- `canPostEnvelope` remains false
- `Send sealed envelope` remains disabled
- production `NIP17_MESSAGES_ENABLED` remains absent or false
- relay publishing remains disabled
- plaintext is never sent to the server
