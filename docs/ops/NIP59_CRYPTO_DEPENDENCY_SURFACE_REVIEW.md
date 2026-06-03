# NIP-59 Crypto Dependency Surface Review

## Decision

This records the observed direct dependency surface for `nostr-tools@2.23.5`.

This does not approve the candidate for production browser crypto.

## Observed dependency surface

The candidate dependency surface was collected outside production on `hodls-MacBook.local` using `npm view`.

Observed direct dependencies:

- `@noble/ciphers@2.1.1`
- `@noble/curves@2.0.1`
- `@noble/hashes@2.0.1`
- `@scure/base@2.0.0`
- `@scure/bip32@2.0.1`
- `@scure/bip39@2.0.1`
- `nostr-wasm@0.1.0`

## Initial review

The Noble and Scure packages expose repository and homepage metadata in npm output and remain pending lockfile/provenance review.

`nostr-wasm@0.1.0` is a blocker before lockfile/build work because the observed npm metadata has:

- no repository URL
- no homepage URL
- short description: `nostr stuff in wasm`
- unknown role in the final browser bundle

## Safety invariant

Until a later reviewed builder PR lands:

- `nostr-tools` remains candidate-only
- no exact version is approved for production crypto
- no `package-lock.json` is committed
- no `node_modules` is committed
- production does not run `npm install`
- root `package.json` remains zero-dependency
- static bundle remains skeleton-only
- `cryptoReady` remains false
- `canFinalizeGiftWrap` remains false
- `canPostEnvelope` remains false
- send remains disabled
- production intake remains disabled
- relay publishing remains disabled

## Required before next build step

Before any lockfile/build PR:

1. Decide whether `nostr-wasm` is needed for browser-side NIP-59 finalization.
2. Review `nostr-wasm` source/provenance outside production.
3. Document whether the final bundle can avoid `nostr-wasm`.
4. Only then generate a lockfile in a non-production builder environment.
