# NIP-59 nostr-tools Candidate Evidence

## Decision

This records observed public npm metadata for `nostr-tools`.

This does not select or pin the dependency for production crypto.

## Evidence source

Metadata was collected outside production on:

- host: `hodls-MacBook.local`
- command: `npm view nostr-tools ... --json`
- node: `v26.0.0`
- npm: `11.12.1`

Production still must not run `npm install`.

## Observed package metadata

- package: `nostr-tools`
- observed version: `2.23.5`
- license: `Unlicense`
- repository: `git+https://github.com/nbd-wtf/nostr-tools.git`
- homepage: `https://github.com/nbd-wtf/nostr-tools#readme`
- tarball: `https://registry.npmjs.org/nostr-tools/-/nostr-tools-2.23.5.tgz`
- integrity: `sha512-Fa7ZlUdjfUW1P4E7H3yBexhOHYi18XNyvd2n7eNHkYR085xADX6Y8V8Vm7nT/XQajaFOBrptXmVIGkJ2E4vfVw==`

## Observed direct dependencies

- `@noble/ciphers`: `2.1.1`
- `@noble/curves`: `2.0.1`
- `@noble/hashes`: `2.0.1`
- `@scure/base`: `2.0.0`
- `@scure/bip32`: `2.0.1`
- `@scure/bip39`: `2.0.1`
- `nostr-wasm`: `0.1.0`

## Not yet approved

This candidate is not yet approved for production browser crypto.

Still required:

- committed lockfile generated outside production
- transitive dependency review
- secp256k1/Schnorr implementation review
- SHA-256/event-hash implementation review
- NIP-44 implementation review
- NIP-59 assumptions review
- `nostr-wasm` role review
- license/advisory review

## Safety invariant

Until a later reviewed builder PR lands:

- root `package.json` remains zero-dependency
- no `package-lock.json`
- no `node_modules`
- no generated crypto bundle
- `cryptoReady` remains false
- `canFinalizeGiftWrap` remains false
- `canPostEnvelope` remains false
- send remains disabled
- production intake remains disabled
- relay publishing remains disabled
