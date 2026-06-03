# NIP-59 nostr-wasm Import Path Review

## Decision

This records evidence about how `nostr-tools@2.23.5` reaches `nostr-wasm@0.1.0`.

This does not approve `nostr-tools` for production browser crypto.

## Evidence source

The package was inspected outside production on `hodls-MacBook.local`.

The diagnostic installed `nostr-tools@2.23.5` in a temporary Mac evidence directory only.

## Observed facts

`nostr-tools@2.23.5` installs `nostr-wasm@0.1.0`.

The observed references show `nostr-wasm` is tied to the explicit wasm path:

- README examples import from `@nostr/tools/wasm`
- README examples import `initNostrWasm` from `nostr-wasm`
- package exports include a separate `./wasm` export
- `lib/esm/wasm.js` imports `nostr-wasm`

## Interpretation

The likely safe browser-bundle path is:

- do not import `@nostr/tools/wasm`
- do not import `nostr-wasm`
- use only the non-wasm `nostr-tools` path if later approved

This is not yet proven by a bundler artifact.

## Safety invariant

Until a later reviewed builder PR proves the bundle contents:

- `nostr-tools` remains candidate-only
- `nostr-wasm` remains excluded from approved crypto path
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

## Required before build/lockfile approval

Before a lockfile/build PR can move forward:

1. Add a builder import contract forbidding `@nostr/tools/wasm`.
2. Add a bundle inspection test proving `nostr-wasm` is absent.
3. Add a bundle inspection test proving WebAssembly payload from `nostr-wasm` is absent.
4. Keep send disabled until finalized gift-wrap validation is independently tested.
