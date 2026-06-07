# NIP-59 Controlled Build Evidence

## Result

The P42 controlled build experiment was executed outside production on the MacBook.

The experiment installed `nostr-tools@2.23.5` in a temporary Mac workspace only.

No production npm install, production lockfile, production `node_modules`, bundle replacement, send, intake, or relay publishing was performed.

## Evidence summary

- Host: `hodls-MacBook.local`
- Path: `/Users/xxi/workspace/hodlxxi-nip59-build-experiment-p42`
- Node: `v26.0.0`
- npm: `11.12.1`
- Package: `nostr-tools@2.23.5`
- Lockfile generated outside production only.
- `node_modules` generated outside production only.

## Safe import check

Normal import path `nostr-tools` exposed:

- `finalizeEvent`
- `verifyEvent`
- `generateSecretKey`
- `getPublicKey`
- `nip44`

## Local crypto probe

The local probe created a throwaway key, signed a local event, and verified it.

Observed:

- `eventVerified=true`
- `networkPost=false`
- `relayPublishing=false`
- `plaintextPost=false`

## Wasm risk observed

The dependency tree includes `nostr-wasm@0.1.0`.

The package exports include a `./wasm` path.

The grep evidence shows `nostr-wasm`, `@nostr/tools/wasm`, `setNostrWasm`, `initNostrWasm`, `NostrWasm`, and `WebAssembly` references in package docs/types/wasm files.

Decision: HODLXXI browser source must not import `@nostr/tools/wasm` or `nostr-wasm`.

## Boundary

This evidence does not approve:

- committing `package-lock.json`
- committing `node_modules`
- replacing the static bundle
- setting `cryptoReady=true`
- enabling send
- enabling production intake
- enabling relay publishing

## Next implementation step

Prepare a minimal reviewed NIP-59 source module that imports from normal `nostr-tools` paths only and still performs no network POST.
