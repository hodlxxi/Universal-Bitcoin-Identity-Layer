# NIP-59 Dependency Provenance Checklist

## Purpose

This checklist defines what must be reviewed before selecting an exact `nostr-tools` version for future browser-side NIP-59 finalization.

This document does not select a version, install npm dependencies, generate a lockfile, replace the bundle, enable crypto, enable send, or enable relay publishing.

## Current state

The current production-safe state remains:

- root `package.json` has zero dependencies
- no lockfile is committed
- production does not require npm
- static bundle remains skeleton-only
- `cryptoReady` remains false
- `canFinalizeGiftWrap` remains false
- `canPostEnvelope` remains false
- `Send sealed envelope` remains disabled

## Required review before exact version selection

Before any future PR pins `nostr-tools`, document:

- exact package name
- exact package version
- package license
- upstream repository URL
- npm package URL
- tarball integrity or lockfile integrity
- direct dependencies
- transitive cryptographic dependencies
- secp256k1/Schnorr implementation path
- SHA-256/event-hash implementation path
- NIP-44 implementation path, if used
- NIP-59 support assumptions
- bundle size impact
- known advisories or audit notes
- reason for selecting this version

## Required implementation gates after version selection

A later builder PR must prove:

- dependency version is exact, not a range
- lockfile is committed
- bundle is built locally from reviewed source
- security-critical crypto is not loaded from CDN
- production runtime does not run `npm install`
- production root package remains zero-dependency unless explicitly changed by a reviewed runtime dependency PR
- send remains disabled until finalized gift-wrap validation passes

## Prohibited in this PR

Do not add:

- exact dependency version
- `package-lock.json`
- `node_modules`
- generated crypto bundle
- `cryptoReady: true`
- send enablement
- POST to `/api/messages/nip17/envelopes`
- relay publishing
