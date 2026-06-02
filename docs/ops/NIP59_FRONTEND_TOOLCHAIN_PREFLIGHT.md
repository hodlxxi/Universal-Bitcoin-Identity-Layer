# NIP-59 Frontend Toolchain Preflight

## Current server state

The production server currently has Node.js available, but npm/npx may not be installed.

The repository currently has no frontend package manifest or lockfile:

- no `package.json`
- no `package-lock.json`
- no `pnpm-lock.yaml`
- no `yarn.lock`

## Decision

Do not install npm or mutate the frontend dependency toolchain directly on the production runtime host as part of NIP-59 work.

The NIP-59 browser finalization bundle must be produced in a controlled development, CI, or dedicated builder environment, then reviewed and committed or deployed as a reproducible static artifact.

## Why

NIP-59 finalization is security-critical. It requires:

- ephemeral wrapper key generation
- Nostr event serialization
- SHA-256 event id calculation
- Schnorr signing
- hex/byte conversion
- finalized kind-1059 validation before POST

These must use pinned, reviewed dependencies and a reproducible build path.

## Required before adding real browser crypto

Before any browser crypto bundle is trusted, the repo must have:

- `package.json`
- committed lockfile
- pinned dependency versions
- documented build command
- generated local static bundle under app-owned static assets
- tests proving the app serves the local bundle
- tests proving no CDN is used for security-critical crypto
- tests proving `Send sealed envelope` remains disabled until final validation passes

## Production safety invariant

Until the dependency pipeline exists and local finalization is implemented:

- production `NIP17_MESSAGES_ENABLED` remains absent or false
- relay publishing remains disabled
- `Send sealed envelope` remains disabled
- plaintext is never sent to the server
- no production npm install is required
- no production build step is required

## Next implementation step

The next implementation PR may introduce a minimal frontend package skeleton in a non-production builder context.

That future PR must still avoid:

- enabling send
- enabling production intake
- relay publishing
- plaintext POST
- server key custody
