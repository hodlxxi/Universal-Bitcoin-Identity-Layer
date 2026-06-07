# NIP-59 Controlled Build Experiment Runbook

## Decision

The next NIP-59 phase is a controlled build experiment outside production.

This runbook does not approve production npm, lockfile commit, bundle replacement, browser crypto, send, intake, or relay publishing.

## Allowed host

Use a non-production builder host only, such as:

- MacBook
- temporary non-production build workspace

Do not run this experiment inside:

- production `/srv/ubid`
- staging `/srv/ubid-staging`

## Allowed evidence to capture

- package metadata
- dependency tree
- lockfile generated outside production
- bundle inspection output
- NIP-59 release gate output

## Not allowed in this phase

Do not commit:

- `package-lock.json`
- `node_modules`
- generated browser bundle
- `cryptoReady: true`
- send-enabled client code

Do not enable:

- POST to `/api/messages/nip17/envelopes`
- production intake
- relay publishing

## Required pollution checks

Before and after the experiment, confirm the repository has no:

- `node_modules`
- `package-lock.json`
- `pnpm-lock.yaml`
- `yarn.lock`

The root `package.json` must remain zero-dependency.

## Required gates before any future commit

Run:

    bash scripts/release_gate_smoke_check.sh

And:

    python scripts/verify_nip59_release_gate.py

## Boundary

This PR only documents the experiment plan.

The actual build experiment must be executed later outside production, and its evidence must be reviewed before any lockfile or bundle is committed.
