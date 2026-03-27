# Public Agent Trust Surface (HODLXXI Herald)

This document describes the public trust surface for `hodlxxi-herald-01` (HODLXXI Herald).

## What this trust surface is

A public package of machine-readable and human-readable artifacts intended to help counterparties inspect:

1. runtime-verifiable behavior history, and
2. a declared operator↔agent covenant alignment structure.

## Current declared covenant state

- real operator pubkey is disclosed
- real agent pubkey is disclosed
- real declared SegWit address is disclosed
- real descriptor/policy string is disclosed
- funding is **not** yet attached in this public surface (`unfunded_declared`)
- therefore this covenant is currently a declared proof/policy surface, not a funded on-chain capital proof

## What the covenant proves

- Declared long-horizon operator↔agent alignment structure.
- Public disclosure of operator/agent keys, declared address, and script policy.

## What the covenant does not prove

- It does **not** prove funded on-chain capital in this current surface.
- It does **not** prove uptime.
- It does **not** prove execution quality.
- It does **not** prove full autonomy.

## Routes

- `/agent/trust/<agent_id>`
- `/agent/binding/<agent_id>`
- `/agent/trust-summary/<agent_id>.json`
- `/agent/covenants/<covenant_id>.json`
- `/reports/<report_id>.json`
- `/reports/<report_id>`
- `/verify/report/<report_id>`
- `/verify/nostr/<event_id>`

## Verifying report hash

1. Fetch report JSON from `/reports/<report_id>.json`.
2. Remove the `report_sha256` field.
3. Canonicalize JSON using sorted keys and compact separators.
4. Compute SHA-256 of canonical JSON bytes.
5. Compare to `report_sha256`.

## Current limitations

- Nostr live relay verification is currently partial/placeholder.
- Covenant funding attachment and on-chain proof checks are not implemented in this surface yet.
- Trust lanes are currently policy classification surface (non-enforcing).
