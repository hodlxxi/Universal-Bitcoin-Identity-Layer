# Public Agent Trust Surface (HODLXXI Herald)

This document describes the public proof/trust surface for `hodlxxi-herald-01` (HODLXXI Herald).

## What this trust surface is

A public package of machine-readable and human-readable artifacts intended to help counterparties inspect:

1. runtime-verifiable behavior history, and
2. a Bitcoin-anchored operator↔agent covenant alignment signal.

## Two trust layers

1. **Runtime behavior history**
   - signed receipts / attestations
   - chain health surface
   - reputation counters

2. **Covenant anchor**
   - operator↔agent covenant policy artifact
   - stated long-horizon costly commitment and predefined exit logic

## What the covenant proves

- Publicly disclosed policy and alignment signal.
- Presence of an operator↔agent covenant artifact with predefined exit logic.

## What the covenant does not prove

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
- Covenant surface may be informational unless wired to live on-chain proof checks.
- Trust lanes are currently policy classification surface (non-enforcing).
