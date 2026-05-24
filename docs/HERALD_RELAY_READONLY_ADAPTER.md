# Herald Relay Read-Only Adapter (Stage 7B)

This document describes the **Stage 7B** Herald relay adapter used for public discovery only.

## Purpose

The adapter enables Herald discovery to read **public Nostr kind-1 notes** from configured relays and feed them into the existing Herald scoring engine.

It is intentionally conservative and read-only.

## Command

```bash
python tools/herald_discovery_scan.py --live-relay-readonly | jq .
```

The CLI output includes:

- `source_mode: "live_relay_readonly"`
- `zap_mode: "dry_run"` (unless manually changed elsewhere)
- candidate scoring output in the same JSON shape used by default and fixture modes

## Explicit safety boundaries

This adapter does **not**:

- execute zaps
- perform outbound spending
- read or use private keys
- publish events to relays
- send DMs

## Timeout and limit behavior

- The live read-only mode enforces small bounded reads.
- Current defaults are:
  - event limit: `100`
  - total socket receive timeout per relay read: `8s`
- Relay/network failures fail closed (empty results + warnings), keeping CLI behavior stable.

## Stage placement

This is **Stage 7B** discovery plumbing before any operator-approved outreach or payment-capable automation.
