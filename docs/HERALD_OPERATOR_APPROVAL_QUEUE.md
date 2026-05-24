# Herald Operator Approval Queue

This document defines Stage 7C for Herald outreach.

## Purpose

Herald may convert dry-run candidate assessments into a local JSON approval queue.

This stage is proposal-only. It does not send zaps, publish Nostr events, send direct messages, sign events, or execute payments.

## Command

Run:

    FRESH_STATE=/tmp/herald-queue-demo-state.json
    QUEUE=/tmp/herald-outreach-queue.json
    HERALD_DISCOVERY_STATE_FILE="$FRESH_STATE" python tools/herald_discovery_scan.py --fixture examples/herald/herald_fixture_events.json --write-outreach-queue "$QUEUE" --max-queue-items 10 | jq .

Review the queue:

    cat /tmp/herald-outreach-queue.json | jq .

## Queue semantics

Each queue item is local JSON with:

- status: pending_operator_approval
- approval_required: true
- action_taken: none
- candidate event metadata
- suggested amount and comment
- safety non-goals

## Non-goals

Stage 7C does not:

- execute zaps
- execute outbound payments
- use NWC
- use NIP-47
- call LND
- publish events to relays
- sign Nostr events
- send direct messages
- use wallet material
- run as a daemon

## Manual review flow

The operator reviews the JSON queue manually and decides whether any later stage should create an approved action.

A future Stage 7C.1 may add an approval command. This stage only writes proposals.
