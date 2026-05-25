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

Stage 7C.1 adds a local-only review command that marks queue items as approved or rejected by an operator.

Run local review:

    python tools/herald_outreach_review.py --queue /tmp/herald-outreach-queue.json --output /tmp/herald-outreach-reviewed.json --approve heraldq_... --reviewer operator --reason "good fit"

This remains local-only and proposal-only. Approval metadata is written to a local JSON file, and no action is executed.

## Stage 7C.2 export manual-send package

After local review, export approved items to a manual operator package:

    python tools/herald_outreach_export.py --reviewed-queue /tmp/herald-reviewed.json --json-output /tmp/herald-send-package.json --markdown-output /tmp/herald-send-package.md

This export stage is manual-send packaging only. It does not execute any action, does not send zaps, and does not execute payments.


## Stage 7C.3 live relay queue rate limits and safety caps

Stage 7C.3 adds explicit live read-only queue controls while keeping manual approval/export safety.

Recommended safe live read-only command:

    HERALD_DISCOVERY_STATE_FILE=/tmp/herald-live-state.json python tools/herald_discovery_scan.py --live-relay-readonly --relay wss://relay.damus.io --limit 25 --timeout 5 --min-score 3.0 --dedupe-authors --cooldown-state /tmp/herald-cooldown.json --cooldown-hours 24 --write-outreach-queue /tmp/herald-live-queue.json --max-queue-items 5 | jq .

Notes:

- read-only relay discovery only; no execution path exists.
- queue output still contains pending_operator_approval items with action_taken set to none.
- cooldown state is local JSON only and suppresses recently queued author/event pairs for cooldown-hours.
- dedupe mode keeps only the highest-scoring candidate per author for a scan run.

Non-goals remain explicit:

- no zaps
- no outbound payments
- no relay publish
- no signing
- no direct messages


## Stage 7C.4 manual outreach receipt recorder

Stage 7C.4 adds a local-only receipt command so an operator can record the manual outcome for one exported queue item after handling it outside software.

Example:

    python tools/herald_outreach_receipt.py --package /tmp/herald-send-package.json --output /tmp/herald-receipt.json --queue-id heraldq_... --completed --operator operator --note "manual Nostr reply sent" --external-reference "nostr-event-id-or-url"

This command only records operator-provided outcome metadata in local JSON. It does not verify, fetch, send, pay, sign, or publish anything.
