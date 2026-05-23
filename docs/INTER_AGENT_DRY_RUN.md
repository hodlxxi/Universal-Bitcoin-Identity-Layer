# HODLXXI Inter-Agent Dry Run

This document defines a local dry-run profile for the existing inter-agent demo harness.

## Status

This is a development harness only.

It does not contact Agent B, does not call `/agent/message`, does not create invoices, does not pay invoices, and does not write registry state.

## Goal

Prove that Agent A can build and sign a job-proposal envelope and verify its own signature before any network, payment, registry, or relay behavior is added.

## Command

```bash
python tools/inter_agent_demo.py \
  --dry-run \
  --agent-a-privkey "$AGENT_A_PRIVKEY_HEX" \
  --agent-b-pubkey "$AGENT_B_PUBKEY_HEX" \
  --message "dry-run ping"
```

## Expected output

- Agent A signed request envelope
- dry-run transcript
- `OK: dry-run request envelope signature verified locally`

## Transcript example

See `examples/agents/inter_agent_dry_run_transcript.json`.

## Non-goals

- no HTTP POST
- no Agent B execution
- no Lightning invoice
- no outbound payment
- no auto-spending
- no registry write
- no relay publishing
