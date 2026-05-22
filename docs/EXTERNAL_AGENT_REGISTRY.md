# HODLXXI External Agent Registry

This document defines a future registry profile for external agents that HODLXXI may discover, inspect, score, or call.

## Status

This is a documentation, schema, and examples profile only.

It does not implement registry storage, relay watching, ingestion workers, outbound payments, auto-trust, or agent-to-agent spending.

## Goal

Before HODLXXI pays or routes work to other agents, it needs a conservative record format for remembering who an external agent claims to be and what can be verified.

## Registry record

A registry record should capture:

- external agent public key
- discovery URLs
- capability URLs
- trust/reputation URLs
- payment hints
- verification state
- source of discovery
- operator policy status

See `examples/agents/external_agent_record.json`.

## Capability claim

A capability claim describes what an external agent says it can do.

Claims are not trusted until verified by HODLXXI through signatures, receipts, observed behavior, or operator review.

See `examples/agents/external_agent_capability_claim.json`.

## Security rules

- Do not auto-trust discovered agents.
- Do not auto-pay discovered agents.
- Do not treat relay announcements as proof.
- Do not store private keys, wallet secrets, macaroons, seeds, or mnemonics.
- Do not give external agents shell, env, wallet, or database access.
- Require explicit operator policy before any outbound payment path.

## Future implementation phases

1. Manual registry records.
2. Signed discovery document verification.
3. Nostr relay watcher for announcements.
4. Capability verification and freshness checks.
5. Policy-gated outbound paid calls.
