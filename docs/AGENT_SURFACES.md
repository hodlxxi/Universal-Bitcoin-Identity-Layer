# HODLXXI Agent Surfaces

This document describes the machine-readable discovery surface for HODLXXI Agent UBID. The goal is to expose verifiable runtime metadata without overstating trust anchors that are not currently proven by the live surface.

## Discovery entrypoints

- `GET /.well-known/agent.json` — canonical identity and discovery document
- `GET /agent/capabilities` — signed capabilities payload
- `GET /agent/capabilities/schema` — JSON Schema for the capabilities payload
- `GET /agent/skills` — first-class skill listing
- `GET /agent/marketplace/listing` — normalized marketplace/discovery record
- `GET /agent/reputation` — aggregate operating history
- `GET /agent/attestations` — append-only signed receipt history
- `GET /agent/chain/health` — continuity check for the attestation chain

## Capability schema

`/agent/capabilities` remains the signed handshake document. `/agent/capabilities/schema` now publishes the canonical JSON Schema for:

- identity metadata
- signed response fields
- supported endpoints
- pricing and limits
- job registry
- embedded skill summary

Clients that want strict validation should fetch the schema from the URI advertised in the capabilities payload itself.

Current high-signal paid jobs include `ping`, `verify_signature`, `covenant_decode`, and `covenant_visualize` (script/descriptor explain + diagram output with conservative `confidence`, `trust_score`, `pattern_match`, and `simplified_visualization` fields). `confidence` reflects interpretation quality, while `trust_score` reflects structural reliability/interpretability of the parsed covenant pattern.

## Skills

`/agent/skills` lists installable public skills discovered from `skills/public/`.

Each item includes:

- `skill_id`
- `name`
- `version`
- `description`
- `homepage`
- `tags`
- file paths for the checked-in skill assets
- install metadata, including the raw GitHub URL for `SKILL.md`

This keeps the repo’s checked-in skills and the runtime discovery surface aligned without maintaining a second manual catalog.

## Marketplace listing

`/agent/marketplace/listing` is the compact directory-facing surface.

It now normalizes:

- `listing_version`
- discovery links
- capability schema reference
- skills summary
- reputation snapshot
- chain health snapshot

The reputation snapshot now includes trust-aware aggregates when completed jobs provide those fields:

- `average_confidence`
- `average_trust_score`
- `pattern_distribution` (recognized `pattern_match.variant` counts)
- `trust_trend` (rolling trust-score average over recent completed trust-scored jobs)

Registries can use it as a lightweight listing document, while serious clients should still inspect `/agent/capabilities`, `/agent/reputation`, `/agent/attestations`, and `/agent/chain/health`.

## Trust linkage

The trust story spans three layers:

1. [`TRUST_MODEL.md`](../TRUST_MODEL.md) — normative trust language, design goals, and assurance boundaries
2. [`AGENT_PROTOCOL.md`](../AGENT_PROTOCOL.md) — protocol contract for discovery, paid execution, receipts, and verification
3. `/.well-known/agent.json` + `/agent/capabilities` — machine-readable runtime surfaces that summarize only what the current runtime exposes

The `trust_model` block in `/.well-known/agent.json` is the compact runtime summary. It distinguishes:

- verified runtime surfaces such as public-key identity and observable behavior
- declared metadata such as operator binding
- optional trust anchors such as time-locked capital, which remain design goals unless a concrete proof surface is published
