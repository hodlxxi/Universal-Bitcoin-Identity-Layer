# HODLXXI Agent Protocol

## Overview

HODLXXI Agent UBID is a Bitcoin-native, Lightning-paid agent service that accepts structured job requests, returns signed results, and records job receipts into an append-only attestation chain.

The protocol is designed around five ideas:

1. payment before execution
2. deterministic job interfaces
3. signed machine-verifiable receipts
4. public reputation surfaces
5. append-only attestation history

This makes the agent legible not only to humans, but to other agents.

The protocol treats trust as a verification problem. In HODLXXI terms, an agent identity is modeled as `public_key + operator_binding + observable_behavior`, with `time_locked_capital` reserved as an optional trust anchor only when the runtime exposes concrete proof. Today, this repository verifies the key, published operator metadata, paid execution path, signed receipts, and observable history surfaces; it does not claim verified on-chain backing or verified time-locked capital on the agent runtime by default.

---

## Identity

- **Service name:** HODLXXI Agent UBID
- **Operator:** HODLXXI
- **Network:** Bitcoin
- **Signature scheme:** secp256k1
- **Agent pubkey:** `02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92`

The public key is the stable identity anchor of the agent. All receipts and attestations are meant to be attributable to this key. The operator field binds human-readable service metadata to that key at the discovery layer, but counterparties should treat that operator binding as declared metadata unless an external proof surface is also provided.

---

## Endpoints

- `GET /agent/capabilities`
- `GET /agent/capabilities/schema`
- `POST /agent/request`
- `GET /agent/jobs/<job_id>`
- `GET /agent/verify/<job_id>`
- `GET /agent/attestations`
- `GET /agent/reputation`
- `GET /agent/chain/health`
- `GET /agent/marketplace/listing`
- `GET /agent/skills`
- `GET /.well-known/agent.json`

---

## Capability Discovery

A client starts by fetching:

`GET /agent/capabilities`

This returns:

- agent identity metadata
- capability schema reference
- supported job types
- pricing
- limits
- skill discovery summary
- settlement-check support
- service endpoints

This is the canonical handshake surface for agent-to-agent integration.

---

## Job Flow

### 1. Discover capabilities

The client reads `/agent/capabilities` to learn:

- what jobs are supported
- what inputs are required
- what each job costs
- how to verify outputs

### 2. Submit request

The client submits a job to:

`POST /agent/request`

The request should specify:

- `job_type`
- `payload` matching the input schema for that job

The server responds with a job record. If payment is required, the job may enter an invoice-pending state until settlement is detected.

### 3. Pay over Lightning

The protocol assumes Lightning settlement before final execution for paid jobs.

The service supports payment settlement checks and can transition a job from pending to done once payment is confirmed.

### 4. Read job result

The client fetches:

`GET /agent/jobs/<job_id>`

This returns the current state and, once complete, the job result.

### 5. Verify receipt

The client fetches:

`GET /agent/verify/<job_id>`

This endpoint is intended to help a verifier confirm that the returned result and associated receipt were signed by the agent identity.

### 6. Inspect attestation history

The client fetches:

`GET /agent/attestations`

This exposes the public chain of job receipts.

---

## Supported Job Types

### `ping`

Purpose: minimal liveness and round-trip test.

**Input**
~~json
{
  "payload": {}
}
~~

**Output**
~~json
{
  "echo": {},
  "job_type": "ping",
  "ok": true
}
~~

**Price:** 21 sats

---

### `verify_signature`

Purpose: verify whether a secp256k1 signature matches a message and pubkey.

**Input**
~~json
{
  "message": "string",
  "pubkey": "compressed secp256k1 hex",
  "signature": "hex"
}
~~

**Output**
~~json
{
  "job_type": "verify_signature",
  "ok": true,
  "valid": true
}
~~

**Price:** 21 sats

---

### `covenant_decode`

Purpose: decode covenant-related script hex and report whether CLTV logic is present.

**Input**
~~json
{
  "script_hex": "hex"
}
~~

**Output**
~~json
{
  "decoded": "string",
  "has_cltv": true,
  "job_type": "covenant_decode",
  "ok": true
}
~~

**Price:** 21 sats

---

## Attestation Model

Each completed job may produce an attestation event containing hashes and a signature. Observed event fields include:

- `event_type`
- `job_id`
- `payment_hash`
- `request_hash`
- `result_hash`
- `prev_event_hash`
- `timestamp`
- `signature`
- `agent_pubkey`

This creates a linked receipt chain rather than isolated, context-free results.

The presence of `prev_event_hash` allows independent observers to detect continuity, breaks, and ordering.

---

## Reputation Surface

`GET /agent/reputation` exposes aggregate service history, including:

- total jobs
- completed jobs
- attestation count
- per-job-type usage

This gives counterparties a quick summary of actual usage and completion history without requiring them to replay every attestation.

---

## Chain Health Surface

`GET /agent/chain/health` exposes whether the attestation chain is internally consistent.

Example health dimensions:

- whether the chain is currently valid
- number of events observed
- latest event hash
- latest previous event hash

This allows fast monitoring of the integrity of the agent’s public receipt history.

---

## Marketplace Surface

`GET /agent/marketplace/listing` provides a compact discovery view for agent registries, aggregators, or directories.

This endpoint is intended for discovery, not deep verification. Serious counterparties should still inspect:

- `/agent/capabilities`
- `/agent/reputation`
- `/agent/attestations`
- `/agent/chain/health`

---

## Skills Surface

`GET /agent/skills` exposes the agent's installable public skills in a normalized machine-readable list.

Each item is meant to identify a skill without duplicating the whole skill body. Typical fields include:

- `skill_id`
- `version`
- `description`
- repo file references
- install metadata such as a raw `SKILL.md` URL

This allows agent registries and clients to discover reusable integration knowledge alongside job capabilities.

---

## Well-Known Agent Document

`GET /.well-known/agent.json` publishes a compact identity and discovery document that ties together:

- the agent pubkey
- discovery links
- capability schema reference
- supported jobs
- trust model summary
- skill summary

This is the broadest discovery entrypoint; deeper protocol details still live under `/agent/*`. The `trust_model` block should be read as a compact summary of the runtime's current verification surfaces and boundaries, not as a claim that every possible trust anchor is already proven.

---

## Design Goal

The protocol is not just for “API calls.”

It is for durable agent identity.

A normal web service proves only that it answered.
A HODLXXI-style agent should prove:

- who answered
- what was paid
- what was requested
- what result was returned
- how that event fits into an ongoing public history

That is the core difference.

---

## Future Extensions

Natural next protocol extensions include:

- challenge-response endpoint for live identity proofs
- stronger receipt canonicalization rules
- external attester co-signatures
- payment proofs bound more tightly to result hashes
- optional long-horizon service commitments when the runtime exposes verifiable proof
- interoperable agent identity documents under `/.well-known/`

---

## Summary

HODLXXI Agent Protocol is a Lightning-paid, receipt-signed, attestation-linked protocol for agents that need to be machine-usable, cryptographically accountable, and discoverable through conservative trust metadata.
