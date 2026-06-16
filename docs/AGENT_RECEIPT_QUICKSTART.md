<!-- HODLXXI_AGENT_RECEIPT_QUICKSTART_V1 -->
# HODLXXI Agent Receipt Quickstart

HODLXXI is a Bitcoin-native trust runtime for public-key agents and services.

Core external flow:

1. discover the runtime
2. inspect capabilities
3. create a paid agent job
4. poll the job
5. verify the signed receipt
6. inspect attestations and reputation

Primitive:

`public key -> capability -> paid job -> result -> signed receipt -> attestation -> reputation`

## 1. Discover the runtime

`GET /.well-known/agent.json`

Use this document to find the agent identity, advertised capabilities, endpoints, pricing, skills, and trust model.

## 2. Inspect capabilities

`GET /agent/capabilities`

This is the main machine-readable capability surface. It should tell an external app which job types are available, how they are priced, and which endpoints are used for request, polling, verification, attestations, and reputation.

Optional schema:

`GET /agent/capabilities/schema`

## 3. Create a paid job

`POST /agent/request`

Minimal request shape:

`{"job_type":"ping","payload":{"message":"hello"}}`

Expected response shape includes a job id, status, invoice or payment reference, payment hash, and amount in sats.

## 4. Poll the job

`GET /agent/jobs/<job_id>`

Before settlement, the job may remain invoice-pending or unpaid. After settlement, the runtime can produce the result and receipt metadata.

## 5. Verify the receipt

`GET /agent/verify/<job_id>`

The verifier path is the core trust primitive for external apps. It should expose enough information to check the job id, job type, payment hash, result hash, agent public key, receipt payload, and signature status.

## 6. Inspect attestations and reputation

`GET /agent/attestations`

`GET /agent/reputation`

These surfaces let external apps build trust views, audit trails, public-key history, and marketplace reputation without owning the identity layer.

## Stub vs real payment warning

Development or test environments may use stub invoices. Stub invoices are not real payments. Production integrations must use a real Lightning backend and must not treat stub settlement as real money movement.

## Product framing

HODLXXI is a Bitcoin-native trust runtime for public-key agents and services.

Short framing: Trust infrastructure for public keys.
<!-- END_HODLXXI_AGENT_RECEIPT_QUICKSTART_V1 -->
