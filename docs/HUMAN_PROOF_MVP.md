# Human Proof MVP

## Purpose

Human Proof MVP is the launch contract for the public HODLXXI Human Proof demo. It documents the current invoice-backed flow, receipt surfaces, verifier surfaces, requester key proof boundary, and operational storage assumptions without changing runtime behavior.

Human Proof MVP is intentionally narrow. It records that the HODLXXI runtime observed a paid job, produced a result, issued a signed receipt, and exposed factual runtime continuity surfaces for audit. It does not turn a receipt into a broader claim about identity, status, investment value, or authority.

## Request -> Pay -> Result -> Verify flow

1. **Request**: a user opens `/demo`, the live Human Proof demo, and prepares a paid Human Proof request through the existing agent runtime.
2. **Pay**: the runtime creates a Lightning invoice through the existing payment path. The MVP documentation does not change payment logic, Lightning logic, invoice creation, or payment detection.
3. **Result**: after the runtime observes settlement, the job can complete and the runtime can issue the existing signed receipt payload.
4. **Verify**: the user or an external verifier can inspect the public verifier surfaces and receipt context without trusting a private browser session.

## Public runtime surfaces

- `/demo` is the live Human Proof demo entry point.
- `/agent/verify` is the public human verifier page for entering or displaying a `job_id`.
- `/agent/verify/<job_id>` is the raw JSON verifier authority for a job after receipt issuance, including the no-receipt and not-found states documented by the receipt verification contract.
- `/agent/receipts/<job_id>.json` is the signed receipt JSON download surface after a receipt exists.
- `/agent/attestations` exposes signed runtime events, including receipt-related events when present.
- `/agent/reputation` exposes factual runtime counters/continuity, not a human trust score.
- `/agent/chain/health` exposes local append-only continuity, not global consensus.

## Receipt and runtime context boundary

A Human Proof receipt proves only the bounded runtime facts encoded by the signed receipt and verifier response. It can show that the HODLXXI runtime recorded an invoice-backed job as settled before issuing a result and receipt. Independent Lightning settlement verification may require separate payment evidence.

Runtime context links such as `/agent/attestations`, `/agent/reputation`, and `/agent/chain/health` help auditors inspect continuity around the receipt. They do not expand the receipt into a broader personal, legal, financial, or consensus claim.

## QR verification affordance

A QR verification affordance can carry the verifier URL for a receipt, such as `/agent/verify/<job_id>`, so a third party can open the public verifier page for that job. QR is discovery/transport only. QR does not replace receipt verification, /agent/verify/<job_id> remains the verification authority, and the signed receipt remains the proof artifact.

The QR code itself is not proof of payment by itself, not proof of identity, not proof of consent, not proof of authority, not proof of moral trustworthiness, not custody, not KYC, not global consensus, and not an investment signal.

## Requester key proof boundary

Requester key proof binds a requester-controlled key proof to the Human Proof request boundary used by the current runtime. It is not legal identity, KYC, consent, authority, custody, or a durable account system by itself.

For the MVP, the requester proof store is process-local memory. That means production launch must use a single worker with session affinity, or the deployment must first replace the process-local memory store with Redis or another shared TTL storage layer. Without that boundary, a requester can start the flow on one worker and finish on another worker that cannot see the pending proof challenge.

## Single-worker/session-affinity requirement

The current requester proof storage requirement is explicit:

- pending requester proof challenges live in process-local memory;
- the launch deployment must run a single worker, or enforce session affinity to the same worker;
- before multi-worker deployment, move pending requester proof challenge state to Redis or another shared TTL storage layer;
- do not treat process-local memory as a cross-worker, durable, or disaster-recovery storage mechanism.

## Non-claims and safety boundaries

Human Proof MVP is:

- not a token sale;
- not an investment;
- not KYC;
- not legal identity;
- not custody;
- not a promise of profit;
- not proof of moral trustworthiness;
- not a guarantee of future performance;
- not ownership of a network;
- not global consensus;
- not consent;
- not authority.

These boundaries apply to the demo, verifier page, raw verifier JSON, receipt JSON download, attestation stream, reputation counters, and chain health continuity surface.

## Related documentation

- [`AGENT_RECEIPT_V1.md`](AGENT_RECEIPT_V1.md) defines the signed receipt v1 fields.
- [`RECEIPT_VERIFICATION.md`](RECEIPT_VERIFICATION.md) documents independent receipt verification and verifier endpoint states.
- [`AGENT_RECEIPT_QUICKSTART.md`](AGENT_RECEIPT_QUICKSTART.md) gives an external developer quickstart for the paid agent runtime.
- [`HUMAN_PROOF_REQUESTER_PROOF_STORE.md`](HUMAN_PROOF_REQUESTER_PROOF_STORE.md) documents the requester proof store launch guard.
- [`ops/HUMAN_PROOF_MVP_RUNBOOK.md`](ops/HUMAN_PROOF_MVP_RUNBOOK.md) gives the operator runbook for launch validation and rollback.
