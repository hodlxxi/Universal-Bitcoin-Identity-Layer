# HODLXXI Agent Protocol v0.2

## 1. Overview

This specification extends HODLXXI from a client → agent interaction model to an agent ↔ agent interaction model.

It addresses the current interoperability gap where one agent can expose capabilities but cannot negotiate, delegate, and exchange verifiable results with another agent in a standardized way.

This extension is designed to compose with existing HODLXXI surfaces, including identity/pubkey flows, receipts, attestations, and current HTTP JSON endpoints, without changing existing endpoint behavior.

## 2. Compatibility Model

- All existing endpoints remain unchanged.
- v0.2 features are opt-in and additive.
- No breaking changes are introduced to current clients or agents.
- Agents that do not implement v0.2 continue operating under existing protocol behavior.

Implementation profile note (current branch):

- The current MVP runtime implements a subset centered on `POST /agent/message` with `job_proposal -> result`.
- Negotiation, discovery exchanges, and settlement remain specified but are not implemented in this runtime slice.

## 3. Protocol Layers

### 3.1 Messaging Layer

Defines signed transport envelopes, message types, basic delivery semantics, and conversation/thread identifiers over HTTP + JSON.

### 3.2 Negotiation Layer

Defines explicit proposal/counter/agreement exchanges for price, deadlines, and optional SLA terms. Agreement is based on signed payload equivalence, not implicit inference.

### 3.3 Tool/Execution Layer

Defines inter-agent task delegation and an LLM bridge format for tool-call compatible requests/responses, while keeping execution policy and runtime controls local to each agent.

### 3.4 Settlement Layer (Future)

Reserved for future payment/escrow/dispute mechanisms. v0.2 permits optional payment references but does not define enforced settlement.

## 4. CANONICAL MESSAGE ENVELOPE (CRITICAL)

All inter-agent messages MUST use the following canonical JSON envelope:

```json
{
  "message_id": "...",
  "conversation_id": "...",
  "thread_id": "...",
  "type": "...",
  "from_pubkey": "...",
  "to_pubkey": "...",
  "created_at": "...",
  "payload": { ... },
  "payment_hash": "... optional ...",
  "references": {
    "parent_message_id": "... optional ..."
  },
  "signature": "secp256k1 signature"
}
```

Canonical signing rules:

- `signature` MUST be a secp256k1 signature verifiable by `from_pubkey`.
- The signature input MUST be UTF-8 bytes of the canonical JSON serialization of the envelope with `signature` removed.
- Canonical JSON serialization for v0.2 is defined as:
  1. JSON object keys sorted lexicographically at every nesting level.
  2. No insignificant whitespace.
  3. UTF-8 encoding.
  4. Numbers encoded as JSON numbers (not quoted).
  5. Omitted optional fields are not serialized; present optional fields are serialized normally.
- Verifiers MUST reject messages whose signature validates only under a non-canonical serialization.

Field semantics:

- `message_id` MUST be globally unique per `from_pubkey` and SHOULD be UUIDv7 or equivalent sortable unique identifier.
- `conversation_id` identifies a bilateral work context between the same `from_pubkey` and `to_pubkey` pair. Reuse across different counterparty pairs is invalid.
- `thread_id` identifies a branch within a `conversation_id`. New delegated branches SHOULD use new `thread_id` values.
- `created_at` SHOULD use RFC 3339 UTC timestamps.
- `references.parent_message_id` links causal parentage and SHOULD refer to a prior message in the same `conversation_id`.

Ordering and idempotency:

- No global ordering is assumed across agents.
- Per-conversation ordering is best-effort and inferred by `(created_at, message_id)`.
- A receiver MUST treat `(from_pubkey, message_id)` as the idempotency key.
- If an already-processed `(from_pubkey, message_id)` is received again with byte-identical canonical body, the receiver MUST NOT re-execute side effects and SHOULD return a deterministic idempotent success response (for example, replaying the prior signed `result`).
- If an already-seen `(from_pubkey, message_id)` is received again with a different canonical body, the receiver MUST reject it as `message_id_conflict`.

## 5. Messaging Model

Endpoints:

- `POST /agent/message`
- `GET /agent/messages`
- `POST /agent/conversations`

Message `type` enum:

- `job_proposal`
- `counter_offer`
- `delegation`
- `result`
- `rejection`
- `ack`

Behavioral model:

- Agents MAY operate statelessly by verifying each signed envelope independently.
- Agents MAY operate statefully by persisting conversations and threads.
- `GET /agent/messages` supports polling as the baseline retrieval mechanism.
- Streaming transports are out of scope for v0.2 and reserved for future extensions.
- Shared memory/state between agents is not required.

Minimal error model:

Errors are returned as JSON with this shape:

```json
{
  "error": {
    "code": "...",
    "message": "...",
    "retryable": false
  }
}
```

Standard `error.code` values for v0.2:

- `invalid_signature`
- `invalid_envelope`
- `unknown_message_type`
- `message_id_conflict`
- `conversation_mismatch`
- `policy_denied`
- `temporarily_unavailable`

`retryable` SHOULD be `true` only for transient conditions such as `temporarily_unavailable`.

Runtime MVP note: the current `/agent/message` implementation uses a compact error payload form `{"error": "<code>"}` for deterministic minimal handling.

## 6. Negotiation Model

Negotiation follows a proposal → counter → agreement pattern.

- A `job_proposal` contains initial terms.
- A `counter_offer` modifies one or more terms.
- Agreement exists only when both sides produce signed messages containing matching final terms.
- No implicit agreement is valid.

Agreement definition (machine-verifiable):

- Let `terms_hash` be SHA-256 over canonical JSON serialization of agreed terms object.
- A negotiation is in `agreed` state only when both counterparties have each sent one signed message in the same `conversation_id` with:
  - `type` equal to `ack` or `result`, and
  - identical `terms_hash`, and
  - `references.parent_message_id` pointing to the last proposal/counter message being accepted.
- Any mismatch in `terms_hash` means no agreement.

Optional terms schema example:

```json
{
  "proposed_price_sats": 50000,
  "deadline_unix": 1770000000,
  "sla": {
    "max_response_seconds": 30,
    "result_format": "json"
  }
}
```

This model is conceptually aligned with Contract Net Protocol style interactions, without formal adoption of that standard.

## 7. Delegation Model

- Agent A MAY delegate work to Agent B.
- Agent B MAY further delegate to Agent C.
- Delegation chains MUST be observable through signed receipts and message references.

Minimal delegation payload:

```json
{
  "task_id": "...",
  "delegator_pubkey": "...",
  "delegatee_pubkey": "...",
  "scope": "...",
  "constraints": {
    "deadline_unix": 1770000000,
    "max_fee_sats": 10000
  }
}
```

Each delegation hop SHOULD reference its parent via `references.parent_message_id` and return a signed `result` or `rejection`.

## 8. TOOL-CALL / LLM BRIDGE

`skill_id`: `llm_tool_call_bridge`

v0.2 defines an optional bridge for model-agnostic tool invocation between agents:

- Request payloads MAY carry OpenAI-compatible tool schema structures (`tools`, `tool_choice`, and tool-call arguments).
- Agents are not required to use any specific model vendor.
- Response payloads MUST include:
  - `tool_calls` (executed or proposed calls and arguments)
  - a signed receipt binding the tool-call output to the responding `from_pubkey`

This bridge standardizes exchange format, not model/runtime internals.

## 9. Discovery Model

Local discovery:

- `GET /agent/discover`

Global discovery:

- `/.well-known/agent.json` (existing)
- Optional external registries
- Optional Nostr-style announcements

Global infrastructure is optional and not required for baseline inter-agent operation.

## 10. BOUNDED SOVEREIGNTY INTERACTION

Inter-agent messaging and negotiation operate within existing bounded sovereignty controls:

- `/agent/policy`
- `/agent/actions`
- `/agent/bounded-status`

Clarifications:

- Receipt of a valid message does not imply automatic execution.
- Any local execution remains policy-constrained.
- Bounded controls remain authoritative over delegated or negotiated requests.

## 11. SECURITY MODEL

- All inter-agent messages are signed.
- Identity is represented by secp256k1 public keys.
- Receivers SHOULD enforce replay protections using `message_id`, sender pubkey, and timestamp windows.
- `payment_hash` MAY optionally bind a message to an external payment context.

v0.2 defines authenticated message integrity and origin, but does not claim complete transport, settlement, or counterparty security guarantees.

## 12. LIMITATIONS

- No guaranteed delivery.
- No global ordering.
- No enforced escrow in v0.2.
- No autonomous spending guarantees (observe-only reality remains).
- No universal cross-agent compatibility guarantee at this stage.

## 13. FUTURE EXTENSIONS

Potential follow-on layers include:

- Escrow / hold invoice integration
- Dispute layer
- Zero-knowledge request formats
- Richer discovery and reputation exchange
- Streaming transports
