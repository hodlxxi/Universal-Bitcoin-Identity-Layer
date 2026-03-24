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

Normative requirements:

- `signature` MUST be produced by `from_pubkey` over a deterministic serialization of the envelope fields excluding `signature`.
- The signed body MUST include: `message_id`, `conversation_id`, `thread_id`, `type`, `from_pubkey`, `to_pubkey`, `created_at`, `payload`, `payment_hash` (if present), and `references` (if present).
- `message_id` MUST be globally unique per sender and SHOULD be UUIDv7 or equivalent sortable unique identifier.
- `conversation_id` groups related negotiation/delegation exchanges.
- `thread_id` groups subflows within a conversation (for example, delegated branches).
- `created_at` SHOULD use RFC 3339 UTC timestamps.

Ordering and idempotency:

- No global ordering is assumed across agents.
- Per-conversation ordering is best-effort and inferred by `(created_at, message_id)`.
- Receivers MUST treat repeated `message_id` values from the same `from_pubkey` as idempotent duplicates.
- Receivers MAY accept out-of-order delivery and reconstruct causal chains via `references.parent_message_id`.

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

## 6. Negotiation Model

Negotiation follows a proposal → counter → agreement pattern.

- A `job_proposal` contains initial terms.
- A `counter_offer` modifies one or more terms.
- Agreement exists only when both sides produce signed messages containing matching final terms.
- No implicit agreement is valid.

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
