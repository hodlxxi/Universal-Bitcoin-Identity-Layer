# Atomic Step-Up Gateway Integration V1

## Status and scope

This integration is dormant and endpoint-independent. It permits
`covenant_draft_create` only in the internal gateway's eligible action set and
only when a caller explicitly injects both a handler and an atomic step-up
repository. It does not register a handler, construct a production gateway,
or expose a route, CLI command, MCP capability, or discovery document.

## Two-repository architecture

`InternalActionGateway` retains its ordinary `OperationRepository`. That
repository reserves non-step-up actions and owns post-reservation lifecycle
operations: the reserved-to-executing compare-and-set, completed and failed
finalization, indeterminate marking, and operation retrieval.

A separate optional repository implements the narrow atomic contract:

```python
reserve_with_step_up(reservation, proof, consumed_at) -> AtomicStepUpReserveResult
```

`SqlAlchemyAtomicStepUpOperationRepository` alone verifies and consumes the
persisted BIP-340 challenge and inserts the bound `ActionOperation` in one
transaction. Keeping these changes atomic prevents a consumed challenge with
no operation, an operation reserved from unverified evidence, and concurrent
reuse between proof verification and reservation. The gateway neither
reimplements that transaction nor precomputes the verification evidence hash.

## Invocation order

The gateway validates the invocation and canonicalizes its payload once. It
then authenticates the bearer and resolves current entitlement before either
operation repository can be touched. For a step-up action it next requires an
explicit eligible handler, the optional atomic repository, and the exact
canonical `StepUpProof` type.

Ordinary authorization is evaluated with the existing policy using
`step_up_verified=True`. This flag evaluates the conditional policy only; it
does not authenticate the proof. Required scope, FULL identity, current FULL
relation, ownership rules, operator denial, and entitlement failures still
fail before atomic reservation.

The reservation binds the canonical actor, OAuth client, token JTI and token
reference, action and resource, request hash, authorization-decision hash,
idempotency namespace, request fingerprint, and proof challenge ID. Its
verification hash is `None`. Only an atomic `NEW` result containing a persisted
operation and successful verification may proceed through compare-and-set and
handler dispatch.

## Result and replay semantics

- `NEW` proceeds through the existing executing, handler, receipt, and
  finalization lifecycle.
- `REPLAY` never verifies or dispatches again and uses the persisted operation
  state. Terminal replay returns the exact stored receipt bytes.
- `IDEMPOTENCY_CONFLICT` returns the bounded gateway conflict result without
  dispatch.
- `STEP_UP_REJECTED` returns only `step_up_rejected`, without exposing proof,
  cryptographic, challenge, exception, or database details.
- Exceptions and malformed atomic results fail closed as bounded storage or
  internal failures.

Completed and explicitly failed receipts copy `step_up_challenge_id` and
`step_up_verification_sha256` from the persisted operation, never from the
submitted proof. Ordinary operations continue to persist and receipt both
fields as `null`.

## Explicit non-claims

This change does not enable covenant creation or any public or production
action execution. It adds no production handler, signer-key loading, runtime
singleton, transport, Flask blueprint, API route, MCP surface, database
migration, Bitcoin Core or wallet RPC, LND or Lightning call, transaction
generation, funding, signing, broadcast, or deployment behavior.

A future activation change would still need an independently reviewed public
transport and authentication boundary, explicit production dependency wiring,
a production action handler, signer/key-management design, operational policy
and audit controls, deployment configuration, and end-to-end safety testing.
