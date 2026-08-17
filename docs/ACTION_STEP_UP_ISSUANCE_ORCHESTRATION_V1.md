# Action Step-Up Issuance Orchestration V1

## Purpose and status

This module is a dormant, endpoint-independent trusted orchestration layer for
issuing an action step-up challenge. It has no route, blueprint, MCP surface,
CLI, application-factory construction site, production singleton, or public
discovery entry. The only eligible action is `covenant_draft_create`, and its
policy requirement must continue to declare `step_up_required=True`.

## Trusted ordering and bindings

One frozen `StepUpIssuanceRequest` contains only the encoded bearer token,
expected OAuth client ID, action, optional resource ID, and request payload.
The orchestrator performs these steps in order:

1. It validates the exact request type, bounded identifiers, known action, and
   canonical JSON payload.
2. It validates the bearer and requires the validated principal's client ID to
   equal the expected client ID.
3. It resolves current entitlement for the authenticated subject.
4. It resolves ownership only when the action policy requires it.
5. It runs `authorize_action()` using the principal's scopes and current
   entitlement.
6. It hashes the already-canonicalized request bytes and calls
   `ActionStepUpService.issue_challenge()` exactly once with a trusted lifetime.

The principal is the only source of actor public key, effective OAuth client
ID, token JTI, and scopes. Entitlement identity and current FULL relation come
only from current resolution. The request digest is computed locally. None of
these values, nor an authorization decision, can be supplied through the
caller-facing request.

For conditional issuance policy evaluation, `step_up_verified=True` means only
"all ordinary non-step-up requirements are currently satisfied, so issuance is
permitted." It does not claim that a proof exists or was verified. Scope, FULL
identity, current FULL relation, operator control-plane denial, ownership,
actor matching, and malformed-scope checks remain active.

## Exact request canonicalization

Issuance and `InternalActionGateway` import the same pure
`canonical_payload_bytes()` function. It preserves the existing 65,536-byte
ceiling, accepted JSON types, sorted keys, compact separators, ASCII escaping,
non-finite-float rejection, cycle rejection, and exact UTF-8 byte output. The
payload is canonicalized once per issuance attempt, and SHA-256 is computed
over that immutable byte snapshot. Later mutation of the caller's object cannot
change the challenge binding.

## Result and storage contract

`StepUpIssuanceResult` is frozen and has bounded reasons: `issued`,
`invalid_request`, `invalid_token`, `entitlement_denied`,
`entitlement_unavailable`, `authorization_denied`, `action_unavailable`,
`ownership_unavailable`, `storage_unavailable`, and `internal_failure`. Its
invariants require a real `StepUpChallenge` exactly for success. A returned
challenge is also checked against every trusted binding; malformed or
mismatched issuer output fails closed.

The existing service remains responsible for UUID and nonce generation,
challenge schema and signature domain, timestamps and lifetime ceilings, and
repository persistence. Storage errors map to a bounded reason. Results never
contain the bearer token, raw resolver/database exceptions, stack traces,
signing material, or a partial challenge. Successful issuance leaves the
durable challenge unconsumed.

## Relationship to atomic execution

The trusted flow has two stages:

1. Issuance: trusted issuance orchestrator →
   `ActionStepUpService.issue_challenge()` → durable unconsumed challenge.
2. Execution: `InternalActionGateway` →
   `SqlAlchemyAtomicStepUpOperationRepository.reserve_with_step_up()` → proof
   verification, challenge consumption, verification hashing, and operation
   reservation in one transaction → compare-and-set dispatch → terminal
   receipt.

Issuance never calls `verify_and_consume()`, consumes a challenge, reserves an
operation, dispatches a handler, loads a receipt signer, finalizes a receipt, or
executes an action. Inserting standalone `verify_and_consume()` before gateway
reservation would reintroduce the split-transaction gap fixed by the atomic
reservation architecture.

## Disabled capabilities and non-claims

This layer has no Flask, MCP, Bitcoin Core, bitcoin-cli, wallet, LND,
Lightning, Nostr, subprocess, shell, network-client, production-configuration,
deployment, or service-management dependency. It does not create, sign, fund,
broadcast, or execute a covenant transaction. It is neither authentication
proof consumption nor action authorization for execution.

Any future public activation still requires separately reviewed transport and
dependency wiring, production entitlement evidence, operational policy and
audit controls, rate limiting and abuse analysis, key-management and handler
design, deployment configuration, and end-to-end safety testing. This document
does not authorize such activation.
