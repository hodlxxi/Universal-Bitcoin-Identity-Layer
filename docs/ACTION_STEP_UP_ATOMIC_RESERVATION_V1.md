# Atomic Step-Up Action Reservation V1

PR6.1 fixes a persistence boundary without enabling an action. Previously,
`verify_and_consume()` and operation `reserve()` committed through separate
repository sessions. A failure between those commits could consume a challenge
without creating its corresponding reservation.

The new dormant composite adapter verifies a persisted BIP-340 proof, consumes
the exact challenge, and inserts the `ActionOperation` in one SQLAlchemy
transaction with one final commit. A challenge consumption cannot commit
without its operation reservation, and a step-up-bound reservation cannot
commit without consuming that exact challenge.

The adapter queries the actor/client/idempotency-key namespace before loading or
verifying a proof. An exact fingerprint match replays the original operation,
including after challenge consumption or expiration. A different fingerprint
returns `idempotency_conflict`; neither path verifies a proof or mutates the
challenge. Concurrent uses of one challenge produce only one new operation;
other namespaces are rejected as consumed, while identical retries resolve as
replay.

Successful verification evidence is serialized as the complete
`VerifiedStepUp.to_dict()` JSON with sorted keys, compact separators, ASCII
escaping, and UTF-8 encoding. Its lowercase SHA-256 digest is stored on the
operation. This digest is audit evidence, not an authorization credential.
Reconstructed `VerifiedStepUp` objects remain non-authoritative. Raw proof
signatures, challenge nonces, bearer tokens, client secrets, private keys, and
raw request or result bodies are not stored on the operation.

The schema adds `uq_action_operations_step_up_challenge`, allowing a challenge
to be referenced by at most one operation, and
`fk_action_operations_step_up_challenge`, linking the nullable reference to the
challenge table with restrictive/default deletion semantics.

Operators must apply migrations in this order:

1. `migrations/2026-07-20_action_step_up_challenges.sql`
2. `migrations/2026-07-20_action_operations.sql`
3. `migrations/2026-07-21_action_step_up_operation_binding.sql`

No migration was applied by this change. The authoritative staging SQLite
database currently contains neither action table, so no staging backfill or
schema mutation was performed.

No route, Flask blueprint, MCP tool, transport, command, or handler was added.
No action was enabled or dispatched. The internal gateway remains fail-closed
for step-up-required actions, current-FULL-relation-required actions, and
covenant draft creation. PR6.1 does not itself authorize or dispatch covenant
actions.
