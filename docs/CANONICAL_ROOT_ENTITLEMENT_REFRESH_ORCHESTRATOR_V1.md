# Canonical Root Entitlement Refresh Orchestrator V1

This internal service composes the existing canonical observation, Root Policy,
materializer, and current-evidence repository. It introduces no new authority or
evidence-writing implementation.

## Sequence and outcomes

`DRY_RUN` performs one fresh edge-local observation and one Root Policy
evaluation, then returns immutable `PREVIEW` data. It does not acquire a write
guard, read evidence for writing, create an evidence UUID, or append evidence.
Both Full and Limited are ordinary policy previews and neither promises future
status.

`COMMIT` requires a caller-provided, subject-scoped guard whose contract states
that it is exclusive. The guard is acquired once and held across latest-evidence
read, fresh observation, policy evaluation, replay classification, optional
materialization, and post-append latest-record verification. `APPENDED` means the
existing materializer appended exactly once and that exact record was verified
as latest. `UNCHANGED` means the latest reconstructed evidence already exactly
represented the fresh decision and no append occurred.

Exact replay requires equality of canonical subject, Root Policy version,
evidence source, source evidence SHA-256, identity class, current-full flag, and
exact observation time. Timestamp-only or class-only equality is insufficient;
an older or expired Full row does not suppress a genuinely fresh decision.

Canonical root-registration-binding provenance is mandatory. The existing Root
Policy alone decides Full or Limited. Limited may be materialized. Root, Genesis,
E923, operator configuration, wallet state, or browser state never implies Full
or Operator, and Social owns no entitlement authority.

Evidence remains immutable. Its 300-second validity window and append
transaction remain owned by the existing materializer and evidence repository.
The orchestrator performs no retry, polling, sleep, transaction/session control,
revocation, extension, or deletion.

Guard exit occurs after post-append verification. If exit fails after a verified
append, the caller receives the sanitized refresh-unavailable error even though
the immutable evidence row may already be persisted. This is deliberately a
post-commit ambiguity: callers must not blindly retry, because doing so could
attempt a second append for an observation that is already stored.

## Deliberate boundaries

This version has no CLI, HTTP write route, scheduler, timer, worker, startup or
login hook, application-factory wiring, environment discovery, default graph,
default subject, default database/RPC configuration, or live execution. A later
reviewed operator entrypoint must inject every runtime dependency. A separate
later boundary must supply a real deployment-level exclusive guard (for example,
an explicitly configured host lock); this service neither chooses nor claims to
implement one. Tests use fakes and isolated temporary SQLite only, so their guard
proves the injection contract rather than deployment-level locking.
