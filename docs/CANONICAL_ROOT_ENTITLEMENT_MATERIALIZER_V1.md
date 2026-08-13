# Canonical Root Entitlement Materializer V1

This internal service is the narrow append primitive between a validated edge-local
root relation and existing current-entitlement evidence. It accepts an explicit graph,
canonical subject, and exact `EdgeLocalCovenantRelationResult`; it always revalidates
that result with `evaluate_canonical_root_entitlement()`.

The Root Policy decision is the sole entitlement authority. Only ordinary participant
`Full` and `Limited` decisions are supported. Root or Genesis status does not grant
Operator, administrative, wallet, payment, OAuth, MCP, or Social authority, and there
is no E923 or environment-derived shortcut.

Before materialization, every returned selector, registration, funding-set, relation,
count, total, height, and source-digest provenance field must exactly match the supplied
edge-local result, and the selection source must remain the canonical root binding. The
complete returned decision, including its canonical policy digest, must equal an
independent evaluation through the original Root Policy function.

The resulting `CurrentEntitlementEvidenceRecord` uses the existing contract version.
Subject, identity class, relation flag, evidence source, policy version, source digest,
and exact observation timestamp come from the policy decision. Validity ends exactly
300 seconds after observation; revocation is unset; creation is the later of the
UTC-normalized materializer clock and observation time. Observations may be at most 60
seconds old or 5 seconds in the future, inclusively. Observation microseconds are not
replaced or truncated.

Policy, type, freshness, clock, UUID, and evidence-contract validation all precede the
single repository `append` call. The injected repository owns its transaction. The
materializer neither reads older evidence nor calls session commit, flush, or rollback.
Ordinary failures are exposed only as the sanitized materialization-unavailable error;
`KeyboardInterrupt` and `SystemExit` remain visible.

This primitive performs no Bitcoin RPC or observation and reads no registrations,
bindings, funding sets, users, wallets, browser sessions, or environment privilege.
It is not invoked by the public GET assertion or runtime resolver. It adds no route,
scheduler, worker, timer, CLI, startup/login hook, live write, model, or migration.
