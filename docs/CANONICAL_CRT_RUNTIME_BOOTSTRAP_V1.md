# Canonical CRT Runtime Bootstrap V1

Status: **IMPLEMENTED OPERATOR TOOLING — NOT PRODUCTION-ACTIVATED — NO ENTITLEMENT GRANT**

This contract bootstraps the already-validated E923 canonical CRT source chain into an empty or partially completed runtime database. It does not infer authority, discover Bitcoin outpoints, write current entitlement evidence, install a scheduler, or grant `FULL` directly.

The exact source bundle is pinned by `docs/data/e923_canonical_crt_runtime_bootstrap_v1.json`. The bootstrap engine also pins the SHA-256 of the exact manifest bytes. Any manifest-byte change requires explicit source review and a code update; semantic similarity is not sufficient.

## Fixed dependency order

Commit mode processes exactly these durable records:

1. canonical E923 Genesis record;
2. trusted mirrored-covenant registration;
3. canonical root-to-registration binding;
4. canonical recognized funding set.

Each repository remains authoritative for its domain validation. After every append, the bootstrap engine performs an exact readback. The trusted registration comparison includes both its canonical record and the authoritative mirrored-pair raw witness scripts.

## Replay and resume semantics

Before any append, the engine inspects the current canonical state. For each pinned identity:

- missing exact record: `append` / `would_append`;
- exact existing record: `unchanged`;
- same identity with different canonical content: fail closed;
- an unexpected Genesis record for the graph, root binding for the subject, or funding set for the registration: fail closed.

The existing storage adapters commit independently. Therefore a process interruption may leave a valid prefix of the four-step chain. A later operator retry is safe only because exact completed steps are `unchanged` and execution resumes at the first missing step. Commit-boundary failures return an ambiguous sanitized error instructing the operator to inspect canonical bootstrap state before retrying.

## Operator boundary

Dry-run:

```bash
python scripts/canonical_root_bootstrap.py --dry-run
```

Dry-run performs no append and requires only `DATABASE_URL` in the environment.

Commit requires both the exact acknowledgement and a private absolute lock directory:

```bash
python scripts/canonical_root_bootstrap.py \
  --commit \
  --lock-directory /absolute/private/lock-directory \
  --ack CANONICAL-CRT-RUNTIME-BOOTSTRAP-V1
```

Commit reuses the canonical-root subject lock used by the entitlement refresh runner, serializing the bootstrap against root entitlement refresh for the same subject.

## Explicit non-effects

Bootstrap V1:

- does not construct a Bitcoin RPC client;
- does not observe or rescan Bitcoin;
- does not write `current_entitlement_evidence`;
- does not call the entitlement materializer;
- does not directly assign `FULL`, `LIMITED`, Operator, admin, or server privileges;
- does not install or enable a systemd timer or any scheduler;
- does not modify schema or run migrations;
- does not deploy or restart a service;
- does not authorize production execution by existing in the repository.

After a separately authorized production bootstrap, the ordinary canonical-root entitlement refresh remains the only mechanism that can observe current Bitcoin state and materialize time-bounded entitlement evidence.

## Activation gate

Source merge is not production activation. Before production commit mode is authorized, the exact release must pass a disposable PostgreSQL rehearsal covering initial append, exact replay, partial-resume behavior, readback, and zero entitlement-evidence writes. Production canonical-table backup/recovery evidence and an explicit operator decision remain separate gates.
