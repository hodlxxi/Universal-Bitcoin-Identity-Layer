# Canonical Root Entitlement Refresh Runner V1

This operator-only program performs exactly one refresh and exits. It adds no
authority: only Canonical Root Entitlement Policy V1 decides Full or Limited;
operator identity, process ownership, database access, RPC access, or the lock
never implies Full or Operator.

Invoke it with exactly one explicit graph and lowercase x-only subject plus one
mode:

```text
python scripts/canonical_root_entitlement_refresh.py --graph GRAPH --subject 64_LOWER_HEX --dry-run
python scripts/canonical_root_entitlement_refresh.py --graph GRAPH --subject 64_LOWER_HEX --commit --lock-directory /ABSOLUTE/PRIVATE/DIRECTORY
```

There are no defaults for graph, subject, database, RPC target, deployment, or
lock directory. Credentials and secrets are not CLI arguments. All arguments
are validated by a standard-library-only boundary before the runner or any
application/domain module is imported. Runtime imports occur only after that
complete validation succeeds and before runtime dependencies are constructed.
Runtime configuration must explicitly provide `DATABASE_URL`, `RPC_HOST`,
`RPC_PORT`, `RPC_USER`, and `RPC_PASSWORD` outside argv. The runner reuses the
existing canonical genesis, admission-edge, root-binding, trusted-registration,
funding-set, and current-evidence repositories, the existing Bitcoin RPC
factory, and the existing immutable materializer; it defines no parallel query
or storage path.

Dry-run performs one fresh observation and returns a Full or Limited PREVIEW.
It constructs no guard and reads or writes no current evidence. Commit holds a
nonblocking Linux subject-scoped `flock` across the existing orchestrator's
complete critical section. The directory must already exist, be absolute,
owned by the process user, private from group/world writes, and not a symlink.
Lock files are digest-named regular files with mode 0600. Contention fails
immediately; there is no polling, sleep, retry, scheduler, worker, or daemon.
The retained lock-directory descriptor has an explicit idempotent lifecycle:
it remains open for the legitimate guard lifetime and is closed on every
normal, failure, and interrupt path, including failures before guard entry.

Success is one bounded normalized JSON line containing only operational fields.
Failures are sanitized and contain no configuration, URL, filesystem database
path, credential, secret, exception detail, or traceback.

Commit is never retried automatically. An error while leaving the guard or the
final boundary can occur after a verified immutable append committed. The
message therefore does not claim whether an append occurred: inspect current
evidence before any manual retry.
