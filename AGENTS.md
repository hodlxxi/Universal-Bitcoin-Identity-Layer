# Agent Operating Rules for UBID

These instructions apply to the entire repository. They are intended for Codex and other automated coding agents. Read this file completely before inspecting or changing source.

Human contribution guidance is in [`CONTRIBUTING.md`](CONTRIBUTING.md). Repository architecture and product claims must come from the current canonical documents identified by [`docs/DOCUMENTATION_MAP.md`](docs/DOCUMENTATION_MAP.md), not from stale summaries or filenames alone.

## 1. Authority and Scope

- Perform only the task the operator authorized.
- A request to inspect, explain, audit, review, or diagnose authorizes read-only work, not implementation.
- A request to implement authorizes edits and safe verification inside the assigned worktree, but not commit, push, pull-request mutation, merge, deployment, migration application, service restart, or live-data access unless those actions are explicitly requested.
- Task instructions may narrow this file. They may relax a safety boundary only when the operator explicitly names the affected environment and operation.
- If a required action exceeds the current authority, stop and report the exact blocker.

## 2. Repository Identity Before Work

Before editing, report and verify:

- absolute worktree path;
- current branch;
- exact `HEAD` commit;
- upstream ref;
- clean or intentionally dirty status;
- intended base branch and remote base commit;
- exact allowed file scope;
- absence of conflicting worktree processes or agent sessions when relevant.

Never assume `main`, `staging`, or an old handoff commit is current. Fetch or read the exact authoritative remote ref when network access is authorized.

Stop if:

- the worktree, branch, base, or upstream is unexpected;
- unexplained changes already exist;
- the requested branch or worktree collides with existing work;
- another process is actively modifying the same worktree;
- required files, contracts, or fixed vectors differ from the task's guards.

## 3. Worktree and Git Safety

- Work only in the isolated feature or corrective worktree assigned to the task.
- Never edit a live production or staging checkout.
- Preserve all pre-existing user changes. Do not reset, clean, checkout over, or delete them.
- Do not use destructive Git commands such as `git reset --hard`, forced checkout, force push, or recursive cleanup.
- Do not repair Git ownership, permissions, objects, refs, or repository internals unless explicitly authorized.
- Do not stage files outside the exact approved scope.
- Before any authorized commit, verify staged scope, staged diff, whitespace, and expected file hashes or content guards.
- Before any authorized push, verify the remote branch and pull-request collision state.
- Before any authorized merge, verify exact PR head, base, readiness, mergeability, and CI for that head.

## 4. Environment Boundaries

Treat production, live staging, databases, sockets, service managers, reverse proxies, credentials, and external APIs as protected resources.

Unless the task explicitly authorizes the exact operation:

- do not contact a live PostgreSQL instance, including the default port `5432`;
- do not use inherited `DATABASE_URL`, Redis, Bitcoin RPC, Lightning, OAuth, service-token, or Unix-socket settings;
- do not call live internal or public application routes;
- do not run migrations against staging or production;
- do not restart, reload, enable, disable, or reconfigure services;
- do not change nginx, systemd, environment files, secrets, permissions, packages, or host configuration;
- do not deploy or update a live checkout.

Database rehearsals require explicit authorization and a disposable PostgreSQL cluster with a unique temporary directory, isolated socket or non-live port, synthetic data, recorded target identity, and verified teardown. Never infer that a local database is disposable.

Unit tests must not silently fall back to live infrastructure. Fail closed when an isolated dependency is unavailable.

## 5. Source, Runtime, and Deployment Are Separate Phases

- Source-only code remains dormant until separately wired.
- Runtime/factory composition is a separate change.
- Adding an HTTP or internal route is a separate change.
- Adding a repository or durable adapter is a separate change.
- Adding a migration does not authorize applying it.
- Merging a PR does not authorize deployment.
- Updating staging does not authorize production promotion.

Every final report must state whether each of these occurred. Use `NO`, not silence, for boundaries that remained unchanged.

## 6. Security and Privacy Invariants

Preserve the repository's public-key identity model and fail-closed security posture.

- Never commit or print private keys, message keys, plaintext messages, passwords, bearer tokens, cookies, database credentials, seed material, or unsanitized sensitive logs.
- Do not add email or phone identity requirements without an explicit product decision.
- Do not expose raw subjects, internal identifiers, public keys, or correlation material through outward contracts unless the relevant canonical contract explicitly requires them.
- OAuth possession alone must not be silently upgraded into stronger cryptographic authorization.
- Authorization, entitlement, binding, routing, storage, and delivery decisions must remain independently verifiable where their contracts require it.
- Reject malformed, ambiguous, duplicate, incomplete, stale, expired, revoked, mismatched, or noncanonical state.
- Public failures must remain non-sensitive and fail closed.

## 7. Canonicalization and Cross-Contract Compatibility

For changes involving cryptographic or durable identity:

1. Locate the existing authoritative preimage, serializer, digest, identifier, and consumer.
2. Record fixed vectors before editing.
3. Reuse one shared canonical implementation when one identity crosses components.
4. Keep distinct concepts distinct; a signature digest, proof ID, row ID, request ID, package ID, handle input, and routing ID must not become interchangeable by convenience.
5. Test the complete boundary: producer output must be accepted byte-for-byte by the real next consumer or by an exact synthetic substitute.
6. Test lifecycle chains, rotation, revocation, replay, idempotency, concurrency assumptions, timestamp semantics, and collision behavior as applicable.
7. Treat any unexpected vector change as a blocker until compatibility and deployment state are established.

Module-local tests are insufficient when two modules share an identifier or wire format. Add explicit cross-contract vectors.

## 8. Change Discipline

- Keep the diff within the authorized files and behavior.
- Do not perform unrelated refactors, formatting sweeps, renames, documentation cleanup, or dependency updates.
- Prefer pure contracts and injected ports before runtime wiring.
- Keep protocol objects immutable where established by surrounding code.
- Preserve legacy behavior unless the task explicitly changes it and supplies a migration or cutover plan.
- New parsing and serialization code must define canonical encodings, bounds, field vocabulary, and one non-sensitive failure contract.
- Do not weaken a guard merely to make a test pass.

If design assumptions conflict, stop before editing and return the competing preimages, semantics, or authorities with a recommended reconciliation.

## 9. Testing and Tooling

Start with the smallest deterministic offline test set that proves the change:

```bash
PYTHONDONTWRITEBYTECODE=1 \
pytest -p no:cacheprovider -q tests/unit/test_<module>.py
```

Then run adjacent compatibility tests. Run broad or full suites when the task requires them or when the change's risk justifies them. Long-running checks should run in `tmux` or another persistent session with captured exit status and logs.

Current CI-aligned blocking lint checks are:

```bash
black --check app/ scripts/ tests/
flake8 app/ scripts/ tests/
```

The expected formatter version is Black 26.1.0. Check the installed version before relying on its output.

Also run, as applicable:

```bash
isort --check-only --profile black app/ scripts/ tests/
mypy app/ --ignore-missing-imports --no-strict-optional
git diff --check
```

Full-tree `isort` and `mypy` are currently non-blocking in CI. Report their results accurately and distinguish pre-existing baseline failures from changed-file regressions. Do not install packages, rewrite unrelated files, or broaden scope to repair the baseline without authorization.

For syntax-only Python verification without bytecode artifacts, use `ast.parse` or set `PYTHONDONTWRITEBYTECODE=1`.

Do not suppress warnings or errors in the final report. If a test environment lacks a dependency, identify the exact missing package and prove whether failures reach changed code. Do not claim the suite passed when it did not.

## 10. Dependencies and Network

- Do not add, remove, upgrade, or install project or system dependencies unless authorized.
- Prefer the existing environment and repository tooling.
- Network access for source inspection does not authorize calls to application services.
- Never download and execute an unverified script.
- Treat generated lockfile or manifest changes as dependency changes even when produced automatically.

## 11. Agent Sessions and Processes

- Use persistent sessions for long jobs when the operator's connection may drop.
- Before starting a new agent, check for an existing session in the same worktree.
- Do not kill broad process patterns. Identify and validate the exact PID, command, session, and working directory first.
- Preserve the worktree and capture the final transcript before stopping an interrupted or completed agent session.
- At handoff, report any remaining background process and its purpose.

## 12. Documentation

- Read the canonical contract document for the subsystem being changed.
- Update documentation when a public contract, security invariant, configuration, migration, or activation state changes.
- Do not present planned or dormant behavior as deployed behavior.
- Do not copy transient SHAs, PR numbers, PIDs, temporary paths, or current phase status into permanent guidance.
- Link to the canonical source instead of duplicating normative details across files.

## 13. Required Final Report

At minimum, return:

```text
BASE_HEAD=
HEAD=
HEAD_UNCHANGED=
BRANCH=
FILES_CHANGED=
FILE_SCOPE=
FOCUSED_TESTS=
COMPATIBILITY_TESTS=
FULL_TESTS=
BLACK_VERSION=
BLACK_CHECK=
FLAKE8=
ISORT=
MYPY=
GIT_DIFF_CHECK=
DEPENDENCY_CHANGE=
MIGRATION_CHANGE=
DATABASE_CONTACTED=
HTTP_ROUTE_ADDED=
RUNTIME_WIRING_CHANGE=
SERVICE_RESTARTS=
STAGING_RUNTIME_CHANGE=
PRODUCTION_CHANGE=
STAGED_FILES=
COMMIT_CREATED=
PUSH_PERFORMED=
OVERALL=
```

Use `NOT_RUN`, `NOT_APPLICABLE`, or a precise blocker instead of implying success. Include exact test counts and the causal boundary of any failure.

## 14. Stop Conditions

Stop and ask the operator before proceeding when:

- authorization, identity, privacy, or durable-storage authority is ambiguous;
- two components compute different identifiers for the same entity;
- a required migration or runtime activation was not explicitly authorized;
- a command would contact live data or restart a service;
- a dependency or permission repair is required;
- unexpected user changes overlap the task;
- safe rollback or exact target identity cannot be established;
- the requested action would exceed the approved file or environment scope.

Stopping before mutation is a successful safety outcome. Report the evidence and the smallest safe next step.
