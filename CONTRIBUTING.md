# Contributing to the Universal Bitcoin Identity Layer

Thank you for contributing to HODLXXI. This repository contains a security-sensitive Bitcoin-native identity and trust runtime. Changes should be small, reviewable, tested, and explicit about whether they affect source code only or a running environment.

Automated coding agents must also follow the repository-root [`AGENTS.md`](AGENTS.md). Human contributors should use it as the operational safety checklist for agent-assisted work.

## Code of Conduct and Security Reports

Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Do not disclose suspected vulnerabilities in a public issue or pull request. Follow the private reporting instructions in [SECURITY.md](SECURITY.md). Never include credentials, private keys, bearer tokens, cookies, database contents, or unsanitized production logs in an issue, commit, test fixture, or agent transcript.

## Repository and Branch Model

The authoritative repository is:

```text
https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer
```

The long-lived branches have different roles:

- `staging` is the integration branch for current UBID development.
- `main` is the production/release source branch.
- Feature and corrective branches normally start from the exact remote branch named by the task and target that same integration branch in their pull request.
- Promotion from `staging` to `main` is a separate, explicitly authorized release operation.

Never assume a base branch from an old example. Before creating a branch, fetch the intended remote ref and record its exact commit ID.

Use short, descriptive branch names such as:

```text
feat/ubid-<capability>-v1
fix/ubid-<contract>-v1
docs/ubid-<topic>-v1
```

## Isolated Development

Use a dedicated Git worktree for each task. Do not develop in a production or live-staging checkout.

Example for a task explicitly based on `staging`:

```bash
git fetch origin staging
git worktree add ../ubid-feature-v1 \
  -b feat/ubid-feature-v1 \
  origin/staging
cd ../ubid-feature-v1
```

Before editing, verify:

```bash
git rev-parse HEAD
git branch --show-current
git rev-parse --abbrev-ref '@{upstream}'
git status --short --branch
```

If the worktree is not on the expected commit and branch, or contains unexplained changes, stop and resolve the discrepancy before editing.

## Development Environment

Use Python 3.12 when matching the current GitHub Actions environment.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel setuptools
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pip install -e "packages/hodlxxi_mcp[test]"
```

Use only synthetic development credentials and isolated test infrastructure. Never point a development shell, test, or migration rehearsal at a live service or database.

Do not install or upgrade dependencies merely to work around a failing test unless the task explicitly authorizes a dependency change. Record missing-environment failures separately from code failures.

## Change Boundaries

Every pull request should declare its boundary:

- **Source-only:** code, contracts, tests, or documentation are added, but no route, factory composition, migration, configuration, service restart, or deployment is performed.
- **Runtime wiring:** a previously dormant component is composed into an application or exposed through an internal or public route.
- **Database:** a schema, migration, repository, or durable-storage behavior changes.
- **Deployment:** a checkout, environment, proxy, service, or production resource changes.

Do not combine these boundaries by implication. Source availability is not runtime activation. A migration file in source is not authorization to apply it. A merged pull request is not authorization to deploy it.

Keep changes within an explicitly reviewed file scope. Unrelated cleanup, formatting, dependency updates, and documentation rewrites should use separate pull requests.

## Compatibility and Security-Critical Contracts

For cryptographic, identity, authorization, storage, routing, and serialization changes:

1. Identify the existing authoritative canonical representation and identifier.
2. Freeze known preimages, digests, signatures, handles, and package vectors before editing.
3. Test compatibility across adjacent components, not only within the changed module.
4. Reject alternative encodings, ambiguous state, partial state, duplicate state, stale state, and mismatched identifiers.
5. Keep public errors non-sensitive and fail closed.
6. Keep private keys, plaintext, message keys, raw subjects, credentials, and unneeded public-key material out of logs and outward storage contracts.
7. Document intentional vector changes and prove that no deployed or persisted data relies on the superseded vector.

A new contract is not complete until its output is accepted byte-for-byte by the next real consumer or an exact synthetic compatibility test proves that boundary.

## Testing

Start with focused tests for the files and contracts changed. Use deterministic, offline execution where possible:

```bash
PYTHONDONTWRITEBYTECODE=1 \
pytest -p no:cacheprovider -q tests/unit/test_<module>.py
```

Expand to adjacent compatibility tests, then to the broader suite appropriate to the change. The complete GitHub Actions pytest job may take up to 45 minutes and installs the MCP test extras.

Current blocking lint commands are:

```bash
black --check app/ scripts/ tests/
flake8 app/ scripts/ tests/
```

The repository currently pins these development-tool versions:

```text
black 26.1.0
flake8 6.1.0
isort 5.13.2
mypy 1.7.1
```

Check import ordering and types where relevant:

```bash
isort --check-only --profile black app/ scripts/ tests/
mypy app/ --ignore-missing-imports --no-strict-optional
```

At present, full-tree `isort` and `mypy` are non-blocking in CI. Do not conceal their output, but distinguish an existing repository baseline failure from a regression introduced by the pull request. Changed files should still pass applicable focused checks.

Before commit:

```bash
git diff --check
git status --short
git diff --stat
git diff
```

Database or integration tests that need PostgreSQL must use a disposable cluster on an explicitly isolated socket or non-live port. They must prove teardown and must never reuse production or staging connection settings.

## Commits and Pull Requests

Use a concise imperative commit subject, for example:

```text
Harden Social recipient routing validation
Add identity-signed device binding authorization
Document UBID agent development safeguards
```

A pull request should state:

- exact base branch and base commit;
- purpose and security boundary;
- exact files changed;
- behavior added, changed, and deliberately not activated;
- compatibility vectors preserved or intentionally changed;
- focused and broader test results;
- known baseline failures, with evidence that they are unrelated;
- database, service, staging, and production impact;
- rollback or recovery plan for any runtime-affecting change.

Open complex or security-sensitive work as a draft. Do not mark it ready until the worktree is clean, the intended review is complete, and CI is green. The operator decides when review is sufficient and when a pull request may merge.

Merging source does not authorize branch deletion, deployment, service restart, migration application, or production change.

## Documentation

Update the canonical document for a changed contract and link rather than duplicating normative rules across multiple files. Use [`docs/DOCUMENTATION_MAP.md`](docs/DOCUMENTATION_MAP.md) to distinguish current, historical, experimental, and archival material.

Do not place transient commit IDs, pull-request numbers, process IDs, temporary paths, or phase-specific status in permanent contributor guidance.

## Project Structure

```text
app/                         Flask runtime, services, contracts, and adapters
deployment/                  deployment documentation and templates
docs/                        architecture, protocol, operations, and phase documents
hodlxxi_sdk/                 Python SDK
migrations/                  reviewed database migrations
packages/hodlxxi_mcp/        MCP package and its tests
scripts/                     maintenance and verification scripts
skills/                      public agent skill definitions
tests/unit/                  isolated unit and contract tests
tests/integration/           multi-component integration tests
tools/                       repository tooling
.github/workflows/           authoritative CI workflows
```

When this guide and an executable workflow disagree, treat the workflow as the current command source and update this guide in a separate documentation correction.

## License

Contributions are licensed under the repository's [MIT License](LICENSE).
