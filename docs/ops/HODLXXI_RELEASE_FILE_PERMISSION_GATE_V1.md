# HODLXXI Release File Permission Gate V1

This source-only hardening gate prevents a repeat of the 2026-08-27 fast-forward failure where Git recorded
`100644`/`100755`, the checkout stayed Git-clean, but root's restrictive umask left release files at modes such as
`0600`/`0700` and the service user could not import the application.

The tool is `scripts/hodlxxi_release_permission_gate.py`. It has exactly two subcommands:

```bash
python scripts/hodlxxi_release_permission_gate.py repair \
  --repo /srv/ubid \
  --base <old-full-commit> \
  --target <new-full-commit> \
  --expected-count <changed-file-count> \
  --service-user hodlxxi

python scripts/hodlxxi_release_permission_gate.py verify \
  --repo /srv/ubid \
  --base <old-full-commit> \
  --target <new-full-commit> \
  --expected-count <changed-file-count> \
  --service-user hodlxxi
```

Success prints `status=PASS`, a deterministic `manifest_sha256`, and `restart_authorized=yes`. Any failure prints
`status=FAIL`, exits nonzero, and carries no restart authority.

## Required Operational Order

1. Stop or hold the relevant deployment timer if that action is separately authorized.
2. Capture runtime and checkout guards.
3. Perform the guarded fast-forward.
4. Run `repair` against the exact old and new commits and expected changed-file count.
5. Run `verify` independently against the same exact old and new commits and expected changed-file count.
6. Import the application as the service user.
7. Only then may a separate rollout controller restart the service.
8. Perform health checks and restore the timer.

The permission tool itself must never stop, start, restart, enable, or disable anything. It carries no deployment
authority.

## Gate Behavior

Both subcommands require an exact Git worktree root, exact full lowercase base and target commit IDs, an expected changed
file count, and a non-root service user. The base must be an ancestor of target, and target must equal current `HEAD`.

Before trusting `git status`, the gate scans the complete tracked index with NUL-delimited Git output and rejects every
`assume-unchanged` or `skip-worktree` entry. It does not clear or modify those flags. Dirty tracked content and
unexpected untracked files are still rejected after the index-flag guard.

The release file set is derived from `git diff --raw -z --no-renames` between base and target. Deletions are excluded.
The output is NUL-delimited and fail-closed: malformed output, duplicate target paths, unsafe paths, unsupported statuses,
unsupported Git modes, symlinks, submodules, missing files, non-regular files, hardlinked release targets, dirty tracked
content, untracked files, wrong `HEAD`, wrong count, and root service users all fail.

Only Git modes `100644` and `100755` are accepted. They map exactly to filesystem modes `0644` and `0755`. `verify` is
read-only and requires every release file to already have its exact expected mode. It records each release file's device,
inode, owner, file type, link count, and mode during preflight and rejects any target whose link count is not exactly one.

Service-user access is proven by running a fixed child probe under the configured non-root user's UID, primary GID, and
real supplementary groups. The gate must have effective root authority to perform that credential switch. The probe uses
argument arrays, a fixed minimal environment, suppressed output, and a timeout. It performs an actual read of every
release file and checks execute access for every Git `100755` file, but it never executes the release file itself. Access
denial and probe unavailability both fail closed.

`repair` runs the same repository, commit, worktree, diff, path, count, file-type, and service-user preflight before
changing anything. It opens every release target with no-follow and close-on-exec protections, validates each descriptor
against the preflight device, inode, owner, regular-file type, single-link contract, and mode before the first mutation,
and holds those descriptors while repairing. It then uses descriptor-based `fchmod` only for release files whose modes are
wrong, applying `0644` or `0755` from the target Git tree. It never uses path-based chmod and does not touch unchanged
files or already-correct release files. After each change it revalidates both the descriptor and release path against the
same inode, owner, type, and single-link contract. Before emitting `PASS`, it re-runs the complete repository, index-flag,
mode, inode, and service-user verification. If any validation or `fchmod` fails, the command exits nonzero and states that
no restart is authorized; a later rerun is safe after the underlying condition is corrected.

## Non-Claims

This gate does not perform recursive chmod or chown.
It does not repair ownership.
It does not prove the later application import under the systemd service identity; that remains a separate rollout gate.
It does not prove service-manager sandboxing, environment, database, network, or application-level behavior.
It does not read secrets or deployment environment files.
It does not run Git checkout, update, fetch, reset, or merge operations.
It does not stop, start, restart, enable, disable, or reload any service or timer.
It does not run database or migration actions.
It does not activate staging or production.
