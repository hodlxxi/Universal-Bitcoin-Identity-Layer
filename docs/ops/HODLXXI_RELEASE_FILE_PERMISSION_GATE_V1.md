# HODLXXI Release File Permission Gate V1

This source-only hardening gate prevents a repeat of the 2026-08-27 fast-forward failure where Git recorded
`100644`/`100755`, the checkout stayed Git-clean, but root's restrictive umask left release files at modes such as
`0600`/`0700` and the service user could not import the application.

The tool is `scripts/hodlxxi_release_permission_gate.py`. It has exactly two subcommands:

```bash
/usr/bin/python3 -I scripts/hodlxxi_release_permission_gate.py repair \
  --repo /srv/ubid \
  --base <old-full-commit> \
  --target <new-full-commit> \
  --expected-count <changed-file-count> \
  --service-user hodlxxi \
  --authorization-lock-fd "$AUTH_LOCK_FD" \
  --authorization-lock-path /run/hodlxxi/release-permission-gate.lock

/usr/bin/python3 -I scripts/hodlxxi_release_permission_gate.py verify \
  --repo /srv/ubid \
  --base <old-full-commit> \
  --target <new-full-commit> \
  --expected-count <changed-file-count> \
  --service-user hodlxxi \
  --authorization-lock-fd "$AUTH_LOCK_FD" \
  --authorization-lock-path /run/hodlxxi/release-permission-gate.lock
```

Success prints `status=PASS`, a deterministic `manifest_sha256`, deterministic authorization-lock device/inode fields,
`lock_bound_authorization=yes`, `authorization_valid_while_caller_retains_lock_fd=yes`, and `restart_authorized=yes`.
Any failure prints `status=FAIL`, exits nonzero, and carries no restart authority.

## Required Operational Order

1. Stop or hold the relevant deployment timer if that action is separately authorized.
2. Capture runtime and checkout guards.
3. Perform the guarded fast-forward.
4. Open the authorization lock in the parent shell, acquire an exclusive nonblocking lock, and retain that descriptor.
5. Run `repair` against the exact old and new commits and expected changed-file count, inheriting the lock descriptor.
6. Run `verify` independently against the same exact old and new commits and expected changed-file count, inheriting the
   same retained lock descriptor.
7. Import the application as the service user.
8. If `verify` printed the lock-bound authorization markers, perform the separately authorized restart while still
   retaining the lock descriptor.
9. Perform health checks.
10. Close the authorization-lock descriptor only after restart verification, then restore the timer.

Example parent-shell handoff:

```bash
AUTH_LOCK_PATH=/run/hodlxxi/release-permission-gate.lock
exec {AUTH_LOCK_FD}<>"$AUTH_LOCK_PATH"
flock -n -x "$AUTH_LOCK_FD"

/usr/bin/python3 -I scripts/hodlxxi_release_permission_gate.py repair \
  --repo /srv/ubid \
  --base "$OLD_COMMIT" \
  --target "$NEW_COMMIT" \
  --expected-count "$CHANGED_FILE_COUNT" \
  --service-user hodlxxi \
  --authorization-lock-fd "$AUTH_LOCK_FD" \
  --authorization-lock-path "$AUTH_LOCK_PATH"

verify_output=$(
  /usr/bin/python3 -I scripts/hodlxxi_release_permission_gate.py verify \
    --repo /srv/ubid \
    --base "$OLD_COMMIT" \
    --target "$NEW_COMMIT" \
    --expected-count "$CHANGED_FILE_COUNT" \
    --service-user hodlxxi \
    --authorization-lock-fd "$AUTH_LOCK_FD" \
    --authorization-lock-path "$AUTH_LOCK_PATH"
)

# While AUTH_LOCK_FD remains open, validate verify_output and run the separately authorized restart.
# After restart verification:
exec {AUTH_LOCK_FD}>&-
```

The gate does not create the lock file for the caller. The lock file should already exist as a regular file owned by the
invoking effective user, with no group or other write bit, and with no hardlinks.

The permission tool itself must never stop, start, restart, enable, or disable anything. It carries no deployment
authority.

## Authorization Lock

Every `verify` or `repair` operation that can print `restart_authorized=yes` requires `--authorization-lock-fd` and
`--authorization-lock-path`. The descriptor must already be open in the caller and inheritable by the gate process. The
path must be the exact absolute normalized path for that lock file.

The gate never opens the authorization lock by pathname. It validates the inherited descriptor with `fstat`, validates
the path with `lstat`, and fails closed unless both identities match the same regular, single-link file. Symlinked,
hardlinked, mismatched, missing, closed, non-inheritable, incorrectly owned, group-writable, other-writable, or
conflicting lock state never carries restart authority.

Before repository preflight, the gate acquires or confirms an exclusive nonblocking `flock` on the inherited open-file
description. Immediately before printing `restart_authorized=yes`, it revalidates the descriptor, path identity, owner,
mode, link count, regular-file type, and exclusive lock state.

The authorization is lock-bound. It is valid only while the parent rollout controller retains its copy of that same
open-file description. A cooperating concurrent rollout process using this protocol cannot acquire the same lock or
enter the authorized restart path until the parent releases the descriptor.

## Gate Behavior

Both subcommands require an exact Git worktree root, exact full lowercase base and target commit IDs, an expected changed
file count, a non-root service user, and the inherited authorization lock. The base must be an ancestor of target, and
target must equal current `HEAD`.

Before trusting `git status`, the gate scans the complete tracked index with NUL-delimited Git output and rejects every
`assume-unchanged` or `skip-worktree` entry. It does not clear or modify those flags. Dirty tracked content and
unexpected untracked files are still rejected after the index-flag guard.

The release file path set is derived from `git diff --raw -z --no-renames` between base and target. Deletions are
excluded. For every retained path, the gate then reads the exact target commit tree to obtain the authoritative Git mode
and target blob object ID. Blob IDs are interpreted with the repository's Git object format, so SHA-1 and SHA-256
repositories use their own native object sizes and digest algorithms.

All Git subprocesses run with replacement-object processing disabled, so local `refs/replace/*` cannot substitute
different commit or tree contents for the exact object IDs being authorized.

The output is NUL-delimited and fail-closed: malformed output, duplicate target paths, unsafe paths, unsupported
statuses, unsupported Git modes, symlinks, submodules, missing files, non-regular files, hardlinked release targets,
dirty tracked content, untracked files, wrong `HEAD`, wrong count, root service users, descriptor hash mismatches, path
replacement, and failed final revalidation all fail.

Only Git modes `100644` and `100755` are accepted. They map exactly to filesystem modes `0644` and `0755`. `verify` is
read-only and requires every release file to already have its exact expected mode. It records each release file's device,
inode, owner, file type, link count, and mode during preflight and rejects any target whose link count is not exactly one.
Both `verify` and `repair` then open every release target without following symlinks and retain those descriptors through
the authorization decision. The gate validates regular-file type, single-link status, device, inode, owner, path binding,
and mode through the retained descriptor. It hashes bytes read from that exact descriptor using Git blob framing
(`blob <size>\0<bytes>`) and requires the digest to equal the target commit blob ID.

Service-user access is proven by running a fixed child probe under the configured non-root user's UID, primary GID, and
real supplementary groups. The gate must have effective root authority to perform that credential switch. The probe uses
argument arrays, a fixed minimal environment, suppressed output, and a timeout. It performs an actual read of every
release file and checks execute access for every Git `100755` file, but it never executes the release file itself. Access
denial and probe unavailability both fail closed.

`repair` runs the same repository, commit, worktree, diff, path, count, and file-type preflight before
changing anything. Before the first release-file `fchmod`, it also proves that the fixed service-user child probe is
available and can perform the required credential switch by running a non-mutating read probe against `/dev/null`. If the release set contains any Git `100755` target, it also exercises the execute-probe path against the resolved regular file behind the fixed probe utility before any release-file mode change.
Failure of effective-root authority, credential switching, child execution, or probe availability therefore fails before
any release-file mode change. Actual read access to every repaired release file, plus execute access for Git `100755`
files, is checked after repair and again at the final authorization boundary. Repair uses descriptor-based `fchmod` only
after the retained descriptor has been revalidated and rehashed as the exact target blob. It never repairs unexpected
content, never uses path-based chmod, and does not touch unchanged or already-correct release files. After each change it
revalidates and rehashes both the descriptor and release path against the same inode, owner, type, single-link contract,
expected mode, and target blob.

Before emitting `PASS` or `restart_authorized=yes`, the gate repeats the hidden-index and clean-worktree checks, repeats
the service-user access probe, revalidates and rehashes every retained descriptor while confirming that every path still
resolves to the same device and inode, and then revalidates the inherited authorization lock. Concurrent writes,
truncation, replacement, unlink, relink, chmod, symlink swap, metadata change, blob mismatch, lock replacement, lock mode
relaxation, lock hardlinking, or failed final revalidation exits nonzero and states that no restart is authorized; a
later rerun is safe after the underlying condition is corrected.

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
It does not protect against an arbitrary privileged process deliberately ignoring the rollout lock. That is host
compromise, outside what a userspace preflight gate can prevent.

## Git filesystem-monitor boundary

All Git probes owned by this gate force `core.fsmonitor=false` on the Git command line. The clean-worktree decision therefore does not trust repository-configured filesystem-monitor hooks or cached fsmonitor changed-path results.

## Descriptor Hash Race Boundary

Each target-blob descriptor hash is bracketed by descriptor metadata and path
validation. A size, mtime, ctime, filesystem-mode, descriptor-identity, or path
binding change observed across the hash fails closed.

After the final post-hash validation, continued stability against authorized
rollout writers relies on the caller retaining the same exclusive rollout lock.
Authorized rollout writers must obey that lock protocol. A process with
filesystem write authority that deliberately ignores the rollout lock is
outside this userspace gate's threat model and is treated as host/protocol
compromise.
## Git configuration and CLI denial hardening

Release-diff derivation explicitly uses `--ignore-submodules=none`. Local
`diff.ignoreSubmodules` or per-submodule ignore configuration therefore cannot
hide a gitlink change from the release set. Git mode `160000` remains
unsupported and fails closed.

Malformed or incomplete `verify` / `repair` command lines are emitted through
the same structured denial boundary as other gate failures:
`status=FAIL` and `operator_action=do_not_restart`. Explicit help output remains
ordinary argparse help behavior and is not treated as a release denial.


## Failure-output injection hardening

Failure reasons are treated as untrusted diagnostic data. Before a reason is
written to the structured failure stream, percent signs, equals signs and
non-printable characters are percent-encoded. This keeps every denial on the
structured fail path and prevents a malicious or unusual release/lock path from
injecting strings such as `restart_authorized=yes` or `status=PASS` into a
failure record.

The trusted structured fields themselves remain unchanged:
`status=FAIL` and `operator_action=do_not_restart`.


## Isolated interpreter and inode-bound service probe

Every operator invocation of this gate uses the fixed isolated interpreter
form `/usr/bin/python3 -I`. The gate's shebang carries the same isolated
interpreter requirement. This prevents the worktree `scripts/` directory from
becoming an import source before gate validation, including stdlib-shadow names
such as `argparse.py` or `hashlib.py`.

The generic credential-switch probe used before repair remains only a probe of
the fixed probing mechanism itself. It is not evidence about a release file.

Release-file authorization uses a separate inode-bound service-user probe.
After dropping to the exact service identity, the child opens the release path
with `O_PATH|O_NOFOLLOW|O_CLOEXEC`, compares the resulting `fstat()` identity
against the complete inspected `FileIdentity`, and only then checks read or
execute access through `/proc/self/fd/<fd>`. A pathname substitution therefore
cannot satisfy the access check for a different inode and later be restored to
obtain restart authorization.


## Bound-probe repair preflight

Before any repair `fchmod`, the gate proves both probe mechanisms are usable
under the target service identity. The generic credential-switch probe is
checked first. The inode-bound probe is then exercised against fixed,
known-accessible targets using exact `FileIdentity` values.

If either probe is unavailable, cannot switch credentials, cannot inspect the
expected inode, or returns an unusable result, repair fails before changing any
release-file mode and no restart is authorized.


## Final fail-closed edge hardening

Clean-worktree status checks explicitly use `--ignore-submodules=none`.
Repository or submodule configuration therefore cannot hide dirty or untracked
submodule state from the release authorization decision.

For read authorization, the inode-bound service-user probe does not rely only
on `access(2)`. After opening and identity-checking the release target under the
service identity, it reopens the retained inode through `/proc/self/fd`, verifies
the same complete `FileIdentity`, and performs an actual one-byte read. Empty
files are valid: a zero-byte read still proves that the open/read operation was
permitted.

Malformed authorization-lock descriptor values, including integers outside the
platform file-descriptor range, remain inside the structured fail-closed path
and cannot escape as an uncaught `OverflowError`.
