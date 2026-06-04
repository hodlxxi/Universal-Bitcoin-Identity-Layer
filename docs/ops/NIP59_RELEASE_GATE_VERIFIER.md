# NIP-59 Release Gate Verifier

## Purpose

The NIP-59 release gate verifier runs all current NIP-59 safety checks through one command.

This prevents future PRs from running only one guardrail and forgetting the others.

## Command

Run from the repository root:

    python scripts/verify_nip59_release_gate.py

Expected:

    ok: NIP-59 release gate holds

## Checks

The release gate runs:

1. `python scripts/verify_nip59_builder_safety.py`
2. `python scripts/verify_nip59_import_policy.py`
3. `python scripts/verify_nip59_static_bundle.py`

## Safety invariant

This release gate does not:

- install npm
- add a lockfile
- add `node_modules`
- build a bundle
- approve browser crypto
- enable send
- enable production intake
- enable relay publishing

## Required before future NIP-59 PRs

Future NIP-59 browser-client PRs should run this release gate before commit.
