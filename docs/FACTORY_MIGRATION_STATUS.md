# Factory Migration Status

## Why this work was started

The earlier factory migration work was started to move the project toward a canonical factory-based application construction path. The technical intent was to reduce monolith-versus-factory drift, preserve legacy compatibility where required, and improve long-term maintainability of runtime initialization.

## What was already attempted

A substantial earlier refactor PR (PR #80) implemented major migration work, including broad runtime-path changes and compatibility handling. That work was merged once, and it should be read as evidence of real architectural effort rather than a draft or placeholder attempt.

## Why it was reverted

The merged migration was later intentionally reverted. The revert was a stability-first decision made to avoid runtime regressions while compatibility and page-level behavior concerns were still being validated against current production behavior.

## Current status

The factory migration direction is deferred, not abandoned. The project is prioritizing current runtime stability and compatibility while keeping factory convergence as an active refactor direction. Future migration work should resume from current repository truth, not from assumptions about the earlier merged state.

## How to interpret the earlier PR

Reviewers and grant evaluators should treat the earlier migration PR as evidence of substantial architectural work that already occurred. It should not be interpreted as current production truth, and it should not be treated as an as-is merge candidate in its prior form.

## Next-step intent

The architectural direction remains to reduce current-state monolith/factory pressure with careful, runtime-verified sequencing. The earlier revert should be understood as engineering caution around compatibility and runtime concerns, not as a permanent rejection of factory-based convergence.
