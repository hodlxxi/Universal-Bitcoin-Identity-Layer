# HODLXXI Wiki Layer Operational Spec

## Purpose
`hodlxxi-wiki` is a repository-local synthesis layer for project intelligence, runtime truth tracking, and documentation continuity. It exists to help maintainers and reviewers navigate evidence already present in code, tests, docs, and captured runtime artifacts.

## Core principles
1. **Evidence-first:** Every substantial claim should be traceable to repository artifacts.
2. **Conservative language:** Prefer wording like "repository indicates" or "tests suggest" when live runtime proof is unavailable.
3. **Additive maintenance:** Preserve prior notes unless they are proven wrong; annotate updates instead of rewriting history.
4. **Explicit uncertainty:** Mark unknowns as `unverified` rather than implied facts.
5. **No runtime authority inflation:** This wiki is not the execution source of truth.

## Hard constraints (critical)
The agent **MUST NOT**:
- mark a feature as **working** without test evidence or runtime evidence;
- infer production readiness from code structure alone;
- upgrade **experimental** to **working** without explicit verification;
- treat documentation claims as proof;
- collapse conceptual framing into runtime guarantees.

If uncertainty exists, the agent **must**:
- mark the claim `unverified`; **or**
- move the claim to `wiki/Experimental.md`.

Violations of these rules are **critical documentation errors** and should be corrected before merge.

## Evidence classes and status labels
Use the following terms explicitly in runtime-oriented pages:
- **Repo-defined:** endpoint/module/config exists in repository code.
- **Test-verified:** behavior is asserted by tests in `tests/`.
- **Runtime-verified:** behavior is evidenced by captured runtime artifacts under `raw/runtime/` (timestamped files).
- **Planned/Aspirational:** documented intent without sufficient code/test/runtime evidence.

## Raw vs wiki separation
- `raw/` contains gathered inputs and evidence snapshots.
- `wiki/` contains human-readable synthesis.
- Never treat `wiki/` synthesis as stronger evidence than `raw/` artifacts or source code.

## Ingestion rules
- Ingest from repository-native sources first: `README.md`, `docs/`, `app/`, `tests/`, and skills.
- For each update cycle, record which source files were consulted in `wiki/log.md`.
- If a claim cannot be backed by a discoverable source file, place it in `wiki/Experimental.md` or mark it `unverified`.

## Raw evidence workflow
- Store runtime captures in `raw/runtime/` using date-stamped filenames.
- Store repo snapshots/excerpts in `raw/repo/` and document snapshots in `raw/docs/`.
- Store tool/run outputs in `raw/logs/`.
- Store non-repo references in `raw/external/` with provenance notes.
- Raw evidence files are append-only artifacts and should not be rewritten after capture.

## Log discipline
- Every update appends an entry to `wiki/log.md`.
- Use normalized format:
  - `[YYYY-MM-DD]`
  - `Event: ...`
  - `Details:` list
  - `Sources reviewed:` list
- Prefer short append-only entries over retrospective rewrites.

## Lint rules
- Keep all required wiki pages present.
- Keep raw subdirectories present with scaffolding docs.
- Avoid empty sections; use `TBD (unverified)` when needed.
- Keep cross-links valid and relative.
- Ensure `wiki/index.md` links all canonical wiki pages.

## Trust discipline
- Separate runtime-confirmed behavior from design intent.
- Do not claim cryptographic or economic guarantees unless corresponding runtime surfaces are visible in code/tests/raw evidence.
- Keep normative framing aligned with `TRUST_MODEL.md`, while preserving runtime caveats.

## Synthesis boundary statement
This wiki is a **synthesis layer**, not execution truth. Canonical runtime truth remains in source code, tests, deployment/runtime evidence, and production telemetry.
