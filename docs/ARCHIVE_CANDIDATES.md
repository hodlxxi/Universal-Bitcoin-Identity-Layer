# HODLXXI Archive Candidates

This file is an index of documents that may be stale, superseded, low-value, unlinked, or candidates for future archival/removal. It is not a deletion request. Candidate files must not be deleted without a separate focused review PR.

## Rules

- Do not delete files in the same PR that introduces or updates this index.
- Do not archive or remove a file if it is linked from current runtime/readiness docs.
- Check `docs/DOCUMENTATION_MAP.md` and `docs/READINESS_EVALUATION.md` before removing anything.
- Schema files require extra care because external systems may reference their `$id` even when Git references are sparse.
- Social/outreach drafts may be kept as historical communication examples even if not operational docs.

## Current candidates

| Path | Current classification | Why it is a candidate | Safe action |
| ---- | ---------------------- | --------------------- | ----------- |
| `docs/CI_PING.md` | Low-value CI marker | one-line ping/checkpoint file; no operational value beyond historical CI noise | remove in a future focused cleanup PR if no current references are added |
| `docs/UI_UNIFICATION.md` | Superseded UI implementation note | Dec 2025 surgical UI/CSS note; not current runtime/readiness truth | move to archive or remove after checking no current UI docs depend on it |
| `docs/agent_ubid_plan.md` | Superseded MVP plan | early agent UBID plan has been superseded by current agent runtime docs, readiness evaluation, receipt docs, and public smoke docs | move to archive or remove after confirming current docs cover the implemented runtime |
| `docs/clawhub/hodlxxi-bitcoin-identity/HEARTBEAT.operator.md` | Tooling/operator side-note | human operator checklist for a ClawHub package; not part of the current public readiness path | keep or archive under tooling docs after a separate ClawHub review |
| `docs/schemas/external_agent_record.schema.json` | Review-before-removal schema | sparse Git references, but schema `$id` may be externally meaningful | do not delete until external schema usage and public URL expectations are checked |
| `examples/social/first_external_paid_call_post.md` | Outreach draft/example | old social post draft for first external paid-call test; not current runtime truth | move to examples/archive or remove after confirming no current outreach docs use it |

## Current references observed

As of the archive-candidates review, these files were primarily referenced from `docs/DOCUMENTATION_MAP.md`. The schema file also contains its own `$id`.

## Not archive candidates

The following are not archive candidates:

- `README.md`
- `docs/READINESS_EVALUATION.md`
- `docs/DOCUMENTATION_MAP.md`
- `AGENT_PROTOCOL.md`
- `docs/AGENT_RUNTIME.md`
- `docs/AGENT_SURFACES.md`
- `docs/AGENT_RECEIPT_V1.md`
- `docs/AGENT_RECEIPT_QUICKSTART.md`
- `docs/OPERATOR_CONTINUITY_E923.md`
- `docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md`
- `docs/sdk/README.md`
- `TRUST_MODEL.md`

## Future cleanup process

1. Open a focused cleanup PR for one candidate or one small group.
2. Show references with `git grep`.
3. Explain whether the file is removed, moved to archive, or kept.
4. Run docs contract tests.
5. Do not mix archive cleanup with runtime changes.
