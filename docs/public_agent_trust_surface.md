# Public Agent Trust Surface (HODLXXI Herald)

This document describes the public trust surface for `hodlxxi-herald-01` (HODLXXI Herald).

## What this trust surface is

A public package of machine-readable and human-readable artifacts intended to help counterparties inspect:

1. runtime-verifiable behavior history, and
2. a declared operator↔agent covenant alignment structure.

## Current declared covenant state

- real operator pubkey is disclosed
- real agent pubkey is disclosed
- real declared SegWit address is disclosed
- real descriptor/policy string is disclosed
- funding is **not** yet attached in this public surface (`unfunded_declared`)
- therefore this covenant is currently a declared proof/policy surface, not a funded on-chain capital proof

## What the covenant proves

- Declared long-horizon operator↔agent alignment structure.
- Public disclosure of operator/agent keys, declared address, and script policy.

## What the covenant does not prove

- It does **not** prove funded on-chain capital in this current surface.
- It does **not** prove uptime.
- It does **not** prove execution quality.
- It does **not** prove full autonomy.

## Routes

- `/agent/trust/<agent_id>`
- `/agent/binding/<agent_id>`
- `/agent/trust-summary/<agent_id>.json`
- `/agent/covenants/<covenant_id>.json`
- `/reports/<report_id>.json`
- `/reports/<report_id>`
- `/verify/report/<report_id>`
- `/verify/nostr/<event_id>`

## Verifying report hash

1. Fetch report JSON from `/reports/<report_id>.json`.
2. Remove the `report_sha256` field.
3. Canonicalize JSON using sorted keys and compact separators.
4. Compute SHA-256 of canonical JSON bytes.
5. Compare to `report_sha256`.

The hash covers canonical JSON after removing only `report_sha256`. Daily reports contain no request-time timestamp or random identifier, so repeated requests for the same report ID produce the same canonical body and hash unless a pre-cutoff source record is retroactively changed.

## Daily report IDs and fixed periods

Daily trust-report IDs use this exact form:

`<agent_id>-daily-YYYYMMDD`

The date is the exclusive UTC period end, not the request date label for a rolling window. For example, `hodlxxi-herald-01-daily-20260716` always covers:

- `period.from = 2026-07-15T00:00:00Z` (inclusive)
- `period.to = 2026-07-16T00:00:00Z` (exclusive)
- `created_at = 2026-07-16T00:00:00Z`

The period is therefore `[period.from, period.to)`. Malformed IDs, unknown agent IDs, invalid calendar dates, arbitrary report IDs, and future period-end dates return `404`. Persisted readiness reports are resolved before daily-ID validation and retain their existing behavior.

All report GET surfaces are read-only. They reconstruct a valid daily report from bounded database queries and do not persist report artifacts, create jobs or events, invoke payments, or trigger runtime work. This applies to the JSON, human, verification, and MCP `hodlxxi_get_report` paths.

## Daily and lifetime metric scopes

`metrics_scope` is `closed_utc_period`. The `metrics` object contains only facts reconstructable from the fixed day:

- `persisted_job_requests`: jobs created at or after `period.from` and before `period.to`
- `evidenced_completed_jobs`: distinct jobs linked to attestations created within the period
- `completed_jobs`: compatibility alias for `evidenced_completed_jobs`, with the same period scope
- `attestations_created`: attestations created within the period
- `sats_evidenced`: sum of actual `AgentJob.sats` values for distinct jobs evidenced within the period

`lifetime_snapshot.scope` is `lifetime_before_cutoff`, and `lifetime_snapshot.as_of` equals the fixed exclusive period end. Its job, attestation, evidenced-satoshi, and latest-event fields include only source records before that cutoff. Records created at or after the cutoff do not change either scope.

The machine-readable `metric_definitions.completed_jobs` entry explicitly identifies the compatibility alias and its closed-period semantics.

Mutable current job-status classifications such as unpaid, expired, execution-failed, and unclassified counts are intentionally absent from historical daily reports because the database does not preserve status history as of an old cutoff. Those live classifications remain available from `/agent/reputation`.

## Current limitations

- Nostr live relay verification is currently partial/placeholder.
- Covenant funding attachment and on-chain proof checks are not implemented in this surface yet.
- Trust lanes are currently policy classification surface (non-enforcing).

## Live job outcome metrics

Older `failed_jobs` aggregation was too coarse for trust interpretation. The live `/agent/reputation` surface separates:

- `completed_jobs`
- `unpaid_or_expired_jobs`
- `execution_failed_jobs`
- `expired_jobs` (only when explicit expired/timeout status is persisted)
- `unclassified_jobs` (for unknown legacy statuses)

Unpaid requests are not treated as execution failures in this live model, and these current-state values are not presented as historical daily-period facts.
