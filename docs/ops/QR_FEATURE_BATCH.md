# QR Feature Batch Integration Plan

## Purpose

The QR Pointer feature batch defines QR Pointer as a discovery and verification entry surface only. A QR scan may help a verifier reach a local, read-only, machine-checkable entry point, but the scan itself is not authority and must not create or imply a runtime decision.

QR Pointer must not be treated as any of the following:

- authority;
- consent;
- approval;
- delegation;
- identity;
- payment proof;
- receipt proof or receipt validity;
- reputation proof;
- trust proof;
- human-presence proof or human presence proof.

This plan exists so the QR feature batch can remain reviewable, auditable, and compatible while the operator collects the related PRs into a later integration branch for final audit and staging validation.

## Current batch PR inventory

| PR | Title / short purpose | Intended role | Merge / integration order | Runtime impact | Notes |
| --- | --- | --- | --- | --- | --- |
| #380 | QR Pointer v0 docs/canon | Establish canonical QR Pointer v0 documentation and non-authority semantics. | 1 | No | Documentation/canon baseline for the rest of the batch. |
| #381 | QR Pointer docs/schema and verifier descriptor | Add schema/docs coverage and expose `qr_pointer` in `/agent/verify` responses. | 2 | Yes | Descriptor-only verifier surface; does not make QR authoritative. |
| #382 | QR Pointer and Delegation v0 non-authority boundary hardening | Harden language and contracts around QR Pointer and Delegation v0 boundaries. | 3 | No | Keeps discovery separate from delegation, approval, identity, trust, payment, and receipt claims. |
| #383 | Read-only local `/qr/<token>` static landing surface | Add a local static QR landing route that is read-only. | 4 | Yes | Must not mutate jobs, issue receipts, create delegations, or act as consent/approval. |
| #384/#385 | Verify-target support and hardening/finalization for QR Pointer route | Add and finalize verify-target support and hardening around the QR Pointer route. | 5 | Yes | Apply the final accepted verify-target PR if #384 and #385 overlap. |

## Batch workflow

These PRs are intentionally not being merged to main immediately. They may currently be parallel PRs against `main` while the QR batch is still under review.

At the end of the batch, the operator will create a dedicated integration branch from the latest `main`. The operator will apply the QR PR branches in logical order, resolve conflicts once in the integration branch, and run formatting, lint, tests, and security-oriented checks there.

Only after the integration branch is clean will staging validation happen. Only after staging validation succeeds will any merge to `main` happen. Production rollout is a separate later step and is not part of this documentation-only PR.

## Integration order

Recommended integration order:

1. #380 — QR Pointer v0 docs/canon.
2. #381 — QR Pointer docs/schema/verifier descriptor.
3. #382 — non-authority hardening.
4. #383 — static read-only QR landing.
5. #384/#385 — verify-target hardening/finalization, or the final accepted verify-target PR.
6. Any later QR export or operator tooling PRs.
7. Final QR integration/audit PR.

## Safety invariants

The final integrated QR batch must preserve these invariants:

- no scan-as-consent;
- no scan-as-approval;
- no scan-as-delegation;
- no scan-as-identity;
- no scan-as-payment;
- no scan-as-receipt-validity;
- no scan-as-trust;
- no scan-as-human-presence;
- no QR bearer credentials;
- no secrets in QR pointer records;
- no external mutable provider as trust base;
- no analytics as audit log;
- no job mutation from `/qr/<token>`;
- no receipt issuance from `/qr/<token>`;
- no delegation runtime unless later explicitly implemented and reviewed.

## Final integration checklist

The following commands are examples for the later integration branch. They are intentionally generic and non-destructive. Operators should adapt branch names to the actual PR branches selected for final integration.

```bash
# Fetch all branches and PR refs available to the local checkout.
git fetch --all --prune

# Create a dedicated integration branch from the latest main.
git checkout main
git pull --ff-only origin main
git checkout -b qr-feature-batch-integration

# Apply or merge QR PR branches in the documented order.
# Example only; use the actual reviewed branch names or cherry-pick ranges.
git merge --no-ff <qr-pr-380-branch>
git merge --no-ff <qr-pr-381-branch>
git merge --no-ff <qr-pr-382-branch>
git merge --no-ff <qr-pr-383-branch>
git merge --no-ff <final-verify-target-branch>

# Run formatting and checks.
python -m black .
python -m ruff check .
python -m pytest -q tests/unit/test_qr_pointer_v0_docs_contract.py
python -m pytest -q tests/integration/test_agent_surface_machine_readable_contract.py
python -m pytest -q tests/integration/test_operator_continuity_surface.py
python -m pytest -q tests/integration/test_agent_ubid.py
python -m pytest -q
```

Additional manual inspection checklist:

- Inspect public surfaces for accidental authority, consent, approval, delegation, identity, payment, receipt validity, trust, or human-presence claims.
- Inspect `/agent/capabilities` and machine-readable descriptors for no accidental `/qr/` advertisement unless a later PR intentionally changes that contract and receives review.
- Confirm `/qr/<token>` remains read-only and cannot mutate jobs, issue receipts, or create delegations.
- Confirm QR pointer records contain no secrets or bearer credentials.
- Confirm no production secrets, credentials, or environment files were touched.
- Confirm no analytics path is treated as an audit log.

## Rollback strategy

Because the batch is integrated in a separate branch first, rollback before merging to `main` is branch deletion or branch-only revert. No production rollback should be needed before a `main` merge because staging validation is intentionally deferred until the integration branch is clean.

If the QR batch is merged to `main` later, rollback should revert the final integration merge or revert QR PRs in reverse order. No DB rollback should be required unless a future QR PR explicitly adds a migration and receives separate review for that migration.

## Staging validation placeholder

Staging validation is intentionally deferred until the QR batch is complete and the dedicated integration branch has passed local formatting, lint, tests, and public-surface inspection.

Placeholder checklist for the later staging validation window:

- Confirm the integration branch commit set matches the reviewed QR PR set.
- Confirm staging configuration contains no new QR-specific secrets.
- Smoke-test public agent discovery and verifier surfaces.
- Smoke-test QR landing behavior as read-only discovery.
- Confirm no scan creates consent, approval, delegation, payment, receipt validity, trust, identity, or human-presence claims.
- Confirm operator rollback notes are current before any later `main` merge.

No active staging commands or production deploy commands are part of this document.
