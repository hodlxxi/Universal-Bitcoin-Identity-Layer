# QR Batch Final Audit Checklist

## A. Purpose

This checklist is the final QR batch gate used after collecting the QR PRs into an integration branch and before staging validation. It is a defensive Blue Team release-readiness checklist for validating the QR feature batch as one reconciled diff, not an authorization to merge, deploy, or expand runtime authority.

## B. Batch inventory to verify

| PR number | Expected role | Expected canonical status |
| --- | --- | --- |
| #380 | QR Pointer v0 docs/canon | Canonical docs/canon source |
| #381 | QR Pointer docs/schema/verifier descriptor | Canonical docs/schema/verifier descriptor source |
| #382 | QR Pointer and Delegation v0 non-authority hardening | Canonical non-authority hardening source |
| #383 | Read-only `/qr/<token>` landing | Canonical landing-surface source if included |
| #384/#385 | Verify-target support and route hardening/finalization | Canonical verify-target hardening/finalization source after reconciliation |
| #386 | QR feature batch integration plan | Canonical integration plan |
| #387 | Duplicate of #386 | Duplicate, not canonical; exclude or close rather than treating as the canonical integration plan |
| #388 | Offline export tooling | Canonical offline export source |
| #389 | Print/revocation workflow | Canonical print/revocation workflow source |

## C. Integration branch gates

- [ ] Branch is created from latest `main`.
- [ ] QR PRs are applied in logical order.
- [ ] Conflicts are resolved once in the integration branch.
- [ ] There is no accidental merge to `main`.
- [ ] There is no production deploy.
- [ ] There is no staging deploy until this checklist passes.
- [ ] Duplicate PRs are excluded or reconciled.
- [ ] Final branch diff is reviewed as a whole.

## D. Runtime surface gates

- [ ] `/qr/<token>` exists only if the landing PR is included.
- [ ] `/qr/<token>` is read-only.
- [ ] There is no auto-redirect.
- [ ] There is no job creation.
- [ ] There is no job mutation.
- [ ] There is no approval mutation.
- [ ] There is no payment mutation.
- [ ] There is no receipt issuance.
- [ ] Revoked/expired pointers are terminal and safe.
- [ ] Unknown pointers fail closed.
- [ ] Malformed records fail closed.
- [ ] There are no external target URLs.
- [ ] There are no protocol-relative target URLs.
- [ ] There is no traversal.
- [ ] There are no arbitrary local targets.
- [ ] `/agent/verify/<job_id>` remains the verification authority.
- [ ] QR landing must not call receipt verification as a side effect.

## E. Capabilities/public-surface gates

- [ ] `/agent/capabilities` does not advertise `/qr/` unless a later explicit audited PR changes that intentionally.
- [ ] No delegation runtime endpoints are advertised.
- [ ] No policy runtime endpoints are advertised.
- [ ] No external provider endpoints are advertised as authority.
- [ ] Public surfaces documentation matches runtime behavior.

## F. Non-authority claim gates

Confirm that no docs, UI, templates, scripts, fixtures, test names, or printed wording imply:

- [ ] Scan proves identity.
- [ ] Scan proves consent.
- [ ] Scan proves approval.
- [ ] Scan proves delegation.
- [ ] Scan proves authorization.
- [ ] Scan proves payment.
- [ ] Scan proves receipt validity.
- [ ] Scan proves reputation.
- [ ] Scan proves trust.
- [ ] Scan proves human presence.
- [ ] QR is a bearer credential.
- [ ] QR is an audit log.
- [ ] Provider analytics are HODLXXI audit evidence.

## G. Secret/privacy gates

- [ ] No secrets in QR records.
- [ ] No private keys.
- [ ] No macaroons.
- [ ] No cookies.
- [ ] No credentials.
- [ ] No access tokens.
- [ ] No refresh tokens.
- [ ] No raw invoices.
- [ ] No payment requests.
- [ ] No customer secrets.
- [ ] No PII embedded in token values.
- [ ] No third-party analytics added.

## H. Offline export gates

- [ ] Offline export script runs offline.
- [ ] Export script does not perform network calls.
- [ ] Export script validates base URL.
- [ ] Export script validates token.
- [ ] Export script validates target allowlist.
- [ ] Export script does not print full record JSON by default.
- [ ] Output file is not written when validation fails.
- [ ] Optional QR image dependency fails clearly if unavailable.
- [ ] Generated QR payload is `<base-url>/qr/<token>`.

## I. Print/revocation workflow gates

- [ ] Safe printed wording documented.
- [ ] Unsafe printed wording documented.
- [ ] Inventory guidance documented.
- [ ] Rotation workflow documented.
- [ ] Revocation workflow documented.
- [ ] Incident workflow documented.
- [ ] Environment separation documented.
- [ ] Staging/test QR material is clearly separated from production material.

## J. Test/lint gates

Example commands for the final integration branch:

```bash
python -m black --check app scripts tests
python -m pytest -q tests/unit/test_qr_pointer_v0_docs_contract.py
python -m pytest -q tests/unit/test_qr_pointer_v0_schema_contract.py
python -m pytest -q tests/unit/test_agent_delegation_v0_contract.py
python -m pytest -q tests/unit/test_qr_feature_batch_docs_contract.py
python -m pytest -q tests/unit/test_qr_pointer_export_contract.py
python -m pytest -q tests/unit/test_qr_pointer_print_revocation_docs_contract.py
python -m pytest -q tests/unit/test_qr_batch_final_audit_docs_contract.py
python -m pytest -q tests/integration/test_qr_pointer_route_contract.py
python -m pytest -q tests/integration/test_agent_surface_machine_readable_contract.py
python -m pytest -q tests/integration/test_operator_continuity_surface.py
python -m pytest -q tests/integration/test_agent_ubid.py
python -m pytest -q
```

Some tests may only exist after the integration branch includes the relevant QR PRs. Missing tests before integration may be expected on isolated PR branches. On the final integration branch, expected QR batch tests must exist or be intentionally reconciled.

## K. Staging validation gates

Staging validation is intentionally deferred until the QR batch integration branch is complete and this final audit checklist passes.

- [ ] Deploy integration branch to staging only after full local/CI tests pass.
- [ ] Smoke test `/qr/<active-token>`.
- [ ] Smoke test revoked token behavior.
- [ ] Smoke test expired token behavior.
- [ ] Smoke test unknown token behavior.
- [ ] Smoke test allowed `/agent/verify/<job_id>` target landing.
- [ ] Verify no redirect.
- [ ] Verify capabilities do not advertise `/qr/` unless intentionally changed.
- [ ] Verify no production secrets are used.
- [ ] Verify staging base URL and tokens are marked staging/test.
- [ ] Record staging results before main merge.

Do not include production deploy commands in this checklist or in staging validation evidence.

## L. Main merge gates

- [ ] Staging passed.
- [ ] Final integration diff reviewed.
- [ ] Rollback branch/commit identified.
- [ ] Operator accepts risk.
- [ ] No unresolved duplicate PRs.
- [ ] Duplicate #387 excluded or closed.
- [ ] Main merge only after staging.

## M. Production rollout gates

Production rollout is separate and later. Production rollout requires its own preflight, backup/rollback, smoke tests, and operator approval. This doc does not authorize production deployment.

## N. Rollback

- [ ] Before main merge: delete or abandon integration branch.
- [ ] After main merge: revert final integration PR or revert QR PRs in reverse order.
- [ ] No DB cleanup expected unless a future PR introduces DB storage.
- [ ] Remove generated QR files and stop distributing printed QR material if needed.
