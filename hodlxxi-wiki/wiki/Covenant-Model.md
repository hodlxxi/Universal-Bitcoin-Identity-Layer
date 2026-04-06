# Covenant Model

## Conceptual framing in repository docs
Repository docs describe long-horizon (21-year themed) Bitcoin covenant/timelock ideas tied to trust continuity and capital commitment.

## Runtime-visible related surfaces
- Descriptor/covenant-related endpoints exist in legacy/compatibility surfaces (e.g., `/verify_pubkey_and_list`, script decode/import/export endpoints).
- Agent trust artifacts include covenant metadata and `funding_status` fields.

## Verified conservative interpretation
- Tests enforce `unfunded_declared` wording and verify report/trust surfaces avoid overclaiming funded status.
- Repository includes covenant artifact JSON under `app/data/trust/` and related trust-surface helpers.

## Not established by this wiki pass
- Live on-chain funded covenant proof is not verified here.
- "Covenant-backed" should be treated as a trust lane declaration unless funding proof surfaces are explicitly exposed and validated.
