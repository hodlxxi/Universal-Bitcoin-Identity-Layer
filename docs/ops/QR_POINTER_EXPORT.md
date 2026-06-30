# QR Pointer Offline Export

## Purpose

`scripts/export_qr_pointer.py` is an offline operator tool for producing a static QR Pointer payload URL, and optionally a local QR image file, from an existing local QR Pointer record. The payload is always the HODLXXI-owned landing URL:

```text
<base-url>/qr/<token>
```

The export tool is discovery-only. It does not make the QR code an authority, approval, delegation, payment, receipt, reputation, trust, or human-presence proof.

This PR keeps validation script-local to avoid runtime imports with side effects; final QR batch integration may consolidate these checks into shared helpers after the canonical QR Pointer modules are present on the integration branch.

## Threat model

The safe authority boundary is HODLXXI pointer state, not possession of a printed code and not an external QR provider dashboard. The tool therefore:

- runs locally and offline;
- reads only local JSON pointer records or a local static registry directory;
- rejects external and protocol-relative targets;
- rejects secret-like fields before printing output;
- rejects authority-claim fields such as `consent`, `approval`, `delegation`, `authorization`, `payment_proof`, `receipt_validity`, `trust`, `reputation`, and `human_presence`;
- does not write analytics or audit events;
- does not mutate pointer records;
- does not call third-party QR provider APIs.

## How to export a static QR payload

From a local pointer record:

```bash
python scripts/export_qr_pointer.py \
  --dry-run \
  --record path/to/pointer.json \
  --base-url https://example.com
```

From a local registry directory, when a matching static record exists:

```bash
python scripts/export_qr_pointer.py \
  --dry-run \
  --registry-dir path/to/registry \
  --token Pointer_123 \
  --base-url https://example.com
```

The command prints the payload URL, the local target path, a status line, and the required discovery-only warning. It never prints the full record JSON by default.

## How to generate a PNG/SVG if supported

If the optional QR image dependency is installed, write a PNG:

```bash
python scripts/export_qr_pointer.py \
  --record path/to/pointer.json \
  --base-url https://example.com \
  --output out/pointer.png
```

SVG output is also supported through the existing `qrcode` package SVG image factory:

```bash
python scripts/export_qr_pointer.py \
  --record path/to/pointer.json \
  --base-url https://example.com \
  --output out/pointer.svg
```

If the QR dependency is unavailable, the script fails clearly and safely with instructions to install project requirements or run without `--output` for payload-only export. Validation happens before any image file is written.

## Why this is offline-only

The export step only needs the canonical token and local target metadata. Network access would increase risk without improving authority. Offline operation keeps the export deterministic, reviewable, and independent of third-party provider availability.

## Why third-party dynamic QR providers are not authority

A third-party provider can host a redirect or modify a destination, but it cannot define HODLXXI pointer validity. HODLXXI remains the only authority and trust base for pointer status and target interpretation.

## Why provider analytics are not audit logs

Provider scan analytics are external observations, not HODLXXI audit records. They can be incomplete, mutable, provider-specific, and disconnected from runtime authorization context. Do not treat provider analytics as evidence of identity, consent, approval, delegation, authorization, payment, receipt validity, reputation, trust, or human presence.

## Safe wording for printed QR

Use wording such as:

- "Scan to discover the current HODLXXI pointer page."
- "Discovery QR: check HODLXXI status before relying on this information."
- "This QR code points to a HODLXXI-controlled discovery page."

## Unsafe wording to avoid

Avoid wording such as:

- "Scan to approve."
- "Scan to prove identity."
- "Scan to authorize delegation."
- "Scan for payment proof."
- "Scan for receipt validity."
- "Scan to prove trust, reputation, or human presence."

## Revocation note

Revoke by changing HODLXXI pointer status. Do not trust provider-side QR mutation, redirect edits, or analytics controls as revocation authority.

## Rollback

Remove generated image files and stop distributing the printed QR. No database cleanup is required because this tool does not create tables, migrations, analytics, audit events, or runtime state.

## Staging validation

Staging validation is deferred until the QR batch is complete and the operator collects the QR PRs into the integration branch for final audit and staging validation.
