# QR Pointer Print and Revocation Workflow

## A. Purpose

Printed QR codes are physical discovery handles. They point to HODLXXI-controlled `/qr/<token>` landing surfaces so a human can open a controlled discovery or receipt-verification page and review current status.

A printed QR code is not proof of identity, consent, approval, delegation, authorization, payment, receipt validity, reputation, trust, or human presence. QR possession, scan events, copied images, and printed placement must never be treated as authority or evidence for those claims.

## B. Operator print workflow

Use this safe sequence before distributing any printed QR Pointer material:

1. Choose or create a static pointer record for the intended environment.
2. Validate that the pointer target is allowlisted and matches the intended HODLXXI path.
3. Export the payload with `scripts/export_qr_pointer.py`.
4. Generate the QR image only offline/local in an operator-controlled workspace.
5. Inspect the payload URL before printing, including scheme, host, environment, path, and token.
6. Print only safe wording that describes discovery or verification, not authority.
7. Record the token and material location in an operator-controlled inventory.
8. Do not store secrets or customer data in the token or printed material.

## C. Safe printed wording

Acceptable printed text should keep the QR code framed as a pointer only. Examples:

- "Open HODLXXI discovery page."
- "Open HODLXXI receipt verification page."
- "This QR code is a pointer only."
- "Verify status on the HODLXXI page before relying on this information."

## D. Unsafe printed wording

Do not print wording that implies possession or scanning creates authority, proof, trust, approval, delegation, or payment evidence. Unsafe examples include:

- "Scan to approve."
- "Scan proves identity."
- "Scan proves consent."
- "Scan proves delegation."
- "Scan proves payment."
- "Scan proves receipt validity."
- "Trusted by QR."
- "Human approved."

## E. Inventory guidance

Operators may track printed QR materials manually in an operator-controlled inventory. Suggested fields:

- token
- target path
- status
- printed material name/location
- print date
- owner/operator
- intended environment: dev/staging/production
- revocation/retirement date
- notes

Inventory must remain least-authority and non-secret-bearing:

- Do not track private keys.
- Do not track credentials.
- Do not track customer secrets.
- Do not track raw invoices.
- Do not track payment requests.
- Do not track cookies, macaroons, session tokens, access tokens, or refresh tokens.

## F. Rotation workflow

When replacing printed QR Pointer material:

1. Create a new token/pointer for the intended target and environment.
2. Export the new payload with `scripts/export_qr_pointer.py`.
3. Print new material using only safe wording.
4. Deploy replacement material to the intended physical location.
5. Revoke or expire the old pointer.
6. Remove old printed material where feasible.
7. Verify the old QR shows a revoked/expired safe page or `410 Gone` if route behavior is present.

## G. Revocation workflow

HODLXXI pointer status is revocation authority for QR Pointer material. Provider dashboard changes are not revocation authority. Analytics are not revocation evidence.

Revocation should make `/qr/<token>` non-authoritative and non-redirecting. Old QR material may still physically exist after revocation, so any landing page must carry a non-claim warning and must not imply identity, consent, approval, delegation, authorization, payment, receipt validity, reputation, trust, or human presence.

## H. Incident workflow

Use the same conservative response pattern for QR material incidents: revoke or expire the pointer, create a replacement token if the material is still needed, remove or cover physical material if feasible, document the issue internally, and do not infer identity, consent, approval, or authority from scans.

Specific incident handling:

- Lost/stolen printed QR material: revoke/expire the pointer, create a replacement token, update inventory, and remove or cover any known copies where feasible.
- QR copied to unauthorized place: revoke/expire the pointer, create replacement material for authorized locations, document where the copy appeared, and avoid using scan activity as proof of human presence.
- Suspected target substitution: revoke/expire the affected pointer, validate the allowlisted target, create a replacement token, and inspect any printed material before redistribution.
- External provider misuse: revoke/expire the HODLXXI pointer even if provider dashboards still show activity; provider actions and analytics do not prove revocation.
- Accidental unsafe wording printed: stop distribution, remove or cover physical material where feasible, revoke/expire the pointer if already public, and reprint with safe wording.
- Old token discovered in public: revoke/expire the pointer, document discovery, remove or cover the material if feasible, and replace with a new token only if the use case is still valid.

## I. Environment separation

Dev, staging, and production QR tokens and base URLs must not be mixed. Staging QR materials must be clearly marked staging/test. Production QR materials must not point to staging.

Staging validation is deferred until the QR batch is complete. Do not use this documentation PR as approval to deploy staging or production QR materials.

## J. Final integration note

This workflow is documentation for the QR feature batch. Runtime validation will occur later in the integration branch. Production rollout is a separate later step.

## K. Rollback

If printed QR Pointer material must be rolled back:

1. Stop distributing printed material.
2. Remove or cover printed QR material where feasible.
3. Revoke or expire the pointer.
4. Remove generated image files from the operator workspace.
5. Perform no DB cleanup unless a future PR introduces DB storage.
