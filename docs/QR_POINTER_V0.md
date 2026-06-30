# QR Pointer v0

QR Pointer v0 is a static, read-only local landing surface for bounded HODLXXI discovery links. A QR Pointer is only a pointer. It is not authority and it does not perform runtime actions.

## Receipt verification target phase

A QR Pointer may target a bounded local receipt verification surface using `/agent/verify/<job_id>`.

Safe user-facing wording:

- “Open HODLXXI receipt verification page.”
- “This QR Pointer only links to a verification surface.”
- “The verification endpoint, not the QR code, performs receipt verification.”

Unsafe wording:

- “QR verified.”
- “Receipt valid because QR scanned.”
- “Scan proves payment.”
- “Scan proves completion.”
- “Scan proves trust.”

Contract requirements:

- QR Pointer possession does not prove receipt validity.
- A copied QR only reopens the same verification surface.
- `/qr/<token>` must not issue receipts or mark jobs complete.
- `/agent/verify/<job_id>` remains the verification authority.
- `/qr/<token>` must not create, mutate, approve, pay, complete, verify, delegate, authorize, or human-approve jobs.
- `/qr/<token>` must not expose request payloads or private job details.
