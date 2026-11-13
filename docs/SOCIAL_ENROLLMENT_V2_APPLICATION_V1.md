# Explicit V2 enrollment application assembly

This source provides a separate operator-selected application factory,
`app.services.social_enrollment_v2_runtime:create_social_enrollment_v2_app()`.
The ordinary factory retains its existing behavior. Source inclusion does not
activate a service, apply SQL, create roles, generate keys or enable messaging.

The factory reads one explicit `SOCIAL_ENROLLMENT_V2_CONFIG_PATH` JSON manifest.
It requires a root-owned regular bounded file without group write or public
access, rejects duplicate fields and symlinks, and accepts only the complete
versioned vocabulary in `social_enrollment_v2_runtime.py`.
The manifest pins two different direct PostgreSQL login roles by name and OID.
The existing credential file supplies only their loopback PostgreSQL credentials.
Every new physical connection verifies database, current and session role, OID
and PostgreSQL 16 before owner work. Pools are not shared: the challenge writer,
native session issuer and assertion replay store use one session factory; the
reservation/finalization owner uses the other. Construction opens no database
connection. Existing viewer JWT configuration is reused by the native issuer;
its signing key is never the dedicated deadline-evidence signer.

The manifest supplies independent service assertion/access-token registries,
dedicated reservation signing material and immutable deadline/statement public
trust registrations. It selects the signed `native-v2-60s-v1` profile. The
challenge lifetime is sixty seconds; first acceptance remains bounded by the
original phone and approver sessions, Full evidence and binding expiry. No
request may select the database role, clock, trust registration or profile.
Both exact confidential V2 blueprints are installed only by this factory.
Their eight service credential configurations use zero clock skew and exclusive
expiry. The shared V1 credential helper and its existing clock policy are unchanged.

Operational activation additionally requires the exact schema and restricted
roles, separate infrastructure signers, a private reverse-proxy allowlist and
an explicit service configuration selecting this entrypoint. Verification of
source or a private synthetic flow does not establish a live browser result.
See [runtime composition](SOCIAL_ENROLLMENT_V2_RUNTIME_COMPOSITION_V1.md),
[ingress](SOCIAL_ENROLLMENT_V2_INGRESS_V1.md) and the Social repository's
`docs/SOCIAL_ENROLLMENT_V2_BROWSER_V1.md` for the respective boundaries.
Registration retains `final_admission=denied`: current device admission,
message encryption, routing and delivery remain independent requirements.
