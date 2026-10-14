"""Explicit profile bytes cross real RSA, canonical CAS and durable consumers."""

import base64
import json
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services import social_enrollment_v2_freshness_policy as policy
from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as canonical
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as storage
from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement
from app.services.social_enrollment_v2_finalization_contract import FinalizationConfig, FinalizationDenied
from app.services.social_enrollment_v2_reservation_contract import _freeze_config
from tests.unit import test_social_enrollment_v2_reservation as reservation_tests
from tests.unit import test_social_preaccepted_enrollment_v2_atomic_acceptance_contract as vectors
from tests.unit.test_social_enrollment_v2_finalization import FinalGraph, FinalSession, signed_statement

FRESHNESS_PROFILE = policy.NATIVE_V2_60S_V1
FRESHNESS_AT = vectors.EVIDENCE["deadlines"]["observedAt"]


def _freshness_b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _freshness_compact(header, payload, key):
    signing = (_freshness_b64(header.encode()) + "." + _freshness_b64(payload.encode())).encode()
    return signing.decode() + "." + _freshness_b64(key.sign(signing, padding.PKCS1v15(), hashes.SHA256()))


def _freshness_artifacts(profile=FRESHNESS_PROFILE, lifetime=60000):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwk = dict(vectors.EVIDENCE["trustRecord"]["jwk"])
    jwk.update(n=_freshness_b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")), e="AQAB")
    ec = replace(
        vectors.evidence_config(),
        freshness_profile=profile,
        trust_records=(evidence.DeadlineEvidenceTrustRecordV1(jwk, 1, FRESHNESS_AT - 1000, FRESHNESS_AT + 600000),),
    )
    sc = replace(vectors.statement_config(), freshness_profile=profile, trusted_jwks=(jwk,))
    values = json.loads(vectors.EVIDENCE["vector"]["payloadWire"])
    values.pop("jti")
    values.update(policy.payload_marker(profile))
    values["expiresAt"] = FRESHNESS_AT + lifetime
    values["jti"] = evidence._jti_from_values(values)
    payload = vectors.canonical(values)
    header = evidence.canonical_messaging_device_verification_deadline_evidence_protected_header_v1_bytes(
        kid=jwk["kid"]
    ).decode()
    signing = evidence.messaging_device_verification_deadline_evidence_signing_input_v1(
        protected_header_wire=header,
        payload_wire=payload,
        freshness_profile=profile,
    )
    compact = evidence.compact_messaging_device_verification_deadline_evidence_v1(
        protected_header_wire=header,
        payload_wire=payload,
        signature=key.sign(signing, padding.PKCS1v15(), hashes.SHA256()),
        freshness_profile=profile,
    )
    sh = statement.canonical_preaccepted_enrollment_verification_statement_protected_header_v2_bytes(
        kid=jwk["kid"]
    ).decode()
    sp = statement.canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(
        issuer=sc.issuer,
        audience=sc.audience,
        client_id=sc.client_id,
        service_principal=sc.service_principal,
        expected_context_wire=vectors.CONTEXT_WIRE,
        expected_input_wire=vectors.INPUT_WIRE,
        issued_at=FRESHNESS_AT,
        expires_at=FRESHNESS_AT + lifetime,
        freshness_profile=profile,
    ).decode()
    ss = (_freshness_b64(sh.encode()) + "." + _freshness_b64(sp.encode())).encode()
    sj = statement.compact_preaccepted_enrollment_verification_statement_v2(
        protected_header_wire=sh,
        payload_wire=sp,
        signature=key.sign(ss, padding.PKCS1v15(), hashes.SHA256()),
        freshness_profile=profile,
    )
    return key, ec, sc, header, payload, compact, sh, sp, sj


def _freshness_verify_evidence(a, *, at=FRESHNESS_AT, config=None, compact=None):
    return evidence.verify_messaging_device_verification_deadline_evidence_v1(
        a[5] if compact is None else compact,
        config=a[1] if config is None else config,
        expected_input_wire=vectors.INPUT_WIRE,
        now=at,
    )


def _freshness_verify_statement(a, *, at=FRESHNESS_AT, config=None, compact=None, **deadlines):
    claims = json.loads(a[4])
    values = dict(
        phone_session_expires_at_ms=claims["phoneSessionExpiresAt"],
        approver_session_expires_at_ms=claims["approverSessionExpiresAt"],
        full_expires_at_ms=claims["fullExpiresAt"],
        x25519_binding_expires_at_ms=claims["x25519BindingExpiresAt"],
    )
    values.update(deadlines)
    return statement.verify_social_preaccepted_enrollment_verification_statement_v2(
        a[8] if compact is None else compact,
        config=a[2] if config is None else config,
        expected_context_wire=vectors.CONTEXT_WIRE,
        expected_input_wire=vectors.INPUT_WIRE,
        now=at,
        **values,
    )


def _freshness_denied(kind, call):
    with pytest.raises(kind) as caught:
        call()
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert len(str(caught.value)) < 120


@pytest.mark.parametrize("invalid", [None, True, False, 60000, "unknown", "", float("inf")])
def test_freshness_unknown_server_profiles_deny_even_disabled(invalid):
    with pytest.raises(ValueError):
        policy.max_lifetime_ms(invalid)
    _freshness_denied(
        evidence.SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied,
        lambda: evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config(freshness_profile=invalid),
    )
    _freshness_denied(
        statement.SocialPreacceptedEnrollmentVerificationStatementV2Denied,
        lambda: statement.SocialPreacceptedEnrollmentVerificationStatementV2Config(freshness_profile=invalid),
    )


def test_freshness_defaults_and_exact_exclusive_legacy_boundary():
    assert not evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config().enabled
    assert not statement.SocialPreacceptedEnrollmentVerificationStatementV2Config().enabled
    assert evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config().freshness_profile == policy.LEGACY_10S
    assert statement.SocialPreacceptedEnrollmentVerificationStatementV2Config().freshness_profile == policy.LEGACY_10S
    assert evidence.MAX_EVIDENCE_LIFETIME_MS == statement.MAX_STATEMENT_LIFETIME_MS == 10000
    a = _freshness_artifacts(policy.LEGACY_10S, 10000)
    assert "freshnessProfile" not in json.loads(a[4]) and "freshnessProfile" not in json.loads(a[7])
    _freshness_verify_evidence(a, at=FRESHNESS_AT + 9999)
    _freshness_verify_statement(a, at=FRESHNESS_AT + 9999)
    _freshness_denied(
        evidence.SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied,
        lambda: _freshness_verify_evidence(a, at=FRESHNESS_AT + 10000),
    )
    _freshness_denied(
        statement.SocialPreacceptedEnrollmentVerificationStatementV2Denied,
        lambda: _freshness_verify_statement(a, at=FRESHNESS_AT + 10000),
    )


@pytest.mark.parametrize("profile,lifetime", [(policy.LEGACY_10S, 10001), (FRESHNESS_PROFILE, 60001)])
def test_freshness_over_bound_real_builders_deny(profile, lifetime):
    _freshness_denied(
        evidence.SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied,
        lambda: _freshness_artifacts(profile, lifetime),
    )
    sc = vectors.statement_config()
    _freshness_denied(
        statement.SocialPreacceptedEnrollmentVerificationStatementV2Denied,
        lambda: statement.canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(
            issuer=sc.issuer,
            audience=sc.audience,
            client_id=sc.client_id,
            service_principal=sc.service_principal,
            expected_context_wire=vectors.CONTEXT_WIRE,
            expected_input_wire=vectors.INPUT_WIRE,
            issued_at=FRESHNESS_AT,
            expires_at=FRESHNESS_AT + lifetime,
            freshness_profile=profile,
        ),
    )


def test_freshness_marked_sixty_second_rsa_jti_and_exclusive_boundary():
    a = _freshness_artifacts()
    assert json.loads(a[4])[policy.PROFILE_FIELD] == json.loads(a[7])[policy.PROFILE_FIELD] == FRESHNESS_PROFILE
    assert _freshness_verify_evidence(a, at=FRESHNESS_AT + 59999).claims.expires_at == FRESHNESS_AT + 60000
    _freshness_verify_statement(a, at=FRESHNESS_AT + 59999)
    without = json.loads(a[7])
    without.pop("jti")
    assert (
        statement.preaccepted_enrollment_verification_statement_jti_v2(
            vectors.canonical(without), freshness_profile=FRESHNESS_PROFILE
        )
        == json.loads(a[7])["jti"]
    )
    _freshness_denied(
        evidence.SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied,
        lambda: _freshness_verify_evidence(a, at=FRESHNESS_AT + 60000),
    )
    _freshness_denied(
        statement.SocialPreacceptedEnrollmentVerificationStatementV2Denied,
        lambda: _freshness_verify_statement(a, at=FRESHNESS_AT + 60000),
    )


@pytest.mark.parametrize(
    "profile,lifetime", [(policy.LEGACY_10S, 9000), (FRESHNESS_PROFILE, 9000), (FRESHNESS_PROFILE, 60000)]
)
def test_freshness_cross_profile_readers_deny_including_marked_short(profile, lifetime):
    a = _freshness_artifacts(profile, lifetime)
    other = FRESHNESS_PROFILE if profile == policy.LEGACY_10S else policy.LEGACY_10S
    _freshness_denied(
        evidence.SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied,
        lambda: _freshness_verify_evidence(a, config=replace(a[1], freshness_profile=other)),
    )
    _freshness_denied(
        statement.SocialPreacceptedEnrollmentVerificationStatementV2Denied,
        lambda: _freshness_verify_statement(a, config=replace(a[2], freshness_profile=other)),
    )


@pytest.mark.parametrize("marker", [None, True, 60000, "unknown", policy.LEGACY_10S])
def test_freshness_bad_signed_markers_and_default_digest_deny(marker):
    a = _freshness_artifacts()
    for index, header_index, verify, domain in [
        (4, 3, _freshness_verify_evidence, evidence),
        (7, 6, _freshness_verify_statement, statement),
    ]:
        value = json.loads(a[index])
        value.pop("jti")
        if marker is None:
            value.pop(policy.PROFILE_FIELD)
        else:
            value[policy.PROFILE_FIELD] = marker
        value["jti"] = domain._jti_from_values(value)
        forged = _freshness_compact(a[header_index], vectors.canonical(value), a[0])
        with pytest.raises(ValueError):
            verify(a, compact=forged)
    _freshness_denied(
        canonical.SocialPreacceptedEnrollmentV2AtomicAcceptanceDenied,
        lambda: canonical.deadline_evidence_payload_digest_v1(a[4]),
    )


@pytest.mark.parametrize("recompute", [False, True])
def test_freshness_tamper_and_recomputed_jti_do_not_replace_signature(recompute):
    a = _freshness_artifacts()
    for payload_index, compact_index, verify, domain in [
        (4, 5, _freshness_verify_evidence, evidence),
        (7, 8, _freshness_verify_statement, statement),
    ]:
        value = json.loads(a[payload_index])
        value["expiresAt"] -= 1
        if recompute:
            value.pop("jti")
            value["jti"] = domain._jti_from_values(value)
        parts = a[compact_index].split(".")
        parts[1] = _freshness_b64(vectors.canonical(value).encode())
        with pytest.raises(ValueError):
            verify(a, compact=".".join(parts))
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(ValueError):
        _freshness_verify_evidence(a, compact=_freshness_compact(a[3], a[4], other))
    with pytest.raises(ValueError):
        _freshness_verify_statement(a, compact=_freshness_compact(a[6], a[7], other))


@pytest.mark.parametrize(
    "field,keyword",
    [
        ("phoneSessionExpiresAt", "phone_session_expires_at_ms"),
        ("approverSessionExpiresAt", "approver_session_expires_at_ms"),
        ("fullExpiresAt", "full_expires_at_ms"),
        ("x25519BindingExpiresAt", "x25519_binding_expires_at_ms"),
    ],
)
def test_freshness_independent_authority_deadlines_still_bound(field, keyword):
    a = _freshness_artifacts()
    value = json.loads(a[4])
    value.pop("jti")
    value[field] = FRESHNESS_AT + 59999
    value["jti"] = evidence._jti_from_values(value)
    with pytest.raises(ValueError):
        _freshness_verify_evidence(a, compact=_freshness_compact(a[3], vectors.canonical(value), a[0]))
    with pytest.raises(ValueError):
        _freshness_verify_statement(a, **{keyword: FRESHNESS_AT + 59999})


@pytest.mark.parametrize("revoked", [False, True])
def test_freshness_trust_not_after_and_revocation_still_deny(revoked):
    a = _freshness_artifacts()
    record = a[1].trust_records[0]
    changed = replace(record, revoked_at=FRESHNESS_AT) if revoked else replace(record, not_after=FRESHNESS_AT + 59999)
    with pytest.raises(ValueError):
        _freshness_verify_evidence(a, config=replace(a[1], trust_records=(changed,)))


def test_freshness_real_pending_cas_stored_history_and_exact_accepted_retry():
    a = _freshness_artifacts()
    auth = _freshness_verify_evidence(a)
    pending_wire = canonical.canonical_pending_atomic_acceptance_reservation_v1_bytes(
        evidence_compact_jws=a[5],
        evidence_config=a[1],
        expected_input_wire=vectors.INPUT_WIRE,
        observed_at=FRESHNESS_AT,
        challenge_revision=1,
    ).decode()
    pending = canonical.parse_atomic_acceptance_reservation_v1(pending_wire)
    row = storage._pending_row_values(pending, input_wire=vectors.INPUT_WIRE, evidence_compact_jws=a[5])
    assert storage.parse_stored_atomic_acceptance_v1(row, evidence_config=a[1]).reservation.wire == pending_wire
    canonical.reservation_retry_disposition_v1(
        pending_wire,
        expected_input_wire=vectors.INPUT_WIRE,
        evidence_compact_jws=a[5],
        now=FRESHNESS_AT + 59999,
        freshness_profile=FRESHNESS_PROFILE,
    )
    obs = json.loads(vectors.VECTOR["finalizationObservationWire"])
    decided = FRESHNESS_AT + 15000
    aw = canonical._authority_wire_from_authenticated_claims(auth.claims, decided)
    obs.update(
        observedAt=decided,
        authoritySnapshot=aw,
        authoritySnapshotDigest=canonical.current_authority_snapshot_digest_v1(aw),
    )
    args = dict(
        reservation_wire=pending_wire,
        finalization_observation_wire=vectors.canonical(obs),
        expected_input_wire=vectors.INPUT_WIRE,
        expected_context_wire=vectors.CONTEXT_WIRE,
        evidence_compact_jws=a[5],
        evidence_config=a[1],
        statement_compact_jws=a[8],
        statement_config=a[2],
        decided_at=decided,
    )
    result = canonical.model_atomic_acceptance_and_cas_v1(**args)
    accepted = canonical.parse_atomic_acceptance_reservation_v1(result.reservation_after_wire)
    row.update(
        state="accepted",
        decided_at=decided,
        statement_digest=accepted.statement_digest,
        effect_id=accepted.effect_id,
        effect_digest=accepted.effect_digest,
        receipt_id=accepted.receipt_id,
        finalization_request_digest=result.finalization_request_digest,
        reservation_wire=accepted.wire,
        statement_compact_jws=a[8],
        finalization_observation_wire=args["finalization_observation_wire"],
        effect_wire=result.effect_wire,
        receipt_wire=result.receipt.wire,
    )
    stored = storage.parse_stored_atomic_acceptance_v1(row, evidence_config=a[1], statement_config=a[2])
    retry = canonical.reservation_retry_disposition_v1(
        accepted.wire,
        expected_input_wire=vectors.INPUT_WIRE,
        evidence_compact_jws=a[5],
        statement_compact_jws=a[8],
        receipt_wire=stored.receipt.wire,
        now=FRESHNESS_AT + 600000,
        freshness_profile=FRESHNESS_PROFILE,
    )
    assert retry.outcome == "return_immutable_receipt_without_effect"
    assert stored.reservation.decided_at == decided and stored.receipt.wire == result.receipt.wire
    for field in ["evidence_compact_jws", "statement_compact_jws", "receipt_wire", "finalization_observation_wire"]:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable):
            storage.parse_stored_atomic_acceptance_v1(
                {**row, field: row[field] + " "}, evidence_config=a[1], statement_config=a[2]
            )
    with pytest.raises(ValueError):
        canonical.model_atomic_acceptance_and_cas_v1(
            **{**args, "statement_config": replace(a[2], freshness_profile=policy.LEGACY_10S)}
        )
    shorter = _freshness_artifacts(lifetime=30000)
    short_pending = canonical.canonical_pending_atomic_acceptance_reservation_v1_bytes(
        evidence_compact_jws=shorter[5],
        evidence_config=shorter[1],
        expected_input_wire=vectors.INPUT_WIRE,
        observed_at=FRESHNESS_AT,
        challenge_revision=1,
    ).decode()
    with pytest.raises(ValueError):
        canonical.model_atomic_acceptance_and_cas_v1(
            **{
                **args,
                "reservation_wire": short_pending,
                "evidence_compact_jws": shorter[5],
                "evidence_config": shorter[1],
            }
        )


def test_freshness_native_producer_copies_real_signer_storage_and_retry(monkeypatch):
    g = reservation_tests.ReservationGraph(monkeypatch)
    try:
        g.config = replace(
            g.config, evidence_config=replace(g.config.evidence_config, freshness_profile=FRESHNESS_PROFILE)
        )
        frozen = _freeze_config(g.config)
        assert frozen.evidence_config.freshness_profile == FRESHNESS_PROFILE
        with pytest.raises(FrozenInstanceError):
            frozen.evidence_config.freshness_profile = policy.LEGACY_10S
        with reservation_tests.ReservationSession(g) as s, s.begin():
            first = reservation_tests.reserve(g, g.owner(s))
        assert first.expires_at - first.observed_at == 60000
        fc, _ = signed_statement(g.input_wire, g.config, first.observed_at, expires_at=first.expires_at)
        assert (
            fc.statement_config.freshness_profile
            == fc.reservation_config.evidence_config.freshness_profile
            == FRESHNESS_PROFILE
        )
        with pytest.raises(FinalizationDenied):
            FinalizationConfig(
                True, g.config, replace(fc.statement_config, freshness_profile=policy.LEGACY_10S), fc.statement_pins
            )
        g.now += timedelta(milliseconds=15000)
        with reservation_tests.ReservationSession(g) as s, s.begin():
            assert reservation_tests.reserve(g, g.owner(s)) == first
        assert g.sign_calls == 1
    finally:
        g.engine.dispose()


def test_freshness_native_finalization_and_historical_retry_no_new_effects(monkeypatch):
    original = reservation_tests.configuration

    def _freshness_configuration(*args, **kwargs):
        rc = original(*args, **kwargs)
        return replace(rc, evidence_config=replace(rc.evidence_config, freshness_profile=FRESHNESS_PROFILE))

    monkeypatch.setattr(reservation_tests, "configuration", _freshness_configuration)
    g = FinalGraph(monkeypatch)
    try:
        g.final_config, g.statement = signed_statement(
            g.input_wire, g.config, g.reservation.observed_at, expires_at=g.reservation.expires_at
        )
        g.now += timedelta(milliseconds=15000)
        with FinalSession(g) as s, s.begin():
            first = g.finalizer(s).finalize(**g.arguments())
        assert g.calls == ["association", "receipt", "consumption", "cas"]
        g.now += timedelta(milliseconds=600000)
        with FinalSession(g) as s, s.begin():
            retry = g.finalizer(s).finalize(**g.arguments())
        assert retry.historical_recovery and retry.receipt_wire == first.receipt_wire
        assert g.calls == ["association", "receipt", "consumption", "cas"]
    finally:
        g.engine.dispose()


def test_freshness_actual_input_expiry_remains_independent_of_maximum():
    a = _freshness_artifacts()
    value = json.loads(a[4])
    value.pop("jti")
    # A valid <=60s duration still cannot cross the original input's expiry.
    value.update(
        observedAt=FRESHNESS_AT + 1,
        expiresAt=FRESHNESS_AT + 60001,
        phoneSessionExpiresAt=FRESHNESS_AT + 61000,
        approverSessionExpiresAt=FRESHNESS_AT + 61000,
        fullExpiresAt=FRESHNESS_AT + 61000,
    )
    value["jti"] = evidence._jti_from_values(value)
    wire = vectors.canonical(value)
    evidence.parse_messaging_device_verification_deadline_evidence_payload_v1(wire, freshness_profile=FRESHNESS_PROFILE)
    with pytest.raises(ValueError):
        evidence.parse_messaging_device_verification_deadline_evidence_payload_v1(
            wire, expected_input_wire=vectors.INPUT_WIRE, freshness_profile=FRESHNESS_PROFILE
        )
    sc = a[2]
    with pytest.raises(ValueError):
        statement.canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(
            issuer=sc.issuer,
            audience=sc.audience,
            client_id=sc.client_id,
            service_principal=sc.service_principal,
            expected_context_wire=vectors.CONTEXT_WIRE,
            expected_input_wire=vectors.INPUT_WIRE,
            issued_at=FRESHNESS_AT + 1,
            expires_at=FRESHNESS_AT + 60001,
            freshness_profile=FRESHNESS_PROFILE,
        )


@pytest.mark.parametrize("change", ["outlives", "predates"])
def test_freshness_authentic_statement_must_fit_authentic_evidence(change):
    a = _freshness_artifacts()
    value = json.loads(a[4])
    value.pop("jti")
    value["expiresAt"] = FRESHNESS_AT + 30000 if change == "outlives" else FRESHNESS_AT + 60000
    if change == "predates":
        value["observedAt"] += 1
    value["jti"] = evidence._jti_from_values(value)
    compact = _freshness_compact(a[3], vectors.canonical(value), a[0])
    auth = _freshness_verify_evidence(a, at=FRESHNESS_AT + 15000, compact=compact)
    _freshness_verify_statement(a, at=FRESHNESS_AT + 15000)
    pending = canonical.canonical_pending_atomic_acceptance_reservation_v1_bytes(
        evidence_compact_jws=compact,
        evidence_config=a[1],
        expected_input_wire=vectors.INPUT_WIRE,
        observed_at=value["observedAt"],
        challenge_revision=1,
    ).decode()
    decided = FRESHNESS_AT + 15000
    obs = json.loads(vectors.VECTOR["finalizationObservationWire"])
    aw = canonical._authority_wire_from_authenticated_claims(auth.claims, decided)
    obs.update(
        observedAt=decided,
        authoritySnapshot=aw,
        authoritySnapshotDigest=canonical.current_authority_snapshot_digest_v1(aw),
    )
    _freshness_denied(
        canonical.SocialPreacceptedEnrollmentV2AtomicAcceptanceDenied,
        lambda: canonical.model_atomic_acceptance_and_cas_v1(
            reservation_wire=pending,
            finalization_observation_wire=vectors.canonical(obs),
            expected_input_wire=vectors.INPUT_WIRE,
            expected_context_wire=vectors.CONTEXT_WIRE,
            evidence_compact_jws=compact,
            evidence_config=a[1],
            statement_compact_jws=a[8],
            statement_config=a[2],
            decided_at=decided,
        ),
    )


def test_freshness_native_observation_after_lock_and_input_deadline_minimum(monkeypatch):
    g = reservation_tests.ReservationGraph(monkeypatch)
    try:
        g.config = replace(
            g.config, evidence_config=replace(g.config.evidence_config, freshness_profile=FRESHNESS_PROFILE)
        )
        g.wait = lambda: setattr(g, "now", g.now + timedelta(milliseconds=1))
        with reservation_tests.ReservationSession(g) as s, s.begin():
            result = reservation_tests.reserve(g, g.owner(s))
        parsed = reservation_tests.v2.parse_preaccepted_enrollment_verification_input_v2(g.input_wire)
        assert result.observed_at > FRESHNESS_AT
        assert result.expires_at == parsed.enrollment.expires_at
        assert result.expires_at - result.observed_at < 60000
    finally:
        g.engine.dispose()


def test_freshness_native_selected_trust_deadline_is_signed_minimum(monkeypatch):
    g = reservation_tests.ReservationGraph(monkeypatch)
    try:
        record = g.config.evidence_config.trust_records[0]
        after = FRESHNESS_AT + 20000
        jwk = dict(record.public_jwk)
        jwk["kid"] = reservation_tests.dedicated_reservation_key_id(
            key_fingerprint=record.key_fingerprint,
            trust_revision=record.trust_revision,
            not_before=record.not_before,
            not_after=after,
        )
        trust = evidence.DeadlineEvidenceTrustRecordV1(jwk, record.trust_revision, record.not_before, after)
        ec = replace(g.config.evidence_config, freshness_profile=FRESHNESS_PROFILE, trust_records=(trust,))
        g.config = replace(
            g.config,
            evidence_config=ec,
            selected_kid=trust.key_id,
            trust_pins=((trust.key_id, trust.trust_revision, trust.trust_record_id),),
        )
        with reservation_tests.ReservationSession(g) as s, s.begin():
            result = reservation_tests.reserve(g, g.owner(s))
        assert result.expires_at == after
        fc, compact = signed_statement(g.input_wire, g.config, result.observed_at, expires_at=after)
        assert fc.statement_config.freshness_profile == FRESHNESS_PROFILE
        assert json.loads(base64.urlsafe_b64decode(compact.split(".")[1] + "=="))["expiresAt"] == after
    finally:
        g.engine.dispose()


@pytest.mark.parametrize("profile", [policy.LEGACY_10S, FRESHNESS_PROFILE])
def test_freshness_recomputed_only_profile_marker_cannot_reuse_real_signature(profile):
    a = _freshness_artifacts(profile, 9000)
    other = FRESHNESS_PROFILE if profile == policy.LEGACY_10S else policy.LEGACY_10S
    for payload_index, compact_index, verify, domain, config_index in [
        (4, 5, _freshness_verify_evidence, evidence, 1),
        (7, 8, _freshness_verify_statement, statement, 2),
    ]:
        value = json.loads(a[payload_index])
        value.pop("jti")
        value.pop(policy.PROFILE_FIELD, None)
        value.update(policy.payload_marker(other))
        value["jti"] = domain._jti_from_values(value)
        parts = a[compact_index].split(".")
        parts[1] = _freshness_b64(vectors.canonical(value).encode())
        with pytest.raises(ValueError):
            verify(a, config=replace(a[config_index], freshness_profile=other), compact=".".join(parts))


def test_freshness_new_profile_exact_field_set_rejects_unrelated_fields():
    a = _freshness_artifacts()
    for payload_index, header_index, verify, domain in [
        (4, 3, _freshness_verify_evidence, evidence),
        (7, 6, _freshness_verify_statement, statement),
    ]:
        value = json.loads(a[payload_index])
        value.pop("jti")
        value["extra"] = "denied"
        value["jti"] = domain._jti_from_values(value)
        with pytest.raises(ValueError):
            verify(a, compact=_freshness_compact(a[header_index], vectors.canonical(value), a[0]))
