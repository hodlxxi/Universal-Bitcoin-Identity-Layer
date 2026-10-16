"""Both pinned SQL profiles; raw SQL shape probes grant no current authority."""

import base64
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path

import pytest

from app.services import social_enrollment_v2_finalization_storage as native
from app.services import social_enrollment_v2_freshness_policy as policy
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as canonical
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as durable
from tests.unit import test_social_enrollment_v2_freshness_policy as signed
from tests.unit import test_social_preaccepted_enrollment_v2_atomic_acceptance_storage as legacy
from tests.unit.test_social_enrollment_v2_finalization_storage import source_functions

ROOT = Path(__file__).parents[2]
OLD = ROOT / "migrations/2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql"
NEW = ROOT / "migrations/2026-10-14_social_enrollment_v2_freshness_profile_guard_v1.sql"
OLD_SHAPE = "IF jsonb_typeof(evidence_payload) <> 'object' OR field_count <> 46 OR"
NEW_SHAPE = """IF jsonb_typeof(evidence_payload) <> 'object' OR
       (NOT (evidence_payload ? 'freshnessProfile') AND
           (field_count <> 46 OR NEW.expires_at - NEW.created_at > 10000)) OR
       ((evidence_payload ? 'freshnessProfile') AND
           (field_count <> 47 OR
            (evidence_payload -> 'freshnessProfile') IS DISTINCT FROM
                '"native-v2-60s-v1"'::jsonb OR
            NEW.expires_at - NEW.created_at > 60000)) OR"""


def _freshness_function_body(source):
    match = re.search(
        r'CREATE(?: OR REPLACE)? FUNCTION "public"\."guard_social_preaccepted_v2_acceptance_v1"\(\).*?AS \$\$(.*?)\$\$;',
        source,
        re.S,
    )
    assert match is not None
    return match.group(1)


def test_freshness_sql_addition_retains_every_other_old_guard_byte_and_pin():
    old = _freshness_function_body(OLD.read_text())
    new = _freshness_function_body(NEW.read_text())
    assert new.count(NEW_SHAPE) == 1
    assert new.replace(NEW_SHAPE, OLD_SHAPE) == old
    assert hashlib.sha256(old.encode("ascii")).hexdigest() == native.CAS_FUNCTION_SOURCE_SHA256
    assert hashlib.sha256(new.encode("ascii")).hexdigest() == durable.FRESHNESS_GUARD_SOURCE_SHA256
    for body, expected in ((old, durable.GUARD_DEFINITION_SHA256), (new, durable.FRESHNESS_GUARD_DEFINITION_SHA256)):
        payload = durable._expected_guard_definition_payload(body, function_cost=100, function_rows=0)
        assert durable._guard_definition_digest(payload) == expected
    assert durable.GUARD_DEFINITION_SHA256 == "f27dd60f6ef9548129a1e0175a4af1e7985f76080bf6a7a51890a273e5b30ca1"


@pytest.mark.parametrize(
    "digest,profile,allowed",
    [
        (durable.GUARD_DEFINITION_SHA256, "original", True),
        (durable.GUARD_DEFINITION_SHA256, "native_v2_finalization", True),
        (durable.FRESHNESS_GUARD_DEFINITION_SHA256, "original", False),
        (durable.FRESHNESS_GUARD_DEFINITION_SHA256, "native_v2_finalization", True),
        ("0" * 64, "native_v2_finalization", False),
        (durable.FRESHNESS_GUARD_DEFINITION_SHA256, "unknown", False),
        (None, "native_v2_finalization", False),
        (True, "native_v2_finalization", False),
    ],
)
def test_freshness_sql_only_named_pinned_native_extension_is_recognized(digest, profile, allowed):
    assert durable._freshness_guard_definition_allowed(digest, profile) is allowed


def test_freshness_sql_same_oid_known_profile_switch_changes_complete_identity():
    row = source_functions()[durable.GUARD_FUNCTION]
    old_identity = native._attest_function(deepcopy(row), durable.GUARD_FUNCTION)
    row["function"]["prosrc"] = _freshness_function_body(NEW.read_text())
    new_identity = native._attest_function(deepcopy(row), durable.GUARD_FUNCTION)
    assert new_identity[:4] == old_identity
    assert new_identity == old_identity + (durable.FRESHNESS_GUARD_SOURCE_SHA256,)
    row["function"]["prosrc"] += "\n-- unregistered definition\n"
    with pytest.raises(ValueError):
        native._attest_function(deepcopy(row), durable.GUARD_FUNCTION)


def _freshness_sql_rows(profile):
    if profile == policy.LEGACY_10S:
        auth = signed.evidence.verify_messaging_device_verification_deadline_evidence_v1(
            signed.vectors.evidence_compact(),
            config=signed.vectors.evidence_config(),
            expected_input_wire=signed.vectors.INPUT_WIRE,
            now=signed.FRESHNESS_AT,
        )
        return legacy.pending_row(), legacy.accepted_row(), auth
    a = signed._freshness_artifacts()
    auth = signed._freshness_verify_evidence(a)
    wire = canonical.canonical_pending_atomic_acceptance_reservation_v1_bytes(
        evidence_compact_jws=a[5],
        evidence_config=a[1],
        expected_input_wire=signed.vectors.INPUT_WIRE,
        observed_at=signed.FRESHNESS_AT,
        challenge_revision=1,
    ).decode("ascii")
    reservation = canonical.parse_atomic_acceptance_reservation_v1(wire)
    pending = durable._pending_row_values(reservation, input_wire=signed.vectors.INPUT_WIRE, evidence_compact_jws=a[5])
    decided = signed.FRESHNESS_AT + 15000
    observation = json.loads(signed.vectors.VECTOR["finalizationObservationWire"])
    authority = canonical._authority_wire_from_authenticated_claims(auth.claims, decided)
    observation.update(
        observedAt=decided,
        authoritySnapshot=authority,
        authoritySnapshotDigest=canonical.current_authority_snapshot_digest_v1(authority),
    )
    result = canonical.model_atomic_acceptance_and_cas_v1(
        reservation_wire=wire,
        finalization_observation_wire=canonical._canonical(observation),
        expected_input_wire=signed.vectors.INPUT_WIRE,
        expected_context_wire=signed.vectors.CONTEXT_WIRE,
        evidence_compact_jws=a[5],
        evidence_config=a[1],
        statement_compact_jws=a[8],
        statement_config=a[2],
        decided_at=decided,
    )
    accepted = canonical.parse_atomic_acceptance_reservation_v1(result.reservation_after_wire)
    row = dict(pending)
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
        finalization_observation_wire=canonical._canonical(observation),
        effect_wire=result.effect_wire,
        receipt_wire=result.receipt.wire,
    )
    durable.parse_stored_atomic_acceptance_v1(row, evidence_config=a[1], statement_config=a[2])
    return pending, row, auth


SQL_CASES = (
    "legacy46",
    "native47",
    "legacy_extra",
    "unknown_marker",
    "null_marker",
    "bool_marker",
    "integer_marker",
    "legacy_marker",
    "native_extra",
    "missing_required",
    "over_sixty",
    "unmarked_long",
)


def _freshness_sql_case(case):
    """Corruption probes fully rechain identities, avoiding unrelated rejections.

    Changed compact bytes intentionally have no authentic replacement signature.
    This isolates SQL format checking on a TEMP copy; real signature rejection
    is established by the separate crypto cases and the complete native suite.
    """
    assert case in SQL_CASES
    profile = policy.LEGACY_10S if case in ("legacy46", "legacy_extra") else policy.NATIVE_V2_60S_V1
    pending, accepted, auth = _freshness_sql_rows(profile)
    if case in ("legacy46", "native47"):
        return pending, accepted, True
    header, segment, signature = pending["evidence_compact_jws"].split(".")
    values = json.loads(base64.urlsafe_b64decode(segment + "=" * ((4 - len(segment) % 4) % 4)))
    if case in ("legacy_extra", "native_extra"):
        values["unexpectedField"] = "denied"
    elif case == "missing_required":
        values.pop("clientId")
        values["unexpectedField"] = "denied"
    elif case == "over_sixty":
        values["expiresAt"] = values["observedAt"] + 60001
    elif case == "unmarked_long":
        values.pop(policy.PROFILE_FIELD)
    else:
        markers = {
            "unknown_marker": "unknown",
            "null_marker": None,
            "bool_marker": True,
            "integer_marker": 60000,
            "legacy_marker": policy.LEGACY_10S,
        }
        values[policy.PROFILE_FIELD] = markers[case]
    values.pop("jti")
    values["jti"] = signed.evidence._jti_from_values(values)
    payload = canonical._canonical(values)
    compact = header + "." + signed._freshness_b64(payload.encode("ascii")) + "." + signature
    evidence_digest = canonical.deadline_evidence_digest_v1(compact)
    payload_digest = canonical._digest(
        canonical.EVIDENCE_PAYLOAD_DIGEST_PREFIX, canonical.EVIDENCE_PAYLOAD_DIGEST_DOMAIN, payload
    )
    rv = json.loads(pending["reservation_wire"])
    rv.update(
        evidenceDigest=evidence_digest,
        evidencePayloadDigest=payload_digest,
        evidenceTokenId=values["jti"],
        expiresAt=values["expiresAt"],
    )
    pending.update(
        evidence_compact_jws=compact,
        evidence_digest=evidence_digest,
        evidence_payload_digest=payload_digest,
        evidence_token_id=values["jti"],
        expires_at=values["expiresAt"],
        reservation_wire=canonical._canonical(rv),
    )
    reservation = canonical.parse_atomic_acceptance_reservation_v1(pending["reservation_wire"])
    observation = canonical.parse_finalization_observation_v1(accepted["finalization_observation_wire"])
    final_digest = canonical._finalization_request_digest(reservation, statement_digest=accepted["statement_digest"])
    effect_wire, effect_id, effect_digest = canonical._effect(
        reservation,
        observation,
        final_digest,
        authenticated_evidence=auth,
    )
    receipt = canonical._receipt(
        reservation,
        statement_digest=accepted["statement_digest"],
        finalization_request_digest=final_digest,
        effect_id=effect_id,
        effect_digest=effect_digest,
        decided_at=accepted["decided_at"],
    )
    accepted_wire = canonical._accepted_reservation_wire(
        reservation,
        statement_digest=accepted["statement_digest"],
        effect_id=effect_id,
        effect_digest=effect_digest,
        receipt=receipt,
        decided_at=accepted["decided_at"],
    )
    accepted.update(
        {
            name: pending[name]
            for name in (
                "evidence_compact_jws",
                "evidence_digest",
                "evidence_payload_digest",
                "evidence_token_id",
                "expires_at",
            )
        }
    )
    accepted.update(
        reservation_wire=accepted_wire,
        finalization_request_digest=final_digest,
        effect_wire=effect_wire,
        effect_id=effect_id,
        effect_digest=effect_digest,
        receipt_wire=receipt.wire,
        receipt_id=receipt.receipt_id,
    )
    return pending, accepted, False
