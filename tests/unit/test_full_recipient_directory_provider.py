from copy import deepcopy

import pytest

from app.services.full_recipient_directory_provider import (
    FullRecipientDirectoryUnavailable,
    build_full_recipient_directory,
)

NOW = 2_000_000
SUBJECT_A = "11" * 32
SUBJECT_B = "22" * 32
KEY_A = "09" + "00" * 31
KEY_B = "0a" + "00" * 31
KEY_A_PLUS_FIELD_PRIME = "f6" + "ff" * 30 + "7f"


def sources(subjects=(SUBJECT_A, SUBJECT_B)):
    entitlement_id = "entitlements:fixture-1"
    binding_id = "bindings:fixture-1"
    entitlements = {
        "schema": "hodlxxi.full_entitlement_snapshot.v1",
        "version": 1,
        "source": "hodlxxi-crt",
        "snapshotId": entitlement_id,
        "complete": True,
        "issuedAt": NOW - 1_000,
        "expiresAt": NOW + 400_000,
        "entitlements": [
            {
                "snapshotId": entitlement_id,
                "subject": subject,
                "status": "full",
                "validFrom": NOW - 2_000,
                "expiresAt": NOW + 500_000,
                "revoked": False,
            }
            for subject in subjects
        ],
    }
    keys = {SUBJECT_A: KEY_A, SUBJECT_B: KEY_B}
    bindings = {
        "schema": "hodlxxi.recipient_key_binding_snapshot.v1",
        "version": 1,
        "source": "hodlxxi-crt",
        "snapshotId": binding_id,
        "complete": True,
        "issuedAt": NOW - 500,
        "expiresAt": NOW + 350_000,
        "bindings": [
            {
                "snapshotId": binding_id,
                "subject": subject,
                "algorithm": "x25519-v1",
                "version": 1,
                "publicKey": keys[subject],
                "validFrom": NOW - 750,
                "expiresAt": NOW + 325_000,
                "revoked": False,
            }
            for subject in subjects
        ],
    }
    return entitlements, bindings


def unavailable(entitlements, bindings, now=NOW):
    with pytest.raises(FullRecipientDirectoryUnavailable) as caught:
        build_full_recipient_directory(entitlements, bindings, now=now)
    assert str(caught.value) == "full recipient directory unavailable"


def test_exact_output_and_deterministic_snapshot_digest():
    entitlements, bindings = sources((SUBJECT_A,))
    result = build_full_recipient_directory(entitlements, bindings, now=NOW)
    assert result == {
        "schema": "hodlxxi.full_recipient_directory.v1",
        "version": 1,
        "source": "hodlxxi-crt",
        "snapshotId": "sha256:a725a741e7cb8f8982463558f8cb016547f0080d4489abc921d4dd5e8be53a53",
        "complete": True,
        "issuedAt": NOW - 500,
        "expiresAt": NOW + 299_500,
        "recipients": [
            {
                "snapshotId": "sha256:a725a741e7cb8f8982463558f8cb016547f0080d4489abc921d4dd5e8be53a53",
                "subject": SUBJECT_A,
                "encryptionKey": {
                    "algorithm": "x25519-v1",
                    "version": 1,
                    "publicKey": KEY_A,
                    "validFrom": NOW - 750,
                    "expiresAt": NOW + 325_000,
                    "revoked": False,
                },
                "authority": {
                    "source": "hodlxxi-crt",
                    "version": 1,
                    "snapshotId": "sha256:a725a741e7cb8f8982463558f8cb016547f0080d4489abc921d4dd5e8be53a53",
                    "subject": SUBJECT_A,
                    "status": "full",
                    "expiresAt": NOW + 299_500,
                },
            }
        ],
    }


def test_complete_empty_directory_is_valid_and_deterministic():
    entitlements, bindings = sources(())
    first = build_full_recipient_directory(entitlements, bindings, now=NOW)
    second = build_full_recipient_directory(deepcopy(entitlements), deepcopy(bindings), now=NOW)
    assert first == second
    assert first["complete"] is True and first["recipients"] == []


def test_binding_covering_directory_and_exact_boundaries_are_accepted():
    entitlements, bindings = sources((SUBJECT_A,))
    covering = build_full_recipient_directory(entitlements, bindings, now=NOW)
    assert covering["recipients"][0]["encryptionKey"]["validFrom"] < covering["issuedAt"]
    assert covering["recipients"][0]["encryptionKey"]["expiresAt"] > covering["expiresAt"]

    bindings["bindings"][0]["validFrom"] = covering["issuedAt"]
    bindings["bindings"][0]["expiresAt"] = covering["expiresAt"]
    exact = build_full_recipient_directory(entitlements, bindings, now=NOW)
    assert exact["recipients"][0]["encryptionKey"]["validFrom"] == exact["issuedAt"]
    assert exact["recipients"][0]["encryptionKey"]["expiresAt"] == exact["expiresAt"]


def test_binding_must_cover_complete_directory_interval():
    mutations = (
        lambda binding: binding.update(validFrom=NOW - 499),
        lambda binding: binding.update(expiresAt=NOW + 299_499),
        lambda binding: binding.update(expiresAt=NOW + 200_000),
    )
    for mutate in mutations:
        entitlements, bindings = sources((SUBJECT_A,))
        mutate(bindings["bindings"][0])
        unavailable(entitlements, bindings)


@pytest.mark.parametrize("which", ["entitlements", "bindings"])
def test_partial_sources_fail_closed(which):
    entitlements, bindings = sources()
    (entitlements if which == "entitlements" else bindings)["complete"] = False
    unavailable(entitlements, bindings)


def test_missing_extra_duplicate_and_unsorted_subjects_fail_closed():
    for mutate in (
        lambda e, b: b["bindings"].pop(),
        lambda e, b: e["entitlements"].pop(),
        lambda e, b: e["entitlements"].append(deepcopy(e["entitlements"][0])),
        lambda e, b: b["bindings"].append(deepcopy(b["bindings"][0])),
        lambda e, b: e["entitlements"].reverse(),
        lambda e, b: b["bindings"].reverse(),
    ):
        entitlements, bindings = sources()
        mutate(entitlements, bindings)
        unavailable(entitlements, bindings)


@pytest.mark.parametrize("status", ["limited", "operator", "unknown", "Full"])
def test_non_full_evidence_fails_closed(status):
    entitlements, bindings = sources()
    entitlements["entitlements"][0]["status"] = status
    unavailable(entitlements, bindings)


def test_stale_future_expired_revoked_and_mismatched_evidence_fail_closed():
    mutations = (
        lambda e, b: e.update(expiresAt=NOW),
        lambda e, b: b.update(issuedAt=NOW + 1),
        lambda e, b: e["entitlements"][0].update(validFrom=NOW + 1),
        lambda e, b: e["entitlements"][0].update(expiresAt=NOW),
        lambda e, b: e["entitlements"][0].update(revoked=True),
        lambda e, b: e["entitlements"][0].update(snapshotId="other"),
        lambda e, b: b["bindings"][0].update(subject="33" * 32),
    )
    for mutate in mutations:
        entitlements, bindings = sources()
        mutate(entitlements, bindings)
        unavailable(entitlements, bindings)


def test_unsupported_malformed_revoked_and_duplicate_bindings_fail_closed():
    mutations = (
        lambda b: b.update(algorithm="x25519"),
        lambda b: b.update(version=0),
        lambda b: b.update(version=True),
        lambda b: b.update(revoked=True),
        lambda b: b.update(publicKey="AA" * 32),
        lambda b: b.update(publicKey=b["subject"]),
    )
    for mutate in mutations:
        entitlements, bindings = sources()
        mutate(bindings["bindings"][0])
        unavailable(entitlements, bindings)
    entitlements, bindings = sources()
    bindings["bindings"][1]["publicKey"] = bindings["bindings"][0]["publicKey"]
    unavailable(entitlements, bindings)


@pytest.mark.parametrize(
    "public_key",
    [
        "00" * 32,
        "01" + "00" * 31,
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e8dcf54e900",
        "ec" + "ff" * 30 + "7f",
        "ed" + "ff" * 30 + "7f",
        "ee" + "ff" * 30 + "7f",
        "09" + "00" * 30 + "80",
    ],
)
def test_prohibited_and_high_bit_x25519_encodings_fail_closed(public_key):
    entitlements, bindings = sources()
    bindings["bindings"][0]["publicKey"] = public_key
    unavailable(entitlements, bindings)


def test_non_canonical_x25519_p_plus_9_alias_fails_closed():
    entitlements, bindings = sources()
    bindings["bindings"][0]["publicKey"] = KEY_A_PLUS_FIELD_PRIME
    unavailable(entitlements, bindings)


def test_non_canonical_x25519_alias_cannot_bypass_duplicate_binding_detection():
    entitlements, bindings = sources()
    bindings["bindings"][0]["publicKey"] = KEY_A
    bindings["bindings"][1]["publicKey"] = KEY_A_PLUS_FIELD_PRIME
    unavailable(entitlements, bindings)


def test_unknown_fields_custom_values_and_non_integer_now_fail_closed():
    entitlements, bindings = sources()
    entitlements["private"] = "detail"
    unavailable(entitlements, bindings)
    entitlements, bindings = sources()
    bindings["bindings"][0] = object()
    unavailable(entitlements, bindings)
    entitlements, bindings = sources()
    unavailable(entitlements, bindings, now=True)


def test_excessive_population_fails_before_record_processing():
    entitlements, bindings = sources(())
    entitlements["entitlements"] = [None] * 4097
    unavailable(entitlements, bindings)


def test_inputs_are_not_mutated_or_retained_and_output_is_isolated():
    entitlements, bindings = sources()
    before = deepcopy((entitlements, bindings))
    result = build_full_recipient_directory(entitlements, bindings, now=NOW)
    assert (entitlements, bindings) == before
    entitlements["entitlements"][0]["subject"] = "ff" * 32
    bindings["bindings"][0]["publicKey"] = "fe" * 32
    assert result["recipients"][0]["subject"] == SUBJECT_A
    assert result["recipients"][0]["encryptionKey"]["publicKey"] == KEY_A


def test_snapshot_digest_is_independent_of_mapping_insertion_order():
    entitlements, bindings = sources()
    reordered_entitlements = {key: entitlements[key] for key in reversed(entitlements)}
    reordered_bindings = {key: bindings[key] for key in reversed(bindings)}
    assert build_full_recipient_directory(entitlements, bindings, now=NOW) == build_full_recipient_directory(
        reordered_entitlements, reordered_bindings, now=NOW
    )
