import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
import inspect
import json
from pathlib import Path
import re

import pytest

import app.services.privacy_safe_full_directory as directory_module
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import EntitlementDecision, EntitlementDenied, EntitlementUnavailable
from app.services.privacy_safe_full_directory import (
    PrivacySafeFullDirectoryDenied,
    PrivacySafeFullDirectoryUnavailable,
    PrivacySafeFullDirectoryV1,
)

NOW = datetime(2026, 8, 30, 12, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1000)
VIEWER_A = "01" * 32
VIEWER_B = "02" * 32
TARGET_A = "deadbeefcafebabe" + "42" * 16 + "facefeeddec0de42"
TARGET_B = "abcdef0123456789" + "57" * 16 + "0123456789abcdef"
ALIAS_SECRET = bytes(range(32))


class PopulationProvider:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error
        self.calls = 0
        self.sensitive_fixture_values = (
            "xpub-sensitive-fixture-value",
            "descriptor-sensitive-fixture-value",
            "x25519-sensitive-fixture-value",
            "nostr-sensitive-fixture-value",
            "covenant-sensitive-fixture-value",
        )

    def __call__(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.value


def decision(subject=VIEWER_A, identity=IdentityClass.FULL, relation=None, **changes):
    values = dict(
        subject=subject,
        identity_class=identity,
        current_full_relation_satisfied=identity is IdentityClass.FULL if relation is None else relation,
        evidence_source="canonical_current_entitlement",
        observed_at=NOW.isoformat(),
    )
    values.update(changes)
    return EntitlementDecision(**values)


def snapshot(subjects=(VIEWER_A, TARGET_A, TARGET_B)):
    issued_at = NOW_MS
    expires_at = NOW_MS + 300_000
    entitlements = [
        {
            "subject": subject,
            "status": "full",
            "validFrom": NOW_MS - 1_000,
            "expiresAt": expires_at,
            "revoked": False,
        }
        for subject in sorted(subjects)
    ]
    evidence = {
        "complete": True,
        "entitlements": entitlements,
        "expiresAt": expires_at,
        "issuedAt": issued_at,
    }
    canonical = json.dumps(evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    snapshot_id = "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
    return {
        "schema": "hodlxxi.full_entitlement_snapshot.v1",
        "version": 1,
        "source": "hodlxxi-crt",
        "snapshotId": snapshot_id,
        "complete": True,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
        "entitlements": [{"snapshotId": snapshot_id, **entitlement} for entitlement in entitlements],
    }


def service(
    *,
    viewer=VIEWER_A,
    resolver=None,
    provider=None,
    alias_secret=ALIAS_SECRET,
    alias_version=1,
):
    resolver = resolver or (lambda subject: decision(subject))
    provider = provider or PopulationProvider(snapshot())
    return PrivacySafeFullDirectoryV1(
        viewer_subject=viewer,
        current_entitlement_resolver=resolver,
        full_population_provider=provider,
        alias_secret=alias_secret,
        alias_version=alias_version,
        clock=lambda: NOW,
    )


def expected_alias(viewer, target, *, secret=ALIAS_SECRET, alias_version=1):
    message = b"\x00".join(
        (
            b"HODLXXI_PRIVACY_DIRECTORY_ALIAS_V1",
            b"1",
            str(alias_version).encode("ascii"),
            viewer.encode("ascii"),
            target.encode("ascii"),
        )
    )
    digest = hmac.new(secret, message, hashlib.sha256).digest()[:16]
    return "p_" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def assert_denied(instance):
    with pytest.raises(PrivacySafeFullDirectoryDenied) as caught:
        instance.current_directory()
    assert str(caught.value) == "privacy-safe full directory denied"


def assert_unavailable(instance):
    with pytest.raises(PrivacySafeFullDirectoryUnavailable) as caught:
        instance.current_directory()
    assert str(caught.value) == "privacy-safe full directory unavailable"


def test_canonical_full_viewer_receives_exact_minimal_directory():
    provider = PopulationProvider(snapshot())
    result = service(provider=provider).current_directory()
    assert provider.calls == 1
    assert set(result) == {"schema", "version", "participants"}
    assert result["schema"] == "hodlxxi.privacy_safe_full_directory.v1"
    assert result["version"] == 1
    assert len(result["participants"]) == 2
    assert all(
        set(entry) == {"alias", "identity_class", "current_full_relation_satisfied"}
        and entry["identity_class"] == "full"
        and entry["current_full_relation_satisfied"] is True
        for entry in result["participants"]
    )


def test_limited_viewer_is_denied_before_population_access():
    provider = PopulationProvider(snapshot())
    assert_denied(
        service(
            resolver=lambda subject: decision(
                subject,
                IdentityClass.LIMITED,
                observed_at=None,
                evidence_source="active_persisted_user",
            ),
            provider=provider,
        )
    )
    assert provider.calls == 0


def test_unknown_viewer_is_denied_before_population_access():
    provider = PopulationProvider(snapshot())

    def unknown(_subject):
        raise EntitlementDenied("subject detail")

    assert_denied(service(resolver=unknown, provider=provider))
    assert provider.calls == 0


def test_entitlement_unavailable_viewer_fails_closed_before_population_access():
    provider = PopulationProvider(snapshot())

    def unavailable(_subject):
        raise EntitlementUnavailable("storage detail")

    assert_unavailable(service(resolver=unavailable, provider=provider))
    assert provider.calls == 0


def test_noncanonical_and_malformed_full_viewers_fail_closed():
    assert_denied(service(viewer=TARGET_A.upper()))
    assert_unavailable(service(resolver=lambda subject: decision(subject, observed_at=None)))
    assert_denied(service(resolver=lambda subject: decision(subject, relation=False)))


def test_incomplete_full_population_fails_closed():
    value = snapshot()
    value["complete"] = False
    assert_unavailable(service(provider=PopulationProvider(value)))


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value.update(extra="unexpected"),
        lambda value: value.update(entitlements="not-a-list"),
        lambda value: value.update(snapshotId="sha256:" + "0" * 64),
        lambda value: value.update(expiresAt=NOW_MS),
        lambda value: value["entitlements"][0].update(status="limited"),
        lambda value: value["entitlements"].reverse(),
        lambda value: value["entitlements"].append(deepcopy(value["entitlements"][0])),
    ),
)
def test_malformed_stale_and_contradictory_populations_fail_closed(mutate):
    value = snapshot()
    mutate(value)
    assert_unavailable(service(provider=PopulationProvider(value)))


def test_population_missing_authorized_viewer_is_contradictory():
    assert_unavailable(service(provider=PopulationProvider(snapshot((TARGET_A, TARGET_B)))))


def test_population_provider_exception_is_generic_and_non_leaking():
    provider = PopulationProvider(error=RuntimeError(f"database failed for {TARGET_A}"))
    with pytest.raises(PrivacySafeFullDirectoryUnavailable) as caught:
        service(provider=provider).current_directory()
    assert str(caught.value) == "privacy-safe full directory unavailable"
    assert TARGET_A not in str(caught.value)


def test_self_is_excluded_and_single_viewer_population_is_empty():
    result = service(provider=PopulationProvider(snapshot((VIEWER_A,)))).current_directory()
    assert result["participants"] == []
    serialized = json.dumps(result, sort_keys=True)
    assert VIEWER_A not in serialized


def test_serialized_directory_leakage_regression_guard():
    provider = PopulationProvider(snapshot())
    result = service(provider=provider).current_directory()
    serialized = json.dumps(result, separators=(",", ":"), sort_keys=True)
    forbidden = (
        VIEWER_A,
        TARGET_A,
        TARGET_B,
        TARGET_A[:16],
        TARGET_A[-16:],
        TARGET_B[:16],
        TARGET_B[-16:],
        *provider.sensitive_fixture_values,
    )
    assert all(marker not in serialized for marker in forbidden)


def test_aliases_are_stable_url_safe_and_match_domain_separated_hmac():
    provider = PopulationProvider(snapshot((VIEWER_A, TARGET_A)))
    first = service(provider=provider).current_directory()
    second = service(provider=provider).current_directory()
    assert first == second
    alias = first["participants"][0]["alias"]
    assert alias == expected_alias(VIEWER_A, TARGET_A)
    assert re.fullmatch(r"p_[A-Za-z0-9_-]{22}", alias)
    assert TARGET_A[:16] not in alias and TARGET_A[-16:] not in alias


def test_same_target_has_different_aliases_for_different_viewers():
    value = snapshot((VIEWER_A, VIEWER_B, TARGET_A))
    first = service(viewer=VIEWER_A, provider=PopulationProvider(value)).current_directory()
    second = service(viewer=VIEWER_B, provider=PopulationProvider(value)).current_directory()
    alias_a = expected_alias(VIEWER_A, TARGET_A)
    alias_b = expected_alias(VIEWER_B, TARGET_A)
    assert alias_a != alias_b
    assert alias_a in {entry["alias"] for entry in first["participants"]}
    assert alias_b in {entry["alias"] for entry in second["participants"]}


def test_same_viewer_has_different_aliases_for_different_targets():
    result = service().current_directory()
    aliases = {entry["alias"] for entry in result["participants"]}
    assert expected_alias(VIEWER_A, TARGET_A) != expected_alias(VIEWER_A, TARGET_B)
    assert aliases == {expected_alias(VIEWER_A, TARGET_A), expected_alias(VIEWER_A, TARGET_B)}


def test_entries_are_sorted_deterministically_by_alias():
    first = service().current_directory()
    second = service(provider=PopulationProvider(deepcopy(snapshot()))).current_directory()
    aliases = [entry["alias"] for entry in first["participants"]]
    assert aliases == sorted(aliases)
    assert first == second


@pytest.mark.parametrize("secret", (None, b"", b"a" * 31, bytearray(b"a" * 32), "a" * 32))
def test_alias_secret_is_required_bytes_with_minimum_strength(secret):
    with pytest.raises(ValueError, match="invalid pairwise alias secret"):
        service(alias_secret=secret)


def test_alias_secret_and_version_rotate_the_namespace():
    original = service(provider=PopulationProvider(snapshot((VIEWER_A, TARGET_A)))).current_directory()
    changed_key = service(
        provider=PopulationProvider(snapshot((VIEWER_A, TARGET_A))),
        alias_secret=b"z" * 32,
    ).current_directory()
    changed_version = service(
        provider=PopulationProvider(snapshot((VIEWER_A, TARGET_A))),
        alias_version=2,
    ).current_directory()
    assert original["participants"][0]["alias"] != changed_key["participants"][0]["alias"]
    assert original["participants"][0]["alias"] != changed_version["participants"][0]["alias"]
    with pytest.raises(ValueError, match="invalid pairwise alias version"):
        service(alias_version=0)


def test_core_requires_no_legacy_wallet_x25519_nostr_or_transport_dependency():
    parameters = inspect.signature(PrivacySafeFullDirectoryV1).parameters
    assert {
        "viewer_subject",
        "current_entitlement_resolver",
        "full_population_provider",
        "alias_secret",
    }.issubset(parameters)
    source = Path(directory_module.__file__).read_text(encoding="utf-8").lower()
    for forbidden in (
        "access_level",
        "online_users",
        "bitcoinrpc",
        "descriptor",
        "xpub",
        "x25519",
        "nostr",
        "flask",
        "blueprint",
    ):
        assert forbidden not in source
    assert service().current_directory()["participants"]
