import hashlib
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import EntitlementDecision
from app.services.privacy_safe_full_directory import derive_privacy_directory_alias
from app.services.recipient_device_resolver import (
    PACKAGE_SCHEMA,
    RecipientAliasInvalid,
    RecipientDeviceResolverDenied,
    RecipientDeviceResolverUnavailable,
    RecipientDeviceResolverV1,
)
from app.services.social_messaging_device_contract import MessagingDeviceBinding

NOW = datetime(2026, 9, 5, 20, 0, 0, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1000)
VIEWER_A = "01" * 32
VIEWER_B = "02" * 32
TARGET = "03" * 32
ALIAS_SECRET = bytes(range(32))
KEY_A = "09" + "00" * 31
KEY_B = "0a" + "00" * 31
DEVICE_A = "11" * 32
DEVICE_B = "12" * 32
BINDING_A = "21" * 32
BINDING_B = "22" * 32
REQUEST_A = "31" * 32
REQUEST_B = "32" * 32


def decision(subject, identity=IdentityClass.FULL):
    return EntitlementDecision(
        subject=subject,
        identity_class=identity,
        current_full_relation_satisfied=identity is IdentityClass.FULL,
        evidence_source="canonical_current_entitlement",
        observed_at=NOW.isoformat(),
    )


def full_snapshot(subjects=(VIEWER_A, TARGET), *, lifetime_ms=300_000):
    issued_at = NOW_MS
    expires_at = NOW_MS + lifetime_ms
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
        "entitlements": [{"snapshotId": snapshot_id, **item} for item in entitlements],
    }


def binding(
    *,
    subject=TARGET,
    device_id=DEVICE_A,
    binding_id=BINDING_A,
    public_key=KEY_A,
    request_id=REQUEST_A,
):
    return MessagingDeviceBinding(
        subject=subject,
        device_id=device_id,
        binding_id=binding_id,
        public_key=public_key,
        binding_version=1,
        valid_from=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=600),
        operation="register",
        prior_binding_id=None,
        request_id=request_id,
        active=True,
    )


class PopulationProvider:
    def __init__(self, value):
        self.value = value
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.value


class Repository:
    def __init__(self, values=None, error=None):
        self.values = [binding()] if values is None else values
        self.error = error
        self.calls = []

    def apply(self, *_args, **_kwargs):
        raise AssertionError("recipient resolver is read-only")

    def current_for_subject(self, subject, *, now, maximum):
        self.calls.append((subject, now, maximum))
        if self.error is not None:
            raise self.error
        return list(self.values)


def resolver(*, population=None, repository=None, entitlement_resolver=None, alias_version=1):
    provider = population or PopulationProvider(full_snapshot())
    repo = repository or Repository()
    entitlement_resolver = entitlement_resolver or (lambda subject: decision(subject))
    instance = RecipientDeviceResolverV1(
        current_entitlement_resolver=entitlement_resolver,
        full_population_provider=provider,
        device_repository=repo,
        alias_secret=ALIAS_SECRET,
        alias_version=alias_version,
        clock=lambda: NOW,
    )
    return instance, provider, repo


def recipient_alias(viewer=VIEWER_A, target=TARGET, alias_version=1):
    return derive_privacy_directory_alias(
        viewer=viewer,
        target=target,
        alias_secret=ALIAS_SECRET,
        alias_version=alias_version,
    )


def test_exact_privacy_minimized_multi_device_package():
    repo = Repository(
        [
            binding(),
            binding(
                device_id=DEVICE_B,
                binding_id=BINDING_B,
                public_key=KEY_B,
                request_id=REQUEST_B,
            ),
        ]
    )
    instance, provider, _ = resolver(repository=repo)
    result = instance.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias())

    assert provider.calls == 1
    assert repo.calls and repo.calls[0][0] == TARGET
    assert set(result) == {
        "schema",
        "version",
        "source",
        "snapshotId",
        "complete",
        "alias",
        "issuedAt",
        "expiresAt",
        "devices",
    }
    assert result["schema"] == PACKAGE_SCHEMA
    assert result["version"] == 1
    assert result["source"] == "hodlxxi-ubid"
    assert result["complete"] is True
    assert result["alias"] == recipient_alias()
    assert len(result["devices"]) == 2
    assert all(
        set(item)
        == {
            "deviceHandle",
            "algorithm",
            "version",
            "publicKey",
            "validFrom",
            "expiresAt",
        }
        and item["algorithm"] == "x25519-v1"
        for item in result["devices"]
    )

    serialized = json.dumps(result, sort_keys=True)
    for forbidden in (VIEWER_A, TARGET, DEVICE_A, DEVICE_B, BINDING_A, BINDING_B, REQUEST_A, REQUEST_B):
        assert forbidden not in serialized


def test_device_handles_are_stable_per_viewer_and_pairwise_across_viewers():
    population = full_snapshot((VIEWER_A, VIEWER_B, TARGET))
    first, _, _ = resolver(population=PopulationProvider(deepcopy(population)))
    second, _, _ = resolver(population=PopulationProvider(deepcopy(population)))

    package_a1 = first.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias(VIEWER_A))
    package_a2 = second.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias(VIEWER_A))
    package_b = first.resolve(viewer_subject=VIEWER_B, recipient_alias=recipient_alias(VIEWER_B))

    handle_a1 = package_a1["devices"][0]["deviceHandle"]
    handle_a2 = package_a2["devices"][0]["deviceHandle"]
    handle_b = package_b["devices"][0]["deviceHandle"]
    assert handle_a1 == handle_a2
    assert handle_a1 != handle_b
    assert handle_a1.startswith("d_")
    assert len(handle_a1) == 24


@pytest.mark.parametrize(
    "alias",
    (
        None,
        "",
        "p_short",
        "rc_" + "A" * 22,
        "p_" + "!" * 22,
        "p_" + "A" * 21,
        "p_" + "A" * 23,
    ),
)
def test_malformed_alias_is_rejected_before_population_or_repository_access(alias):
    instance, provider, repo = resolver()
    with pytest.raises(RecipientAliasInvalid, match="recipient alias invalid"):
        instance.resolve(viewer_subject=VIEWER_A, recipient_alias=alias)
    assert provider.calls == 0
    assert repo.calls == []


def test_unknown_but_well_formed_alias_fails_without_target_repository_access():
    instance, provider, repo = resolver()
    with pytest.raises(RecipientDeviceResolverUnavailable, match="recipient messaging devices unavailable"):
        instance.resolve(viewer_subject=VIEWER_A, recipient_alias="p_" + "A" * 22)
    assert provider.calls == 1
    assert repo.calls == []


def test_limited_viewer_is_denied_before_population_or_repository_access():
    instance, provider, repo = resolver(entitlement_resolver=lambda subject: decision(subject, IdentityClass.LIMITED))
    with pytest.raises(RecipientDeviceResolverDenied, match="recipient messaging device resolution denied"):
        instance.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias())
    assert provider.calls == 0
    assert repo.calls == []


def test_malformed_or_stale_population_fails_closed_before_repository_access():
    value = full_snapshot()
    value["complete"] = False
    instance, provider, repo = resolver(population=PopulationProvider(value))
    with pytest.raises(RecipientDeviceResolverUnavailable):
        instance.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias())
    assert provider.calls == 1
    assert repo.calls == []


def test_recipient_without_active_device_is_unavailable():
    repo = Repository(values=[])
    instance, _, _ = resolver(repository=repo)
    with pytest.raises(RecipientDeviceResolverUnavailable):
        instance.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias())
    assert repo.calls and repo.calls[0][0] == TARGET


def test_repository_failure_is_generic_and_does_not_leak_target():
    repo = Repository(error=RuntimeError(f"database failed for {TARGET}"))
    instance, _, _ = resolver(repository=repo)
    with pytest.raises(RecipientDeviceResolverUnavailable) as caught:
        instance.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias())
    assert str(caught.value) == "recipient messaging devices unavailable"
    assert TARGET not in str(caught.value)


def test_malformed_repository_binding_fails_closed():
    repo = Repository(values=[{"subject": TARGET}])
    instance, _, _ = resolver(repository=repo)
    with pytest.raises(RecipientDeviceResolverUnavailable):
        instance.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias())


def test_package_validity_is_clamped_to_full_population_and_device_snapshot():
    population = PopulationProvider(full_snapshot(lifetime_ms=120_000))
    instance, _, _ = resolver(population=population)
    result = instance.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias())
    assert result["issuedAt"] == NOW_MS
    assert result["expiresAt"] == NOW_MS + 120_000


def test_alias_version_changes_both_recipient_alias_and_device_handle_namespace():
    first, _, _ = resolver(alias_version=1)
    second, _, _ = resolver(alias_version=2)
    package_one = first.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias(alias_version=1))
    package_two = second.resolve(viewer_subject=VIEWER_A, recipient_alias=recipient_alias(alias_version=2))
    assert package_one["alias"] != package_two["alias"]
    assert package_one["devices"][0]["deviceHandle"] != package_two["devices"][0]["deviceHandle"]


@pytest.mark.parametrize(
    "changes",
    (
        {"current_entitlement_resolver": None},
        {"full_population_provider": None},
        {"device_repository": object()},
        {"alias_secret": b"x" * 31},
        {"alias_version": 0},
        {"clock": "not-callable"},
    ),
)
def test_constructor_rejects_incomplete_or_unsafe_dependencies(changes):
    values = {
        "current_entitlement_resolver": lambda subject: decision(subject),
        "full_population_provider": PopulationProvider(full_snapshot()),
        "device_repository": Repository(),
        "alias_secret": ALIAS_SECRET,
        "alias_version": 1,
        "clock": lambda: NOW,
    }
    values.update(changes)
    with pytest.raises(ValueError, match="invalid recipient device resolver dependency"):
        RecipientDeviceResolverV1(**values)
