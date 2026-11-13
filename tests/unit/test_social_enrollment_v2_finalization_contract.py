"""Offline configuration and the unchanged canonical producer/consumer wires."""

import copy
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from app.services.social_enrollment_v2_finalization_authority import LockedFinalizationPlan
from app.services.social_enrollment_v2_finalization_contract import (
    FinalizationConfig,
    FinalizationDenied,
    StatementTrustPin,
)


@pytest.mark.parametrize("factory", [FinalizationConfig, lambda: FinalizationConfig(enabled=True)])
def test_default_off_and_incomplete_enablement_denies(factory):
    if factory is FinalizationConfig:
        assert factory().enabled is False
    else:
        with pytest.raises(FinalizationDenied):
            factory()


@pytest.mark.parametrize(
    "action",
    [
        lambda: LockedFinalizationPlan(),
        lambda: copy.copy(object.__new__(LockedFinalizationPlan)),
        lambda: copy.deepcopy(object.__new__(LockedFinalizationPlan)),
    ],
)
def test_detached_plan_construction_and_copy_deny(action):
    with pytest.raises(FinalizationDenied) as caught:
        action()
    assert str(caught.value) == "social enrollment v2 finalization denied"
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize(
    "changes",
    [
        dict(revision=True),
        dict(not_before=True),
        dict(not_after=0),
        dict(fingerprint="private"),
        dict(not_before=10, not_after=10),
    ],
)
def test_statement_registration_is_closed_and_bounded(changes):
    good = StatementTrustPin("test", "sha256:" + "a" * 64, 1, 0, 100)
    with pytest.raises(FinalizationDenied):
        replace(good, **changes)


@pytest.mark.parametrize(
    "name,digest",
    [
        ("social_preacceptance_ed25519_handoff_v2", "4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc"),
        (
            "social_messaging_device_verification_deadline_evidence_v1",
            "5c2d9fa2c73b295ff6e4d3477c591273ec06251c65551b646468b62a35343dbb",
        ),
        (
            "social_preaccepted_enrollment_verification_statement_v2",
            "fdbbed748f28d1ef850ef3d82b1680e7dca12b0f7a2d863acf14dc7b75770f39",
        ),
        (
            "social_preaccepted_enrollment_v2_atomic_acceptance_v1",
            "6bbbf4c94f3120dbad57def6bceed7d5a9b563723402afb7cf1ca1e3121db7e8",
        ),
    ],
)
def test_fixed_vectors_remain_byte_identical(name, digest):
    path = Path(__file__).parents[1] / "fixtures" / (name + ".json")
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
