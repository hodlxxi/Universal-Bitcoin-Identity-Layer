"""Purpose-specific authority boundary and real RS256 signing."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.services.social_enrollment_v2_reservation_authority import LockedReservationCandidate
from app.services.social_enrollment_v2_reservation_contract import ReservationConfig, ReservationDenied
from app.services.social_enrollment_v2_reservation_signer import DedicatedRS256EvidenceSigner
from tests.unit.test_social_enrollment_v2_reservation import ReservationSession, configuration, reservation_graph


def test_generic_key_or_default_configuration_cannot_sign():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    config = configuration(key)
    for value in ({"private_key": key}, lambda: key, "generic-oauth-key", None, key.public_key()):
        with pytest.raises(ReservationDenied):
            DedicatedRS256EvidenceSigner(private_key=value, config=config)
    with pytest.raises(ReservationDenied):
        DedicatedRS256EvidenceSigner(private_key=key, config=ReservationConfig())
    with pytest.raises(ReservationDenied):
        DedicatedRS256EvidenceSigner(
            private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048), config=config
        )


@pytest.mark.parametrize(
    "forgery", ["dict", "dataclass", "unregistered", "other_owner", "stale_candidate", "signed_twice"]
)
def test_only_this_owners_registered_one_use_candidate_can_sign(reservation_graph, forgery):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        owner = g.owner(s)
        a = owner.authority
        candidate = a.prepare(g.input_wire, g.issuance_id)
        if forgery == "dict":
            candidate = {"payload": "{}", "current": True}
        elif forgery == "dataclass":
            candidate = SimpleNamespace(owner=a, payload_wire="{}")
        elif forgery == "unregistered":
            candidate = object.__new__(LockedReservationCandidate)
        elif forgery == "other_owner":
            candidate = g.owner(s).authority.prepare(g.input_wire, g.issuance_id)
        elif forgery == "stale_candidate":
            a.prepare(g.input_wire, g.issuance_id)
        elif forgery == "signed_twice":
            owner.signer.sign(candidate, owner=a)
        with pytest.raises(ReservationDenied) as error:
            owner.signer.sign(candidate, owner=a)
        assert a.failed and a.guard.poisoned
        assert error.value.__context__ is None


def test_selected_trust_lifecycle_not_before_exclusive_after_and_revocation(reservation_graph):
    from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
    from app.services.social_enrollment_v2_reservation_contract import dedicated_reservation_key_id

    g = reservation_graph
    record = g.config.selected_trust()
    for modified in (
        replace(record, revoked_at=record.not_before),
        replace(record, not_before=int(g.now.timestamp()) * 1000 + 1),
        replace(record, not_after=int(g.now.timestamp()) * 1000),
    ):
        jwk = dict(modified.public_jwk)
        jwk["kid"] = dedicated_reservation_key_id(
            key_fingerprint=modified.key_fingerprint,
            trust_revision=modified.trust_revision,
            not_before=modified.not_before,
            not_after=modified.not_after,
        )
        modified = evidence.DeadlineEvidenceTrustRecordV1(
            jwk,
            modified.trust_revision,
            modified.not_before,
            modified.not_after,
            modified.revoked_at,
        )
        ec = replace(g.config.evidence_config, trust_records=(modified,))
        kwargs = dict(
            evidence_config=ec,
            selected_kid=modified.key_id,
            trust_pins=((modified.key_id, modified.trust_revision, modified.trust_record_id),),
        )
        with ReservationSession(g) as s, s.begin():
            with pytest.raises(ReservationDenied):
                owner = g.owner(s, replace(g.config, **kwargs))
                owner.reserve(g.input_wire, issuance_id=g.issuance_id)


class DelayedRSA(rsa.RSAPrivateKey):
    """An already-held real ephemeral key, with delay at the actual sign call."""

    def __init__(self, key, after):
        self.key, self.after = key, after

    @property
    def key_size(self):
        return self.key.key_size

    def public_key(self):
        return self.key.public_key()

    def sign(self, data, padding, algorithm):
        signed = self.key.sign(data, padding, algorithm)
        self.after()
        return signed

    def decrypt(self, ciphertext, padding):
        raise AssertionError("not a reservation operation")

    def private_numbers(self):
        raise AssertionError("no private material extraction")

    def private_bytes(self, *args, **kwargs):
        raise AssertionError("no private serialization")

    def __copy__(self):
        raise AssertionError("no key copy")

    def __deepcopy__(self, memo):
        raise AssertionError("no key copy")


def test_expiry_during_real_rsa_private_operation_never_returns_signature(reservation_graph):
    from datetime import timedelta

    from tests.unit.test_social_session_issuance_v2_storage import NOW

    g = reservation_graph
    delayed = DelayedRSA(g.evidence_key, lambda: setattr(g, "now", NOW + timedelta(seconds=10)))
    with ReservationSession(g) as s:
        tx = s.begin()
        owner = g.owner(s, key=delayed)
        candidate = owner.authority.prepare(g.input_wire, g.issuance_id)
        with pytest.raises(ReservationDenied):
            owner.signer.sign(candidate, owner=owner.authority)
        assert owner.authority.failed and tx.is_active
        tx.rollback()
    assert not g.rows()


def test_registry_snapshot_cannot_be_mutated_even_with_object_setattr(reservation_graph):
    from app.services.social_enrollment_v2_reservation_authority import _RECORDS

    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        owner = g.owner(s)
        candidate = owner.authority.prepare(g.input_wire, g.issuance_id)
        record = _RECORDS[candidate]
        with pytest.raises(AttributeError):
            object.__setattr__(record, "expires_at", record.expires_at + 1)
        with pytest.raises(AttributeError):
            object.__setattr__(candidate, "payload_wire", "{}")
        assert g.input_wire not in repr(record)
        compact = owner.signer.sign(candidate, owner=owner.authority)
        assert compact.count(".") == 2
