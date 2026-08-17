"""Injected SQLAlchemy persistence for dormant trusted covenant registrations."""

from __future__ import annotations

from datetime import timezone
import uuid

from app.models import (
    TrustedCovenantRegisteredOutpoint as OutpointRow,
    TrustedCovenantRegistration as RegistrationRow,
)
from app.services.covenant_relation import CovenantDirection
from app.services.mirrored_covenant_pair import (
    CovenantDeltaProfile,
    validate_mirrored_covenant_pair,
)
from app.services.trusted_covenant_registration import (
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
    trusted_outpoints_from_registration,
    trusted_registration_sha256,
)
from app.services.trusted_covenant_observation import TrustedCovenantOutpoint


class TrustedCovenantRegistrationStorageError(RuntimeError):
    """Registration persistence is unavailable or contains malformed state."""

    def __init__(self):
        super().__init__("trusted covenant registration storage unavailable")


def _canonical_id(value: object) -> str:
    if type(value) is not str:
        raise TrustedCovenantRegistrationStorageError()
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise TrustedCovenantRegistrationStorageError() from None
    if value != canonical:
        raise TrustedCovenantRegistrationStorageError()
    return value


def _db_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _revalidated(value: object) -> TrustedCovenantRegistration:
    if type(value) is not TrustedCovenantRegistration:
        raise TrustedCovenantRegistrationStorageError()
    try:
        canonical_trusted_registration_bytes(value)
        return TrustedCovenantRegistration(
            *(getattr(value, field) for field in TrustedCovenantRegistration.__dataclass_fields__)
        )
    except Exception:
        raise TrustedCovenantRegistrationStorageError() from None


def _registration_from_rows(row: RegistrationRow, outpoint_rows: list[OutpointRow]) -> TrustedCovenantRegistration:
    if len(outpoint_rows) != 2:
        raise TrustedCovenantRegistrationStorageError()
    try:
        profile = CovenantDeltaProfile(row.delta_profile)
        pair = validate_mirrored_covenant_pair(
            row.earlier_leg_script_hex,
            row.later_leg_script_hex,
            subject_pubkey=row.subject_pubkey,
            allowed_delta_profiles=(profile,),
        )
        registration = TrustedCovenantRegistration(
            row.schema,
            row.registration_version,
            row.registration_id,
            row.network,
            row.pair_sha256,
            row.validator_version,
            row.subject_pubkey,
            row.subject_xonly_pubkey,
            row.counterparty_pubkey,
            row.counterparty_xonly_pubkey,
            pair.template_family.__class__(row.template_family),
            profile,
            row.delta_blocks,
            TrustedCovenantRegistrationLifecycle(row.lifecycle_state),
            _db_utc(row.registered_at),
            _db_utc(row.lifecycle_changed_at),
            row.superseded_by_registration_id,
            tuple(
                RegisteredCovenantOutpoint(
                    CovenantDirection(item.direction),
                    item.txid,
                    item.vout,
                    item.amount_sats,
                    item.witness_script_sha256,
                    item.descriptor_sha256,
                )
                for item in outpoint_rows
            ),
            pair,
        )
        if trusted_registration_sha256(registration) != row.registration_sha256:
            raise TrustedCovenantRegistrationStorageError()
        return registration
    except TrustedCovenantRegistrationStorageError:
        raise
    except Exception:
        raise TrustedCovenantRegistrationStorageError() from None


class SqlAlchemyTrustedCovenantRegistrationRepository:
    """Append and retrieve registrations through a caller-provided session factory."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def append(self, registration: TrustedCovenantRegistration) -> None:
        session = None
        try:
            registration = _revalidated(registration)
            pair = registration.mirrored_pair
            session = self._session_factory()
            session.add(
                RegistrationRow(
                    registration_id=registration.registration_id,
                    schema=registration.schema,
                    registration_version=registration.registration_version,
                    network=registration.network,
                    pair_sha256=registration.pair_sha256,
                    registration_sha256=trusted_registration_sha256(registration),
                    validator_version=registration.validator_version,
                    subject_pubkey=registration.subject_pubkey,
                    subject_xonly_pubkey=registration.subject_xonly_pubkey,
                    counterparty_pubkey=registration.counterparty_pubkey,
                    counterparty_xonly_pubkey=registration.counterparty_xonly_pubkey,
                    template_family=registration.template_family.value,
                    delta_profile=registration.delta_profile.value,
                    delta_blocks=registration.delta_blocks,
                    lifecycle_state=registration.lifecycle_state.value,
                    registered_at=registration.registered_at,
                    lifecycle_changed_at=registration.lifecycle_changed_at,
                    superseded_by_registration_id=registration.superseded_by_registration_id,
                    earlier_leg_script_hex=pair.earlier_leg.raw_script_hex,
                    later_leg_script_hex=pair.later_leg.raw_script_hex,
                    outpoints=[
                        OutpointRow(
                            direction=item.direction.value,
                            txid=item.txid,
                            vout=item.vout,
                            amount_sats=item.amount_sats,
                            witness_script_sha256=item.witness_script_sha256,
                            descriptor_sha256=item.descriptor_sha256,
                        )
                        for item in registration.outpoints
                    ],
                )
            )
            session.commit()
        except (KeyboardInterrupt, SystemExit):
            if session is not None:
                session.rollback()
            raise
        except Exception:
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            raise TrustedCovenantRegistrationStorageError() from None
        finally:
            if session is not None:
                session.close()

    def get(self, registration_id: str) -> TrustedCovenantRegistration | None:
        registration_id = _canonical_id(registration_id)
        try:
            with self._session_factory() as session:
                rows = session.query(RegistrationRow).filter(RegistrationRow.registration_id == registration_id).all()
                if not rows:
                    return None
                if len(rows) != 1:
                    raise TrustedCovenantRegistrationStorageError()
                outpoints = (
                    session.query(OutpointRow)
                    .filter(OutpointRow.registration_id == registration_id)
                    .order_by(OutpointRow.id.asc())
                    .all()
                )
                return _registration_from_rows(rows[0], outpoints)
        except (KeyboardInterrupt, SystemExit):
            raise
        except TrustedCovenantRegistrationStorageError:
            raise
        except Exception:
            raise TrustedCovenantRegistrationStorageError() from None

    def get_active_outpoints(self, registration_id: str) -> tuple[TrustedCovenantOutpoint, ...] | None:
        registration = self.get(registration_id)
        if registration is None:
            return None
        return trusted_outpoints_from_registration(registration)
