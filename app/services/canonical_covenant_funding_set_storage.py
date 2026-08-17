"""Injected SQLAlchemy persistence for canonical covenant funding sets."""

from datetime import timezone
import uuid

from app.models import CanonicalCovenantFundingOutpointRow as OutpointRow
from app.models import CanonicalCovenantFundingSetRow as FundingSetRow
from app.services.canonical_covenant_funding_set import (
    CovenantFundingSetLifecycle,
    canonical_covenant_funding_set_bytes,
    canonical_covenant_funding_set_sha256,
    parse_canonical_covenant_funding_set,
    validate_funding_set_registration,
)


class CanonicalCovenantFundingSetStorageError(RuntimeError):
    def __init__(self):
        super().__init__("canonical covenant funding set storage unavailable")


def _id(value):
    if type(value) is not str:
        raise CanonicalCovenantFundingSetStorageError()
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise CanonicalCovenantFundingSetStorageError() from None
    if canonical != value:
        raise CanonicalCovenantFundingSetStorageError()
    return value


def _utc(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _row_values(value):
    return {
        "funding_set_id": value.funding_set_id,
        "schema": value.schema,
        "funding_set_version": value.funding_set_version,
        "trusted_registration_id": value.trusted_registration_id,
        "trusted_registration_sha256": value.trusted_registration_sha256,
        "pair_sha256": value.pair_sha256,
        "subject_xonly_pubkey": value.subject_xonly_pubkey,
        "counterparty_xonly_pubkey": value.counterparty_xonly_pubkey,
        "lifecycle_state": value.lifecycle_state.value,
        "created_at": value.created_at,
        "lifecycle_changed_at": value.lifecycle_changed_at,
        "effective_at": value.effective_at,
        "superseded_by_funding_set_id": value.superseded_by_funding_set_id,
        "canonical_funding_set_sha256": canonical_covenant_funding_set_sha256(value),
        "canonical_record_json": canonical_covenant_funding_set_bytes(value).decode("ascii"),
    }


def _from_rows(row, children):
    try:
        value = parse_canonical_covenant_funding_set(row.canonical_record_json)
        expected = _row_values(value)
        for name, wanted in expected.items():
            stored = getattr(row, name)
            if name.endswith("_at"):
                stored = _utc(stored)
            if stored != wanted:
                raise CanonicalCovenantFundingSetStorageError()
        child_projection = tuple(
            (
                item.direction.value,
                item.txid,
                item.vout,
                item.amount_sats,
                item.witness_script_sha256,
                item.descriptor_sha256,
            )
            for item in value.recognized_outpoints
        )
        stored_projection = tuple(
            (item.direction, item.txid, item.vout, item.amount_sats, item.witness_script_sha256, item.descriptor_sha256)
            for item in children
        )
        if stored_projection != child_projection:
            raise CanonicalCovenantFundingSetStorageError()
        return value
    except CanonicalCovenantFundingSetStorageError:
        raise
    except Exception:
        raise CanonicalCovenantFundingSetStorageError() from None


class SqlAlchemyCanonicalCovenantFundingSetRepository:
    def __init__(self, session_factory, *, trusted_registration_repository):
        self._session_factory = session_factory
        self._trusted_registration_repository = trusted_registration_repository

    def _registration(self, value):
        try:
            registration = self._trusted_registration_repository.get(value.trusted_registration_id)
            if registration is None:
                raise CanonicalCovenantFundingSetStorageError()
            return validate_funding_set_registration(value, registration)
        except CanonicalCovenantFundingSetStorageError:
            raise
        except Exception:
            raise CanonicalCovenantFundingSetStorageError() from None

    def append(self, value):
        session = None
        try:
            value = parse_canonical_covenant_funding_set(canonical_covenant_funding_set_bytes(value))
            value = self._registration(value)
            session = self._session_factory()
            parent = FundingSetRow(**_row_values(value))
            parent.recognized_outpoints = [
                OutpointRow(
                    direction=x.direction.value,
                    txid=x.txid,
                    vout=x.vout,
                    amount_sats=x.amount_sats,
                    witness_script_sha256=x.witness_script_sha256,
                    descriptor_sha256=x.descriptor_sha256,
                )
                for x in value.recognized_outpoints
            ]
            session.add(parent)
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
            raise CanonicalCovenantFundingSetStorageError() from None
        finally:
            if session is not None:
                session.close()

    def _rows(self, filters):
        try:
            with self._session_factory() as session:
                parents = (
                    session.query(FundingSetRow)
                    .filter(*filters)
                    .order_by(FundingSetRow.created_at.asc(), FundingSetRow.funding_set_id.asc())
                    .all()
                )
                values = []
                for row in parents:
                    children = (
                        session.query(OutpointRow)
                        .filter(OutpointRow.funding_set_id == row.funding_set_id)
                        .order_by(OutpointRow.direction.asc(), OutpointRow.txid.asc(), OutpointRow.vout.asc())
                        .all()
                    )
                    values.append(_from_rows(row, children))
                return tuple(values)
        except (KeyboardInterrupt, SystemExit):
            raise
        except CanonicalCovenantFundingSetStorageError:
            raise
        except Exception:
            raise CanonicalCovenantFundingSetStorageError() from None

    def get(self, funding_set_id):
        rows = self._rows((FundingSetRow.funding_set_id == _id(funding_set_id),))
        if len(rows) > 1:
            raise CanonicalCovenantFundingSetStorageError()
        if not rows:
            return None
        return (
            self._registration(rows[0])
            if (rows[0].lifecycle_state is CovenantFundingSetLifecycle.EFFECTIVE)
            else rows[0]
        )

    def list_by_registration(self, trusted_registration_id):
        rows = self._rows((FundingSetRow.trusted_registration_id == _id(trusted_registration_id),))
        return tuple(
            self._registration(value) if (value.lifecycle_state is CovenantFundingSetLifecycle.EFFECTIVE) else value
            for value in rows
        )

    def resolve_effective(self, trusted_registration_id):
        rows = self._rows(
            (
                FundingSetRow.trusted_registration_id == _id(trusted_registration_id),
                FundingSetRow.lifecycle_state == CovenantFundingSetLifecycle.EFFECTIVE.value,
            )
        )
        if len(rows) != 1:
            raise CanonicalCovenantFundingSetStorageError()
        return self._registration(rows[0])
