"""Injected append-only SQLAlchemy persistence for canonical genesis records."""

from __future__ import annotations

from datetime import timezone
import uuid

from app.models import CanonicalGenesisRecordRow
from app.services.canonical_genesis_record import (
    CanonicalGenesisRecord,
    canonical_genesis_record_bytes,
    canonical_genesis_record_sha256,
    parse_canonical_genesis_record,
)


class CanonicalGenesisRecordStorageError(RuntimeError):
    def __init__(self):
        super().__init__("canonical genesis record storage unavailable")


def _id(value: object) -> str:
    if type(value) is not str:
        raise CanonicalGenesisRecordStorageError()
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise CanonicalGenesisRecordStorageError() from None
    if canonical != value:
        raise CanonicalGenesisRecordStorageError()
    return value


def _utc(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _from_row(row: CanonicalGenesisRecordRow) -> CanonicalGenesisRecord:
    try:
        record = parse_canonical_genesis_record(row.canonical_record_json)
        digest = canonical_genesis_record_sha256(record)
        expected = {
            "record_id": record.record_id,
            "schema": record.schema,
            "record_version": record.record_version,
            "graph_or_protocol_id": record.graph_or_protocol_id,
            "genesis_participant_id": record.genesis_participant_id,
            "compressed_public_key": record.identity_anchor.compressed_public_key,
            "x_only_public_key": record.identity_anchor.x_only_public_key,
            "lifecycle_state": record.lifecycle_state.value,
            "created_at": record.created_at,
            "lifecycle_changed_at": record.lifecycle_changed_at,
            "effective_at": record.effective_at,
            "superseded_by_record_id": record.superseded_by_record_id,
            "canonical_record_sha256": digest,
        }
        for name, value in expected.items():
            stored = getattr(row, name)
            if name.endswith("_at"):
                stored = _utc(stored)
            if stored != value:
                raise CanonicalGenesisRecordStorageError()
        return record
    except CanonicalGenesisRecordStorageError:
        raise
    except Exception:
        raise CanonicalGenesisRecordStorageError() from None


class SqlAlchemyCanonicalGenesisRecordRepository:
    """Append/read through a caller-provided session factory; no global wiring."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def append(self, record: CanonicalGenesisRecord) -> None:
        session = None
        try:
            record = parse_canonical_genesis_record(canonical_genesis_record_bytes(record))
            session = self._session_factory()
            session.add(
                CanonicalGenesisRecordRow(
                    record_id=record.record_id,
                    schema=record.schema,
                    record_version=record.record_version,
                    graph_or_protocol_id=record.graph_or_protocol_id,
                    genesis_participant_id=record.genesis_participant_id,
                    compressed_public_key=record.identity_anchor.compressed_public_key,
                    x_only_public_key=record.identity_anchor.x_only_public_key,
                    lifecycle_state=record.lifecycle_state.value,
                    created_at=record.created_at,
                    lifecycle_changed_at=record.lifecycle_changed_at,
                    effective_at=record.effective_at,
                    superseded_by_record_id=record.superseded_by_record_id,
                    canonical_record_sha256=canonical_genesis_record_sha256(record),
                    canonical_record_json=canonical_genesis_record_bytes(record).decode("ascii"),
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
            raise CanonicalGenesisRecordStorageError() from None
        finally:
            if session is not None:
                session.close()

    def get(self, record_id: str) -> CanonicalGenesisRecord | None:
        record_id = _id(record_id)
        try:
            with self._session_factory() as session:
                rows = (
                    session.query(CanonicalGenesisRecordRow)
                    .filter(CanonicalGenesisRecordRow.record_id == record_id)
                    .all()
                )
                if not rows:
                    return None
                if len(rows) != 1:
                    raise CanonicalGenesisRecordStorageError()
                return _from_row(rows[0])
        except CanonicalGenesisRecordStorageError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise CanonicalGenesisRecordStorageError() from None

    def list_for_graph(self, graph_or_protocol_id: str) -> tuple[CanonicalGenesisRecord, ...]:
        if type(graph_or_protocol_id) is not str or not graph_or_protocol_id:
            raise CanonicalGenesisRecordStorageError()
        try:
            with self._session_factory() as session:
                rows = (
                    session.query(CanonicalGenesisRecordRow)
                    .filter(CanonicalGenesisRecordRow.graph_or_protocol_id == graph_or_protocol_id)
                    .order_by(
                        CanonicalGenesisRecordRow.created_at,
                        CanonicalGenesisRecordRow.record_id,
                    )
                    .all()
                )
                return tuple(_from_row(row) for row in rows)
        except CanonicalGenesisRecordStorageError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise CanonicalGenesisRecordStorageError() from None
