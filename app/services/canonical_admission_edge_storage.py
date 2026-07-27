"""Injected append-only persistence for canonical admission edges."""

from __future__ import annotations

from datetime import timezone
import uuid

from app.models import CanonicalAdmissionEdgeLegRow, CanonicalAdmissionEdgeRow
from app.services.canonical_admission_edge import (
    AdmissionEdgeLifecycle,
    CanonicalAdmissionEdge,
    canonical_admission_edge_bytes,
    canonical_admission_edge_sha256,
    parse_canonical_admission_edge,
    validate_admission_sources,
)


class CanonicalAdmissionEdgeStorageError(RuntimeError):
    def __init__(self):
        super().__init__("canonical admission edge storage unavailable")


def _id(value):
    try:
        canonical = str(uuid.UUID(value)) if type(value) is str else None
    except ValueError:
        canonical = None
    if canonical != value:
        raise CanonicalAdmissionEdgeStorageError()
    return value


def _utc(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _from_rows(row, leg_rows):
    try:
        if len(leg_rows) != 2:
            raise CanonicalAdmissionEdgeStorageError()
        rank = {"sponsor_to_child": 0, "child_to_sponsor": 1}
        directions = [item.direction for item in leg_rows]
        if set(directions) != set(rank) or len(set(directions)) != 2:
            raise CanonicalAdmissionEdgeStorageError()
        record = parse_canonical_admission_edge(row.canonical_record_json)
        expected = {
            "edge_id": record.edge_id,
            "schema": record.schema,
            "edge_version": record.edge_version,
            "graph_or_protocol_id": record.graph_or_protocol_id,
            "network": record.network,
            "human_profile": record.human_profile,
            "template_family": "cltv_only",
            "delta_blocks": 777,
            "sponsor_participant_id": record.sponsor_participant_id,
            "sponsor_compressed_public_key": record.sponsor_compressed_public_key,
            "sponsor_x_only_public_key": record.sponsor_x_only_public_key,
            "sponsor_depth": record.sponsor_depth,
            "child_participant_id": record.child_participant_id,
            "child_compressed_public_key": record.child_compressed_public_key,
            "child_x_only_public_key": record.child_x_only_public_key,
            "child_depth": record.child_depth,
            "early_height": record.early_height,
            "middle_height": record.middle_height,
            "late_height": record.late_height,
            "trusted_registration_id": record.trusted_registration_id,
            "trusted_registration_sha256": record.trusted_registration_sha256,
            "pair_sha256": record.pair_sha256,
            "validator_version": record.validator_version,
            "sponsor_basis_kind": record.sponsor_basis_kind.value,
            "sponsor_basis_record_id": record.sponsor_basis_record_id,
            "sponsor_basis_record_sha256": record.sponsor_basis_record_sha256,
            "lifecycle_state": record.lifecycle_state.value,
            "created_at": record.created_at,
            "lifecycle_changed_at": record.lifecycle_changed_at,
            "effective_at": record.effective_at,
            "superseded_by_edge_id": record.superseded_by_edge_id,
            "canonical_edge_sha256": canonical_admission_edge_sha256(record),
        }
        for name, value in expected.items():
            stored = getattr(row, name)
            if name.endswith("_at"):
                stored = _utc(stored)
            if stored != value:
                raise CanonicalAdmissionEdgeStorageError()
        ordered = sorted(leg_rows, key=lambda item: rank[item.direction])
        for stored, leg in zip(ordered, record.legs):
            for name in leg.__dataclass_fields__:
                expected_value = getattr(leg, name)
                if name == "direction":
                    expected_value = expected_value.value
                if getattr(stored, name) != expected_value:
                    raise CanonicalAdmissionEdgeStorageError()
        return record
    except CanonicalAdmissionEdgeStorageError:
        raise
    except Exception:
        raise CanonicalAdmissionEdgeStorageError() from None


class SqlAlchemyCanonicalAdmissionEdgeRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def append(self, record, *, trusted_registration, genesis_evaluation=None, parent_edge=None):
        session = None
        try:
            record = validate_admission_sources(
                record,
                trusted_registration,
                genesis_evaluation=genesis_evaluation,
                parent_edge=parent_edge,
                require_active=record.lifecycle_state is AdmissionEdgeLifecycle.EFFECTIVE,
            )
            record = parse_canonical_admission_edge(canonical_admission_edge_bytes(record))
            session = self._session_factory()
            row = CanonicalAdmissionEdgeRow(
                edge_id=record.edge_id,
                schema=record.schema,
                edge_version=record.edge_version,
                graph_or_protocol_id=record.graph_or_protocol_id,
                network=record.network,
                human_profile=record.human_profile,
                template_family="cltv_only",
                delta_blocks=777,
                sponsor_participant_id=record.sponsor_participant_id,
                sponsor_compressed_public_key=record.sponsor_compressed_public_key,
                sponsor_x_only_public_key=record.sponsor_x_only_public_key,
                sponsor_depth=record.sponsor_depth,
                child_participant_id=record.child_participant_id,
                child_compressed_public_key=record.child_compressed_public_key,
                child_x_only_public_key=record.child_x_only_public_key,
                child_depth=record.child_depth,
                early_height=record.early_height,
                middle_height=record.middle_height,
                late_height=record.late_height,
                trusted_registration_id=record.trusted_registration_id,
                trusted_registration_sha256=record.trusted_registration_sha256,
                pair_sha256=record.pair_sha256,
                validator_version=record.validator_version,
                sponsor_basis_kind=record.sponsor_basis_kind.value,
                sponsor_basis_record_id=record.sponsor_basis_record_id,
                sponsor_basis_record_sha256=record.sponsor_basis_record_sha256,
                lifecycle_state=record.lifecycle_state.value,
                created_at=record.created_at,
                lifecycle_changed_at=record.lifecycle_changed_at,
                effective_at=record.effective_at,
                superseded_by_edge_id=record.superseded_by_edge_id,
                canonical_edge_sha256=canonical_admission_edge_sha256(record),
                canonical_record_json=canonical_admission_edge_bytes(record).decode("ascii"),
                legs=[
                    CanonicalAdmissionEdgeLegRow(
                        **{
                            name: (getattr(leg, name).value if name == "direction" else getattr(leg, name))
                            for name in leg.__dataclass_fields__
                        }
                    )
                    for leg in record.legs
                ],
            )
            session.add(row)
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
            raise CanonicalAdmissionEdgeStorageError() from None
        finally:
            if session is not None:
                session.close()

    def _rows(self, filters, order=True):
        try:
            with self._session_factory() as session:
                query = session.query(CanonicalAdmissionEdgeRow).filter(*filters)
                if order:
                    query = query.order_by(
                        CanonicalAdmissionEdgeRow.created_at,
                        CanonicalAdmissionEdgeRow.edge_id,
                    )
                rows = query.all()
                result = []
                for row in rows:
                    legs = (
                        session.query(CanonicalAdmissionEdgeLegRow)
                        .filter(CanonicalAdmissionEdgeLegRow.edge_id == row.edge_id)
                        .all()
                    )
                    result.append(_from_rows(row, legs))
                return tuple(result)
        except (KeyboardInterrupt, SystemExit):
            raise
        except CanonicalAdmissionEdgeStorageError:
            raise
        except Exception:
            raise CanonicalAdmissionEdgeStorageError() from None

    def get(self, edge_id):
        rows = self._rows((CanonicalAdmissionEdgeRow.edge_id == _id(edge_id),), False)
        if len(rows) > 1:
            raise CanonicalAdmissionEdgeStorageError()
        return rows[0] if rows else None

    def list_for_graph(self, graph_or_protocol_id):
        if type(graph_or_protocol_id) is not str or not graph_or_protocol_id:
            raise CanonicalAdmissionEdgeStorageError()
        return self._rows((CanonicalAdmissionEdgeRow.graph_or_protocol_id == graph_or_protocol_id,))

    def list_for_child(self, graph_or_protocol_id, child_x_only_public_key):
        return self._rows(
            (
                CanonicalAdmissionEdgeRow.graph_or_protocol_id == graph_or_protocol_id,
                CanonicalAdmissionEdgeRow.child_x_only_public_key == child_x_only_public_key,
            )
        )

    def list_for_sponsor(self, graph_or_protocol_id, sponsor_x_only_public_key):
        return self._rows(
            (
                CanonicalAdmissionEdgeRow.graph_or_protocol_id == graph_or_protocol_id,
                CanonicalAdmissionEdgeRow.sponsor_x_only_public_key == sponsor_x_only_public_key,
            )
        )

    def get_effective_for_child(self, graph_or_protocol_id, child_x_only_public_key):
        rows = self._rows(
            (
                CanonicalAdmissionEdgeRow.graph_or_protocol_id == graph_or_protocol_id,
                CanonicalAdmissionEdgeRow.child_x_only_public_key == child_x_only_public_key,
                CanonicalAdmissionEdgeRow.lifecycle_state == "effective",
            )
        )
        if len(rows) > 1:
            raise CanonicalAdmissionEdgeStorageError()
        return rows[0] if rows else None
