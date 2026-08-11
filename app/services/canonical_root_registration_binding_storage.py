"""Injected SQLAlchemy persistence for canonical root registration bindings."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

from app.models import CanonicalRootRegistrationBindingRow
from app.services.canonical_genesis_record import evaluate_canonical_genesis
from app.services.canonical_root_registration_binding import (
    CanonicalRootRegistrationBinding,
    RootRegistrationBindingLifecycle,
    canonical_root_registration_binding_bytes,
    canonical_root_registration_binding_sha256,
    parse_canonical_root_registration_binding,
    validate_binding_sources,
    validate_root_registration_binding_transition,
)


class CanonicalRootRegistrationBindingStorageError(RuntimeError):
    def __init__(self):
        super().__init__("canonical root registration binding storage unavailable")


def _id(value: object) -> str:
    if type(value) is not str:
        raise CanonicalRootRegistrationBindingStorageError()
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise CanonicalRootRegistrationBindingStorageError() from None
    if canonical != value:
        raise CanonicalRootRegistrationBindingStorageError()
    return value


def _subject(value: object) -> str:
    if type(value) is not str or len(value) != 64 or value != value.lower():
        raise CanonicalRootRegistrationBindingStorageError()
    try:
        bytes.fromhex(value)
    except ValueError:
        raise CanonicalRootRegistrationBindingStorageError() from None
    return value


def _utc(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _from_row(row: CanonicalRootRegistrationBindingRow) -> CanonicalRootRegistrationBinding:
    try:
        binding = parse_canonical_root_registration_binding(row.canonical_record_json)
        if row.canonical_record_json != canonical_root_registration_binding_bytes(binding).decode("ascii"):
            raise CanonicalRootRegistrationBindingStorageError()
        expected = {
            "binding_id": binding.binding_id,
            "schema": binding.schema,
            "binding_version": binding.binding_version,
            "graph_or_protocol_id": binding.graph_or_protocol_id,
            "root_x_only_public_key": binding.root_x_only_public_key,
            "trusted_registration_id": binding.trusted_registration_id,
            "trusted_registration_sha256": binding.trusted_registration_sha256,
            "lifecycle_state": binding.lifecycle_state.value,
            "created_at": binding.created_at,
            "lifecycle_changed_at": binding.lifecycle_changed_at,
            "effective_at": binding.effective_at,
            "superseded_by_binding_id": binding.superseded_by_binding_id,
            "canonical_binding_sha256": canonical_root_registration_binding_sha256(binding),
        }
        for name, value in expected.items():
            stored = getattr(row, name)
            if name.endswith("_at"):
                stored = _utc(stored)
            if stored != value:
                raise CanonicalRootRegistrationBindingStorageError()
        return binding
    except CanonicalRootRegistrationBindingStorageError:
        raise
    except Exception:
        raise CanonicalRootRegistrationBindingStorageError() from None


def _row_values(binding: CanonicalRootRegistrationBinding) -> dict:
    return {
        "binding_id": binding.binding_id,
        "schema": binding.schema,
        "binding_version": binding.binding_version,
        "graph_or_protocol_id": binding.graph_or_protocol_id,
        "root_x_only_public_key": binding.root_x_only_public_key,
        "trusted_registration_id": binding.trusted_registration_id,
        "trusted_registration_sha256": binding.trusted_registration_sha256,
        "lifecycle_state": binding.lifecycle_state.value,
        "created_at": binding.created_at,
        "lifecycle_changed_at": binding.lifecycle_changed_at,
        "effective_at": binding.effective_at,
        "superseded_by_binding_id": binding.superseded_by_binding_id,
        "canonical_binding_sha256": canonical_root_registration_binding_sha256(binding),
        "canonical_record_json": canonical_root_registration_binding_bytes(binding).decode("ascii"),
    }


class SqlAlchemyCanonicalRootRegistrationBindingRepository:
    """Append/read through injected canonical repositories and session factory."""

    def __init__(self, session_factory, *, genesis_repository, trusted_registration_repository):
        self._session_factory = session_factory
        self._genesis_repository = genesis_repository
        self._trusted_registration_repository = trusted_registration_repository

    def _sources(
        self,
        binding,
        evaluated_at: datetime,
        *,
        require_active: bool = True,
        require_digest: bool = True,
    ):
        records = self._genesis_repository.list_for_graph(binding.graph_or_protocol_id)
        genesis = evaluate_canonical_genesis(
            records,
            graph_or_protocol_id=binding.graph_or_protocol_id,
            evaluated_at=evaluated_at,
        )
        registration = self._trusted_registration_repository.get(binding.trusted_registration_id)
        if registration is None:
            raise CanonicalRootRegistrationBindingStorageError()
        return validate_binding_sources(
            binding,
            genesis_evaluation=genesis,
            trusted_registration=registration,
            require_active=require_active,
            require_digest=require_digest,
        )[0]

    def append(self, binding: CanonicalRootRegistrationBinding, *, evaluated_at: datetime) -> None:
        session = None
        try:
            binding = self._sources(binding, evaluated_at)
            binding = parse_canonical_root_registration_binding(canonical_root_registration_binding_bytes(binding))
            session = self._session_factory()
            session.add(CanonicalRootRegistrationBindingRow(**_row_values(binding)))
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
            raise CanonicalRootRegistrationBindingStorageError() from None
        finally:
            if session is not None:
                session.close()

    def transition(
        self,
        binding_id: str,
        transitioned: CanonicalRootRegistrationBinding,
        *,
        evaluated_at: datetime,
        replacement: CanonicalRootRegistrationBinding | None = None,
    ) -> None:
        """Persist one validated lifecycle change and optional rotation atomically."""
        session = None
        try:
            require_current = transitioned.lifecycle_state is RootRegistrationBindingLifecycle.EFFECTIVE
            transitioned = self._sources(
                transitioned,
                evaluated_at,
                require_active=require_current,
                require_digest=require_current,
            )
            if transitioned.binding_id != _id(binding_id):
                raise CanonicalRootRegistrationBindingStorageError()
            if transitioned.lifecycle_state is RootRegistrationBindingLifecycle.SUPERSEDED:
                if (
                    replacement is None
                    or transitioned.superseded_by_binding_id != replacement.binding_id
                    or replacement.lifecycle_state is not RootRegistrationBindingLifecycle.EFFECTIVE
                ):
                    raise CanonicalRootRegistrationBindingStorageError()
                replacement = self._sources(replacement, evaluated_at)
                if (
                    replacement.graph_or_protocol_id != transitioned.graph_or_protocol_id
                    or replacement.root_x_only_public_key != transitioned.root_x_only_public_key
                ):
                    raise CanonicalRootRegistrationBindingStorageError()
            elif replacement is not None:
                raise CanonicalRootRegistrationBindingStorageError()
            session = self._session_factory()
            rows = (
                session.query(CanonicalRootRegistrationBindingRow)
                .filter(CanonicalRootRegistrationBindingRow.binding_id == binding_id)
                .all()
            )
            if len(rows) != 1:
                raise CanonicalRootRegistrationBindingStorageError()
            previous = _from_row(rows[0])
            validate_root_registration_binding_transition(previous, transitioned)
            for name, value in _row_values(transitioned).items():
                setattr(rows[0], name, value)
            if replacement is not None:
                session.add(CanonicalRootRegistrationBindingRow(**_row_values(replacement)))
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
            raise CanonicalRootRegistrationBindingStorageError() from None
        finally:
            if session is not None:
                session.close()

    def _rows(self, filters) -> tuple[CanonicalRootRegistrationBinding, ...]:
        try:
            with self._session_factory() as session:
                rows = session.query(CanonicalRootRegistrationBindingRow).filter(*filters).all()
                return tuple(_from_row(row) for row in rows)
        except (KeyboardInterrupt, SystemExit):
            raise
        except CanonicalRootRegistrationBindingStorageError:
            raise
        except Exception:
            raise CanonicalRootRegistrationBindingStorageError() from None

    def get(self, binding_id: str) -> CanonicalRootRegistrationBinding | None:
        rows = self._rows((CanonicalRootRegistrationBindingRow.binding_id == _id(binding_id),))
        if len(rows) > 1:
            raise CanonicalRootRegistrationBindingStorageError()
        return rows[0] if rows else None

    def list_for_root(self, graph_or_protocol_id: str, root_x_only_public_key: str):
        if type(graph_or_protocol_id) is not str or not graph_or_protocol_id:
            raise CanonicalRootRegistrationBindingStorageError()
        return self._rows(
            (
                CanonicalRootRegistrationBindingRow.graph_or_protocol_id == graph_or_protocol_id,
                CanonicalRootRegistrationBindingRow.root_x_only_public_key == _subject(root_x_only_public_key),
            )
        )

    def resolve_effective(
        self,
        graph_or_protocol_id: str,
        root_x_only_public_key: str,
        *,
        evaluated_at: datetime,
    ) -> CanonicalRootRegistrationBinding:
        rows = self._rows(
            (
                CanonicalRootRegistrationBindingRow.graph_or_protocol_id == graph_or_protocol_id,
                CanonicalRootRegistrationBindingRow.root_x_only_public_key == _subject(root_x_only_public_key),
                CanonicalRootRegistrationBindingRow.lifecycle_state
                == RootRegistrationBindingLifecycle.EFFECTIVE.value,
            )
        )
        if len(rows) != 1:
            raise CanonicalRootRegistrationBindingStorageError()
        try:
            return self._sources(rows[0], evaluated_at)
        except Exception:
            raise CanonicalRootRegistrationBindingStorageError() from None
