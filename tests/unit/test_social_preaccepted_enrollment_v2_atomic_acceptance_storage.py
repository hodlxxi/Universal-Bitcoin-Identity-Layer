"""Unit guards for dormant V2 atomic-acceptance PostgreSQL durability."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import struct
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint, create_engine, inspect
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from app.models import Base
from app.services import social_messaging_device_verification_deadline_evidence_v1 as deadline
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as contract
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as storage
from app.services import social_preaccepted_enrollment_verification_statement_v2 as verification
from tests.unit import test_social_preaccepted_enrollment_v2_atomic_acceptance_contract as vectors

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "app/services/social_preaccepted_enrollment_v2_atomic_acceptance_storage.py"
MIGRATION = ROOT / "migrations/2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql"
ERROR = "^social preaccepted enrollment v2 atomic acceptance storage unavailable$"

_EXPECTED_GUARD_DEFINITION_PAYLOAD_SHAPE = {
    "function": {
        "allArgumentTypes": None,
        "argumentCount": None,
        "argumentDefaults": None,
        "argumentModes": None,
        "argumentNames": None,
        "argumentTypeOids": None,
        "binary": None,
        "config": None,
        "cost": None,
        "defaultArgumentCount": None,
        "kind": None,
        "language": None,
        "leakproof": None,
        "name": None,
        "parallel": None,
        "returnType": None,
        "returnsSet": None,
        "rows": None,
        "securityDefiner": None,
        "source": None,
        "sqlBody": None,
        "strict": None,
        "supportFunctionOid": None,
        "transformTypes": None,
        "variadicTypeOid": None,
        "volatility": None,
    },
    "relation": {
        "accessMethod": None,
        "checkConstraintCount": None,
        "columnCount": None,
        "forceRowSecurity": None,
        "hasIndexes": None,
        "hasRules": None,
        "hasSubclasses": None,
        "hasTriggers": None,
        "isPartition": None,
        "isPopulated": None,
        "isShared": None,
        "kind": None,
        "name": None,
        "ofTypeOid": None,
        "options": None,
        "partitionBound": None,
        "persistence": None,
        "replicaIdentity": None,
        "rowSecurity": None,
        "tablespaceOid": None,
        "toast": {
            "accessMethod": None,
            "checkConstraintCount": None,
            "columnCount": None,
            "forceRowSecurity": None,
            "hasIndexes": None,
            "hasRules": None,
            "hasSubclasses": None,
            "hasTriggers": None,
            "isPartition": None,
            "isPopulated": None,
            "isShared": None,
            "kind": None,
            "nameMatchesRelationOid": None,
            "namespace": None,
            "ofTypeOid": None,
            "options": None,
            "partitionBound": None,
            "persistence": None,
            "replicaIdentity": None,
            "rowSecurity": None,
            "rowTypeOid": None,
            "tablespaceOid": None,
        },
    },
    "triggers": [
        {
            "argumentCount": None,
            "argumentsHex": None,
            "attributes": None,
            "constraintIndexOid": None,
            "constraintOid": None,
            "constraintRelationOid": None,
            "deferrable": None,
            "enabled": None,
            "functionMatches": None,
            "initiallyDeferred": None,
            "internal": None,
            "name": None,
            "newTable": None,
            "oldTable": None,
            "parentOid": None,
            "qualification": None,
            "type": None,
        },
        {
            "argumentCount": None,
            "argumentsHex": None,
            "attributes": None,
            "constraintIndexOid": None,
            "constraintOid": None,
            "constraintRelationOid": None,
            "deferrable": None,
            "enabled": None,
            "functionMatches": None,
            "initiallyDeferred": None,
            "internal": None,
            "name": None,
            "newTable": None,
            "oldTable": None,
            "parentOid": None,
            "qualification": None,
            "type": None,
        },
    ],
}


def _recursive_payload_key_shape(value: object) -> object:
    if type(value) is dict:
        return {key: _recursive_payload_key_shape(item) for key, item in value.items()}  # type: ignore[union-attr]
    if type(value) is list and value and all(type(item) is dict for item in value):
        return [_recursive_payload_key_shape(item) for item in value]
    return None


def denied(callable_value) -> None:
    with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR) as failure:
        callable_value()
    assert failure.value.args == (storage.UNAVAILABLE_MESSAGE,)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


def pending_row() -> dict[str, object]:
    reservation = contract.parse_atomic_acceptance_reservation_v1(vectors.VECTOR["pendingReservationWire"])
    return storage._pending_row_values(
        reservation,
        input_wire=vectors.INPUT_WIRE,
        evidence_compact_jws=vectors.evidence_compact(),
    )


def _canonical(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _domain_sha256(domain: str, source: str) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + source.encode("ascii")).hexdigest()


def accepted_row() -> dict[str, object]:
    row = pending_row()
    result = vectors.model()
    reservation = contract.parse_atomic_acceptance_reservation_v1(result.reservation_after_wire)
    row.update(
        state="accepted",
        decided_at=reservation.decided_at,
        statement_digest=reservation.statement_digest,
        effect_id=reservation.effect_id,
        effect_digest=reservation.effect_digest,
        receipt_id=reservation.receipt_id,
        finalization_request_digest=result.finalization_request_digest,
        reservation_wire=reservation.wire,
        statement_compact_jws=vectors.STATEMENT["vector"]["compactJws"],
        finalization_observation_wire=vectors.VECTOR["finalizationObservationWire"],
        effect_wire=result.effect_wire,
        receipt_wire=result.receipt.wire,
    )
    return row


def forged_evidence_mismatched_accepted_row() -> dict[str, object]:
    """Reproduce the reviewed fullProofId-only, fully recomputed forgery."""

    observation = json.loads(vectors.VECTOR["finalizationObservationWire"])
    authority = json.loads(observation["authoritySnapshot"])
    authority["fullProofId"] = "hodlxxi-full-entitlement-v1-sha256:" + "f" * 64
    authority_wire = _canonical(authority)
    authority_digest = contract.current_authority_snapshot_digest_v1(authority_wire)
    observation.update(
        authoritySnapshot=authority_wire,
        authoritySnapshotDigest=authority_digest,
    )
    observation_wire = _canonical(observation)

    effect = json.loads(vectors.VECTOR["effectWire"])
    effect_preimage = _canonical(
        {
            "acceptanceId": effect["acceptanceId"],
            "associationId": effect["associationId"],
            "authoritySnapshotDigest": authority_digest,
            "challengeId": effect["challengeId"],
            "finalizationRequestDigest": effect["finalizationRequestDigest"],
            "reservationId": effect["reservationId"],
            "reservationRevision": effect["reservationRevision"],
            "schema": contract.EFFECT_ID_PREIMAGE_SCHEMA,
            "version": contract.VERSION,
        }
    )
    effect["effectId"] = _domain_sha256(contract.EFFECT_ID_DOMAIN, effect_preimage)
    effect_wire = _canonical(effect)
    effect_digest = contract.EFFECT_DIGEST_PREFIX + _domain_sha256(contract.EFFECT_DIGEST_DOMAIN, effect_wire)

    receipt = json.loads(vectors.VECTOR["receiptWire"])
    receipt.update(effectId=effect["effectId"], effectDigest=effect_digest)
    receipt_preimage = _canonical(
        {
            "effectDigest": effect_digest,
            "effectId": effect["effectId"],
            "finalizationRequestDigest": receipt["finalizationRequestDigest"],
            "reservationId": receipt["reservationId"],
            "reservationRevision": receipt["reservationRevision"],
            "schema": contract.RECEIPT_ID_PREIMAGE_SCHEMA,
            "version": contract.VERSION,
        }
    )
    receipt["receiptId"] = _domain_sha256(contract.RECEIPT_ID_DOMAIN, receipt_preimage)
    receipt_wire = _canonical(receipt)

    result = vectors.model()
    reservation = json.loads(result.reservation_after_wire)
    reservation.update(
        effectDigest=effect_digest,
        effectId=effect["effectId"],
        receiptId=receipt["receiptId"],
    )
    row = pending_row()
    row.update(
        state="accepted",
        decided_at=reservation["decidedAt"],
        statement_digest=reservation["statementDigest"],
        effect_id=effect["effectId"],
        effect_digest=effect_digest,
        receipt_id=receipt["receiptId"],
        finalization_request_digest=result.finalization_request_digest,
        reservation_wire=_canonical(reservation),
        statement_compact_jws=vectors.STATEMENT["vector"]["compactJws"],
        finalization_observation_wire=observation_wire,
        effect_wire=effect_wire,
        receipt_wire=receipt_wire,
    )
    return row


def recomputed_accepted_row(
    *,
    observation_wire: str | None = None,
    statement_wire: str | None = None,
) -> dict[str, object]:
    """Recompute the complete accepted chain after one selected byte change."""

    row = accepted_row()
    selected_observation = observation_wire or str(row["finalization_observation_wire"])
    selected_statement = statement_wire or str(row["statement_compact_jws"])
    observation = contract.parse_finalization_observation_v1(selected_observation)
    statement_digest = contract.STATEMENT_DIGEST_PREFIX + _domain_sha256(
        contract.STATEMENT_DIGEST_DOMAIN,
        selected_statement,
    )
    finalization_preimage = _canonical(
        {
            "evidenceDigest": row["evidence_digest"],
            "inputDigest": row["input_digest"],
            "inputPayloadDigest": row["input_payload_digest"],
            "reservationId": row["reservation_id"],
            "reservationRevision": row["reservation_revision"],
            "statementDigest": statement_digest,
        }
    )
    finalization_digest = contract.FINALIZATION_REQUEST_DIGEST_PREFIX + _domain_sha256(
        contract.FINALIZATION_REQUEST_DIGEST_DOMAIN,
        finalization_preimage,
    )
    effect = json.loads(str(row["effect_wire"]))
    effect["finalizationRequestDigest"] = finalization_digest
    effect_preimage = _canonical(
        {
            "acceptanceId": effect["acceptanceId"],
            "associationId": effect["associationId"],
            "authoritySnapshotDigest": observation.authority_snapshot_digest,
            "challengeId": effect["challengeId"],
            "finalizationRequestDigest": finalization_digest,
            "reservationId": effect["reservationId"],
            "reservationRevision": effect["reservationRevision"],
            "schema": contract.EFFECT_ID_PREIMAGE_SCHEMA,
            "version": contract.VERSION,
        }
    )
    effect["effectId"] = _domain_sha256(contract.EFFECT_ID_DOMAIN, effect_preimage)
    effect_wire = _canonical(effect)
    effect_digest = contract.EFFECT_DIGEST_PREFIX + _domain_sha256(contract.EFFECT_DIGEST_DOMAIN, effect_wire)
    receipt = json.loads(str(row["receipt_wire"]))
    receipt.update(
        statementDigest=statement_digest,
        finalizationRequestDigest=finalization_digest,
        effectId=effect["effectId"],
        effectDigest=effect_digest,
    )
    receipt_preimage = _canonical(
        {
            "effectDigest": effect_digest,
            "effectId": effect["effectId"],
            "finalizationRequestDigest": finalization_digest,
            "reservationId": receipt["reservationId"],
            "reservationRevision": receipt["reservationRevision"],
            "schema": contract.RECEIPT_ID_PREIMAGE_SCHEMA,
            "version": contract.VERSION,
        }
    )
    receipt["receiptId"] = _domain_sha256(contract.RECEIPT_ID_DOMAIN, receipt_preimage)
    receipt_wire = _canonical(receipt)
    reservation = json.loads(str(row["reservation_wire"]))
    reservation.update(
        statementDigest=statement_digest,
        effectId=effect["effectId"],
        effectDigest=effect_digest,
        receiptId=receipt["receiptId"],
    )
    row.update(
        statement_compact_jws=selected_statement,
        statement_digest=statement_digest,
        finalization_observation_wire=selected_observation,
        finalization_request_digest=finalization_digest,
        effect_id=effect["effectId"],
        effect_digest=effect_digest,
        receipt_id=receipt["receiptId"],
        effect_wire=effect_wire,
        receipt_wire=receipt_wire,
        reservation_wire=_canonical(reservation),
    )
    return row


def changed_observation_challenge_revision_accepted_row() -> dict[str, object]:
    observation = json.loads(vectors.VECTOR["finalizationObservationWire"])
    observation["challengeRevision"] = int(observation["challengeRevision"]) + 1
    return recomputed_accepted_row(observation_wire=_canonical(observation))


def changed_observation_time_accepted_row() -> dict[str, object]:
    observation = json.loads(vectors.VECTOR["finalizationObservationWire"])
    authority = json.loads(observation["authoritySnapshot"])
    authority["observedAt"] = int(authority["observedAt"]) + 1
    authority_wire = _canonical(authority)
    observation.update(
        observedAt=int(observation["observedAt"]) + 1,
        authoritySnapshot=authority_wire,
        authoritySnapshotDigest=(
            contract.AUTHORITY_SNAPSHOT_DIGEST_PREFIX
            + _domain_sha256(contract.AUTHORITY_SNAPSHOT_DIGEST_DOMAIN, authority_wire)
        ),
    )
    return recomputed_accepted_row(observation_wire=_canonical(observation))


def forged_statement_signature_accepted_row() -> dict[str, object]:
    statement = str(accepted_row()["statement_compact_jws"])
    forged = statement[:-1] + ("Q" if statement[-1] != "Q" else "g")
    assert forged[:-1] == statement[:-1] and forged[-1] != statement[-1]
    return recomputed_accepted_row(statement_wire=forged)


def terminal_row(state: str) -> dict[str, object]:
    row = pending_row()
    decided_at = vectors.VECTOR["decidedAt"] if state != "expired" else json.loads(row["reservation_wire"])["expiresAt"]
    wire = contract.transition_pending_reservation_terminal_v1_bytes(
        row["reservation_wire"],
        state=state,
        decided_at=decided_at,
    ).decode("ascii")
    row.update(state=state, decided_at=decided_at, reservation_wire=wire)
    return row


def changed_wire(source: str, **changes: object) -> str:
    return json.dumps({**json.loads(source), **changes}, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def parse_row(row: dict[str, object]) -> storage.StoredAtomicAcceptanceV1:
    return storage.parse_stored_atomic_acceptance_v1(
        row,
        evidence_config=vectors.evidence_config(),
        statement_config=vectors.statement_config(),
    )


def test_pending_and_accepted_fixture_history_reparse_exactly_without_granting_authority():
    pending = parse_row(pending_row())
    accepted = parse_row(accepted_row())

    assert pending.reservation.state == "pending"
    assert pending.effect is pending.receipt is None
    assert accepted.reservation.state == "accepted"
    assert accepted.effect.effect_id == vectors.VECTOR["effectId"]
    assert accepted.receipt.receipt_id == vectors.VECTOR["receiptId"]
    for stored in (pending, accepted):
        assert stored.current_authority == "not_established_by_storage"
        assert stored.bearer_authority == stored.reexecution_authority == "none"
        assert stored.publication_status == "provisional_until_caller_commit"
        assert stored.final_admission == "denied"
        assert stored.runtime_enabled is False
        with pytest.raises(FrozenInstanceError):
            stored.current_authority = "active"

    denied(
        lambda: storage.parse_stored_atomic_acceptance_v1(
            accepted_row(),
            evidence_config=vectors.evidence_config(),
        )
    )


def test_effect_parser_exposes_the_existing_identity_without_changing_fixture_bytes():
    reservation = contract.parse_atomic_acceptance_reservation_v1(vectors.VECTOR["pendingReservationWire"])
    authenticated_evidence = deadline.verify_messaging_device_verification_deadline_evidence_v1(
        vectors.evidence_compact(),
        config=vectors.evidence_config(),
        expected_input_wire=vectors.INPUT_WIRE,
        now=vectors.EVIDENCE["deadlines"]["observedAt"],
    )
    effect = contract.parse_atomic_acceptance_effect_v1(
        vectors.VECTOR["effectWire"],
        finalization_observation_wire=vectors.VECTOR["finalizationObservationWire"],
        authenticated_evidence=authenticated_evidence,
        expected_reservation_id=reservation.reservation_id,
        expected_reservation_revision=reservation.reservation_revision,
        expected_acceptance_id=reservation.acceptance_id,
        expected_association_id=reservation.association_id,
        expected_challenge_id=reservation.challenge_id,
        expected_challenge_revision=reservation.challenge_revision,
        expected_observed_at=vectors.VECTOR["decidedAt"],
        expected_finalization_request_digest=vectors.VECTOR["finalizationRequestDigest"],
    )
    assert effect.effect_id == vectors.VECTOR["effectId"]
    assert effect.effect_digest == vectors.VECTOR["effectDigest"]
    assert effect.finalization_request_digest == vectors.VECTOR["finalizationRequestDigest"]


def test_recomputed_full_proof_forgery_is_not_authenticated_durable_history():
    row = forged_evidence_mismatched_accepted_row()
    observation = contract.parse_finalization_observation_v1(row["finalization_observation_wire"])
    assert json.loads(observation.authority_snapshot_wire)["fullProofId"].endswith("f" * 64)
    denied(lambda: parse_row(row))


def test_changed_observation_challenge_revision_with_recomputed_chain_is_denied():
    row = changed_observation_challenge_revision_accepted_row()
    observation = contract.parse_finalization_observation_v1(row["finalization_observation_wire"])
    assert observation.challenge_revision == 2
    denied(lambda: parse_row(row))


def test_changed_observation_time_with_recomputed_chain_is_denied():
    row = changed_observation_time_accepted_row()
    observation = contract.parse_finalization_observation_v1(row["finalization_observation_wire"])
    assert observation.observed_at == cast_int(row["decided_at"]) + 1
    denied(lambda: parse_row(row))


def test_forged_statement_signature_and_fully_recomputed_chain_are_denied():
    row = forged_statement_signature_accepted_row()
    claims = deadline.parse_messaging_device_verification_deadline_evidence_payload_v1(
        vectors.EVIDENCE["vector"]["payloadWire"],
        expected_input_wire=vectors.INPUT_WIRE,
    )
    with pytest.raises(verification.SocialPreacceptedEnrollmentVerificationStatementV2Denied):
        verification.verify_social_preaccepted_enrollment_verification_statement_v2(
            row["statement_compact_jws"],
            config=vectors.statement_config(),
            expected_context_wire=vectors.CONTEXT_WIRE,
            expected_input_wire=vectors.INPUT_WIRE,
            now=vectors.VECTOR["decidedAt"],
            phone_session_expires_at_ms=claims.phone_session_expires_at,
            approver_session_expires_at_ms=claims.approver_session_expires_at,
            full_expires_at_ms=claims.full_expires_at,
            x25519_binding_expires_at_ms=claims.x25519_binding_expires_at,
        )
    denied(lambda: parse_row(row))


def test_noncanonical_observation_bytes_are_not_durable_history():
    row = accepted_row()
    row["finalization_observation_wire"] = " " + str(row["finalization_observation_wire"])
    denied(lambda: parse_row(row))


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("reservation_id", "01" * 32),
        ("request_id", "02" * 32),
        ("operation_id", "03" * 32),
        ("subject", "04" * 32),
        ("device_id", "05" * 32),
        ("acceptance_id", "06" * 32),
        ("challenge_id", "07" * 32),
        ("challenge_revision", 2),
        ("association_id", "08" * 32),
        ("input_digest", "changed"),
        ("input_payload_digest", "changed"),
        ("evidence_token_id", "09" * 32),
        ("evidence_digest", "changed"),
        ("evidence_payload_digest", "changed"),
        ("state", "accepted"),
        ("created_at", 1),
        ("expires_at", 2),
    ),
)
def test_changed_duplicated_identity_is_corrupt_and_denied(field: str, replacement: object):
    row = pending_row()
    row[field] = replacement
    denied(lambda: parse_row(row))


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("input_wire", "{}"),
        ("evidence_compact_jws", "a.b.c"),
        ("statement_compact_jws", "a.b.c"),
        ("finalization_observation_wire", "{}"),
        ("effect_wire", "{}"),
        ("receipt_wire", "{}"),
        ("finalization_request_digest", "changed"),
    ),
)
def test_changed_security_relevant_accepted_bytes_are_denied(field: str, replacement: object):
    row = accepted_row()
    row[field] = replacement
    denied(lambda: parse_row(row))


def test_same_receipt_identity_with_changed_receipt_decision_time_is_denied():
    row = accepted_row()
    row["receipt_wire"] = changed_wire(
        row["receipt_wire"],
        decidedAt=cast_int(row["decided_at"]) + 1,
    )
    denied(lambda: parse_row(row))


def cast_int(value: object) -> int:
    assert type(value) is int
    return value


@pytest.mark.parametrize("state", ("rejected", "expired", "cancelled"))
def test_terminal_rows_are_immutable_history_and_never_authorize_device_reuse(state: str):
    stored = parse_row(terminal_row(state))
    assert stored.reservation.state == state
    assert contract.terminal_device_id_reuse_semantics_v1(stored.reservation.wire).startswith(
        "new_reservation_only_after_locked_no_effect_no_receipt_no_association_proof"
    )
    unique_names = {
        item.name for item in storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__.constraints
    }
    assert "uq_social_preaccepted_v2_acceptance_device" in unique_names
    assert not hasattr(storage.SqlAlchemyTransactionBoundAtomicAcceptanceStorage, "release_device_id")
    assert not hasattr(storage.SqlAlchemyTransactionBoundAtomicAcceptanceStorage, "delete")


def test_missing_extra_ambiguous_or_incomplete_durable_shape_denies():
    missing = pending_row()
    missing.pop("reservation_wire")
    extra = {**pending_row(), "current": True}
    incomplete = accepted_row()
    incomplete["receipt_wire"] = None
    for row in (missing, extra, incomplete):
        denied(lambda row=row: parse_row(row))


def test_sqlite_or_missing_caller_transaction_never_becomes_a_storage_backend():
    engine = create_engine("sqlite:///:memory:")
    try:
        with Session(engine) as session:
            denied(lambda: storage.SqlAlchemyTransactionBoundAtomicAcceptanceStorage(session))
        with Session(engine) as session:
            transaction = session.begin()
            denied(lambda: storage.SqlAlchemyTransactionBoundAtomicAcceptanceStorage(session))
            transaction.rollback()
    finally:
        engine.dispose()


def test_catalog_options_are_sorted_and_preserve_null_versus_empty():
    assert storage._canonical_catalog_options(None) is None
    assert storage._canonical_catalog_options([]) == []
    assert storage._canonical_catalog_options(("zeta=1", "alpha=2")) == ["alpha=2", "zeta=1"]
    for invalid in ("fillfactor=80", ["ok=1", 2], [""]):
        denied(lambda invalid=invalid: storage._canonical_catalog_options(invalid))


def test_dormant_public_model_is_isolated_from_shared_sqlite_metadata():
    table = storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__
    assert table.metadata is not Base.metadata
    assert table.schema == storage.SCHEMA == "public"
    assert table.key not in Base.metadata.tables
    assert f"{storage.SCHEMA}.{storage.TABLE}" in str(CreateTable(table).compile(dialect=postgresql.dialect()))

    engine = create_engine("sqlite:///:memory:")
    try:
        Base.metadata.create_all(engine)
        assert storage.TABLE not in inspect(engine).get_table_names()
        Base.metadata.drop_all(engine)
        assert inspect(engine).get_table_names() == []
    finally:
        engine.dispose()


def test_migration_and_source_freeze_transaction_cas_and_no_authority_surface():
    source = SOURCE.read_text(encoding="ascii")
    migration = MIGRATION.read_text(encoding="ascii")
    normalized_migration = re.sub(r"\s+", "", migration)
    assert hashlib.sha256(MIGRATION.read_bytes()).hexdigest() == (
        "227d1c064ca143b2e6add17ab1d2f86a6c056cc7c05950f99cc3ae4d1c42e26f"
    )
    ast.parse(source)
    assert storage.RUNTIME_ENABLED is False
    assert storage.SCHEMA == "public"
    assert storage.CURRENT_AUTHORITY == "not_established_by_storage"
    assert storage.WRITER_SURFACE == "injected_transaction_only"
    assert storage.FINAL_ADMISSION == "denied"
    assert ".with_for_update()" in source
    assert ".on_conflict_do_nothing()" in source
    assert 'table.c.state == "pending"' in source
    assert "SHOW transaction_isolation" in source
    assert "read committed" in source
    assert "to_regclass" not in source
    assert "pg_catalog.pg_trigger" in source
    assert "installed_trigger.tgqual::text" in source
    assert "has_schema_privilege" in source
    assert "has_table_privilege" in source
    assert "has_function_privilege" in source
    assert 'CREATE TABLE "public"."social_preaccepted_enrollment_v2_atomic_acceptances"' in migration
    assert 'CREATE FUNCTION "public"."guard_social_preaccepted_v2_acceptance_v1"()' in migration
    assert "SET search_path = pg_catalog" in migration
    assert "uq_social_preaccepted_v2_acceptance_device UNIQUE (device_id)" in migration
    assert "OLD.state <> 'pending' OR NEW.state = 'pending'" in migration
    assert "TG_OP IN ('DELETE', 'TRUNCATE')" in migration
    for forbidden in (
        ".commit(",
        ".rollback(",
        "create_engine(",
        "sessionmaker(",
        "DATABASE_URL",
        "datetime.now(",
        "time.time(",
        "MAX(",
        "ORDER BY",
        "private_key",
        "signing_secret",
        "create_app",
        "Blueprint(",
    ):
        assert forbidden not in source

    table = storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__
    assert table.name == storage.TABLE
    assert table.schema == storage.SCHEMA == "public"
    postgresql_ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    assert f"{storage.SCHEMA}.{storage.TABLE}" in postgresql_ddl
    table_body = re.search(
        r'CREATE TABLE "public"\."social_preaccepted_enrollment_v2_atomic_acceptances" \((.*?)\n\);',
        migration,
        re.DOTALL,
    )
    assert table_body is not None
    migration_columns: list[tuple[str, str, bool, bool]] = []
    for line in table_body.group(1).splitlines():
        if line == "":
            continue
        if line.lstrip().startswith("CONSTRAINT"):
            break
        match = re.fullmatch(
            r"    ([a-z][a-z0-9_]*) (VARCHAR\([0-9]+\)|BIGINT|TEXT)( NOT NULL)?( PRIMARY KEY)?,",
            line,
        )
        assert match is not None, line
        name, sql_type, not_null, primary_key = match.groups()
        migration_columns.append((name, sql_type, not bool(not_null or primary_key), bool(primary_key)))
    model_columns = [
        (
            column.name,
            column.type.compile(dialect=postgresql.dialect()),
            column.nullable,
            column.primary_key,
        )
        for column in table.columns
    ]
    assert model_columns == migration_columns
    model_constraints = {item.name for item in table.constraints if item.name is not None}
    migration_constraints = set(re.findall(r"\bCONSTRAINT\s+([a-z0-9_]+)\s+(?:UNIQUE|CHECK)", migration))
    assert model_constraints == migration_constraints

    model_uniques = {
        item.name: tuple(column.name for column in item.columns)
        for item in table.constraints
        if isinstance(item, UniqueConstraint)
    }
    migration_uniques = {
        name: tuple(column.strip() for column in columns.split(","))
        for name, columns in re.findall(
            r"CONSTRAINT\s+([a-z0-9_]+)\s+UNIQUE\s*\(([^)]+)\)",
            migration,
        )
    }
    assert model_uniques == migration_uniques

    for constraint in table.constraints:
        if isinstance(constraint, CheckConstraint):
            expression = str(constraint.sqltext.compile(dialect=postgresql.dialect()))
            expected = re.sub(r"\s+", "", f"CONSTRAINT {constraint.name} CHECK ({expression})")
            assert expected in normalized_migration
    function_source = re.search(
        r'CREATE FUNCTION "public"\."guard_social_preaccepted_v2_acceptance_v1"\(\).*?AS \$\$(.*?)\$\$;',
        migration,
        re.DOTALL,
    )
    assert function_source is not None
    function_header = function_source.group(0).split("AS $$", 1)[0]
    migration_cost_match = re.search(r"\nCOST ([0-9]+)\n", function_header)
    assert migration_cost_match is not None
    migration_cost = int(migration_cost_match.group(1))
    assert migration_cost == 100
    assert " ROWS " not in function_header
    assert " SUPPORT " not in function_header
    migration_rows = 0
    expected_payload = storage._expected_guard_definition_payload(
        function_source.group(1),
        function_cost=migration_cost,
        function_rows=migration_rows,
    )
    assert _recursive_payload_key_shape(expected_payload) == _EXPECTED_GUARD_DEFINITION_PAYLOAD_SHAPE
    assert expected_payload["function"]["cost"] == struct.pack("!f", migration_cost).hex() == "42c80000"
    assert expected_payload["function"]["rows"] == struct.pack("!f", migration_rows).hex() == "00000000"
    assert expected_payload["function"]["supportFunctionOid"] == 0
    assert expected_payload["relation"]["columnCount"] == len(table.columns) == 31
    assert expected_payload["relation"]["checkConstraintCount"] == 20
    assert expected_payload["relation"]["options"] is None
    assert expected_payload["relation"]["toast"]["options"] is None
    assert source.count("pg_catalog.encode(pg_catalog.float4send(") == 2
    assert "pg_catalog.float4send(guard_function.procost)" in source
    assert "pg_catalog.float4send(guard_function.prorows)" in source
    assert "guard_function.procost::text" not in source
    assert "guard_function.prorows::text" not in source
    expected_definition_digest = storage._guard_definition_digest(expected_payload)
    assert expected_definition_digest == storage.GUARD_DEFINITION_SHA256
    sqlite_ddl = str(CreateTable(table).compile(dialect=sqlite.dialect()))
    assert not any(token in sqlite_ddl for token in ("!~", "octet_length"))
