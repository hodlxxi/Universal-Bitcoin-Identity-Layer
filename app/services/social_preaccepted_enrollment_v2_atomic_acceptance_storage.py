"""Dormant PostgreSQL durability for the V2 atomic-acceptance contract.

The caller owns one already-active READ COMMITTED transaction.  This module
locks, compares and changes only its own reservation row.  It never treats a
stored row, caller observation, timestamp or historical maximum as current
authorization.  A future orchestrator must lock and recheck every external
authority in this same transaction before asking for an accepted transition.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Mapping, NoReturn, cast

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.engine import Connection, NestedTransaction, RootTransaction
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.sql import quoted_name
from sqlalchemy.sql.expression import ColumnElement

from app.models import Base, _CanonicalLowerHex
from app.services import social_messaging_device_verification_deadline_evidence_v1 as deadline
from app.services import social_messaging_mobile_pre_enrollment_v2 as preacceptance
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as contract
from app.services import social_preaccepted_enrollment_verification_statement_v2 as verification

TABLE = "social_preaccepted_enrollment_v2_atomic_acceptances"
SCHEMA = "public"
GUARD_FUNCTION = "guard_social_preaccepted_v2_acceptance_v1"
GUARD_TRIGGER = "trg_social_preaccepted_v2_acceptance_guard"
NO_TRUNCATE_TRIGGER = "trg_social_preaccepted_v2_acceptance_no_truncate"
GUARD_DEFINITION_SHA256 = "f27dd60f6ef9548129a1e0175a4af1e7985f76080bf6a7a51890a273e5b30ca1"
RUNTIME_ENABLED = False
TRANSACTION_OWNER = "caller_owned_postgresql_read_committed"
CURRENT_AUTHORITY = "not_established_by_storage"
WRITER_SURFACE = "injected_transaction_only"
FINAL_ADMISSION = "denied"
UNAVAILABLE_MESSAGE = "social preaccepted enrollment v2 atomic acceptance storage unavailable"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_SCHEMA_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,62}\Z").fullmatch
_TERMINAL_STATES = frozenset(("rejected", "expired", "cancelled"))


class SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable(ValueError):
    """The one non-sensitive public failure for this durable owner."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


def _deny() -> NoReturn:
    raise SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable() from None


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _integer(value: object) -> int:
    if type(value) is not int or value < 0 or value > contract.MAX_SAFE_INTEGER:
        _deny()
    return cast(int, value)


def _schema_identifier(value: object) -> str:
    if type(value) is not str or _SCHEMA_IDENTIFIER(value) is None:
        _deny()
    return cast(str, value)


def _canonical_catalog_options(value: object) -> list[str] | None:
    if value is None:
        return None
    if type(value) not in (list, tuple):
        _deny()
    options = list(cast(list[object] | tuple[object, ...], value))
    if any(type(option) is not str or not option for option in options):
        _deny()
    return sorted(cast(list[str], options))


def _guard_trigger_definition(
    *,
    name: object,
    trigger_type: object,
    enabled: object,
    function_matches: object,
    argument_count: object,
    arguments_hex: object,
    attributes: object,
    internal: object,
    constraint_oid: object,
    constraint_relation_oid: object,
    constraint_index_oid: object,
    deferrable: object,
    initially_deferred: object,
    qualification: object,
    old_table: object,
    new_table: object,
    parent_oid: object,
) -> dict[str, object]:
    return {
        "argumentCount": argument_count,
        "argumentsHex": arguments_hex,
        "attributes": attributes,
        "constraintIndexOid": constraint_index_oid,
        "constraintOid": constraint_oid,
        "constraintRelationOid": constraint_relation_oid,
        "deferrable": deferrable,
        "enabled": enabled,
        "functionMatches": function_matches,
        "initiallyDeferred": initially_deferred,
        "internal": internal,
        "name": name,
        "newTable": new_table,
        "oldTable": old_table,
        "parentOid": parent_oid,
        "qualification": qualification,
        "type": trigger_type,
    }


def _migration_float4send_hex(value: object) -> str:
    if type(value) is not int:
        _deny()
    try:
        return struct.pack("!f", cast(int, value)).hex()
    except Exception:
        pass
    _deny()


def _expected_guard_definition_payload(
    function_source: object,
    *,
    function_cost: object,
    function_rows: object,
) -> dict[str, object]:
    if type(function_source) is not str:
        _deny()
    return {
        "function": {
            "allArgumentTypes": None,
            "argumentCount": 0,
            "argumentDefaults": None,
            "argumentModes": None,
            "argumentNames": None,
            "argumentTypeOids": "",
            "binary": None,
            "config": ["search_path=pg_catalog"],
            "cost": _migration_float4send_hex(function_cost),
            "defaultArgumentCount": 0,
            "kind": "f",
            "language": "plpgsql",
            "leakproof": False,
            "name": GUARD_FUNCTION,
            "parallel": "u",
            "rows": _migration_float4send_hex(function_rows),
            "returnType": "trigger",
            "returnsSet": False,
            "securityDefiner": False,
            "source": function_source,
            "sqlBody": None,
            "strict": False,
            "supportFunctionOid": 0,
            "transformTypes": None,
            "variadicTypeOid": "0",
            "volatility": "v",
        },
        "relation": {
            "accessMethod": "heap",
            "checkConstraintCount": 20,
            "columnCount": 31,
            "forceRowSecurity": False,
            "hasIndexes": True,
            "hasRules": False,
            "hasSubclasses": False,
            "hasTriggers": True,
            "isPartition": False,
            "isPopulated": True,
            "isShared": False,
            "kind": "r",
            "name": TABLE,
            "ofTypeOid": 0,
            "options": None,
            "partitionBound": None,
            "persistence": "p",
            "replicaIdentity": "d",
            "rowSecurity": False,
            "tablespaceOid": 0,
            "toast": {
                "accessMethod": "heap",
                "checkConstraintCount": 0,
                "columnCount": 3,
                "forceRowSecurity": False,
                "hasIndexes": True,
                "hasRules": False,
                "hasSubclasses": False,
                "hasTriggers": False,
                "isPartition": False,
                "isPopulated": True,
                "isShared": False,
                "kind": "t",
                "nameMatchesRelationOid": True,
                "namespace": "pg_toast",
                "ofTypeOid": 0,
                "options": None,
                "partitionBound": None,
                "persistence": "p",
                "replicaIdentity": "n",
                "rowSecurity": False,
                "rowTypeOid": 0,
                "tablespaceOid": 0,
            },
        },
        "triggers": [
            _guard_trigger_definition(
                name=GUARD_TRIGGER,
                trigger_type=31,
                enabled="O",
                function_matches=True,
                argument_count=0,
                arguments_hex="",
                attributes="",
                internal=False,
                constraint_oid=0,
                constraint_relation_oid=0,
                constraint_index_oid=0,
                deferrable=False,
                initially_deferred=False,
                qualification=None,
                old_table=None,
                new_table=None,
                parent_oid=0,
            ),
            _guard_trigger_definition(
                name=NO_TRUNCATE_TRIGGER,
                trigger_type=34,
                enabled="O",
                function_matches=True,
                argument_count=0,
                arguments_hex="",
                attributes="",
                internal=False,
                constraint_oid=0,
                constraint_relation_oid=0,
                constraint_index_oid=0,
                deferrable=False,
                initially_deferred=False,
                qualification=None,
                old_table=None,
                new_table=None,
                parent_oid=0,
            ),
        ],
    }


def _guard_definition_digest(payload: Mapping[str, object]) -> str:
    try:
        canonical = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()
    except Exception:
        pass
    _deny()


class _PostgreSQLAtomicAcceptanceCheck(ColumnElement):
    """Compile the authoritative PostgreSQL checks safely in shared metadata."""

    inherit_cache = False
    type = Boolean()

    def __init__(self, expression: str) -> None:
        self.postgresql_sql = expression


@compiles(_PostgreSQLAtomicAcceptanceCheck)
@compiles(_PostgreSQLAtomicAcceptanceCheck, "postgresql")
def _compile_postgresql_atomic_acceptance_check(element, _compiler, **_kwargs):
    return element.postgresql_sql


@compiles(_PostgreSQLAtomicAcceptanceCheck, "sqlite")
def _compile_sqlite_atomic_acceptance_check(_element, _compiler, **_kwargs):
    return "1"


class SocialPreacceptedEnrollmentV2AtomicAcceptanceRow(Base):
    """One immutable identity root with a single pending-to-terminal CAS."""

    __tablename__ = TABLE

    reservation_id = Column(String(64), primary_key=True)
    reservation_revision = Column(BigInteger, nullable=False)
    request_id = Column(String(64), nullable=False)
    operation_id = Column(String(64), nullable=False)
    subject = Column(String(64), nullable=False)
    device_id = Column(String(64), nullable=False)
    acceptance_id = Column(String(64), nullable=False)
    challenge_id = Column(String(64), nullable=False)
    challenge_revision = Column(BigInteger, nullable=False)
    association_id = Column(String(64), nullable=False)
    input_digest = Column(String(131), nullable=False)
    input_payload_digest = Column(String(146), nullable=False)
    evidence_token_id = Column(String(64), nullable=False)
    evidence_digest = Column(String(139), nullable=False)
    evidence_payload_digest = Column(String(138), nullable=False)
    state = Column(String(9), nullable=False)
    created_at = Column(BigInteger, nullable=False)
    expires_at = Column(BigInteger, nullable=False)
    decided_at = Column(BigInteger, nullable=True)
    statement_digest = Column(String(146), nullable=True)
    effect_id = Column(String(64), nullable=True)
    effect_digest = Column(String(129), nullable=True)
    receipt_id = Column(String(64), nullable=True)
    finalization_request_digest = Column(String(143), nullable=True)
    reservation_wire = Column(Text, nullable=False)
    input_wire = Column(Text, nullable=False)
    evidence_compact_jws = Column(Text, nullable=False)
    statement_compact_jws = Column(Text, nullable=True)
    finalization_observation_wire = Column(Text, nullable=True)
    effect_wire = Column(Text, nullable=True)
    receipt_wire = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("request_id", name="uq_social_preaccepted_v2_acceptance_request"),
        UniqueConstraint("operation_id", name="uq_social_preaccepted_v2_acceptance_operation"),
        UniqueConstraint("device_id", name="uq_social_preaccepted_v2_acceptance_device"),
        UniqueConstraint("acceptance_id", name="uq_social_preaccepted_v2_acceptance_acceptance"),
        UniqueConstraint("challenge_id", name="uq_social_preaccepted_v2_acceptance_challenge"),
        UniqueConstraint("association_id", name="uq_social_preaccepted_v2_acceptance_association"),
        UniqueConstraint("input_digest", name="uq_social_preaccepted_v2_acceptance_input"),
        UniqueConstraint("evidence_token_id", name="uq_social_preaccepted_v2_acceptance_evidence_token"),
        UniqueConstraint("evidence_digest", name="uq_social_preaccepted_v2_acceptance_evidence"),
        UniqueConstraint("effect_id", name="uq_social_preaccepted_v2_acceptance_effect"),
        UniqueConstraint("receipt_id", name="uq_social_preaccepted_v2_acceptance_receipt"),
        CheckConstraint(_CanonicalLowerHex("reservation_id", 64), name="ck_social_preaccepted_v2_reservation_id"),
        CheckConstraint(_CanonicalLowerHex("request_id", 64), name="ck_social_preaccepted_v2_request_id"),
        CheckConstraint(_CanonicalLowerHex("operation_id", 64), name="ck_social_preaccepted_v2_operation_id"),
        CheckConstraint(_CanonicalLowerHex("subject", 64), name="ck_social_preaccepted_v2_subject"),
        CheckConstraint(_CanonicalLowerHex("device_id", 64), name="ck_social_preaccepted_v2_device_id"),
        CheckConstraint(_CanonicalLowerHex("acceptance_id", 64), name="ck_social_preaccepted_v2_acceptance_id"),
        CheckConstraint(_CanonicalLowerHex("challenge_id", 64), name="ck_social_preaccepted_v2_challenge_id"),
        CheckConstraint(_CanonicalLowerHex("association_id", 64), name="ck_social_preaccepted_v2_association_id"),
        CheckConstraint(_CanonicalLowerHex("evidence_token_id", 64), name="ck_social_preaccepted_v2_token_id"),
        CheckConstraint(
            "state IN ('pending','accepted','rejected','expired','cancelled')",
            name="ck_social_preaccepted_v2_state",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck("reservation_revision = 1"),
            name="ck_social_preaccepted_v2_revision",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck("challenge_revision BETWEEN 1 AND 9007199254740991"),
            name="ck_social_preaccepted_v2_challenge_revision",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck(
                "created_at BETWEEN 0 AND 9007199254740991 AND "
                "expires_at BETWEEN 1 AND 9007199254740991 AND created_at < expires_at AND "
                "(decided_at IS NULL OR decided_at BETWEEN 0 AND 9007199254740991)"
            ),
            name="ck_social_preaccepted_v2_times",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck(
                "octet_length(reservation_wire) BETWEEN 1 AND 8192 AND reservation_wire !~ '[^ -~]'"
            ),
            name="ck_social_preaccepted_v2_reservation_wire",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck("octet_length(input_wire) BETWEEN 1 AND 24576 AND input_wire !~ '[^ -~]'"),
            name="ck_social_preaccepted_v2_input_wire",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck(
                "octet_length(evidence_compact_jws) BETWEEN 1 AND 16384 AND " "evidence_compact_jws !~ '[^ -~]'"
            ),
            name="ck_social_preaccepted_v2_evidence_wire",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck(
                "statement_compact_jws IS NULL OR "
                "(octet_length(statement_compact_jws) BETWEEN 1 AND 4096 AND "
                "statement_compact_jws !~ '[^ -~]')"
            ),
            name="ck_social_preaccepted_v2_statement_wire",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck(
                "finalization_observation_wire IS NULL OR "
                "(octet_length(finalization_observation_wire) BETWEEN 1 AND 16384 AND "
                "finalization_observation_wire !~ '[^ -~]')"
            ),
            name="ck_social_preaccepted_v2_observation_wire",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck(
                "effect_wire IS NULL OR " "(octet_length(effect_wire) BETWEEN 1 AND 8192 AND effect_wire !~ '[^ -~]')"
            ),
            name="ck_social_preaccepted_v2_effect_wire",
        ),
        CheckConstraint(
            _PostgreSQLAtomicAcceptanceCheck(
                "receipt_wire IS NULL OR "
                "(octet_length(receipt_wire) BETWEEN 1 AND 8192 AND receipt_wire !~ '[^ -~]')"
            ),
            name="ck_social_preaccepted_v2_receipt_wire",
        ),
        {"schema": SCHEMA},
    )


def _qualified_table(schema: object):
    trusted_schema = _schema_identifier(schema)
    return SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__.to_metadata(
        MetaData(),
        name=quoted_name(TABLE, quote=True),
        schema=quoted_name(trusted_schema, quote=True),
    )


def _test_only_qualified_table(schema: object):
    """Expose a strictly validated alternate schema only to isolated tests."""

    return _qualified_table(schema)


@dataclass(frozen=True, slots=True, repr=False)
class StoredAtomicAcceptanceV1:
    """Parsed durable history; never present authority or a bearer value."""

    reservation: contract.AtomicAcceptanceReservationV1
    input_wire: str
    evidence_compact_jws: str = field(repr=False)
    statement_compact_jws: str | None = field(repr=False)
    finalization_observation_wire: str | None = field(repr=False)
    effect: contract.AtomicAcceptanceEffectV1 | None = field(repr=False)
    receipt: contract.AtomicAcceptanceReceiptV1 | None = field(repr=False)
    finalization_request_digest: str | None
    current_authority: str = field(default=CURRENT_AUTHORITY, init=False)
    bearer_authority: str = field(default="none", init=False)
    reexecution_authority: str = field(default="none", init=False)
    publication_status: str = field(default="provisional_until_caller_commit", init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)
    runtime_enabled: bool = field(default=RUNTIME_ENABLED, init=False)


def _row_values(row: Mapping[str, object]) -> dict[str, object]:
    try:
        fields = set(SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__.columns.keys())
        if set(row) != fields:
            raise ValueError
        return {name: row[name] for name in fields}
    except Exception:
        pass
    _deny()


def _catalog_guard_definition_payload(rows: list[Mapping[str, object]]) -> dict[str, object]:
    try:
        if len(rows) != 2:
            raise ValueError
        ordered_rows = sorted(rows, key=lambda row: cast(str, row["trigger_name"]))
        first = ordered_rows[0]
        function_config = first["function_config"]
        if type(function_config) not in (list, tuple):
            raise ValueError
        normalized_function_config = cast(list[object] | tuple[object, ...], function_config)
        triggers = [
            _guard_trigger_definition(
                name=row["trigger_name"],
                trigger_type=row["trigger_type"],
                enabled=row["trigger_enabled"],
                function_matches=row["trigger_function_oid"] == row["function_oid"],
                argument_count=row["trigger_argument_count"],
                arguments_hex=row["trigger_arguments_hex"],
                attributes=row["trigger_attributes"],
                internal=row["trigger_internal"],
                constraint_oid=row["trigger_constraint_oid"],
                constraint_relation_oid=row["trigger_constraint_relation_oid"],
                constraint_index_oid=row["trigger_constraint_index_oid"],
                deferrable=row["trigger_deferrable"],
                initially_deferred=row["trigger_initially_deferred"],
                qualification=row["trigger_qualification"],
                old_table=row["trigger_old_table"],
                new_table=row["trigger_new_table"],
                parent_oid=row["trigger_parent_oid"],
            )
            for row in ordered_rows
        ]
        return {
            "function": {
                "allArgumentTypes": first["function_all_argument_types"],
                "argumentCount": first["function_argument_count"],
                "argumentDefaults": first["function_argument_defaults"],
                "argumentModes": first["function_argument_modes"],
                "argumentNames": first["function_argument_names"],
                "argumentTypeOids": first["function_argument_type_oids"],
                "binary": first["function_binary"],
                "config": list(normalized_function_config),
                "cost": first["function_cost"],
                "defaultArgumentCount": first["function_default_argument_count"],
                "kind": first["function_kind"],
                "language": first["function_language"],
                "leakproof": first["function_leakproof"],
                "name": first["function_name"],
                "parallel": first["function_parallel"],
                "rows": first["function_rows"],
                "returnType": first["function_return_type"],
                "returnsSet": first["function_returns_set"],
                "securityDefiner": first["function_security_definer"],
                "source": first["function_source"],
                "sqlBody": first["function_sql_body"],
                "strict": first["function_strict"],
                "supportFunctionOid": first["function_support_oid"],
                "transformTypes": first["function_transform_types"],
                "variadicTypeOid": first["function_variadic_type_oid"],
                "volatility": first["function_volatility"],
            },
            "relation": {
                "accessMethod": first["relation_access_method"],
                "checkConstraintCount": first["relation_check_constraint_count"],
                "columnCount": first["relation_column_count"],
                "forceRowSecurity": first["relation_force_row_security"],
                "hasIndexes": first["relation_has_indexes"],
                "hasRules": first["relation_has_rules"],
                "hasSubclasses": first["relation_has_subclasses"],
                "hasTriggers": first["relation_has_triggers"],
                "isPartition": first["relation_is_partition"],
                "isPopulated": first["relation_is_populated"],
                "isShared": first["relation_is_shared"],
                "kind": first["relation_kind"],
                "name": first["relation_name"],
                "ofTypeOid": first["relation_of_type_oid"],
                "options": _canonical_catalog_options(first["relation_options"]),
                "partitionBound": first["relation_partition_bound"],
                "persistence": first["relation_persistence"],
                "replicaIdentity": first["relation_replica_identity"],
                "rowSecurity": first["relation_row_security"],
                "tablespaceOid": first["relation_tablespace_oid"],
                "toast": {
                    "accessMethod": first["toast_access_method"],
                    "checkConstraintCount": first["toast_check_constraint_count"],
                    "columnCount": first["toast_column_count"],
                    "forceRowSecurity": first["toast_force_row_security"],
                    "hasIndexes": first["toast_has_indexes"],
                    "hasRules": first["toast_has_rules"],
                    "hasSubclasses": first["toast_has_subclasses"],
                    "hasTriggers": first["toast_has_triggers"],
                    "isPartition": first["toast_is_partition"],
                    "isPopulated": first["toast_is_populated"],
                    "isShared": first["toast_is_shared"],
                    "kind": first["toast_kind"],
                    "nameMatchesRelationOid": first["toast_name_matches_relation_oid"],
                    "namespace": first["toast_namespace"],
                    "ofTypeOid": first["toast_of_type_oid"],
                    "options": _canonical_catalog_options(first["toast_options"]),
                    "partitionBound": first["toast_partition_bound"],
                    "persistence": first["toast_persistence"],
                    "replicaIdentity": first["toast_replica_identity"],
                    "rowSecurity": first["toast_row_security"],
                    "rowTypeOid": first["toast_row_type_oid"],
                    "tablespaceOid": first["toast_tablespace_oid"],
                },
            },
            "triggers": triggers,
        }
    except Exception:
        pass
    _deny()


def parse_stored_atomic_acceptance_v1(
    row: Mapping[str, object],
    *,
    evidence_config: deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config,
    statement_config: verification.SocialPreacceptedEnrollmentVerificationStatementV2Config | None = None,
) -> StoredAtomicAcceptanceV1:
    """Authenticate both signed artifacts, then reparse every durable byte."""

    try:
        value = _row_values(row)
        reservation = contract.validate_reservation_historical_identity_v1(
            value["reservation_wire"],
            expected_input_wire=value["input_wire"],
            evidence_compact_jws=value["evidence_compact_jws"],
        )
        authenticated_evidence = deadline.verify_messaging_device_verification_deadline_evidence_v1(
            value["evidence_compact_jws"],
            config=evidence_config,
            expected_input_wire=value["input_wire"],
            now=reservation.decided_at if reservation.state == "accepted" else reservation.created_at,
        )
        duplicated = {
            "reservation_id": reservation.reservation_id,
            "reservation_revision": reservation.reservation_revision,
            "request_id": reservation.request_id,
            "operation_id": reservation.operation_id,
            "subject": reservation.subject,
            "device_id": reservation.device_id,
            "acceptance_id": reservation.acceptance_id,
            "challenge_id": reservation.challenge_id,
            "challenge_revision": reservation.challenge_revision,
            "association_id": reservation.association_id,
            "input_digest": reservation.input_digest,
            "input_payload_digest": reservation.input_payload_digest,
            "evidence_token_id": reservation.evidence_token_id,
            "evidence_digest": reservation.evidence_digest,
            "evidence_payload_digest": reservation.evidence_payload_digest,
            "state": reservation.state,
            "created_at": reservation.created_at,
            "expires_at": reservation.expires_at,
            "decided_at": reservation.decided_at,
            "statement_digest": reservation.statement_digest,
            "effect_id": reservation.effect_id,
            "effect_digest": reservation.effect_digest,
            "receipt_id": reservation.receipt_id,
        }
        if any(value[name] != expected for name, expected in duplicated.items()):
            raise ValueError
        optional = (
            "statement_compact_jws",
            "finalization_observation_wire",
            "effect_wire",
            "receipt_wire",
            "finalization_request_digest",
        )
        if reservation.state == "pending" or reservation.state in _TERMINAL_STATES:
            if any(value[name] is not None for name in optional):
                raise ValueError
            return StoredAtomicAcceptanceV1(
                reservation=reservation,
                input_wire=cast(str, value["input_wire"]),
                evidence_compact_jws=cast(str, value["evidence_compact_jws"]),
                statement_compact_jws=None,
                finalization_observation_wire=None,
                effect=None,
                receipt=None,
                finalization_request_digest=None,
            )
        if reservation.state != "accepted" or any(type(value[name]) is not str for name in optional):
            raise ValueError
        statement_wire = cast(str, value["statement_compact_jws"])
        observation_wire = cast(str, value["finalization_observation_wire"])
        effect_wire = cast(str, value["effect_wire"])
        receipt_wire = cast(str, value["receipt_wire"])
        finalization_digest = cast(str, value["finalization_request_digest"])
        if reservation.decided_at is None:
            raise ValueError
        evidence_projection = deadline.project_authenticated_messaging_device_verification_deadline_evidence_v1(
            authenticated_evidence
        )
        claims = evidence_projection["claims"]
        if (
            type(claims) is not deadline.DeadlineEvidenceClaimsV1
            or type(statement_config) is not verification.SocialPreacceptedEnrollmentVerificationStatementV2Config
        ):
            raise ValueError
        parsed_input = preacceptance.parse_preaccepted_enrollment_verification_input_v2(value["input_wire"])
        authenticated_statement = verification.verify_social_preaccepted_enrollment_verification_statement_v2(
            statement_wire,
            config=statement_config,
            expected_context_wire=parsed_input.context.wire,
            expected_input_wire=parsed_input.wire,
            now=reservation.decided_at,
            phone_session_expires_at_ms=claims.phone_session_expires_at,
            approver_session_expires_at_ms=claims.approver_session_expires_at,
            full_expires_at_ms=claims.full_expires_at,
            x25519_binding_expires_at_ms=claims.x25519_binding_expires_at,
        )
        statement_projection = (
            verification.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(
                authenticated_statement
            )
        )
        observation = contract.parse_evidence_bound_finalization_observation_v1(
            observation_wire,
            authenticated_evidence=authenticated_evidence,
            expected_reservation_id=reservation.reservation_id,
            expected_reservation_revision=reservation.reservation_revision,
            expected_challenge_id=reservation.challenge_id,
            expected_challenge_revision=reservation.challenge_revision,
            expected_observed_at=reservation.decided_at,
        )
        effect = contract.parse_atomic_acceptance_effect_v1(
            effect_wire,
            finalization_observation_wire=observation_wire,
            authenticated_evidence=authenticated_evidence,
            expected_reservation_id=reservation.reservation_id,
            expected_reservation_revision=reservation.reservation_revision,
            expected_acceptance_id=reservation.acceptance_id,
            expected_association_id=reservation.association_id,
            expected_challenge_id=reservation.challenge_id,
            expected_challenge_revision=reservation.challenge_revision,
            expected_observed_at=reservation.decided_at,
            expected_finalization_request_digest=finalization_digest,
        )
        receipt = contract.parse_atomic_acceptance_receipt_v1(receipt_wire)
        contract.reservation_retry_disposition_v1(
            reservation.wire,
            expected_input_wire=value["input_wire"],
            evidence_compact_jws=value["evidence_compact_jws"],
            statement_compact_jws=statement_wire,
            receipt_wire=receipt_wire,
            now=reservation.decided_at,
        )
        if (
            observation.reservation_id != reservation.reservation_id
            or observation.reservation_revision != reservation.reservation_revision
            or observation.challenge_id != reservation.challenge_id
            or observation.challenge_revision != reservation.challenge_revision
            or observation.observed_at != reservation.decided_at
            or effect.reservation_id != reservation.reservation_id
            or effect.reservation_revision != reservation.reservation_revision
            or effect.acceptance_id != reservation.acceptance_id
            or effect.association_id != reservation.association_id
            or effect.challenge_id != reservation.challenge_id
            or effect.effect_id != reservation.effect_id
            or effect.effect_digest != reservation.effect_digest
            or effect.finalization_request_digest != finalization_digest
            or receipt.finalization_request_digest != finalization_digest
            or receipt.effect_id != effect.effect_id
            or receipt.effect_digest != effect.effect_digest
            or receipt.reservation_id != reservation.reservation_id
            or receipt.reservation_revision != reservation.reservation_revision
            or receipt.acceptance_id != reservation.acceptance_id
            or receipt.association_id != reservation.association_id
            or receipt.challenge_id != reservation.challenge_id
            or receipt.evidence_digest != reservation.evidence_digest
            or receipt.input_digest != reservation.input_digest
            or receipt.statement_digest != reservation.statement_digest
            or receipt.decided_at != reservation.decided_at
            or contract.verification_statement_digest_v1(statement_wire) != reservation.statement_digest
            or parsed_input.approval.envelope.pre_enrollment.subject != reservation.subject
            or parsed_input.approval.envelope.pre_enrollment.device_id != reservation.device_id
            or parsed_input.approval.envelope.pre_enrollment.request_id != reservation.request_id
            or parsed_input.acceptance_id != reservation.acceptance_id
            or parsed_input.association_id != reservation.association_id
            or parsed_input.enrollment.enrollment_challenge_id != reservation.challenge_id
            or parsed_input.context.attempt_id != claims.attempt_id
            or statement_projection["issuer"] != parsed_input.context.audience
            or statement_projection["audience"] != statement_config.audience
            or statement_projection["clientId"] != statement_config.client_id
            or statement_projection["servicePrincipal"] != statement_config.service_principal
            or statement_projection["purpose"] != statement_config.purpose
            or statement_projection["result"] != verification.STATEMENT_RESULT
            or statement_projection["acceptanceId"] != reservation.acceptance_id
            or statement_projection["associationId"] != reservation.association_id
            or statement_projection["enrollmentChallengeId"] != reservation.challenge_id
            or statement_projection["attemptId"] != claims.attempt_id
            or statement_projection["inputDigest"] != reservation.input_digest
            or type(statement_projection["issuedAt"]) is not int
            or type(statement_projection["expiresAt"]) is not int
            or not claims.observed_at <= statement_projection["issuedAt"] <= reservation.decided_at
            or not reservation.decided_at < statement_projection["expiresAt"] <= claims.expires_at
        ):
            raise ValueError
        return StoredAtomicAcceptanceV1(
            reservation=reservation,
            input_wire=cast(str, value["input_wire"]),
            evidence_compact_jws=cast(str, value["evidence_compact_jws"]),
            statement_compact_jws=statement_wire,
            finalization_observation_wire=observation_wire,
            effect=effect,
            receipt=receipt,
            finalization_request_digest=finalization_digest,
        )
    except Exception:
        pass
    _deny()


def _pending_row_values(
    reservation: contract.AtomicAcceptanceReservationV1,
    *,
    input_wire: str,
    evidence_compact_jws: str,
) -> dict[str, object]:
    return {
        "reservation_id": reservation.reservation_id,
        "reservation_revision": reservation.reservation_revision,
        "request_id": reservation.request_id,
        "operation_id": reservation.operation_id,
        "subject": reservation.subject,
        "device_id": reservation.device_id,
        "acceptance_id": reservation.acceptance_id,
        "challenge_id": reservation.challenge_id,
        "challenge_revision": reservation.challenge_revision,
        "association_id": reservation.association_id,
        "input_digest": reservation.input_digest,
        "input_payload_digest": reservation.input_payload_digest,
        "evidence_token_id": reservation.evidence_token_id,
        "evidence_digest": reservation.evidence_digest,
        "evidence_payload_digest": reservation.evidence_payload_digest,
        "state": reservation.state,
        "created_at": reservation.created_at,
        "expires_at": reservation.expires_at,
        "decided_at": None,
        "statement_digest": None,
        "effect_id": None,
        "effect_digest": None,
        "receipt_id": None,
        "finalization_request_digest": None,
        "reservation_wire": reservation.wire,
        "input_wire": input_wire,
        "evidence_compact_jws": evidence_compact_jws,
        "statement_compact_jws": None,
        "finalization_observation_wire": None,
        "effect_wire": None,
        "receipt_wire": None,
    }


class SqlAlchemyTransactionBoundAtomicAcceptanceStorage:
    """Lock and CAS one durable decision inside the caller's transaction."""

    def __init__(self, session: Session) -> None:
        self._initialize(session, schema=SCHEMA)

    @classmethod
    def _for_test_schema(
        cls,
        session: Session,
        *,
        schema: object,
    ) -> SqlAlchemyTransactionBoundAtomicAcceptanceStorage:
        """Construct only for a validated isolated test schema."""

        instance = cls.__new__(cls)
        instance._initialize(session, schema=schema)
        return instance

    def _initialize(self, session: Session, *, schema: object) -> None:
        self._session = session
        self._failed = False
        self._schema = ""
        self._table: Table | None = None
        self._connection: Connection | None = None
        self._database_transaction: RootTransaction | None = None
        self._database_nested_transaction: NestedTransaction | None = None
        self._relation_oid: int | None = None
        self._relation_type_oid: int | None = None
        self._toast_relation_oid: int | None = None
        self._trigger_function_oid: int | None = None
        self._trigger_oids: tuple[tuple[str, int], ...] | None = None
        self._relation_owner_oid: int | None = None
        self._toast_relation_owner_oid: int | None = None
        self._trigger_function_owner_oid: int | None = None
        self._guard_definition_sha256: str | None = None
        try:
            self._schema = _schema_identifier(schema)
            self._table = _qualified_table(self._schema)
            self._transaction = session.get_transaction()
            self._nested_transaction = session.get_nested_transaction()
            self._check_transaction()
            return
        except Exception:
            self._failed = True
        _deny()

    def _check_transaction(self) -> Connection:
        try:
            session = self._session
            if (
                self._failed
                or self._transaction is None
                or not self._transaction.is_active
                or session.get_transaction() is not self._transaction
                or session.get_nested_transaction() is not self._nested_transaction
                or session.in_transaction() is not True
                or not session.is_active
                or session.new
                or session.dirty
                or session.deleted
                or session.get_bind().dialect.name != "postgresql"
            ):
                _deny()
            connection = session.connection()
            if (
                connection.closed
                or connection.invalidated
                or not connection.in_transaction()
                or getattr(connection.connection.dbapi_connection, "autocommit", None) is not False
            ):
                _deny()
            if self._connection is None:
                self._connection = connection
                self._database_transaction = connection.get_transaction()
                self._database_nested_transaction = connection.get_nested_transaction()
            if (
                connection is not self._connection
                or self._database_transaction is None
                or connection.get_transaction() is not self._database_transaction
                or connection.get_nested_transaction() is not self._database_nested_transaction
                or not self._database_transaction.is_active
                or connection.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed"
            ):
                _deny()
            catalog_rows = (
                connection.execute(
                    text(
                        "SELECT relation.oid::bigint AS relation_oid, "
                        "relation.relname AS relation_name, relation.relowner::bigint AS relation_owner_oid, "
                        "relation.reltype::bigint AS relation_type_oid, "
                        "relation.reloftype::bigint AS relation_of_type_oid, "
                        "relation_access_method.amname AS relation_access_method, "
                        "relation.reltablespace::bigint AS relation_tablespace_oid, "
                        "relation.reltoastrelid::bigint AS toast_relation_oid, "
                        "relation.relhasindex AS relation_has_indexes, "
                        "relation.relisshared AS relation_is_shared, "
                        "relation.relkind AS relation_kind, relation.relpersistence AS relation_persistence, "
                        "relation.relnatts AS relation_column_count, "
                        "relation.relchecks AS relation_check_constraint_count, "
                        "relation.relhasrules AS relation_has_rules, "
                        "relation.relhastriggers AS relation_has_triggers, "
                        "relation.relhassubclass AS relation_has_subclasses, "
                        "relation.relrowsecurity AS relation_row_security, "
                        "relation.relforcerowsecurity AS relation_force_row_security, "
                        "relation.relispopulated AS relation_is_populated, "
                        "relation.relreplident AS relation_replica_identity, "
                        "relation.relispartition AS relation_is_partition, "
                        "relation.reloptions AS relation_options, "
                        "relation.relpartbound::text AS relation_partition_bound, "
                        "toast_relation.relowner::bigint AS toast_relation_owner_oid, "
                        "toast_relation.reltype::bigint AS toast_row_type_oid, "
                        "toast_relation.reloftype::bigint AS toast_of_type_oid, "
                        "toast_access_method.amname AS toast_access_method, "
                        "toast_relation.reltablespace::bigint AS toast_tablespace_oid, "
                        "toast_relation.relhasindex AS toast_has_indexes, "
                        "toast_relation.relisshared AS toast_is_shared, "
                        "toast_relation.relpersistence AS toast_persistence, "
                        "toast_relation.relkind AS toast_kind, "
                        "toast_relation.relnatts AS toast_column_count, "
                        "toast_relation.relchecks AS toast_check_constraint_count, "
                        "toast_relation.relhasrules AS toast_has_rules, "
                        "toast_relation.relhastriggers AS toast_has_triggers, "
                        "toast_relation.relhassubclass AS toast_has_subclasses, "
                        "toast_relation.relrowsecurity AS toast_row_security, "
                        "toast_relation.relforcerowsecurity AS toast_force_row_security, "
                        "toast_relation.relispopulated AS toast_is_populated, "
                        "toast_relation.relreplident AS toast_replica_identity, "
                        "toast_relation.relispartition AS toast_is_partition, "
                        "toast_relation.reloptions AS toast_options, "
                        "toast_relation.relpartbound::text AS toast_partition_bound, "
                        "toast_namespace.nspname AS toast_namespace, "
                        "toast_relation.relname = "
                        "('pg_toast_' || relation.oid::text)::name AS toast_name_matches_relation_oid, "
                        "guard_function.oid::bigint AS function_oid, "
                        "guard_function.proname AS function_name, "
                        "guard_function.proowner::bigint AS function_owner_oid, "
                        "function_language.lanname AS function_language, "
                        "guard_function.prokind AS function_kind, "
                        "guard_function.prosecdef AS function_security_definer, "
                        "guard_function.proleakproof AS function_leakproof, "
                        "guard_function.proisstrict AS function_strict, "
                        "guard_function.proretset AS function_returns_set, "
                        "guard_function.provolatile AS function_volatility, "
                        "guard_function.proparallel AS function_parallel, "
                        "pg_catalog.encode(pg_catalog.float4send(guard_function.procost), 'hex') "
                        "AS function_cost, "
                        "pg_catalog.encode(pg_catalog.float4send(guard_function.prorows), 'hex') "
                        "AS function_rows, "
                        "guard_function.prosupport::oid::bigint AS function_support_oid, "
                        "guard_function.pronargs AS function_argument_count, "
                        "guard_function.pronargdefaults AS function_default_argument_count, "
                        "guard_function.provariadic::oid::text AS function_variadic_type_oid, "
                        "guard_function.prorettype::pg_catalog.regtype::text AS function_return_type, "
                        "guard_function.proargtypes::text AS function_argument_type_oids, "
                        "guard_function.proallargtypes::text AS function_all_argument_types, "
                        "guard_function.proargmodes::text AS function_argument_modes, "
                        "guard_function.proargnames::text AS function_argument_names, "
                        "guard_function.proargdefaults::text AS function_argument_defaults, "
                        "guard_function.protrftypes::text AS function_transform_types, "
                        "guard_function.prosrc AS function_source, guard_function.probin AS function_binary, "
                        "guard_function.prosqlbody::text AS function_sql_body, "
                        "guard_function.proconfig AS function_config, "
                        "installed_trigger.oid::bigint AS trigger_oid, "
                        "installed_trigger.tgname AS trigger_name, "
                        "installed_trigger.tgfoid::bigint AS trigger_function_oid, "
                        "installed_trigger.tgtype AS trigger_type, "
                        "installed_trigger.tgenabled AS trigger_enabled, "
                        "installed_trigger.tgisinternal AS trigger_internal, "
                        "installed_trigger.tgnargs AS trigger_argument_count, "
                        "pg_catalog.encode(installed_trigger.tgargs, 'hex') AS trigger_arguments_hex, "
                        "installed_trigger.tgattr::text AS trigger_attributes, "
                        "installed_trigger.tgconstraint::bigint AS trigger_constraint_oid, "
                        "installed_trigger.tgconstrrelid::bigint AS trigger_constraint_relation_oid, "
                        "installed_trigger.tgconstrindid::bigint AS trigger_constraint_index_oid, "
                        "installed_trigger.tgdeferrable AS trigger_deferrable, "
                        "installed_trigger.tginitdeferred AS trigger_initially_deferred, "
                        "installed_trigger.tgqual::text AS trigger_qualification, "
                        "installed_trigger.tgoldtable AS trigger_old_table, "
                        "installed_trigger.tgnewtable AS trigger_new_table, "
                        "installed_trigger.tgparentid::bigint AS trigger_parent_oid "
                        "FROM pg_catalog.pg_class AS relation "
                        "JOIN pg_catalog.pg_namespace AS relation_namespace "
                        "ON relation_namespace.oid = relation.relnamespace "
                        "JOIN pg_catalog.pg_am AS relation_access_method "
                        "ON relation_access_method.oid = relation.relam "
                        "JOIN pg_catalog.pg_class AS toast_relation "
                        "ON toast_relation.oid = relation.reltoastrelid "
                        "JOIN pg_catalog.pg_namespace AS toast_namespace "
                        "ON toast_namespace.oid = toast_relation.relnamespace "
                        "JOIN pg_catalog.pg_am AS toast_access_method "
                        "ON toast_access_method.oid = toast_relation.relam "
                        "JOIN pg_catalog.pg_proc AS guard_function "
                        "ON guard_function.proname = :function_name "
                        "JOIN pg_catalog.pg_namespace AS function_namespace "
                        "ON function_namespace.oid = guard_function.pronamespace "
                        "JOIN pg_catalog.pg_language AS function_language "
                        "ON function_language.oid = guard_function.prolang "
                        "LEFT JOIN pg_catalog.pg_trigger AS installed_trigger "
                        "ON installed_trigger.tgrelid = relation.oid "
                        "WHERE relation_namespace.nspname = :schema_name "
                        "AND relation.relname = :table_name "
                        "AND function_namespace.nspname = :schema_name "
                        "AND guard_function.pronargs = 0"
                    ),
                    {
                        "function_name": GUARD_FUNCTION,
                        "schema_name": self._schema,
                        "table_name": TABLE,
                    },
                )
                .mappings()
                .all()
            )
            rows = [cast(Mapping[str, object], row) for row in catalog_rows]
            if len(rows) != 2:
                _deny()
            first = rows[0]
            relation_oid = cast(int, first["relation_oid"])
            relation_type_oid = cast(int, first["relation_type_oid"])
            toast_relation_oid = cast(int, first["toast_relation_oid"])
            function_oid = cast(int, first["function_oid"])
            trigger_oids = tuple(
                sorted((cast(str, row["trigger_name"]), cast(int, row["trigger_oid"])) for row in rows)
            )
            relation_owner_oid = cast(int, first["relation_owner_oid"])
            toast_relation_owner_oid = cast(int, first["toast_relation_owner_oid"])
            function_owner_oid = cast(int, first["function_owner_oid"])
            definition_sha256 = _guard_definition_digest(_catalog_guard_definition_payload(rows))
            security = (
                connection.execute(
                    text(
                        "SELECT current_user = session_user AS direct_runtime_login, "
                        "runtime.rolsuper AS role_superuser, runtime.rolinherit AS role_inherit, "
                        "runtime.rolcreaterole AS role_create_role, runtime.rolcreatedb AS role_create_database, "
                        "runtime.rolcanlogin AS role_can_login, runtime.rolreplication AS role_replication, "
                        "runtime.rolbypassrls AS role_bypass_rls, "
                        "pg_catalog.pg_has_role(runtime.oid, CAST(:relation_owner_oid AS oid), 'MEMBER') "
                        "AS relation_owner_member, "
                        "pg_catalog.pg_has_role(runtime.oid, CAST(:function_owner_oid AS oid), 'MEMBER') "
                        "AS function_owner_member, "
                        "pg_catalog.pg_has_role(runtime.oid, namespace.nspowner, 'MEMBER') AS schema_owner_member, "
                        "pg_catalog.has_schema_privilege(runtime.oid, namespace.oid, 'USAGE') AS schema_usage, "
                        "pg_catalog.has_schema_privilege(runtime.oid, namespace.oid, 'CREATE') AS schema_create, "
                        "pg_catalog.has_table_privilege(runtime.oid, CAST(:relation_oid AS oid), 'SELECT') "
                        "AS table_select, "
                        "pg_catalog.has_table_privilege(runtime.oid, CAST(:relation_oid AS oid), 'INSERT') "
                        "AS table_insert, "
                        "pg_catalog.has_table_privilege(runtime.oid, CAST(:relation_oid AS oid), 'UPDATE') "
                        "AS table_update, "
                        "pg_catalog.has_table_privilege(runtime.oid, CAST(:relation_oid AS oid), 'DELETE') "
                        "AS table_delete, "
                        "pg_catalog.has_table_privilege(runtime.oid, CAST(:relation_oid AS oid), 'TRUNCATE') "
                        "AS table_truncate, "
                        "pg_catalog.has_table_privilege(runtime.oid, CAST(:relation_oid AS oid), 'REFERENCES') "
                        "AS table_references, "
                        "pg_catalog.has_table_privilege(runtime.oid, CAST(:relation_oid AS oid), 'TRIGGER') "
                        "AS table_trigger, "
                        "pg_catalog.has_function_privilege(runtime.oid, CAST(:function_oid AS oid), 'EXECUTE') "
                        "AS function_execute, "
                        "ARRAY(SELECT candidate.rolname FROM pg_catalog.pg_roles AS candidate "
                        "WHERE candidate.oid <> runtime.oid "
                        "AND pg_catalog.pg_has_role(runtime.oid, candidate.oid, 'MEMBER')) AS member_roles "
                        "FROM pg_catalog.pg_roles AS runtime "
                        "JOIN pg_catalog.pg_namespace AS namespace ON namespace.nspname = :schema_name "
                        "WHERE runtime.rolname = current_user"
                    ),
                    {
                        "function_oid": function_oid,
                        "function_owner_oid": function_owner_oid,
                        "relation_oid": relation_oid,
                        "relation_owner_oid": relation_owner_oid,
                        "schema_name": self._schema,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if security is None or (
                security["direct_runtime_login"] is not True
                or security["role_superuser"] is not False
                or security["role_inherit"] is not True
                or security["role_create_role"] is not False
                or security["role_create_database"] is not False
                or security["role_can_login"] is not True
                or security["role_replication"] is not False
                or security["role_bypass_rls"] is not False
                or security["relation_owner_member"] is not False
                or security["function_owner_member"] is not False
                or security["schema_owner_member"] is not False
                or security["schema_usage"] is not True
                or security["schema_create"] is not False
                or security["table_select"] is not True
                or security["table_insert"] is not True
                or security["table_update"] is not True
                or security["table_delete"] is not False
                or security["table_truncate"] is not False
                or security["table_references"] is not False
                or security["table_trigger"] is not False
                or security["function_execute"] is not False
                or sorted(security["member_roles"]) != ["pg_read_all_settings"]
                or relation_type_oid <= 0
                or toast_relation_oid <= 0
                or toast_relation_owner_oid != relation_owner_oid
                or any(trigger_oid <= 0 for _name, trigger_oid in trigger_oids)
                or definition_sha256 != GUARD_DEFINITION_SHA256
            ):
                _deny()
            if self._relation_oid is None:
                self._relation_oid = relation_oid
                self._relation_type_oid = relation_type_oid
                self._toast_relation_oid = toast_relation_oid
                self._trigger_function_oid = function_oid
                self._trigger_oids = trigger_oids
                self._relation_owner_oid = relation_owner_oid
                self._toast_relation_owner_oid = toast_relation_owner_oid
                self._trigger_function_owner_oid = function_owner_oid
                self._guard_definition_sha256 = definition_sha256
            elif (
                relation_oid != self._relation_oid
                or relation_type_oid != self._relation_type_oid
                or toast_relation_oid != self._toast_relation_oid
                or function_oid != self._trigger_function_oid
                or trigger_oids != self._trigger_oids
                or relation_owner_oid != self._relation_owner_oid
                or toast_relation_owner_oid != self._toast_relation_owner_oid
                or function_owner_oid != self._trigger_function_owner_oid
                or definition_sha256 != self._guard_definition_sha256
            ):
                _deny()
            return connection
        except Exception:
            self._failed = True
        _deny()

    def _lock_one(self, reservation_id: str) -> Mapping[str, object]:
        connection = self._check_transaction()
        table = self._table
        if table is None:
            _deny()
        rows = (
            connection.execute(
                select(table)
                .where(table.c.reservation_id == reservation_id)
                .with_for_update()
                .execution_options(autoflush=False)
            )
            .mappings()
            .all()
        )
        if len(rows) != 1:
            _deny()
        return cast(Mapping[str, object], rows[0])

    def reserve_pending(
        self,
        *,
        evidence_compact_jws: object,
        evidence_config: deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config,
        expected_input_wire: object,
        observed_at: object,
        challenge_revision: object,
        now: object | None = None,
    ) -> StoredAtomicAcceptanceV1:
        """Insert once or return the one exact locked pending retry."""

        try:
            wire = contract.canonical_pending_atomic_acceptance_reservation_v1_bytes(
                evidence_compact_jws=evidence_compact_jws,
                evidence_config=evidence_config,
                expected_input_wire=expected_input_wire,
                observed_at=observed_at,
                challenge_revision=challenge_revision,
            ).decode("ascii")
            candidate = contract.parse_atomic_acceptance_reservation_v1(wire)
            input_wire = cast(str, expected_input_wire)
            evidence_wire = cast(str, evidence_compact_jws)
            current = _integer(observed_at if now is None else now)
            connection = self._check_transaction()
            table = self._table
            if table is None:
                _deny()
            connection.execute(
                postgresql_insert(table)
                .values(**_pending_row_values(candidate, input_wire=input_wire, evidence_compact_jws=evidence_wire))
                .on_conflict_do_nothing()
                .execution_options(autoflush=False)
            )
            collision = or_(
                table.c.reservation_id == candidate.reservation_id,
                table.c.request_id == candidate.request_id,
                table.c.operation_id == candidate.operation_id,
                table.c.device_id == candidate.device_id,
                table.c.acceptance_id == candidate.acceptance_id,
                table.c.challenge_id == candidate.challenge_id,
                table.c.association_id == candidate.association_id,
                table.c.input_digest == candidate.input_digest,
                table.c.evidence_token_id == candidate.evidence_token_id,
                table.c.evidence_digest == candidate.evidence_digest,
            )
            rows = (
                connection.execute(select(table).where(collision).with_for_update().execution_options(autoflush=False))
                .mappings()
                .all()
            )
            if len(rows) != 1:
                _deny()
            stored = parse_stored_atomic_acceptance_v1(
                cast(Mapping[str, object], rows[0]),
                evidence_config=evidence_config,
            )
            if (
                stored.reservation.wire != candidate.wire
                or stored.input_wire != input_wire
                or stored.evidence_compact_jws != evidence_wire
            ):
                _deny()
            disposition = contract.reservation_retry_disposition_v1(
                stored.reservation.wire,
                expected_input_wire=input_wire,
                evidence_compact_jws=evidence_wire,
                now=current,
            )
            if disposition.outcome != "return_existing_pending_evidence_without_resigning":
                _deny()
            return stored
        except Exception:
            self._failed = True
        _deny()

    def reconcile_exact(
        self,
        reservation_id: object,
        *,
        expected_input_wire: object,
        evidence_compact_jws: object,
        evidence_config: deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config,
        statement_config: verification.SocialPreacceptedEnrollmentVerificationStatementV2Config | None = None,
        now: object,
        statement_compact_jws: object | None = None,
    ) -> StoredAtomicAcceptanceV1:
        """Return only exact pending or accepted history after locking it."""

        try:
            key = _hex64(reservation_id)
            current = _integer(now)
            row = self._lock_one(key)
            stored = parse_stored_atomic_acceptance_v1(
                row,
                evidence_config=evidence_config,
                statement_config=statement_config,
            )
            if stored.input_wire != expected_input_wire or stored.evidence_compact_jws != evidence_compact_jws:
                _deny()
            receipt_wire = None if stored.receipt is None else stored.receipt.wire
            disposition = contract.reservation_retry_disposition_v1(
                stored.reservation.wire,
                expected_input_wire=expected_input_wire,
                evidence_compact_jws=evidence_compact_jws,
                statement_compact_jws=statement_compact_jws,
                receipt_wire=receipt_wire,
                now=current,
            )
            if stored.reservation.state == "pending":
                if disposition.outcome != "return_existing_pending_evidence_without_resigning":
                    _deny()
            elif (
                stored.reservation.state != "accepted"
                or stored.statement_compact_jws != statement_compact_jws
                or disposition.outcome != "return_immutable_receipt_without_effect"
            ):
                _deny()
            return stored
        except Exception:
            self._failed = True
        _deny()

    def finalize_accepted(
        self,
        reservation_id: object,
        *,
        finalization_observation_wire: object,
        expected_input_wire: object,
        expected_context_wire: object,
        evidence_compact_jws: object,
        evidence_config: deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config,
        statement_compact_jws: object,
        statement_config: verification.SocialPreacceptedEnrollmentVerificationStatementV2Config,
        decided_at: object,
    ) -> StoredAtomicAcceptanceV1:
        """CAS pending to accepted from caller-provided, non-authoritative evidence."""

        try:
            key = _hex64(reservation_id)
            decided = _integer(decided_at)
            row = self._lock_one(key)
            stored = parse_stored_atomic_acceptance_v1(
                row,
                evidence_config=evidence_config,
                statement_config=statement_config,
            )
            if stored.input_wire != expected_input_wire or stored.evidence_compact_jws != evidence_compact_jws:
                _deny()
            if stored.reservation.state == "accepted":
                if (
                    stored.statement_compact_jws != statement_compact_jws
                    or stored.finalization_observation_wire != finalization_observation_wire
                    or stored.reservation.decided_at != decided
                ):
                    _deny()
                contract.reservation_retry_disposition_v1(
                    stored.reservation.wire,
                    expected_input_wire=expected_input_wire,
                    evidence_compact_jws=evidence_compact_jws,
                    statement_compact_jws=statement_compact_jws,
                    receipt_wire=stored.receipt.wire if stored.receipt is not None else None,
                    now=decided,
                )
                return stored
            if stored.reservation.state != "pending":
                _deny()
            provisional = contract.model_atomic_acceptance_and_cas_v1(
                reservation_wire=stored.reservation.wire,
                finalization_observation_wire=finalization_observation_wire,
                expected_input_wire=expected_input_wire,
                expected_context_wire=expected_context_wire,
                evidence_compact_jws=evidence_compact_jws,
                evidence_config=evidence_config,
                statement_compact_jws=statement_compact_jws,
                statement_config=statement_config,
                decided_at=decided,
            )
            accepted = contract.parse_atomic_acceptance_reservation_v1(provisional.reservation_after_wire)
            table = self._table
            if table is None:
                _deny()
            connection = self._check_transaction()
            changed = (
                connection.execute(
                    update(table)
                    .where(
                        table.c.reservation_id == key,
                        table.c.state == "pending",
                        table.c.reservation_wire == stored.reservation.wire,
                    )
                    .values(
                        state="accepted",
                        decided_at=accepted.decided_at,
                        statement_digest=accepted.statement_digest,
                        effect_id=accepted.effect_id,
                        effect_digest=accepted.effect_digest,
                        receipt_id=accepted.receipt_id,
                        finalization_request_digest=provisional.finalization_request_digest,
                        reservation_wire=accepted.wire,
                        statement_compact_jws=statement_compact_jws,
                        finalization_observation_wire=finalization_observation_wire,
                        effect_wire=provisional.effect_wire,
                        receipt_wire=provisional.receipt.wire,
                    )
                    .returning(*table.c)
                    .execution_options(autoflush=False)
                )
                .mappings()
                .all()
            )
            if len(changed) != 1:
                _deny()
            return parse_stored_atomic_acceptance_v1(
                cast(Mapping[str, object], changed[0]),
                evidence_config=evidence_config,
                statement_config=statement_config,
            )
        except Exception:
            self._failed = True
        _deny()

    def transition_terminal(
        self,
        reservation_id: object,
        *,
        expected_input_wire: object,
        evidence_compact_jws: object,
        evidence_config: deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config,
        state: object,
        decided_at: object,
    ) -> StoredAtomicAcceptanceV1:
        """CAS pending to one immutable non-accepting terminal outcome."""

        try:
            key = _hex64(reservation_id)
            if type(state) is not str or state not in _TERMINAL_STATES:
                _deny()
            decided = _integer(decided_at)
            row = self._lock_one(key)
            stored = parse_stored_atomic_acceptance_v1(
                row,
                evidence_config=evidence_config,
            )
            if (
                stored.reservation.state != "pending"
                or stored.input_wire != expected_input_wire
                or stored.evidence_compact_jws != evidence_compact_jws
            ):
                _deny()
            wire = contract.transition_pending_reservation_terminal_v1_bytes(
                stored.reservation.wire,
                state=state,
                decided_at=decided,
            ).decode("ascii")
            terminal = contract.parse_atomic_acceptance_reservation_v1(wire)
            table = self._table
            if table is None:
                _deny()
            connection = self._check_transaction()
            changed = (
                connection.execute(
                    update(table)
                    .where(
                        table.c.reservation_id == key,
                        table.c.state == "pending",
                        table.c.reservation_wire == stored.reservation.wire,
                    )
                    .values(state=terminal.state, decided_at=terminal.decided_at, reservation_wire=terminal.wire)
                    .returning(*table.c)
                    .execution_options(autoflush=False)
                )
                .mappings()
                .all()
            )
            if len(changed) != 1:
                _deny()
            return parse_stored_atomic_acceptance_v1(
                cast(Mapping[str, object], changed[0]),
                evidence_config=evidence_config,
            )
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "CURRENT_AUTHORITY",
    "FINAL_ADMISSION",
    "GUARD_DEFINITION_SHA256",
    "GUARD_FUNCTION",
    "GUARD_TRIGGER",
    "NO_TRUNCATE_TRIGGER",
    "RUNTIME_ENABLED",
    "SCHEMA",
    "SocialPreacceptedEnrollmentV2AtomicAcceptanceRow",
    "SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable",
    "SqlAlchemyTransactionBoundAtomicAcceptanceStorage",
    "StoredAtomicAcceptanceV1",
    "TABLE",
    "TRANSACTION_OWNER",
    "UNAVAILABLE_MESSAGE",
    "WRITER_SURFACE",
    "parse_stored_atomic_acceptance_v1",
]
