import copy
import ipaddress
import json
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
JSON_PATH = ROOT / "docs/data/production_host_database_metadata_audit_v1.json"
DOC_PATH = ROOT / "docs/PRODUCTION_HOST_DATABASE_METADATA_AUDIT_V1.md"
README_PATH = ROOT / "docs/README.md"

REPORT_SHA = "1b30768d3a00ccf188e15bf75dc5ce1007065b093c502ab1187e95a41ca8984f"
MIGRATIONS = [
    "migrations/2026-07-20_action_operations.sql",
    "migrations/2026-07-20_action_step_up_challenges.sql",
    "migrations/2026-07-21_action_step_up_operation_binding.sql",
    "migrations/2026-07-22_current_entitlement_evidence.sql",
    "migrations/2026-07-25_trusted_covenant_registration.sql",
    "migrations/2026-07-26_canonical_admission_edge_registry_v1.sql",
    "migrations/2026-07-26_canonical_e923_genesis_record_v1.sql",
]
BLOCKERS = [
    "PRODUCTION_SCHEMA_TRUTH_UNKNOWN", "MIGRATION_LEDGER_TRUTH_UNKNOWN",
    "MIGRATION_REHEARSAL_ABSENT", "ROLLBACK_SQL_ABSENT_OR_INCOMPLETE",
    "OLD_CODE_NEW_SCHEMA_COMPATIBILITY", "NEW_CODE_OLD_SCHEMA_COMPATIBILITY",
    "UNIQUENESS_FK_CONFLICT_RISK", "POSTGRESQL_LOCK_DURATION_RISK",
    "BACKUP_RESTORE_REHEARSAL", "STAGING_RUNTIME_NOT_PROVEN_BY_REPOSITORY",
    "OAUTH_OIDC_JWT_COMPATIBILITY", "APPLICATION_STARTUP_IMPORT_COMPATIBILITY",
    "FEATURE_FLAG_AND_ROLLBACK_CONTROLS", "SHADOW_COMPARISON_NOT_IMPLEMENTED",
    "CANONICAL_ENTITLEMENT_NOT_IMPLEMENTED",
    "PRODUCTION_BITCOIN_RPC_ORCHESTRATION_NOT_IMPLEMENTED",
    "LEGACY_BALANCE_TO_FULL_ACTIVE",
    "SIGNED_PORTABLE_AUTHORITY_AND_FEDERATION_DEFERRED",
]
DISPOSITIONS = {"RESOLVED_BY_HOST_METADATA", "RESOLVED_BY_DATABASE_CATALOG", "PARTIALLY_RESOLVED", "STILL_BLOCKED", "DEFERRED", "OPERATOR_DECISION_REQUIRED"}
EXPECTED_BLOCKER_STATUSES = [
    "PARTIALLY_RESOLVED",
    "PARTIALLY_RESOLVED",
    "STILL_BLOCKED",
    "OPERATOR_DECISION_REQUIRED",
    "STILL_BLOCKED",
    "STILL_BLOCKED",
    "PARTIALLY_RESOLVED",
    "STILL_BLOCKED",
    "STILL_BLOCKED",
    "RESOLVED_BY_HOST_METADATA",
    "STILL_BLOCKED",
    "STILL_BLOCKED",
    "OPERATOR_DECISION_REQUIRED",
    "DEFERRED",
    "DEFERRED",
    "DEFERRED",
    "PARTIALLY_RESOLVED",
    "DEFERRED",
]
NON_CLAIMS = [
    "no deployment approval", "no deployment performed", "no migration applied",
    "no migration rehearsal", "no database write", "no application-row inspection",
    "no production data export", "no environment value inspection", "no secret inspection",
    "no credential inspection", "no service restart", "no runtime configuration change",
    "no route change", "no authentication behavior change", "no authorization behavior change",
    "no Bitcoin RPC call", "no LND call", "no wallet operation",
    "no backup proof from tooling presence", "no restore proof",
    "no startup compatibility proof", "no OAuth/OIDC/JWT compatibility proof",
    "no production readiness claim", "no legacy cutover", "no proof signing",
    "no portable authority", "no federation or replication",
]


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load():
    return json.loads(JSON_PATH.read_text(), object_pairs_hook=_no_duplicates)


def walk(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield path + (key,), child
            yield from walk(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield path + (str(index),), child
            yield from walk(child, path + (str(index),))


def validate(data):
    assert data["schema"] == "hodlxxi.production_host_database_metadata_audit.v1"
    assert data["audit_version"] == "1"
    assert data["source_report_sha256"] == REPORT_SHA
    assert data["production_head"] == "6873e8fb73cbea8fda43fe3609bbdbb2817d8299"
    assert data["protected_staging_head"] == "fe333cdb5068a73b4dc57b875e1b0223b01855f7"
    assert data["remote_staging_basis"] == "b458470b409ed5a5f66844eddaf4a892bd335e12"
    assert data["source_result_verdict"] == "PASS"
    assert data["audit_mode"] == "READ_ONLY"
    assert data["protected_checkouts_unchanged"] is True
    assert data["application_database_candidate_count"] == 1
    assert re.fullmatch(r"[0-9a-f]{64}", data["application_database_id_sha256"])
    assert data["application_database"]["identifier_sha256"] == data["application_database_id_sha256"]

    for path, value in walk(data):
        lowered = path[-1].lower()
        assert lowered not in {"database_name", "dbname", "db_name", "generated_at", "timestamp"}
        assert not lowered.endswith("_timestamp")
        assert lowered not in {"environment_value", "env_value", "secret", "password", "credential", "token_value", "private_key", "macaroon"}
        if isinstance(value, str):
            candidates = re.findall(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])", value)
            candidates += re.findall(r"(?<![\w])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:%]*(?![\w])", value)
            for candidate in candidates:
                try:
                    ipaddress.ip_address(candidate.split("%")[0])
                except ValueError:
                    continue
                raise AssertionError(f"IP literal at {path}")

    readiness = data["migration_readiness"]
    assert len(readiness) == 7
    assert [item["migration_file"] for item in readiness] == MIGRATIONS
    assert all(item["status"] in {"PRESENT_COMPATIBLE_NOT_PROVEN", "ABSENT", "PARTIAL_OR_CONFLICT_POSSIBLE", "UNKNOWN"} for item in readiness)
    for item in readiness:
        if item["production_structure_presence"] == "ABSENT":
            assert item["status"] != "PRESENT_COMPATIBLE_NOT_PROVEN"

    blockers = data["blocker_disposition"]
    assert [item["id"] for item in blockers] == BLOCKERS
    assert all(item["status"] in DISPOSITIONS for item in blockers)
    assert [item["status"] for item in blockers] == EXPECTED_BLOCKER_STATUSES

    trains = data["release_train_disposition"]
    assert trains == [
        {"train":"TRAIN_0","status":"COMPLETE","reason":"Repository and metadata inventory complete."},
        {"train":"TRAIN_1","status":"NOT_RELEASE_APPROVED","reason":"Requires sanitized production-like startup and auth compatibility rehearsal."},
        {"train":"TRAIN_2","status":"NOT_RELEASE_APPROVED","reason":"Requires migration and backup/restore rehearsals."},
        {"train":"TRAINS_3_THROUGH_10","status":"DEPENDENT_ON_PR6_21_GATES","reason":"Existing ordered gates remain binding."},
    ]
    assert data["explicit_non_claims"] == NON_CLAIMS
    backup = data["backup_restore"]
    assert backup["pg_dump_present"] and backup["pg_restore_present"]
    assert backup["backup_exists"] == "NOT_PROVEN"
    assert backup["restore_readiness"] == "NOT_PROVEN"
    ledger = data["migration_ledger"]
    assert ledger["alembic_version"] == "ABSENT"
    assert ledger["alternate_ledgers"] == "UNKNOWN"
    assert ledger["migration_application"] == "NOT_PROVEN"


def test_audit_contract():
    validate(load())


def test_duplicate_keys_rejected_recursively():
    with pytest.raises(ValueError, match="duplicate JSON key"):
        json.loads('{"outer":{"x":1,"x":2}}', object_pairs_hook=_no_duplicates)


def test_human_contract_and_readme_link():
    document = DOC_PATH.read_text()
    assert REPORT_SHA in document
    for term in ("repository presence", "deployed presence", "active service", "Configured", "health"):
        assert term.lower() in document.lower()
    assert "PRODUCTION_HOST_DATABASE_METADATA_AUDIT_V1.md" in README_PATH.read_text()


@pytest.mark.parametrize("mutation", [
    "database_name", "ip_literal", "report_sha", "train_1_approved",
    "missing_migration_compatible", "blocker_resolved", "non_claim_removed",
    "environment_value",
])
def test_negative_mutations(mutation):
    data = copy.deepcopy(load())
    if mutation == "database_name":
        data["application_database"]["database_name"] = "forbidden"
    elif mutation == "ip_literal":
        data["nginx_routes"]["upstreams"].append("127.0.0.1")
    elif mutation == "report_sha":
        data["source_report_sha256"] = "0" * 64
    elif mutation == "train_1_approved":
        data["release_train_disposition"][1]["status"] = "APPROVED"
    elif mutation == "missing_migration_compatible":
        data["migration_readiness"][0]["status"] = "PRESENT_COMPATIBLE_NOT_PROVEN"
    elif mutation == "blocker_resolved":
        data["blocker_disposition"][0]["status"] = "RESOLVED_BY_DATABASE_CATALOG"
    elif mutation == "non_claim_removed":
        data["explicit_non_claims"].pop()
    elif mutation == "environment_value":
        data["systemd_units"][0]["environment_value"] = "forbidden"
    with pytest.raises(AssertionError):
        validate(data)
