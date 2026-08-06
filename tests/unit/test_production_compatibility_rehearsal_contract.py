from __future__ import annotations

import copy
import ipaddress
import json
import re
from pathlib import Path

import pytest

from tools import production_compatibility_rehearsal_v1 as rehearsal


ROOT = Path(__file__).resolve().parents[2]
JSON_PATH = ROOT / "docs/data/production_compatibility_rehearsal_plan_v1.json"
DOCUMENT_PATH = ROOT / "docs/PRODUCTION_COMPATIBILITY_REHEARSAL_PLAN_V1.md"
README_PATH = ROOT / "docs/README.md"
FIXTURE_PATH = ROOT / "tests/fixtures/production_catalog_baseline_v1.sql"


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load():
    return json.loads(JSON_PATH.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def walk(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield path + (key,), child
            yield from walk(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield path + (str(index),), child
            yield from walk(child, path + (str(index),))


def validate(value):
    rehearsal.validate_plan_contract(value)


def test_exact_basis_schema_version_and_not_run_authority():
    value = load()
    validate(value)
    assert value["schema"] == "hodlxxi.production_compatibility_rehearsal_plan.v1"
    assert value["plan_version"] == 1
    assert value["production_sha"] == rehearsal.PRODUCTION_SHA
    assert value["staging_sha"] == rehearsal.STAGING_SHA
    assert value["source_audit_report_sha256"] == rehearsal.SOURCE_AUDIT_REPORT_SHA256
    assert value["source_database_identifier_sha256"] == rehearsal.SOURCE_DATABASE_IDENTIFIER_SHA256
    assert value["execution_status"] == "NOT_RUN"
    assert value["release_authority"] == "NONE"


def test_exact_phase_and_migration_order_with_no_claimed_phase_pass():
    value = load()
    assert [item["phase"] for item in value["phases"]] == list(rehearsal.PHASES)
    assert len(value["phases"]) == 14
    assert all(item["status"] == "NOT_RUN" for item in value["phases"])
    assert value["migration_order"] == list(rehearsal.MIGRATIONS)
    assert len(value["migration_order"]) == 7
    assert all(item["status"] == "NOT_RUN" for item in value["auth_probe_matrix"])
    assert value["startup_probe"]["unsupported_dependency"]["status"] == "BLOCKED"


def test_exact_release_dispositions_pr6_24_boundary_and_non_claims():
    value = load()
    release = value["release_gate_effect"]
    assert release["effect"] == "NONE"
    assert release["train_disposition"] == list(rehearsal.TRAIN_DISPOSITION)
    boundary = value["next_required_work"]["pr6_24_boundary"]
    assert boundary["may"] == list(rehearsal.PR6_24_MAY)
    assert boundary["may_not"] == list(rehearsal.PR6_24_MAY_NOT)
    assert value["explicit_non_claims"] == list(rehearsal.NON_CLAIMS)
    assert len(value["explicit_non_claims"]) == len(set(value["explicit_non_claims"])) == 38


def test_no_nondeterministic_or_sensitive_result_material():
    value = load()
    forbidden_exact_keys = {
        "database_name",
        "dbname",
        "db_name",
        "generated_at",
        "timestamp",
        "environment_value",
        "env_value",
        "password",
        "secret_value",
        "credential_value",
        "token_value",
        "private_key",
        "macaroon",
    }
    for path, child in walk(value):
        assert path[-1].lower() not in forbidden_exact_keys
        if isinstance(child, str):
            assert not re.search(r"(?i)\bpostgres(?:ql)?(?:\+[a-z0-9_]+)?://", child)
            assert not rehearsal.DATABASE_TARGET_PATTERN.fullmatch(child)
            candidates = re.findall(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])", child)
            candidates += re.findall(r"(?<![\w])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:%]*(?![\w])", child)
            for candidate in candidates:
                try:
                    ipaddress.ip_address(candidate.split("%", 1)[0])
                except ValueError:
                    continue
                raise AssertionError(f"IP literal at {path}")


def test_result_schema_has_exact_sanitized_phase_fields():
    schema = load()["result_schema"]
    assert schema["schema"] == "hodlxxi.production_compatibility_rehearsal_result.v1"
    assert schema["execution_status_values"] == ["NOT_RUN", "PASS", "FAIL", "BLOCKED"]
    assert schema["phase_result_fields"] == [
        "phase",
        "status",
        "evidence_code",
        "duration_ms",
        "sanitized_detail",
        "artifact_sha256",
        "cleanup_status",
    ]
    template = schema["phase_result_template"]
    assert set(template) == set(schema["phase_result_fields"])
    assert template["status"] == "NOT_RUN"
    assert template["duration_ms"] is None
    assert template["artifact_sha256"] is None


def test_synthetic_fixture_is_schema_only_and_matches_observed_catalog_identity():
    value = load()["synthetic_baseline"]
    sql = FIXTURE_PATH.read_text(encoding="utf-8")
    assert value["catalog_reconstruction_is_complete_clone"] is False
    assert value["inserted_records"] == 0
    assert value["fixture_sha256"] == rehearsal._sha256_file(FIXTURE_PATH)
    assert not re.search(r"\bINSERT\b", sql, re.IGNORECASE)
    assert not re.search(r"\b(?:CREATE|ALTER)\s+DATABASE\b", sql, re.IGNORECASE)
    assert not re.search(r"\bsetval\s*\(", sql, re.IGNORECASE)
    assert not re.search(r"\b[0-9a-f]{64}\b", sql, re.IGNORECASE)
    assert [item["table"] for item in value["tables"]] == [
        "oauth_clients",
        "oauth_codes",
        "oauth_tokens",
        "users",
    ]
    constraints = {
        item["primary_key"] for item in value["tables"]
    } | {
        name for item in value["tables"] for name in item["foreign_keys"]
    }
    indexes = {name for item in value["tables"] for name in item["indexes"]}
    assert len(constraints) == 8
    assert len(indexes) == 20
    for item in value["tables"]:
        assert f"CREATE TABLE {item['table']}" in sql
        for column in item["columns"]:
            assert re.search(rf"^\s*{re.escape(column)}\s", sql, re.MULTILINE)
        for name in [item["primary_key"], *item["foreign_keys"], *item["indexes"]]:
            assert name in sql


def test_human_plan_basis_distinctions_compass_and_readme_link():
    document = DOCUMENT_PATH.read_text(encoding="utf-8")
    readme = README_PATH.read_text(encoding="utf-8")
    for required in (
        rehearsal.PRODUCTION_SHA,
        rehearsal.STAGING_SHA,
        rehearsal.SOURCE_AUDIT_REPORT_SHA256,
        rehearsal.SOURCE_DATABASE_IDENTIFIER_SHA256,
        "Plan mode, future execution evidence, and release approval are three distinct things",
        "PR6.23 creates a plan and harness only. PR6.24 may execute it only in an explicitly approved isolated non-production environment.",
        "SQLite",
        "not a complete production schema clone",
        "HC-03",
        "HC-07",
        "HC-08",
        "HC-09",
        "HC-14",
        "HC-15",
        "HC-16",
        "does not grant membership, authorization, administrator authority, or `FULL` status",
    ):
        assert required in document
    for phase in rehearsal.PHASES:
        assert phase in document
    for migration in rehearsal.MIGRATIONS:
        assert migration in document
    assert "[PRODUCTION_COMPATIBILITY_REHEARSAL_PLAN_V1.md](PRODUCTION_COMPATIBILITY_REHEARSAL_PLAN_V1.md)" in readme


def test_duplicate_json_keys_are_rejected_recursively():
    with pytest.raises(ValueError, match="duplicate JSON key"):
        json.loads('{"outer":{"x":1,"x":2}}', object_pairs_hook=no_duplicates)
    with pytest.raises(rehearsal.PlanContractError, match="duplicate JSON key"):
        json.loads('{"outer":{"x":1,"x":2}}', object_pairs_hook=rehearsal._no_duplicate_keys)


@pytest.mark.parametrize(
    "mutation",
    [
        "phase_pass",
        "train_1_approved",
        "train_2_approved",
        "migration_order",
        "database_name",
        "ip_address",
        "password_dsn",
        "root_rejection",
        "inherited_environment",
        "tcp_postgresql",
        "non_claim",
        "production_sha",
        "staging_sha",
    ],
)
def test_negative_mutations_fail_closed(mutation):
    value = copy.deepcopy(load())
    if mutation == "phase_pass":
        value["phases"][0]["status"] = "PASS"
    elif mutation == "train_1_approved":
        value["release_gate_effect"]["train_disposition"][1]["status"] = "APPROVED"
    elif mutation == "train_2_approved":
        value["release_gate_effect"]["train_disposition"][2]["status"] = "APPROVED"
    elif mutation == "migration_order":
        value["migration_order"][0], value["migration_order"][1] = (
            value["migration_order"][1],
            value["migration_order"][0],
        )
    elif mutation == "database_name":
        value["synthetic_baseline"]["database_name"] = "forbidden"
    elif mutation == "ip_address":
        value["source_isolation"]["network_target"] = "192.0.2.10"
    elif mutation == "password_dsn":
        value["source_isolation"]["connection"] = "postgresql://user:password@host/example"
    elif mutation == "root_rejection":
        value["safety_invariants"].remove("REJECT_UID_0")
    elif mutation == "inherited_environment":
        value["safety_invariants"].remove("REJECT_INHERITED_CONFIGURATION")
        value["startup_probe"]["inherited_environment"] = "ALLOWED"
    elif mutation == "tcp_postgresql":
        value["source_isolation"]["cluster_architecture"]["transport"] = "TCP"
        value["source_isolation"]["cluster_architecture"]["listen_addresses"] = "*"
    elif mutation == "non_claim":
        value["explicit_non_claims"].pop()
    elif mutation == "production_sha":
        value["production_sha"] = "0" * 40
    elif mutation == "staging_sha":
        value["staging_sha"] = "f" * 40
    with pytest.raises(rehearsal.PlanContractError):
        validate(value)
