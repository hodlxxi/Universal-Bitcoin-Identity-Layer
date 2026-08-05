import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
JP = ROOT / "docs/data/production_compatibility_inventory_v1.json"
DP = ROOT / "docs/PRODUCTION_COMPATIBILITY_INVENTORY_V1.md"

MAIN = "6873e8fb73cbea8fda43fe3609bbdbb2817d8299"
STAGING = "0f5688692f70029d53589f7d03df54a6abae5d1b"

REQUIRED_GROUPS = {
    "SECURITY_AUTH_FOUNDATION",
    "SCHEMA_MIGRATION",
    "ACTIVE_RUNTIME_COMPATIBILITY",
    "DORMANT_CRT_DOMAIN",
    "READ_ONLY_PROOF_SURFACE",
    "LIVE_SOURCE_LOOKUP",
    "BITCOIN_OBSERVATION_WIRING",
    "SHADOW_ENTITLEMENT",
    "ENFORCEMENT",
    "DEPLOYMENT_TOOLING",
    "FEDERATION_REPLICATION",
    "DOCUMENTATION_TEST_ONLY",
}

REQUIRED_BLOCKERS = {
    "PRODUCTION_SCHEMA_TRUTH_UNKNOWN":
        "REQUIRES_READ_ONLY_DATABASE_METADATA_AUDIT",
    "MIGRATION_LEDGER_TRUTH_UNKNOWN":
        "REQUIRES_READ_ONLY_DATABASE_METADATA_AUDIT",
    "MIGRATION_REHEARSAL_ABSENT":
        "REQUIRES_SANITIZED_REHEARSAL",
    "ROLLBACK_SQL_ABSENT_OR_INCOMPLETE":
        "OPERATOR_DECISION_REQUIRED",
    "OLD_CODE_NEW_SCHEMA_COMPATIBILITY":
        "REQUIRES_SANITIZED_REHEARSAL",
    "NEW_CODE_OLD_SCHEMA_COMPATIBILITY":
        "REQUIRES_SANITIZED_REHEARSAL",
    "UNIQUENESS_FK_CONFLICT_RISK":
        "REQUIRES_READ_ONLY_DATABASE_METADATA_AUDIT",
    "POSTGRESQL_LOCK_DURATION_RISK":
        "REQUIRES_SANITIZED_REHEARSAL",
    "BACKUP_RESTORE_REHEARSAL":
        "REQUIRES_SANITIZED_REHEARSAL",
    "STAGING_RUNTIME_NOT_PROVEN_BY_REPOSITORY":
        "REQUIRES_READ_ONLY_HOST_AUDIT",
    "OAUTH_OIDC_JWT_COMPATIBILITY":
        "REQUIRES_SANITIZED_REHEARSAL",
    "APPLICATION_STARTUP_IMPORT_COMPATIBILITY":
        "REQUIRES_SANITIZED_REHEARSAL",
    "FEATURE_FLAG_AND_ROLLBACK_CONTROLS":
        "OPERATOR_DECISION_REQUIRED",
    "SHADOW_COMPARISON_NOT_IMPLEMENTED":
        "DEFERRED",
    "CANONICAL_ENTITLEMENT_NOT_IMPLEMENTED":
        "DEFERRED",
    "PRODUCTION_BITCOIN_RPC_ORCHESTRATION_NOT_IMPLEMENTED":
        "DEFERRED",
    "LEGACY_BALANCE_TO_FULL_ACTIVE":
        "VERIFIED_FROM_REPOSITORY",
    "SIGNED_PORTABLE_AUTHORITY_AND_FEDERATION_DEFERRED":
        "DEFERRED",
}

REQUIRED_DECISIONS = [
    "FIRST_RELEASE_TRAIN_CONTENTS",
    "READ_ONLY_CRT_ROUTES_IN_FIRST_DEPLOYMENT",
    "MIGRATION_WINDOW",
    "ROLLBACK_TOLERANCE",
    "PROOF_FRESHNESS_POLICY",
    "SHADOW_OBSERVATION_DURATION",
    "MISMATCH_ACCEPTANCE_THRESHOLD",
    "BOUNDED_ENFORCEMENT_POPULATION",
    "LEGACY_FALLBACK_RETIREMENT_GATE",
    "REVOCATION_AUTHORITY",
    "DESCENDANT_BEHAVIOR_AFTER_SPONSOR_REVOCATION",
    "RE_SPONSORSHIP_POLICY",
    "SIGNING_AND_PORTABILITY_TIMING",
]

REQUIRED_NONCLAIMS = [
    "no deployment approval",
    "no migration application",
    "no migration rehearsal claim",
    "no production database inspection",
    "no production schema truth claim",
    "no production data read",
    "no secret inspection",
    "no service restart",
    "no runtime configuration change",
    "no route or blueprint change by PR6.21",
    "no authentication behavior change by PR6.21",
    "no authorization behavior change by PR6.21",
    "no Bitcoin RPC call",
    "no LND call",
    "no wallet operation",
    "no session or JWT mutation",
    "no entitlement write",
    "no action authorization",
    "no legacy cutover",
    "no proof signing",
    "no portable authority claim",
    "no federation or replication claim",
    "no rollback proof beyond repository evidence",
    "no production readiness claim from tests alone",
]


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def data():
    return json.loads(
        JP.read_text(encoding="utf-8"),
        object_pairs_hook=no_duplicates,
    )


def test_basis_schema_counts_and_json():
    value = data()

    assert value["schema"] == (
        "hodlxxi.production_compatibility_inventory.v1"
    )
    assert value["inventory_version"] == "1"

    assert (
        value["production_main_sha"],
        value["staging_sha"],
        value["merge_base_sha"],
    ) == (MAIN, STAGING, MAIN)

    assert (
        value["behind_by"],
        value["ahead_by"],
        value["total_commit_count"],
        value["merge_commit_count"],
    ) == (0, 64, 64, 30)

    assert value["changed_file_count"] == 167
    assert value["additions"] == 31453
    assert value["deletions"] == 162
    assert value["migration_count"] == 7
    assert json.loads(JP.read_text(encoding="utf-8")) == value


def test_exact_migrations_once():
    expected = sorted(
        f"migrations/{name}"
        for name in [
            "2026-07-20_action_operations.sql",
            "2026-07-20_action_step_up_challenges.sql",
            "2026-07-21_action_step_up_operation_binding.sql",
            "2026-07-22_current_entitlement_evidence.sql",
            "2026-07-25_trusted_covenant_registration.sql",
            "2026-07-26_canonical_admission_edge_registry_v1.sql",
            "2026-07-26_canonical_e923_genesis_record_v1.sql",
        ]
    )

    migrations = data()["migrations"]
    paths = [item["path"] for item in migrations]

    assert sorted(paths) == expected
    assert len(paths) == len(set(paths)) == 7

    required_fields = {
        "path",
        "purpose",
        "additive_or_destructive",
        "tables_or_structures_affected",
        "runtime_consumer_category",
        "application_compatibility_assumptions",
        "rollback_limitation",
        "rehearsal_status",
    }

    assert all(set(item) == required_fields for item in migrations)
    assert all(
        item["rehearsal_status"] == "NOT_PROVEN_FROM_REPOSITORY"
        for item in migrations
    )


def test_groups_trains_blockers_and_decisions_are_exact():
    value = data()

    groups = {item["id"]: item for item in value["component_groups"]}
    assert set(groups) == REQUIRED_GROUPS

    required_group_fields = {
        "id",
        "files",
        "current_staging_status",
        "production_status",
        "startup_activation_behavior",
        "database_dependency",
        "network_rpc_dependency",
        "migration_dependency",
        "user_visible_effect",
        "risk",
        "release_train_assignment",
        "rollback_boundary",
        "explicit_non_claims",
    }
    assert all(
        set(item) == required_group_fields
        for item in value["component_groups"]
    )

    trains = value["release_trains"]
    assert [item["id"] for item in trains] == [
        f"TRAIN_{number}" for number in range(11)
    ]
    assert [item["order"] for item in trains] == list(range(11))

    required_train_fields = {
        "id",
        "order",
        "name",
        "scope",
        "entry_gates",
        "migration_requirements",
        "staging_validation",
        "telemetry",
        "rollback",
        "exit_gates",
        "dependencies",
        "explicit_exclusions",
    }
    assert all(set(item) == required_train_fields for item in trains)

    blockers = {
        item["id"]: item["status"]
        for item in value["production_blockers"]
    }
    assert blockers == REQUIRED_BLOCKERS
    assert value["operator_decisions"] == REQUIRED_DECISIONS


def test_document_terms_compass_readme_and_basis():
    value = data()
    doc = DP.read_text(encoding="utf-8")
    readme = (ROOT / "docs/README.md").read_text(encoding="utf-8")

    for term in (
        "HC-03",
        "HC-07",
        "HC-08",
        "HC-09",
        "HC-14",
        "HC-15",
        "HC-16",
        "Active",
        "Dormant",
        "Deployed",
        "not deployed",
        MAIN,
        STAGING,
        "NOT DEPLOYMENT APPROVAL",
        "no migration rehearsal claim",
        "no production schema truth claim",
    ):
        assert term in doc

    assert value["production_main_sha"] in doc
    assert value["staging_sha"] in doc
    assert "PRODUCTION_COMPATIBILITY_INVENTORY_V1.md" in readme

    groups = {item["id"]: item for item in value["component_groups"]}
    assert groups["ACTIVE_RUNTIME_COMPATIBILITY"][
        "current_staging_status"
    ].startswith("ACTIVE_")
    assert groups["DORMANT_CRT_DOMAIN"][
        "current_staging_status"
    ].startswith("IMPLEMENTED_DORMANT")
    assert "NOT_DEPLOYED" in groups["READ_ONLY_PROOF_SURFACE"][
        "production_status"
    ]


def test_no_secret_fields_or_nondeterministic_timestamp():
    value = data()
    forbidden = re.compile(
        r"(^|_)(password|secret|private_key|macaroon|credential|"
        r"token_value|wallet_seed)($|_)",
        re.IGNORECASE,
    )

    def walk(item):
        if isinstance(item, dict):
            for key, child in item.items():
                assert key not in {"generated_at", "timestamp"}
                assert not forbidden.search(key)
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)

    try:
        json.loads(
            '{"x":1,"x":2}',
            object_pairs_hook=no_duplicates,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate key accepted")


def test_exact_nonclaims():
    claims = data()["explicit_non_claims"]
    assert claims == REQUIRED_NONCLAIMS
    assert len(claims) == len(set(claims)) == 24
