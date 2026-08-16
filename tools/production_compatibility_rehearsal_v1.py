"""Sanitized production compatibility rehearsal plan and harness V1.

Plan mode is the default and is deliberately inert. Execute mode is a
repository-supported, fail-closed disposable workflow whose real PostgreSQL
execution always requires a separate explicit operator authorization.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence
from urllib.parse import parse_qs, quote, urlencode, urlsplit

PRODUCTION_SHA = "6873e8fb73cbea8fda43fe3609bbdbb2817d8299"
STAGING_SHA = "b3b8ed776d94bbdda88371de7bee8fed17d505f0"
SOURCE_AUDIT_REPORT_SHA256 = "1b30768d3a00ccf188e15bf75dc5ce1007065b093c502ab1187e95a41ca8984f"
SOURCE_DATABASE_IDENTIFIER_SHA256 = "cd098bd0f85e4f7b5767fdc94daa08d4f9d08bbda0c60ebb6065bbc754ce0106"
ACKNOWLEDGEMENT = "DISPOSABLE-NONPRODUCTION-REHEARSAL-V1"

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = REPOSITORY_ROOT / "docs/data/production_compatibility_rehearsal_plan_v1.json"
FIXTURE_RELATIVE_PATH = Path("tests/fixtures/production_catalog_baseline_v1.sql")
OWNERSHIP_MARKER = ".hodlxxi-rehearsal-owner-v1"
OWNERSHIP_SCHEMA = "hodlxxi.production_compatibility_rehearsal_workspace.v1"
REHEARSAL_ROLE = "rehearsal_owner"
REHEARSAL_PORT = "55432"

PHASES = (
    "REHEARSAL_00_PREFLIGHT",
    "REHEARSAL_01_EPHEMERAL_CLUSTER",
    "REHEARSAL_02_SYNTHETIC_OLD_SCHEMA",
    "REHEARSAL_03_NEW_CODE_OLD_SCHEMA_STARTUP",
    "REHEARSAL_04_NEW_CODE_OLD_SCHEMA_AUTH",
    "REHEARSAL_05_APPLY_NINE_MIGRATIONS",
    "REHEARSAL_06_VERIFY_MIGRATED_CATALOG",
    "REHEARSAL_07_OLD_CODE_NEW_SCHEMA_STARTUP",
    "REHEARSAL_08_NEW_CODE_NEW_SCHEMA_STARTUP_AUTH",
    "REHEARSAL_09_BACKUP",
    "REHEARSAL_10_RESTORE",
    "REHEARSAL_11_COMPARE",
    "REHEARSAL_12_CLEANUP",
    "REHEARSAL_13_RESULT",
)

STARTUP_PROBE_EVIDENCE = (
    "APPLICATION_STARTUP",
    "REQUIRED_BLUEPRINT_REGISTRATION",
    "DISPOSABLE_TARGET_QUERYABILITY",
)

AUTH_PROBE_EVIDENCE = (
    "APPLICATION_STARTUP",
    "BLUEPRINT_REGISTRATION",
    "OAUTH_CLIENT_REGISTRATION_VALIDATION",
    "REDIRECT_URI_VALIDATION",
    "PKCE_REQUIREMENTS",
    "SCOPE_POLICY",
    "AUTHORIZATION_CODE_ONE_TIME_CONSUMPTION",
    "TOKEN_ISSUE",
    "BEARER_PARSING",
    "TOKEN_VALIDATION",
    "TOKEN_INTROSPECTION",
    "REVOKED_OR_EXPIRED_TOKEN_REJECTION",
    "INACTIVE_USER_REJECTION",
    "EXACT_LIMITED_ENTITLEMENT",
    "NO_CRT_FULL_FROM_REHEARSAL_METADATA",
)

MIGRATIONS = (
    "migrations/2026-07-20_action_operations.sql",
    "migrations/2026-07-20_action_step_up_challenges.sql",
    "migrations/2026-07-21_action_step_up_operation_binding.sql",
    "migrations/2026-07-22_current_entitlement_evidence.sql",
    "migrations/2026-07-25_trusted_covenant_registration.sql",
    "migrations/2026-07-26_canonical_admission_edge_registry_v1.sql",
    "migrations/2026-07-26_canonical_e923_genesis_record_v1.sql",
    "migrations/2026-08-11_canonical_root_registration_binding_v1.sql",
    "migrations/2026-08-12_canonical_covenant_funding_set_v1.sql",
)

APPLICATION_ENVIRONMENT_KEYS = (
    "APP_VERSION",
    "DATABASE_URL",
    "DISABLE_FORCE_HTTPS",
    "FLASK_ENV",
    "FLASK_SECRET_KEY",
    "HOME",
    "JWKS_DIR",
    "JWT_ALGORITHM",
    "JWT_ISSUER",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONPATH",
    "RATE_LIMIT_ENABLED",
    "TESTING",
    "TMPDIR",
)

# Exact primary-key, unique, and foreign-key shapes created by the immutable
# nine-migration transition. Names alone are insufficient evidence: a
# constraint with the right name on the wrong table or columns must fail.
# Fields are table|type|columns|referenced_table|referenced_columns|delete_action.
MIGRATION_RELATIONAL_CONSTRAINTS = frozenset(
    {
        "action_operations|p|operation_id|||",
        "action_operations|u|actor_pubkey,oauth_client_id,idempotency_key_sha256|||",
        "action_operations|u|step_up_challenge_id|||",
        "action_operations|f|step_up_challenge_id|action_step_up_challenges|challenge_id|a",
        "action_step_up_challenges|p|challenge_id|||",
        "action_step_up_challenges|u|nonce|||",
        "current_entitlement_evidence|p|evidence_id|||",
        "trusted_covenant_registrations|p|registration_id|||",
        "trusted_covenant_registrations|u|registration_sha256|||",
        "trusted_covenant_registered_outpoints|p|id|||",
        "trusted_covenant_registered_outpoints|u|registration_id,direction|||",
        "trusted_covenant_registered_outpoints|u|txid,vout|||",
        ("trusted_covenant_registered_outpoints|f|registration_id|" "trusted_covenant_registrations|registration_id|c"),
        "canonical_admission_edges|p|edge_id|||",
        "canonical_admission_edges|u|trusted_registration_id|||",
        "canonical_admission_edges|u|trusted_registration_sha256|||",
        "canonical_admission_edges|u|canonical_edge_sha256|||",
        "canonical_admission_edge_legs|p|id|||",
        "canonical_admission_edge_legs|u|edge_id,direction|||",
        "canonical_admission_edge_legs|u|txid,vout|||",
        "canonical_admission_edge_legs|f|edge_id|canonical_admission_edges|edge_id|a",
        "canonical_genesis_records|p|record_id|||",
        "canonical_genesis_records|u|canonical_record_sha256|||",
        "canonical_root_registration_bindings|p|binding_id|||",
        "canonical_root_registration_bindings|u|canonical_binding_sha256|||",
        "canonical_covenant_funding_sets|p|funding_set_id|||",
        "canonical_covenant_funding_sets|u|canonical_funding_set_sha256|||",
        "canonical_covenant_funding_outpoints|p|id|||",
        "canonical_covenant_funding_outpoints|u|funding_set_id,txid,vout|||",
        ("canonical_covenant_funding_outpoints|f|funding_set_id|"
         "canonical_covenant_funding_sets|funding_set_id|c"),
    }
)

# Phase-6 contracts for structures whose semantics are not proved by a name.
# Fields are table|index|unique|ordered_columns|predicate_kind, followed by
# table|column|type|default|sequence|owned_table|owned_column.
MIGRATION_8_9_INDEX_SEMANTICS = frozenset(
    {
        "canonical_root_registration_bindings|idx_root_registration_binding_graph_root|false|graph_or_protocol_id,root_x_only_public_key|none",
        "canonical_root_registration_bindings|idx_root_registration_binding_registration|false|trusted_registration_id|none",
        "canonical_root_registration_bindings|uq_root_registration_binding_effective_root|true|graph_or_protocol_id,root_x_only_public_key|partial",
        "canonical_covenant_funding_sets|idx_funding_set_registration|false|trusted_registration_id|none",
        "canonical_covenant_funding_sets|uq_funding_set_effective_registration|true|trusted_registration_id|partial",
        "canonical_covenant_funding_outpoints|idx_funding_outpoint_set|false|funding_set_id|none",
    }
)

MIGRATION_8_9_SERIAL_SEMANTICS = frozenset(
    {
        "canonical_covenant_funding_outpoints|id|bigint|nextval('canonical_covenant_funding_outpoints_id_seq'::regclass)|canonical_covenant_funding_outpoints_id_seq|canonical_covenant_funding_outpoints|id"
    }
)

# Fields are table|constraint|canonical referenced-column set. This supplements
# the exact per-table CHECK counts with column semantics for every named CHECK
# in migrations eight and nine.
MIGRATION_8_9_CHECK_SEMANTICS = frozenset(
    {
        "canonical_root_registration_bindings|ck_root_registration_binding_schema|schema",
        "canonical_root_registration_bindings|ck_root_registration_binding_version|binding_version",
        "canonical_root_registration_bindings|ck_root_registration_binding_id|binding_id",
        "canonical_root_registration_bindings|ck_root_registration_binding_root|root_x_only_public_key",
        "canonical_root_registration_bindings|ck_root_registration_binding_registration_id|trusted_registration_id",
        "canonical_root_registration_bindings|ck_root_registration_binding_registration_digest|trusted_registration_sha256",
        "canonical_root_registration_bindings|ck_root_registration_binding_digest|canonical_binding_sha256",
        "canonical_root_registration_bindings|ck_root_registration_binding_lifecycle|lifecycle_state",
        "canonical_root_registration_bindings|ck_root_registration_binding_changed_order|created_at,lifecycle_changed_at",
        "canonical_root_registration_bindings|ck_root_registration_binding_lifecycle_consistency|created_at,effective_at,lifecycle_changed_at,lifecycle_state,superseded_by_binding_id",
        "canonical_root_registration_bindings|ck_root_registration_binding_successor|binding_id,superseded_by_binding_id",
        "canonical_covenant_funding_sets|ck_funding_set_schema|schema",
        "canonical_covenant_funding_sets|ck_funding_set_version|funding_set_version",
        "canonical_covenant_funding_sets|ck_funding_set_lifecycle|lifecycle_state",
        "canonical_covenant_funding_sets|ck_funding_set_id|funding_set_id",
        "canonical_covenant_funding_sets|ck_funding_set_registration_id|trusted_registration_id",
        "canonical_covenant_funding_sets|ck_funding_set_source_digests|pair_sha256,trusted_registration_sha256",
        "canonical_covenant_funding_sets|ck_funding_set_participants|counterparty_xonly_pubkey,subject_xonly_pubkey",
        "canonical_covenant_funding_sets|ck_funding_set_changed_order|created_at,lifecycle_changed_at",
        "canonical_covenant_funding_sets|ck_funding_set_lifecycle_consistency|created_at,effective_at,lifecycle_changed_at,lifecycle_state,superseded_by_funding_set_id",
        "canonical_covenant_funding_sets|ck_funding_set_successor|funding_set_id,superseded_by_funding_set_id",
        "canonical_covenant_funding_sets|ck_funding_set_digest|canonical_funding_set_sha256",
        "canonical_covenant_funding_outpoints|ck_funding_outpoint_direction|direction",
        "canonical_covenant_funding_outpoints|ck_funding_outpoint_txid|txid",
        "canonical_covenant_funding_outpoints|ck_funding_outpoint_vout|vout",
        "canonical_covenant_funding_outpoints|ck_funding_outpoint_amount|amount_sats",
        "canonical_covenant_funding_outpoints|ck_funding_outpoint_script|witness_script_sha256",
        "canonical_covenant_funding_outpoints|ck_funding_outpoint_descriptor|descriptor_sha256",
    }
)

NON_CLAIMS = (
    "no deployment approval",
    "no deployment performed",
    "no production migration",
    "no migration rehearsal executed",
    "no database created",
    "no database contacted",
    "no database write",
    "no application-row inspection",
    "no production data copied",
    "no production database name",
    "no environment-value inspection",
    "no secret inspection",
    "no credential inspection",
    "no service restart",
    "no runtime configuration change",
    "no route change",
    "no authentication behavior change",
    "no authorization behavior change",
    "no Bitcoin RPC call",
    "no LND call",
    "no wallet operation",
    "no network request",
    "no PostgreSQL subprocess executed",
    "no backup created",
    "no restore executed",
    "no startup compatibility proof",
    "no OAuth/OIDC/JWT compatibility proof",
    "no migration compatibility proof",
    "no backup availability proof",
    "no restore readiness proof",
    "no production readiness claim",
    "no Train 1 approval",
    "no Train 2 approval",
    "no legacy cutover",
    "no CRT FULL grant",
    "no proof signing",
    "no portable authority",
    "no federation or replication",
)

PR6_24_MAY = (
    "provision an isolated disposable laboratory",
    "run the PR6.23 harness",
    "use synthetic data only",
    "emit a sanitized result artifact",
    "classify phases PASS, FAIL or BLOCKED",
    "propose release-gate changes based on evidence",
)

PR6_24_MAY_NOT = (
    "contact or modify production resources outside the disposable laboratory",
    "use the production PostgreSQL cluster",
    "use production rows",
    "use production credentials",
    "use production database names",
    "deploy staging",
    "apply production migrations",
    "restart production services",
    "call production Bitcoin RPC or LND",
    "change entitlement or enforcement",
    "merge release trains",
    "declare production readiness automatically",
)

TRAIN_DISPOSITION = (
    {"train": "TRAIN_0", "status": "COMPLETE"},
    {"train": "TRAIN_1", "status": "NOT_RELEASE_APPROVED"},
    {"train": "TRAIN_2", "status": "NOT_RELEASE_APPROVED"},
    {"train": "TRAINS_3_THROUGH_10", "status": "DEPENDENT_ON_PR6_21_GATES"},
)

REQUIRED_TOP_LEVEL_FIELDS = (
    "schema",
    "plan_version",
    "production_sha",
    "staging_sha",
    "source_audit_report_sha256",
    "source_database_identifier_sha256",
    "purpose",
    "execution_status",
    "release_authority",
    "safety_invariants",
    "prohibited_targets",
    "required_tools",
    "source_isolation",
    "synthetic_baseline",
    "migration_order",
    "phases",
    "startup_probe",
    "auth_probe_matrix",
    "backup_restore_probe",
    "result_schema",
    "release_gate_effect",
    "next_required_work",
    "explicit_non_claims",
)

POSTGRESQL_TOOLS = (
    "initdb",
    "pg_ctl",
    "postgres",
    "createdb",
    "psql",
    "pg_dump",
    "pg_restore",
)

APPROVED_TEMPORARY_ROOTS = (Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"))
PROHIBITED_ROOTS = (
    Path("/srv/ubid"),
    Path("/srv/ubid-staging"),
    Path("/etc/postgresql"),
    Path("/var/lib/postgresql"),
    Path("/var/backups/hodlxxi"),
    Path("/opt/hodlxxi"),
    Path("/srv/hodlxxi"),
)

INHERITED_RUNTIME_KEYS = frozenset(
    {
        "DATABASE_URL",
        "POSTGRES_URL",
        "PGHOST",
        "PGPORT",
        "PGDATABASE",
        "PGUSER",
        "PGPASSWORD",
        "DB_HOST",
        "DB_PORT",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "REDIS_URL",
        "REDIS_DSN",
        "REDIS_HOST",
        "REDIS_PASSWORD",
        "RPC_HOST",
        "RPC_PORT",
        "RPC_USER",
        "RPC_PASSWORD",
        "RPC_WALLET",
        "LND_REST_URL",
        "LND_GRPC_HOST",
        "LND_MACAROON_PATH",
        "LND_TLS_CERT_PATH",
        "FLASK_SECRET_KEY",
        "JWT_SECRET",
        "JWKS_DIR",
        "OAUTH_CLIENT_SECRET",
    }
)

DATABASE_TARGET_PATTERN = re.compile(r"^hodlxxi_rehearsal_[a-z0-9_]+$")
SAFE_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IPV4_CANDIDATE = re.compile(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")
IPV6_CANDIDATE = re.compile(r"(?<![\w])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:%]*(?![\w])")
DSN_PATTERN = re.compile(r"(?i)\bpostgres(?:ql)?(?:\+[a-z0-9_]+)?://")


class PlanContractError(ValueError):
    """The committed deterministic plan violates its contract."""


class SafetyViolation(RuntimeError):
    """Execute-mode preflight rejected an unsafe request."""

    def __init__(self, evidence_code: str):
        super().__init__(evidence_code)
        self.evidence_code = evidence_code


class CommandFailure(RuntimeError):
    """A command failed; raw output is intentionally not retained here."""

    def __init__(self, evidence_code: str):
        super().__init__(evidence_code)
        self.evidence_code = evidence_code


class ProbeUnsupported(RuntimeError):
    """A reviewed probe dependency cannot be isolated by this harness."""

    def __init__(self, evidence_code: str):
        super().__init__(evidence_code)
        self.evidence_code = evidence_code


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PlanContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _walk(value: object, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + (str(key),)
            yield child_path, child
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = path + (str(index),)
            yield child_path, child
            yield from _walk(child, child_path)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanContractError(message)


def _contains_ip_literal(value: str) -> bool:
    candidates = IPV4_CANDIDATE.findall(value) + IPV6_CANDIDATE.findall(value)
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError:
            continue
        return True
    return False


def validate_plan_contract(plan: Mapping[str, object]) -> None:
    """Validate the normative plan without reading process state."""

    _require(tuple(plan) == REQUIRED_TOP_LEVEL_FIELDS, "unexpected top-level plan fields or ordering")
    _require(plan["schema"] == "hodlxxi.production_compatibility_rehearsal_plan.v1", "invalid plan schema")
    _require(plan["plan_version"] == 1, "invalid plan version")
    _require(plan["production_sha"] == PRODUCTION_SHA, "invalid production SHA")
    _require(plan["staging_sha"] == STAGING_SHA, "invalid staging SHA")
    _require(plan["source_audit_report_sha256"] == SOURCE_AUDIT_REPORT_SHA256, "invalid audit SHA")
    _require(
        plan["source_database_identifier_sha256"] == SOURCE_DATABASE_IDENTIFIER_SHA256,
        "invalid sanitized database identifier",
    )
    _require(plan["execution_status"] == "NOT_RUN", "committed plan must be NOT_RUN")
    _require(plan["release_authority"] == "NONE", "committed plan has no release authority")

    phases = plan["phases"]
    _require(isinstance(phases, list), "phases must be a list")
    _require(tuple(item.get("phase") for item in phases if isinstance(item, dict)) == PHASES, "invalid phase order")
    _require(
        all(isinstance(item, dict) and item.get("status") == "NOT_RUN" for item in phases), "phase claimed execution"
    )
    _require(tuple(plan["migration_order"]) == MIGRATIONS, "invalid migration order")
    _require(tuple(plan["explicit_non_claims"]) == NON_CLAIMS, "invalid non-claim list")

    release = plan["release_gate_effect"]
    _require(isinstance(release, dict) and release.get("effect") == "NONE", "plan changed a release gate")
    _require(release.get("train_disposition") == list(TRAIN_DISPOSITION), "invalid train disposition")

    boundary = plan["next_required_work"]
    _require(isinstance(boundary, dict), "missing next work")
    pr6_24 = boundary.get("pr6_24_boundary")
    _require(isinstance(pr6_24, dict), "missing PR6.24 boundary")
    _require(tuple(pr6_24.get("may", ())) == PR6_24_MAY, "invalid PR6.24 may boundary")
    _require(tuple(pr6_24.get("may_not", ())) == PR6_24_MAY_NOT, "invalid PR6.24 may-not boundary")

    invariants = plan["safety_invariants"]
    for required in (
        "REJECT_UID_0",
        "REJECT_INHERITED_CONFIGURATION",
        "UNIX_SOCKET_ONLY",
        "TCP_DISABLED_LISTEN_ADDRESSES_EMPTY",
        "HARNESS_OWNERSHIP_MARKER_REQUIRED",
        "FAIL_CLOSED_PHASE_DEPENDENCIES",
    ):
        _require(required in invariants, f"missing safety invariant: {required}")

    isolation = plan["source_isolation"]
    _require(isinstance(isolation, dict), "missing source isolation")
    cluster = isolation.get("cluster_architecture")
    _require(isinstance(cluster, dict), "missing cluster architecture")
    _require(cluster.get("transport") == "UNIX_SOCKET_ONLY", "TCP architecture allowed")
    _require(cluster.get("listen_addresses") == "", "listen_addresses must be empty")
    _require(cluster.get("tcp") == "DISABLED", "TCP must be disabled")
    _require(cluster.get("existing_cluster") == "FORBIDDEN", "existing cluster allowed")
    _require(isolation.get("network_clone") is False, "network clone allowed")

    startup_probe = plan["startup_probe"]
    _require(isinstance(startup_probe, dict), "missing startup probe")
    _require(
        startup_probe.get("configuration_source") == "EXPLICIT_ALLOWLIST_ONLY",
        "startup configuration is not allowlisted",
    )
    _require(
        tuple(startup_probe.get("allowlisted_variable_names", ())) == APPLICATION_ENVIRONMENT_KEYS,
        "startup environment allowlist does not match the executable probe",
    )
    _require(startup_probe.get("inherited_environment") == "FORBIDDEN", "inherited environment allowed")

    result_schema = plan["result_schema"]
    _require(isinstance(result_schema, dict), "missing result schema")
    _require(
        result_schema.get("phase_result_fields")
        == [
            "phase",
            "status",
            "evidence_code",
            "duration_ms",
            "sanitized_detail",
            "artifact_sha256",
            "cleanup_status",
        ],
        "invalid phase result fields",
    )
    template = result_schema.get("phase_result_template")
    _require(isinstance(template, dict) and template.get("status") == "NOT_RUN", "result template claimed execution")

    forbidden_field = re.compile(
        r"(^|_)(database_name|db_name|dbname|generated_at|timestamp|environment_value|env_value|"
        r"password|credential_value|secret_value|token_value|private_key|macaroon)($|_)",
        re.IGNORECASE,
    )
    for path, value in _walk(plan):
        key = path[-1]
        _require(not forbidden_field.search(key), f"forbidden plan field: {'.'.join(path)}")
        if isinstance(value, str):
            _require(not _contains_ip_literal(value), f"IP literal in plan: {'.'.join(path)}")
            _require(not DSN_PATTERN.search(value), f"DSN in plan: {'.'.join(path)}")
            if DATABASE_TARGET_PATTERN.fullmatch(value):
                raise PlanContractError("generated database target in deterministic plan")


def load_plan(path: Path | None = None) -> dict[str, object]:
    """Load the deterministic plan with recursive duplicate-key rejection."""

    source = PLAN_PATH if path is None else Path(path)
    value = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    if not isinstance(value, dict):
        raise PlanContractError("plan must be a JSON object")
    validate_plan_contract(value)
    return value


def canonical_plan_json(plan: Mapping[str, object] | None = None) -> str:
    """Return stable JSON without timestamps, randomness, or process state."""

    value = load_plan() if plan is None else dict(plan)
    validate_plan_contract(value)
    return json.dumps(value, ensure_ascii=False, indent=2, separators=(",", ": ")) + "\n"


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        input_text: str | None = None,
        timeout: int = 120,
    ) -> CommandResult: ...


class SubprocessCommandRunner:
    """Real runner used only by an explicitly acknowledged execute command."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        input_text: str | None = None,
        timeout: int = 120,
    ) -> CommandResult:
        if env is None:
            raise SafetyViolation("CHILD_ENVIRONMENT_NOT_EXPLICIT")
        completed = subprocess.run(
            [str(item) for item in argv],
            cwd=str(cwd),
            env={str(key): str(value) for key, value in env.items()},
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            shell=False,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True)
class ExecuteRequest:
    acknowledgement: str
    repository: Path
    workspace: Path
    temporary_root: Path
    production_sha: str
    staging_sha: str
    git_binary: Path
    python_binary: Path
    postgresql_binary_directory: Path
    environment_keys: frozenset[str] = frozenset()
    effective_uid: int | None = None
    transport: str = "unix"
    listen_addresses: str = ""
    external_dsn: str | None = None
    requested_target: str | None = None
    output_path: Path | None = None


@dataclass(frozen=True)
class ResolvedTools:
    git: Path
    python: Path
    postgresql: Mapping[str, Path]


@dataclass(frozen=True)
class ResolvedRequest:
    request: ExecuteRequest
    repository: Path
    workspace: Path
    temporary_root: Path
    tools: ResolvedTools


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_prohibited(path: Path) -> bool:
    return any(path == root or _is_within(path, root) for root in PROHIBITED_ROOTS)


def _resolve_executable(path: Path, evidence_code: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SafetyViolation(evidence_code) from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SafetyViolation(evidence_code)
    return resolved


def _validated_launcher_path(path: Path, evidence_code: str) -> Path:
    """Return an absolute launcher path after validating its resolved target."""

    launcher = Path(os.path.abspath(os.fspath(path)))
    _resolve_executable(launcher, evidence_code)
    return launcher


def _dsn_contains_password(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        if parsed.password is not None:
            return True
        query = parse_qs(parsed.query, keep_blank_values=True)
        return any(key.casefold() in {"password", "passfile"} for key in query)
    except Exception:
        return bool(re.search(r"(?i)(password\s*=|://[^/@:]+:[^/@]+@)", value))


def validate_database_target(name: str) -> str:
    """Accept only execute-time rehearsal target syntax and reject defaults."""

    if not isinstance(name, str) or len(name) > 63 or not DATABASE_TARGET_PATTERN.fullmatch(name):
        raise SafetyViolation("DATABASE_TARGET_PATTERN_REJECTED")
    if name in {"postgres", "template0", "template1"}:
        raise SafetyViolation("RESERVED_DATABASE_TARGET_REJECTED")
    return name


def generate_database_targets(token_factory: Callable[[], str] | None = None) -> tuple[str, str]:
    """Generate target identities only when called from execute mode."""

    factory = token_factory or (lambda: secrets.token_hex(12))
    raw = str(factory()).lower()
    suffix = re.sub(r"[^a-z0-9_]", "", raw)
    if not suffix:
        suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    primary = validate_database_target(f"hodlxxi_rehearsal_{suffix}")
    restored = validate_database_target(f"{primary}_restored")
    if primary == restored:
        raise SafetyViolation("DATABASE_TARGET_COLLISION")
    return primary, restored


def _validate_path_text(path: Path) -> None:
    rendered = str(path)
    if any(character in rendered for character in ("\n", "\r", "'", "\x00")):
        raise SafetyViolation("UNSAFE_PATH_TEXT")


def validate_execute_request(request: ExecuteRequest) -> ResolvedRequest:
    """Apply all non-mutating execute safety gates before any runner call."""

    if request.acknowledgement != ACKNOWLEDGEMENT:
        raise SafetyViolation("ACKNOWLEDGEMENT_REQUIRED")
    if request.production_sha != PRODUCTION_SHA:
        raise SafetyViolation("PRODUCTION_SHA_MISMATCH")
    if request.staging_sha != STAGING_SHA:
        raise SafetyViolation("STAGING_SHA_MISMATCH")
    if request.effective_uid is None:
        raise SafetyViolation("EFFECTIVE_UID_REQUIRED")
    if not isinstance(request.effective_uid, int) or request.effective_uid <= 0:
        raise SafetyViolation("ROOT_EXECUTION_REFUSED")
    if INHERITED_RUNTIME_KEYS.intersection(request.environment_keys):
        raise SafetyViolation("INHERITED_RUNTIME_CONFIGURATION_REFUSED")
    if request.external_dsn:
        if _dsn_contains_password(request.external_dsn):
            raise SafetyViolation("PASSWORD_BEARING_DSN_REFUSED")
        raise SafetyViolation("EXTERNAL_DSN_REFUSED")
    if request.requested_target is not None:
        raise SafetyViolation("EXTERNAL_DATABASE_TARGET_REFUSED")
    if request.transport != "unix" or request.listen_addresses != "":
        raise SafetyViolation("TCP_POSTGRESQL_REFUSED")

    repository_input = Path(os.path.abspath(os.fspath(request.repository)))
    _validate_path_text(repository_input)
    if _is_prohibited(repository_input):
        raise SafetyViolation("PROTECTED_REPOSITORY_PATH_REFUSED")

    try:
        repository = request.repository.resolve(strict=True)
        temporary_root = request.temporary_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SafetyViolation("EXPLICIT_PATH_INVALID") from exc
    workspace = request.workspace.resolve(strict=False)
    for path in (repository, temporary_root, workspace):
        _validate_path_text(path)
    if not repository.is_dir():
        raise SafetyViolation("REPOSITORY_PATH_INVALID")
    if _is_prohibited(repository):
        raise SafetyViolation("PROTECTED_REPOSITORY_PATH_REFUSED")
    if not temporary_root.is_dir() or temporary_root.is_symlink():
        raise SafetyViolation("TEMPORARY_ROOT_INVALID")
    approved = [root.resolve(strict=True) for root in APPROVED_TEMPORARY_ROOTS if root.exists()]
    if not any(temporary_root == root or _is_within(temporary_root, root) for root in approved):
        raise SafetyViolation("TEMPORARY_ROOT_NOT_APPROVED")
    if workspace.parent != temporary_root or workspace == temporary_root:
        raise SafetyViolation("WORKSPACE_OUTSIDE_EXPLICIT_TEMPORARY_ROOT")
    if _is_prohibited(workspace):
        raise SafetyViolation("PROHIBITED_WORKSPACE_PATH")
    if workspace.exists() or workspace.is_symlink():
        raise SafetyViolation("WORKSPACE_MUST_NOT_EXIST")
    if request.output_path is not None:
        output = request.output_path.resolve(strict=False)
        _validate_path_text(output)
        if output.exists() or output.is_symlink() or not output.parent.is_dir():
            raise SafetyViolation("OUTPUT_PATH_MUST_BE_NEW")
        if _is_prohibited(output) or output == workspace or _is_within(output, workspace):
            raise SafetyViolation("OUTPUT_PATH_PROHIBITED")

    git = _resolve_executable(request.git_binary, "GIT_BINARY_INVALID")
    python = _validated_launcher_path(request.python_binary, "PYTHON_BINARY_INVALID")
    try:
        pg_directory = request.postgresql_binary_directory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SafetyViolation("POSTGRESQL_BINARY_DIRECTORY_INVALID") from exc
    if not pg_directory.is_dir() or pg_directory.is_symlink():
        raise SafetyViolation("POSTGRESQL_BINARY_DIRECTORY_INVALID")
    pg_tools: dict[str, Path] = {}
    for name in POSTGRESQL_TOOLS:
        candidate = _resolve_executable(pg_directory / name, f"POSTGRESQL_BINARY_MISSING_{name.upper()}")
        if candidate.parent != pg_directory:
            raise SafetyViolation("POSTGRESQL_BINARY_ESCAPES_DIRECTORY")
        pg_tools[name] = candidate
    return ResolvedRequest(request, repository, workspace, temporary_root, ResolvedTools(git, python, pg_tools))


@dataclass
class WorkspaceGuard:
    workspace: Path
    temporary_root: Path
    ownership_token: str

    @property
    def marker(self) -> Path:
        return self.workspace / OWNERSHIP_MARKER

    @classmethod
    def create(cls, workspace: Path, temporary_root: Path, ownership_token: str) -> "WorkspaceGuard":
        if workspace.exists() or workspace.parent != temporary_root:
            raise SafetyViolation("WORKSPACE_CREATION_REFUSED")
        workspace.mkdir(mode=0o700, parents=False)
        guard = cls(workspace, temporary_root, ownership_token)
        payload = json.dumps(
            {"schema": OWNERSHIP_SCHEMA, "ownership_token": ownership_token},
            sort_keys=True,
            separators=(",", ":"),
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(guard.marker, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
            guard.assert_owned()
            return guard
        except BaseException:
            # This method alone created the mode-0700 workspace and exclusive
            # marker. Remove only that regular partial marker and only if the
            # workspace is otherwise empty; unexpected contents are retained.
            try:
                marker_stat = guard.marker.lstat()
                if stat.S_ISREG(marker_stat.st_mode) and marker_stat.st_uid == os.geteuid():
                    guard.marker.unlink()
            except OSError:
                pass
            try:
                workspace.rmdir()
            except OSError:
                pass
            raise

    def assert_owned(self) -> None:
        if self.workspace.parent != self.temporary_root or self.workspace.is_symlink():
            raise SafetyViolation("WORKSPACE_OWNERSHIP_REFUSED")
        if not self.workspace.is_dir() or self.marker.is_symlink() or not self.marker.is_file():
            raise SafetyViolation("OWNERSHIP_MARKER_MISSING")
        try:
            payload = json.loads(self.marker.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
        except Exception as exc:
            raise SafetyViolation("OWNERSHIP_MARKER_INVALID") from exc
        expected = {"schema": OWNERSHIP_SCHEMA, "ownership_token": self.ownership_token}
        if payload != expected:
            raise SafetyViolation("OWNERSHIP_MARKER_MISMATCH")

    def assert_no_existing_cluster(self) -> None:
        self.assert_owned()
        data = self.workspace / "cluster"
        forbidden = ("PG_VERSION", "postmaster.pid", "base", "global")
        if any((data / name).exists() for name in forbidden):
            raise SafetyViolation("EXISTING_POSTGRESQL_CLUSTER_REFUSED")

    def cleanup(self) -> None:
        self.assert_owned()
        for root, directories, files in os.walk(self.workspace, topdown=False, followlinks=False):
            root_path = Path(root)
            for name in files:
                path = root_path / name
                if not path.is_symlink():
                    try:
                        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                    except OSError:
                        pass
            for name in directories:
                path = root_path / name
                if not path.is_symlink():
                    try:
                        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                    except OSError:
                        pass
        self.workspace.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        self.assert_owned()
        shutil.rmtree(self.workspace)


@dataclass
class PhaseOutcome:
    status: str
    evidence_code: str
    sanitized_detail: str
    artifact_sha256: str | None = None
    cleanup_status: str = "PENDING"
    unsupported: bool = False


@dataclass
class ExecutionState:
    resolved: ResolvedRequest
    plan: Mapping[str, object]
    guard: WorkspaceGuard | None = None
    production_snapshot: Path | None = None
    staging_snapshot: Path | None = None
    fixture_copy: Path | None = None
    jwks_directory: Path | None = None
    cluster_started: bool = False
    primary_target: str | None = None
    restored_target: str | None = None
    archive_path: Path | None = None
    archive_sha256: str | None = None


def _phase_result(
    phase: str,
    outcome: PhaseOutcome,
    duration_ms: int,
) -> dict[str, object]:
    if phase not in PHASES:
        raise ValueError("unknown phase")
    if outcome.status not in {"NOT_RUN", "PASS", "FAIL", "BLOCKED"}:
        raise ValueError("unknown phase status")
    if outcome.unsupported and outcome.status == "PASS":
        raise ValueError("unsupported probe cannot pass")
    if outcome.artifact_sha256 is not None and not SHA256_PATTERN.fullmatch(outcome.artifact_sha256):
        raise ValueError("invalid artifact digest")
    return {
        "phase": phase,
        "status": outcome.status,
        "evidence_code": outcome.evidence_code,
        "duration_ms": duration_ms,
        "sanitized_detail": outcome.sanitized_detail,
        "artifact_sha256": outcome.artifact_sha256,
        "cleanup_status": outcome.cleanup_status,
    }


DETAILS = {
    "PREFLIGHT_COMPLETE": "All execute-mode safety gates completed.",
    "EPHEMERAL_CLUSTER_READY": "The marker-owned Unix-socket-only cluster started.",
    "SYNTHETIC_BASELINE_READY": "The schema-only sanitized baseline loaded and matched its catalog contract.",
    "STARTUP_PROBE_COMPLETE": "The isolated startup probe completed with sanitized evidence.",
    "AUTH_PROBE_COMPLETE": "The supported synthetic authentication matrix completed with sanitized evidence.",
    "NINE_MIGRATIONS_APPLIED": "All nine immutable migrations completed in the required order.",
    "MIGRATED_CATALOG_VERIFIED": "Migration-declared catalog objects matched the required contract.",
    "BACKUP_ARCHIVE_VERIFIED": "The disposable custom-format archive and checksum were verified.",
    "RESTORE_COMPLETE": "The archive restored into the second disposable target.",
    "RESTORE_COMPARISON_COMPLETE": (
        "Catalog schema semantics, ownership categories, object counts, per-table synthetic row counts and "
        "queryability matched."
    ),
    "CLEANUP_COMPLETE": "Only marker-owned temporary artifacts were removed.",
    "CLEANUP_NOT_REQUIRED": "No marker-owned workspace required cleanup.",
    "SANITIZED_RESULT_EMITTED": "A sanitized result object was produced with no release authority.",
    "PREREQUISITE_NOT_PASS": "The phase was not run because a prerequisite did not pass.",
    "SAFETY_GATE_BLOCKED": "A fail-closed execute-mode safety gate blocked the rehearsal.",
    "COMMAND_FAILED": "A laboratory command failed; raw output was discarded.",
    "PROBE_BLOCKED": "A probe dependency could not be safely isolated.",
    "PROBE_FAILED": "A compatibility probe failed; raw output was discarded.",
    "CLEANUP_FAILED": "Cleanup could not be proven safe and incomplete artifacts were left in place.",
    "UNEXPECTED_FAILURE": "The phase failed closed; exception detail was not retained.",
}


def _checked(
    runner: CommandRunner,
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    evidence_code: str,
    input_text: str | None = None,
    timeout: int = 120,
) -> CommandResult:
    lowered = [str(item).casefold() for item in argv]
    if any(token in {"clone", "fetch", "pull"} for token in lowered):
        raise SafetyViolation("NETWORK_GIT_OPERATION_REFUSED")
    result = runner.run(argv, cwd=cwd, env=env, input_text=input_text, timeout=timeout)
    if result.returncode != 0:
        raise CommandFailure(evidence_code)
    return result


def _git_environment(temporary_root: Path) -> dict[str, str]:
    return {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(temporary_root),
        "LANG": "C",
        "LC_ALL": "C",
    }


def verify_local_source_objects(
    runner: CommandRunner,
    resolved: ResolvedRequest,
) -> None:
    """Verify cleanliness and the two exact local commit objects read-only."""

    git = str(resolved.tools.git)
    repository = resolved.repository
    environment = _git_environment(resolved.temporary_root)
    status = _checked(
        runner,
        [git, "-C", str(repository), "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
        env=environment,
        evidence_code="SOURCE_REPOSITORY_STATUS_FAILED",
    )
    if status.stdout:
        raise SafetyViolation("SOURCE_REPOSITORY_DIRTY")
    for sha, label in ((PRODUCTION_SHA, "PRODUCTION"), (STAGING_SHA, "STAGING")):
        _checked(
            runner,
            [git, "-C", str(repository), "cat-file", "-e", f"{sha}^{{commit}}"],
            cwd=repository,
            env=environment,
            evidence_code=f"{label}_GIT_OBJECT_MISSING",
        )
        resolved_object = _checked(
            runner,
            [git, "-C", str(repository), "rev-parse", "--verify", f"{sha}^{{commit}}"],
            cwd=repository,
            env=environment,
            evidence_code=f"{label}_GIT_OBJECT_INVALID",
        )
        if resolved_object.stdout.strip() != sha:
            raise SafetyViolation(f"{label}_GIT_OBJECT_MISMATCH")


def _safe_extract_archive(archive: Path, destination: Path) -> None:
    if destination.exists():
        raise SafetyViolation("SOURCE_SNAPSHOT_ALREADY_EXISTS")
    destination.mkdir(mode=0o700)
    destination_root = destination.resolve(strict=True)
    try:
        with tarfile.open(archive, mode="r:") as bundle:
            for member in bundle.getmembers():
                if member.issym() or member.islnk() or member.isdev():
                    raise SafetyViolation("SOURCE_ARCHIVE_SPECIAL_ENTRY_REFUSED")
                member_path = (destination / member.name).resolve(strict=False)
                if member_path != destination_root and not _is_within(member_path, destination_root):
                    raise SafetyViolation("SOURCE_ARCHIVE_PATH_TRAVERSAL_REFUSED")
            bundle.extractall(destination, filter="data")
    except Exception:
        if destination.exists():
            shutil.rmtree(destination)
        raise


def _make_snapshot_read_only(snapshot: Path) -> None:
    for root, directories, files in os.walk(snapshot, topdown=False, followlinks=False):
        root_path = Path(root)
        for name in files:
            path = root_path / name
            if not path.is_symlink():
                path.chmod(stat.S_IRUSR)
        for name in directories:
            path = root_path / name
            if not path.is_symlink():
                path.chmod(stat.S_IRUSR | stat.S_IXUSR)
    snapshot.chmod(stat.S_IRUSR | stat.S_IXUSR)


def extract_local_snapshot(
    runner: CommandRunner,
    resolved: ResolvedRequest,
    guard: WorkspaceGuard,
    *,
    sha: str,
    label: str,
) -> Path:
    guard.assert_owned()
    archives = guard.workspace / "archives"
    sources = guard.workspace / "sources"
    archives.mkdir(mode=0o700, exist_ok=True)
    sources.mkdir(mode=0o700, exist_ok=True)
    archive = archives / f"{label}.tar"
    destination = sources / label
    _checked(
        runner,
        [
            str(resolved.tools.git),
            "-C",
            str(resolved.repository),
            "archive",
            "--format=tar",
            f"--output={archive}",
            sha,
        ],
        cwd=resolved.repository,
        env=_git_environment(resolved.temporary_root),
        evidence_code="SOURCE_ARCHIVE_FAILED",
        timeout=300,
    )
    if not archive.is_file() or archive.is_symlink() or archive.stat().st_size == 0:
        raise CommandFailure("SOURCE_ARCHIVE_NOT_CREATED")
    _safe_extract_archive(archive, destination)
    archive.unlink()
    _make_snapshot_read_only(destination)
    return destination


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_ephemeral_jwks(directory: Path, token_factory: Callable[[], str] | None = None) -> None:
    """Create execute-only synthetic RS256 material inside the owned workspace."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if directory.exists():
        raise SafetyViolation("JWKS_DIRECTORY_ALREADY_EXISTS")
    directory.mkdir(mode=0o700)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = (token_factory or (lambda: secrets.token_hex(10)))()
    kid = str(int(hashlib.sha256(str(token).encode("utf-8")).hexdigest()[:15], 16))
    private_path = directory / f"private_key_{kid}.pem"
    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    numbers = key.public_key().public_numbers()
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    document = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _b64url(modulus),
                "e": _b64url(exponent),
            }
        ]
    }
    public_path = directory / "jwks.json"
    public_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    public_path.chmod(0o600)


PROBE_PROGRAM = r"""
import base64
import hashlib
import io
import json
import os
import smtplib
import socket
import subprocess
import sys
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit


class ProbeFailure(RuntimeError):
    def __init__(self, code):
        self.code = code


class ProbeBlocked(RuntimeError):
    def __init__(self, code):
        self.code = code


side_effect_attempts = []


def blocked_side_effect(*_args, **_kwargs):
    side_effect_attempts.append("blocked")
    raise ProbeBlocked("EXTERNAL_SIDE_EFFECT_GUARD_TRIGGERED")


original_connect = socket.socket.connect
original_connect_ex = socket.socket.connect_ex
original_sendto = socket.socket.sendto


def guarded_connect(instance, address):
    if instance.family in (socket.AF_INET, socket.AF_INET6):
        return blocked_side_effect(address)
    return original_connect(instance, address)


def guarded_connect_ex(instance, address):
    if instance.family in (socket.AF_INET, socket.AF_INET6):
        return blocked_side_effect(address)
    return original_connect_ex(instance, address)


def guarded_sendto(instance, *args, **kwargs):
    if instance.family in (socket.AF_INET, socket.AF_INET6):
        return blocked_side_effect(*args, **kwargs)
    return original_sendto(instance, *args, **kwargs)


socket.socket.connect = guarded_connect
socket.socket.connect_ex = guarded_connect_ex
socket.socket.sendto = guarded_sendto
socket.create_connection = blocked_side_effect
socket.getaddrinfo = blocked_side_effect
socket.gethostbyaddr = blocked_side_effect
socket.gethostbyname = blocked_side_effect
urllib.request.urlopen = blocked_side_effect
smtplib.SMTP = blocked_side_effect
smtplib.SMTP_SSL = blocked_side_effect
os.system = blocked_side_effect
os.popen = blocked_side_effect
subprocess.Popen = blocked_side_effect
subprocess.call = blocked_side_effect
subprocess.check_call = blocked_side_effect
subprocess.check_output = blocked_side_effect
subprocess.run = blocked_side_effect


def require(value, code):
    if not value:
        raise ProbeFailure(code)


def build_app():
    configuration = {
        "APP_VERSION": os.environ["APP_VERSION"],
        "DATABASE_URL": os.environ["DATABASE_URL"],
        "DISABLE_FORCE_HTTPS": True,
        "FLASK_ENV": "testing",
        "FLASK_SECRET_KEY": os.environ["FLASK_SECRET_KEY"],
        "FORCE_HTTPS": False,
        "JWKS_DIR": os.environ["JWKS_DIR"],
        "JWT_ALGORITHM": "RS256",
        "JWT_EXPIRATION_HOURS": 1,
        "JWT_ISSUER": os.environ["JWT_ISSUER"],
        "RATE_LIMIT_ENABLED": False,
        "REDIS_URL": None,
        "SOCKETIO_CORS": "*",
        "TESTING": True,
        "TOKEN_TTL": 3600,
    }
    return create_app(configuration)


def startup_probe():
    from sqlalchemy import text
    from app.database import close_all, session_scope

    application = build_app()
    routes = {rule.rule for rule in application.url_map.iter_rules()}
    required_routes = {
        "/.well-known/openid-configuration",
        "/oauth/authorize",
        "/oauth/introspect",
        "/oauth/jwks.json",
        "/oauth/register",
        "/oauth/token",
    }
    require(required_routes <= routes, "BLUEPRINT_REGISTRATION_MISMATCH")
    with session_scope() as session:
        require(session.execute(text("SELECT 1")).scalar_one() == 1, "DATABASE_QUERYABILITY_FAILED")
        for table in ("oauth_clients", "oauth_codes", "oauth_tokens", "users"):
            session.execute(text(f"SELECT 1 FROM {table} LIMIT 0"))
    require(not side_effect_attempts, "SIDE_EFFECT_ATTEMPTED")
    close_all()
    return ["APPLICATION_STARTUP", "REQUIRED_BLUEPRINT_REGISTRATION", "DISPOSABLE_TARGET_QUERYABILITY"]


def pkce_pair():
    verifier = "synthetic-rehearsal-verifier-000000000000000000000001"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    return verifier, challenge


SYNTHETIC_SUBJECT = "ab" * 32


def admit_synthetic_browser(client):
    from app.services.canonical_oauth_browser_subject import persist_verified_browser_subject

    subject = persist_verified_browser_subject(SYNTHETIC_SUBJECT)
    require(subject == SYNTHETIC_SUBJECT, "SYNTHETIC_SUBJECT_PERSISTENCE_FAILED")
    with client.session_transaction() as state:
        state["logged_in_pubkey"] = subject
        state["login_method"] = "legacy"
        state["access_level"] = "limited"


def authorization_code(client, registration, scope):
    verifier, challenge = pkce_pair()
    admit_synthetic_browser(client)
    response = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "scope": scope,
            "state": "synthetic-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    require(response.status_code == 302, "AUTHORIZATION_CODE_ISSUE_FAILED")
    code = parse_qs(urlsplit(response.location).query).get("code", [None])[0]
    require(isinstance(code, str) and code, "AUTHORIZATION_CODE_MISSING")
    return verifier, code


def auth_probe():
    try:
        from app.services.bearer_credentials import BearerHeaderError, parse_bearer_authorization_header
        from app.services.current_entitlement import resolve_current_entitlement
        from app.services.oauth_bearer_validation import validate_canonical_access_token
    except ImportError as exc:
        raise ProbeBlocked("AUTH_DEPENDENCY_UNAVAILABLE") from exc

    import jwt
    from app.database import close_all, session_scope
    from app.jwks import get_key_by_kid
    from app.models import OAuthToken, User

    application = build_app()
    client = application.test_client()
    safe_redirect = "https://synthetic-client.invalid/callback"
    registration_response = client.post(
        "/oauth/register",
        json={"client_name": "Synthetic Rehearsal Client", "redirect_uris": [safe_redirect]},
    )
    require(registration_response.status_code == 201, "CLIENT_REGISTRATION_FAILED")
    registration = registration_response.get_json()
    require(isinstance(registration, dict), "CLIENT_REGISTRATION_RESPONSE_INVALID")

    unsafe = client.post(
        "/oauth/register",
        json={"client_name": "Synthetic Unsafe Client", "redirect_uris": ["data:text/plain,blocked"]},
    )
    managed = client.post(
        "/oauth/register",
        json={"client_name": "Synthetic Managed Client", "redirect_uris": [safe_redirect], "trust_class": "operator_managed"},
    )
    require(unsafe.status_code == 400 and managed.status_code == 400, "CLIENT_REGISTRATION_VALIDATION_FAILED")

    verifier, challenge = pkce_pair()
    common = {
        "response_type": "code",
        "client_id": registration["client_id"],
        "redirect_uri": safe_redirect,
        "scope": "openid profile self:read",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    admit_synthetic_browser(client)
    mismatched = client.get("/oauth/authorize", query_string={**common, "redirect_uri": "https://mismatch.invalid/callback"})
    missing_pkce = client.get("/oauth/authorize", query_string={key: value for key, value in common.items() if key != "code_challenge"})
    plain_pkce = client.get("/oauth/authorize", query_string={**common, "code_challenge_method": "plain"})
    rejected_scope = client.get("/oauth/authorize", query_string={**common, "scope": "covenant:draft:create"})
    require(mismatched.status_code == 400, "REDIRECT_URI_VALIDATION_FAILED")
    require(missing_pkce.status_code == 400 and plain_pkce.status_code == 400, "PKCE_REQUIREMENT_FAILED")
    require(rejected_scope.status_code == 400, "SCOPE_REJECTION_FAILED")

    verifier, code = authorization_code(client, registration, "openid profile self:read")
    bad_exchange = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": safe_redirect,
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
            "code_verifier": verifier + "x",
        },
    )
    require(bad_exchange.status_code == 400, "BAD_PKCE_VERIFIER_ACCEPTED")
    token_response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": safe_redirect,
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
            "code_verifier": verifier,
        },
    )
    require(token_response.status_code == 200, "TOKEN_ISSUE_FAILED")
    token_payload = token_response.get_json()
    access_token = token_payload.get("access_token") if isinstance(token_payload, dict) else None
    id_token = token_payload.get("id_token") if isinstance(token_payload, dict) else None
    require(isinstance(access_token, str) and access_token, "ACCESS_TOKEN_MISSING")
    require(
        isinstance(id_token, str) and len(id_token.split(".")) == 3,
        "ID_TOKEN_MISSING",
    )
    try:
        id_header = jwt.get_unverified_header(id_token)
        require(
            id_header.get("alg") == "RS256" and isinstance(id_header.get("kid"), str),
            "ID_TOKEN_VALIDATION_FAILED",
        )
        id_signing_key = get_key_by_kid(os.environ["JWKS_DIR"], id_header["kid"])
        require(id_signing_key is not None, "ID_TOKEN_VALIDATION_FAILED")
        id_verification_key = id_signing_key.public_key()
        id_claims = jwt.decode(
            id_token,
            id_verification_key,
            algorithms=["RS256"],
            audience=registration["client_id"],
            issuer=os.environ["JWT_ISSUER"],
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
    except ProbeFailure:
        raise
    except Exception as exc:
        raise ProbeFailure("ID_TOKEN_VALIDATION_FAILED") from exc
    require(id_claims.get("sub") == SYNTHETIC_SUBJECT, "ID_TOKEN_VALIDATION_FAILED")
    reused = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": safe_redirect,
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
            "code_verifier": verifier,
        },
    )
    require(reused.status_code == 400, "AUTHORIZATION_CODE_REUSE_ACCEPTED")

    require(parse_bearer_authorization_header("Bearer " + access_token) == access_token, "BEARER_PARSE_FAILED")
    try:
        parse_bearer_authorization_header("Bearer  " + access_token)
    except BearerHeaderError:
        pass
    else:
        raise ProbeFailure("AMBIGUOUS_BEARER_ACCEPTED")

    with application.app_context():
        principal = validate_canonical_access_token(access_token)
    require(principal.client_id == registration["client_id"], "TOKEN_VALIDATION_FAILED")
    introspection_form = {
        "token": access_token,
        "client_id": registration["client_id"],
        "client_secret": registration["client_secret"],
    }
    active = client.post("/oauth/introspect", data=introspection_form)
    require(active.status_code == 200 and active.get_json().get("active") is True, "TOKEN_INTROSPECTION_FAILED")

    claims = jwt.decode(access_token, options={"verify_signature": False})
    jti = claims["jti"]
    expected_expiration = datetime.fromtimestamp(claims["exp"], timezone.utc).replace(tzinfo=None)
    with session_scope() as session:
        record = session.query(OAuthToken).filter_by(id=jti).one()
        record.is_revoked = True
    revoked = client.post("/oauth/introspect", data=introspection_form)
    require(revoked.get_json().get("active") is False, "REVOKED_TOKEN_ACCEPTED")
    with session_scope() as session:
        record = session.query(OAuthToken).filter_by(id=jti).one()
        record.is_revoked = False
        record.access_token_expires_at = datetime.fromtimestamp(1, timezone.utc).replace(tzinfo=None)
    expired = client.post("/oauth/introspect", data=introspection_form)
    require(expired.get_json().get("active") is False, "EXPIRED_TOKEN_ACCEPTED")
    with session_scope() as session:
        record = session.query(OAuthToken).filter_by(id=jti).one()
        record.access_token_expires_at = expected_expiration
        user = session.query(User).filter_by(id=record.user_id).one()
        user.is_active = False
    inactive = client.post("/oauth/introspect", data=introspection_form)
    require(inactive.get_json().get("active") is False, "INACTIVE_USER_TOKEN_ACCEPTED")
    with session_scope() as session:
        record = session.query(OAuthToken).filter_by(id=jti).one()
        user = session.query(User).filter_by(id=record.user_id).one()
        user.is_active = True
        subject = user.pubkey
    with application.app_context():
        entitlement = resolve_current_entitlement(subject)
    require(str(entitlement.identity_class.value).lower() == "limited", "LIMITED_ENTITLEMENT_MISMATCH")
    require(entitlement.current_full_relation_satisfied is False, "CRT_FULL_GRANTED_BY_REHEARSAL")
    require(not side_effect_attempts, "SIDE_EFFECT_ATTEMPTED")
    close_all()
    return [
        "APPLICATION_STARTUP",
        "BLUEPRINT_REGISTRATION",
        "OAUTH_CLIENT_REGISTRATION_VALIDATION",
        "REDIRECT_URI_VALIDATION",
        "PKCE_REQUIREMENTS",
        "SCOPE_POLICY",
        "AUTHORIZATION_CODE_ONE_TIME_CONSUMPTION",
        "TOKEN_ISSUE",
        "BEARER_PARSING",
        "TOKEN_VALIDATION",
        "TOKEN_INTROSPECTION",
        "REVOKED_OR_EXPIRED_TOKEN_REJECTION",
        "INACTIVE_USER_REJECTION",
        "EXACT_LIMITED_ENTITLEMENT",
        "NO_CRT_FULL_FROM_REHEARSAL_METADATA",
    ]


with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
    try:
        try:
            import requests

            requests.sessions.Session.request = blocked_side_effect
        except ImportError:
            pass

        try:
            import redis

            def redis_disabled(*_args, **_kwargs):
                raise redis.exceptions.ConnectionError("rehearsal-disabled")

            redis.Redis.ping = redis_disabled
            redis.client.Redis.ping = redis_disabled
        except ImportError:
            pass

        import app.utils

        app.utils.get_rpc_connection = blocked_side_effect

        from app.factory import create_app

        mode = sys.argv[1]
        evidence = startup_probe() if mode == "startup" else auth_probe() if mode == "auth" else None
        if evidence is None:
            raise ProbeBlocked("UNKNOWN_PROBE_MODE")
        probe_payload = {"status": "PASS", "evidence_codes": evidence}
        probe_returncode = 0
    except ProbeBlocked as exc:
        probe_payload = {"status": "BLOCKED", "evidence_code": exc.code}
        probe_returncode = 3
    except (ImportError, ModuleNotFoundError):
        probe_payload = {"status": "BLOCKED", "evidence_code": "PROBE_DEPENDENCY_UNAVAILABLE"}
        probe_returncode = 3
    except ProbeFailure as exc:
        probe_payload = {"status": "FAIL", "evidence_code": exc.code}
        probe_returncode = 4
    except Exception:
        probe_payload = {"status": "FAIL", "evidence_code": "UNCLASSIFIED_PROBE_FAILURE"}
        probe_returncode = 4
    except SystemExit:
        probe_payload = {"status": "FAIL", "evidence_code": "UNCLASSIFIED_PROBE_FAILURE"}
        probe_returncode = 4
    except KeyboardInterrupt:
        probe_payload = {"status": "FAIL", "evidence_code": "UNCLASSIFIED_PROBE_FAILURE"}
        probe_returncode = 4
    except BaseException:
        probe_payload = {"status": "FAIL", "evidence_code": "UNCLASSIFIED_PROBE_FAILURE"}
        probe_returncode = 4

sys.stdout.write(json.dumps(probe_payload, sort_keys=True, separators=(",", ":")) + "\n")
raise SystemExit(probe_returncode)
"""


def _postgres_environment(state: ExecutionState) -> dict[str, str]:
    if state.guard is None:
        raise SafetyViolation("OWNED_WORKSPACE_REQUIRED")
    state.guard.assert_owned()
    home = state.guard.workspace / "home"
    temporary = state.guard.workspace / "tmp"
    home.mkdir(mode=0o700, exist_ok=True)
    temporary.mkdir(mode=0o700, exist_ok=True)
    return {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PGCONNECT_TIMEOUT": "5",
        "PGSSLMODE": "disable",
        "TMPDIR": str(temporary),
    }


def _socket_directory(state: ExecutionState) -> Path:
    if state.guard is None:
        raise SafetyViolation("OWNED_WORKSPACE_REQUIRED")
    return state.guard.workspace / "socket"


def _cluster_directory(state: ExecutionState) -> Path:
    if state.guard is None:
        raise SafetyViolation("OWNED_WORKSPACE_REQUIRED")
    return state.guard.workspace / "cluster"


def _pg_connection_arguments(state: ExecutionState) -> list[str]:
    return [
        "--host",
        str(_socket_directory(state)),
        "--port",
        REHEARSAL_PORT,
        "--username",
        REHEARSAL_ROLE,
        "--no-password",
    ]


def _internal_database_url(state: ExecutionState, target: str) -> str:
    validate_database_target(target)
    query = urlencode({"host": str(_socket_directory(state)), "port": REHEARSAL_PORT})
    value = f"postgresql+psycopg2://{REHEARSAL_ROLE}@/{quote(target, safe='')}?{query}"
    parsed = urlsplit(value)
    parameters = parse_qs(parsed.query)
    if (
        parsed.password is not None
        or parsed.hostname is not None
        or parsed.username != REHEARSAL_ROLE
        or parameters.get("host") != [str(_socket_directory(state))]
    ):
        raise SafetyViolation("INTERNAL_UNIX_DSN_INVALID")
    return value


def _application_environment(state: ExecutionState, snapshot: Path, target: str) -> dict[str, str]:
    if state.guard is None or state.jwks_directory is None:
        raise SafetyViolation("APPLICATION_PROBE_WORKSPACE_INCOMPLETE")
    state.guard.assert_owned()
    environment = {
        "APP_VERSION": "1.0.0-beta",
        "DATABASE_URL": _internal_database_url(state, target),
        "DISABLE_FORCE_HTTPS": "1",
        "FLASK_ENV": "testing",
        "FLASK_SECRET_KEY": "synthetic-rehearsal-flask-key-v1",
        "HOME": str(state.guard.workspace / "home"),
        "JWKS_DIR": str(state.jwks_directory),
        "JWT_ALGORITHM": "RS256",
        "JWT_ISSUER": "https://rehearsal.invalid",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(snapshot),
        "RATE_LIMIT_ENABLED": "false",
        "TESTING": "1",
        "TMPDIR": str(state.guard.workspace / "tmp"),
    }
    if tuple(environment) != APPLICATION_ENVIRONMENT_KEYS:
        raise SafetyViolation("APPLICATION_ENVIRONMENT_ALLOWLIST_MISMATCH")
    return environment


def _parse_probe_payload(output: str) -> Mapping[str, object]:
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        raise CommandFailure("PROBE_RESULT_MISSING")
    try:
        payload = json.loads(lines[-1], object_pairs_hook=_no_duplicate_keys)
    except Exception as exc:
        raise CommandFailure("PROBE_RESULT_INVALID") from exc
    if not isinstance(payload, dict) or set(payload) not in (
        {"status", "evidence_codes"},
        {"status", "evidence_code"},
    ):
        raise CommandFailure("PROBE_RESULT_SCHEMA_INVALID")
    return payload


def _run_application_probe(
    runner: CommandRunner,
    state: ExecutionState,
    *,
    snapshot: Path,
    target: str,
    mode: str,
) -> PhaseOutcome:
    if mode not in {"startup", "auth"}:
        raise SafetyViolation("UNKNOWN_PROBE_MODE")
    result = runner.run(
        [str(state.resolved.tools.python), "-c", PROBE_PROGRAM, mode],
        cwd=snapshot,
        env=_application_environment(state, snapshot, target),
        timeout=300,
    )
    if not result.stdout.strip() and result.returncode != 0:
        if result.returncode == 3:
            return PhaseOutcome(
                "BLOCKED",
                "PROBE_PROCESS_BLOCKED",
                DETAILS["PROBE_BLOCKED"],
                unsupported=True,
            )
        return PhaseOutcome("FAIL", "PROBE_PROCESS_FAILED", DETAILS["PROBE_FAILED"])
    payload = _parse_probe_payload(result.stdout)
    status = payload.get("status")
    if status == "PASS" and result.returncode == 0:
        codes = payload.get("evidence_codes")
        required_codes = AUTH_PROBE_EVIDENCE if mode == "auth" else STARTUP_PROBE_EVIDENCE
        if not isinstance(codes, list) or tuple(codes) != required_codes:
            raise CommandFailure("PROBE_EVIDENCE_INVALID")
        evidence_code = "AUTH_PROBE_COMPLETE" if mode == "auth" else "STARTUP_PROBE_COMPLETE"
        return PhaseOutcome("PASS", evidence_code, DETAILS[evidence_code])
    evidence = payload.get("evidence_code")
    if not isinstance(evidence, str) or not re.fullmatch(r"[A-Z0-9_]+", evidence):
        evidence = "PROBE_RESULT_INVALID"
    if status == "BLOCKED":
        return PhaseOutcome("BLOCKED", evidence, DETAILS["PROBE_BLOCKED"], unsupported=True)
    return PhaseOutcome("FAIL", evidence, DETAILS["PROBE_FAILED"])


def _psql(
    runner: CommandRunner,
    state: ExecutionState,
    target: str,
    *,
    sql: str | None = None,
    file_path: Path | None = None,
    evidence_code: str,
    timeout: int = 300,
) -> CommandResult:
    validate_database_target(target)
    if (sql is None) == (file_path is None):
        raise ValueError("exactly one psql input is required")
    argv = [
        str(state.resolved.tools.postgresql["psql"]),
        "-X",
        "--quiet",
        "--set=ON_ERROR_STOP=1",
        *_pg_connection_arguments(state),
        "--dbname",
        target,
    ]
    if sql is not None:
        argv.extend(["--tuples-only", "--no-align", "--command", sql])
    else:
        if file_path is None or not file_path.is_file() or file_path.is_symlink():
            raise SafetyViolation("SQL_INPUT_INVALID")
        argv.extend(["--file", str(file_path)])
    return _checked(
        runner,
        argv,
        cwd=state.guard.workspace if state.guard else state.resolved.temporary_root,
        env=_postgres_environment(state),
        evidence_code=evidence_code,
        timeout=timeout,
    )


def _createdb(runner: CommandRunner, state: ExecutionState, target: str) -> None:
    validate_database_target(target)
    _checked(
        runner,
        [
            str(state.resolved.tools.postgresql["createdb"]),
            *_pg_connection_arguments(state),
            "--template",
            "template0",
            target,
        ],
        cwd=state.guard.workspace if state.guard else state.resolved.temporary_root,
        env=_postgres_environment(state),
        evidence_code="DISPOSABLE_DATABASE_CREATE_FAILED",
        timeout=120,
    )


def _sql_string(value: str) -> str:
    if not SAFE_IDENTIFIER.fullmatch(value):
        raise SafetyViolation("CATALOG_IDENTIFIER_INVALID")
    return "'" + value + "'"


def _query_expected_set(
    runner: CommandRunner,
    state: ExecutionState,
    target: str,
    *,
    sql: str,
    expected: set[str],
    evidence_code: str,
) -> None:
    result = _psql(runner, state, target, sql=sql, evidence_code=evidence_code)
    actual = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    if actual != expected:
        raise CommandFailure(evidence_code)


def _verify_baseline_catalog(runner: CommandRunner, state: ExecutionState) -> None:
    if state.primary_target is None:
        raise SafetyViolation("PRIMARY_TARGET_MISSING")
    baseline = state.plan["synthetic_baseline"]
    if not isinstance(baseline, dict) or not isinstance(baseline.get("tables"), list):
        raise PlanContractError("baseline catalog missing")
    tables = {str(item["table"]) for item in baseline["tables"]}
    columns = {f"{item['table']}.{column}" for item in baseline["tables"] for column in item["columns"]}
    constraints = {str(item["primary_key"]) for item in baseline["tables"]} | {
        str(name) for item in baseline["tables"] for name in item["foreign_keys"]
    }
    indexes = {str(name) for item in baseline["tables"] for name in item["indexes"]}
    table_literals = ",".join(_sql_string(name) for name in sorted(tables))
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT table_name FROM information_schema.tables "
            f"WHERE table_schema='public' AND table_name IN ({table_literals}) ORDER BY table_name;"
        ),
        expected=tables,
        evidence_code="BASELINE_TABLE_CATALOG_MISMATCH",
    )
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT table_name||'.'||column_name FROM information_schema.columns "
            f"WHERE table_schema='public' AND table_name IN ({table_literals}) ORDER BY 1;"
        ),
        expected=columns,
        evidence_code="BASELINE_COLUMN_CATALOG_MISMATCH",
    )
    constraint_literals = ",".join(_sql_string(name) for name in sorted(constraints))
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=f"SELECT conname FROM pg_constraint WHERE conname IN ({constraint_literals}) ORDER BY conname;",
        expected=constraints,
        evidence_code="BASELINE_CONSTRAINT_CATALOG_MISMATCH",
    )
    index_literals = ",".join(_sql_string(name) for name in sorted(indexes))
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT indexname FROM pg_indexes "
            f"WHERE schemaname='public' AND indexname IN ({index_literals}) ORDER BY indexname;"
        ),
        expected=indexes,
        evidence_code="BASELINE_INDEX_CATALOG_MISMATCH",
    )


def _matching_parenthesis(text: str, opening: int) -> int:
    depth = 0
    quoted = False
    index = opening
    while index < len(text):
        character = text[index]
        if character == "'":
            if quoted and index + 1 < len(text) and text[index + 1] == "'":
                index += 2
                continue
            quoted = not quoted
        elif not quoted:
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    raise PlanContractError("unbalanced CREATE TABLE statement")


def _split_sql_definitions(body: str) -> list[str]:
    definitions: list[str] = []
    depth = 0
    quoted = False
    start = 0
    index = 0
    while index < len(body):
        character = body[index]
        if character == "'":
            if quoted and index + 1 < len(body) and body[index + 1] == "'":
                index += 2
                continue
            quoted = not quoted
        elif not quoted:
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            elif character == "," and depth == 0:
                definitions.append(body[start:index].strip())
                start = index + 1
        index += 1
    definitions.append(body[start:].strip())
    return [definition for definition in definitions if definition]


def _migration_catalog_contract(snapshot: Path) -> tuple[set[str], set[str], set[str], set[str]]:
    tables: set[str] = set()
    columns: set[str] = set()
    constraints: set[str] = set()
    indexes: set[str] = set()
    create_table = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z][a-z0-9_]*)\s*\(", re.I)
    for relative in MIGRATIONS:
        path = snapshot / relative
        text = path.read_text(encoding="utf-8")
        for match in create_table.finditer(text):
            table = match.group(1).lower()
            if not SAFE_IDENTIFIER.fullmatch(table):
                raise PlanContractError("invalid migration table identifier")
            tables.add(table)
            opening = text.find("(", match.start())
            closing = _matching_parenthesis(text, opening)
            for definition in _split_sql_definitions(text[opening + 1 : closing]):
                if re.match(r"^(CONSTRAINT|CHECK|UNIQUE|PRIMARY|FOREIGN)\b", definition, re.I):
                    continue
                column_match = re.match(r'^"?([a-z][a-z0-9_]*)"?\s+', definition, re.I)
                if column_match:
                    columns.add(f"{table}.{column_match.group(1).lower()}")
                    if re.search(r"\bPRIMARY\s+KEY\b", definition, re.I):
                        constraints.add(f"{table}_pkey")
                        indexes.add(f"{table}_pkey")
        constraints.update(
            match.group(1).lower() for match in re.finditer(r"\bCONSTRAINT\s+([a-z][a-z0-9_]*)", text, re.I)
        )
        indexes.update(
            match.group(1).lower()
            for match in re.finditer(
                r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z][a-z0-9_]*)",
                text,
                re.I,
            )
        )
    return tables, columns, constraints, indexes


def _migration_named_constraint_contract(snapshot: Path) -> set[str]:
    """Return table-qualified names for every declared named constraint."""

    expected: set[str] = set()
    create_table = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z][a-z0-9_]*)\s*\(", re.I)
    alter_constraint = re.compile(
        r"\bALTER\s+TABLE\s+([a-z][a-z0-9_]*)\s+ADD\s+CONSTRAINT\s+([a-z][a-z0-9_]*)",
        re.I,
    )
    for relative in MIGRATIONS:
        text = (snapshot / relative).read_text(encoding="utf-8")
        for match in create_table.finditer(text):
            table = match.group(1).lower()
            opening = text.find("(", match.start())
            closing = _matching_parenthesis(text, opening)
            body = text[opening + 1 : closing]
            for constraint in re.finditer(r"\bCONSTRAINT\s+([a-z][a-z0-9_]*)", body, re.I):
                expected.add(f"{table}|{constraint.group(1).lower()}")
            for definition in _split_sql_definitions(body):
                if not re.match(r"^CONSTRAINT\b", definition, re.I) and re.search(
                    r"\bPRIMARY\s+KEY\b", definition, re.I
                ):
                    expected.add(f"{table}|{table}_pkey")
        for constraint in alter_constraint.finditer(text):
            expected.add(f"{constraint.group(1).lower()}|{constraint.group(2).lower()}")
    return expected


def _migration_check_constraint_counts(snapshot: Path) -> set[str]:
    """Return exact per-table CHECK counts, including unnamed inline checks."""

    expected: set[str] = set()
    create_table = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z][a-z0-9_]*)\s*\(", re.I)
    for relative in MIGRATIONS:
        text = (snapshot / relative).read_text(encoding="utf-8")
        for match in create_table.finditer(text):
            table = match.group(1).lower()
            opening = text.find("(", match.start())
            closing = _matching_parenthesis(text, opening)
            count = len(re.findall(r"\bCHECK\s*\(", text[opening + 1 : closing], re.I))
            expected.add(f"{table}|{count}")
    return expected


def _migration_explicit_index_contract(snapshot: Path) -> set[str]:
    """Return table-qualified explicit index identities from the nine files."""

    expected: set[str] = set()
    create_index = re.compile(
        r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?" r"([a-z][a-z0-9_]*)\s+ON\s+([a-z][a-z0-9_]*)",
        re.I,
    )
    for relative in MIGRATIONS:
        text = (snapshot / relative).read_text(encoding="utf-8")
        for match in create_index.finditer(text):
            expected.add(f"{match.group(2).lower()}|{match.group(1).lower()}")
    return expected


PG_NODE_TREE_LOCATION_PATTERN = r"(^|[ {])(:location )-?[0-9]+(?=[ }])"
PG_NODE_TREE_LOCATION_REPLACEMENT = r"\1\2-1"


def _normalized_pg_node_tree_sql(operand: str) -> str:
    """Canonicalize only parser-location metadata in a pg_node_tree operand."""

    return (
        f"regexp_replace({operand}::text,"
        f"'{PG_NODE_TREE_LOCATION_PATTERN}',"
        f"'{PG_NODE_TREE_LOCATION_REPLACEMENT}','g')"
    )


def _migration_8_9_check_semantics_sql(snapshot: Path) -> str:
    """Build a PostgreSQL parse-tree comparison against the two immutable files."""

    tables = {
        "canonical_root_registration_bindings": "phase_6_root_checks",
        "canonical_covenant_funding_sets": "phase_6_funding_set_checks",
        "canonical_covenant_funding_outpoints": "phase_6_funding_outpoint_checks",
    }
    statements = ["/* PHASE_6_CHECK_SEMANTICS_V1 */", "BEGIN;"]
    for table, probe in tables.items():
        statements.append(f"CREATE TEMP TABLE {probe} (LIKE public.{table});")
    create_table = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z][a-z0-9_]*)\s*\(", re.I
    )
    for relative in MIGRATIONS[-2:]:
        text = (snapshot / relative).read_text(encoding="utf-8")
        for match in create_table.finditer(text):
            table = match.group(1).lower()
            if table not in tables:
                continue
            opening = text.find("(", match.start())
            closing = _matching_parenthesis(text, opening)
            for definition in _split_sql_definitions(text[opening + 1 : closing]):
                named = re.search(r"\bCONSTRAINT\s+([a-z][a-z0-9_]*)\s+CHECK\s*\(", definition, re.I)
                if named is None:
                    continue
                name = named.group(1).lower()
                if not SAFE_IDENTIFIER.fullmatch(name):
                    raise PlanContractError("invalid migration constraint identifier")
                check_opening = definition.find("(", named.start())
                check_closing = _matching_parenthesis(definition, check_opening)
                check_definition = definition[named.start() : check_closing + 1]
                statements.append(f"ALTER TABLE {tables[table]} ADD {check_definition};")
    statements.append(
        "SELECT actual_table.relname||'|'||actual_constraint.conname||'|'||"
        "COALESCE((SELECT string_agg(attribute.attname,',' ORDER BY attribute.attname) "
        "FROM unnest(actual_constraint.conkey) AS key(attnum) "
        "JOIN pg_attribute attribute ON attribute.attrelid=actual_constraint.conrelid "
        "AND attribute.attnum=key.attnum),'') FROM pg_constraint actual_constraint "
        "JOIN pg_class actual_table ON actual_table.oid=actual_constraint.conrelid "
        "JOIN pg_namespace actual_namespace ON actual_namespace.oid=actual_table.relnamespace "
        "JOIN (VALUES "
        + ",".join(
            f"('{table}','{probe}')" for table, probe in tables.items()
        )
        + ") AS mapping(actual_table_name,probe_table_name) ON mapping.actual_table_name=actual_table.relname "
        "JOIN pg_class probe_table ON probe_table.relname=mapping.probe_table_name "
        "AND probe_table.relnamespace=pg_my_temp_schema() "
        "JOIN pg_constraint probe_constraint ON probe_constraint.conrelid=probe_table.oid "
        "AND probe_constraint.conname=actual_constraint.conname "
        "WHERE actual_namespace.nspname='public' AND actual_constraint.contype='c' "
        "AND "
        + _normalized_pg_node_tree_sql("actual_constraint.conbin")
        + "="
        + _normalized_pg_node_tree_sql("probe_constraint.conbin")
        + " ORDER BY 1;"
    )
    statements.append("ROLLBACK;")
    return "\n".join(statements)


PHASE_6_INDEX_SEMANTICS_SQL = f"""
/* PHASE_6_INDEX_SEMANTICS_V1 */
BEGIN;
CREATE TEMP TABLE phase_6_root_indexes (LIKE public.canonical_root_registration_bindings);
CREATE TEMP TABLE phase_6_funding_set_indexes (LIKE public.canonical_covenant_funding_sets);
CREATE UNIQUE INDEX phase_6_root_effective_reference
  ON phase_6_root_indexes (graph_or_protocol_id, root_x_only_public_key)
  WHERE lifecycle_state = 'effective';
CREATE UNIQUE INDEX phase_6_funding_set_effective_reference
  ON phase_6_funding_set_indexes (trusted_registration_id)
  WHERE lifecycle_state = 'effective';
SELECT table_relation.relname||'|'||index_relation.relname||'|'||index_catalog.indisunique::text||'|'||
       COALESCE((SELECT string_agg(attribute.attname,',' ORDER BY key.ordinality)
                 FROM unnest(index_catalog.indkey) WITH ORDINALITY AS key(attnum,ordinality)
                 JOIN pg_attribute attribute ON attribute.attrelid=index_catalog.indrelid
                                             AND attribute.attnum=key.attnum
                 WHERE key.ordinality <= index_catalog.indnkeyatts),'')||'|'||
       CASE
         WHEN mapping.reference_index_name IS NULL AND index_catalog.indpred IS NULL THEN 'none'
         WHEN reference_catalog.indpred IS NOT NULL
              AND {_normalized_pg_node_tree_sql("index_catalog.indpred")}
                  ={_normalized_pg_node_tree_sql("reference_catalog.indpred")} THEN 'partial'
         ELSE 'mismatch'
       END
FROM pg_index index_catalog
JOIN pg_class index_relation ON index_relation.oid=index_catalog.indexrelid
JOIN pg_class table_relation ON table_relation.oid=index_catalog.indrelid
JOIN pg_namespace table_namespace ON table_namespace.oid=table_relation.relnamespace
JOIN (VALUES
  ('idx_root_registration_binding_graph_root',NULL),
  ('idx_root_registration_binding_registration',NULL),
  ('uq_root_registration_binding_effective_root','phase_6_root_effective_reference'),
  ('idx_funding_set_registration',NULL),
  ('uq_funding_set_effective_registration','phase_6_funding_set_effective_reference'),
  ('idx_funding_outpoint_set',NULL)
) AS mapping(actual_index_name,reference_index_name)
  ON mapping.actual_index_name=index_relation.relname
LEFT JOIN pg_class reference_index
  ON reference_index.relname=mapping.reference_index_name
 AND reference_index.relnamespace=pg_my_temp_schema()
LEFT JOIN pg_index reference_catalog ON reference_catalog.indexrelid=reference_index.oid
WHERE table_namespace.nspname='public'
ORDER BY 1;
ROLLBACK;
"""


def _verify_migrated_catalog(runner: CommandRunner, state: ExecutionState) -> None:
    if state.primary_target is None or state.staging_snapshot is None:
        raise SafetyViolation("MIGRATED_CATALOG_STATE_INCOMPLETE")
    tables, columns, _constraints, _indexes = _migration_catalog_contract(state.staging_snapshot)
    named_constraints = _migration_named_constraint_contract(state.staging_snapshot)
    check_counts = _migration_check_constraint_counts(state.staging_snapshot)
    explicit_indexes = _migration_explicit_index_contract(state.staging_snapshot)
    relational_tables = {item.split("|", 1)[0] for item in MIGRATION_RELATIONAL_CONSTRAINTS}
    if relational_tables != tables:
        raise PlanContractError("relational constraint contract does not cover every migrated table")
    table_literals = ",".join(_sql_string(name) for name in sorted(tables))
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT table_name FROM information_schema.tables "
            f"WHERE table_schema='public' AND table_name IN ({table_literals}) ORDER BY table_name;"
        ),
        expected=tables,
        evidence_code="MIGRATED_TABLE_CATALOG_MISMATCH",
    )
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT table_name||'.'||column_name FROM information_schema.columns "
            f"WHERE table_schema='public' AND table_name IN ({table_literals}) ORDER BY 1;"
        ),
        expected=columns,
        evidence_code="MIGRATED_COLUMN_CATALOG_MISMATCH",
    )
    constraint_names = {item.split("|", 1)[1] for item in named_constraints}
    constraint_literals = ",".join(_sql_string(name) for name in sorted(constraint_names))
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT r.relname||'|'||c.conname FROM pg_constraint c "
            "JOIN pg_class r ON r.oid=c.conrelid "
            "JOIN pg_namespace n ON n.oid=r.relnamespace "
            f"WHERE n.nspname='public' AND r.relname IN ({table_literals}) "
            f"AND c.conname IN ({constraint_literals}) ORDER BY 1;"
        ),
        expected=named_constraints,
        evidence_code="MIGRATED_CONSTRAINT_CATALOG_MISMATCH",
    )
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT r.relname||'|'||c.contype::text||'|'||"
            "COALESCE((SELECT string_agg(a.attname,',' ORDER BY k.ordinality) "
            "FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality) "
            "JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum),'')||'|'||"
            "CASE WHEN c.contype='f' THEN rr.relname ELSE '' END||'|'||"
            "CASE WHEN c.contype='f' THEN COALESCE((SELECT string_agg(a.attname,',' ORDER BY k.ordinality) "
            "FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum,ordinality) "
            "JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum),'') ELSE '' END||'|'||"
            "CASE WHEN c.contype='f' THEN c.confdeltype::text ELSE '' END "
            "FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid "
            "JOIN pg_namespace n ON n.oid=r.relnamespace "
            "LEFT JOIN pg_class rr ON rr.oid=c.confrelid "
            f"WHERE n.nspname='public' AND r.relname IN ({table_literals}) "
            "AND c.contype IN ('p','u','f') ORDER BY 1;"
        ),
        expected=set(MIGRATION_RELATIONAL_CONSTRAINTS),
        evidence_code="MIGRATED_RELATIONAL_CONSTRAINT_MISMATCH",
    )
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT r.relname||'|'||count(*)::text FROM pg_constraint c "
            "JOIN pg_class r ON r.oid=c.conrelid "
            "JOIN pg_namespace n ON n.oid=r.relnamespace "
            f"WHERE n.nspname='public' AND r.relname IN ({table_literals}) AND c.contype='c' "
            "GROUP BY r.relname ORDER BY r.relname;"
        ),
        expected=check_counts,
        evidence_code="MIGRATED_CHECK_CONSTRAINT_COUNT_MISMATCH",
    )
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=_migration_8_9_check_semantics_sql(state.staging_snapshot),
        expected=set(MIGRATION_8_9_CHECK_SEMANTICS),
        evidence_code="MIGRATED_CHECK_SEMANTICS_MISMATCH",
    )
    index_names = {item.split("|", 1)[1] for item in explicit_indexes}
    index_literals = ",".join(_sql_string(name) for name in sorted(index_names))
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT tablename||'|'||indexname FROM pg_indexes "
            f"WHERE schemaname='public' AND tablename IN ({table_literals}) "
            f"AND indexname IN ({index_literals}) ORDER BY 1;"
        ),
        expected=explicit_indexes,
        evidence_code="MIGRATED_INDEX_CATALOG_MISMATCH",
    )
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=PHASE_6_INDEX_SEMANTICS_SQL,
        expected=set(MIGRATION_8_9_INDEX_SEMANTICS),
        evidence_code="MIGRATED_INDEX_SEMANTICS_MISMATCH",
    )
    _query_expected_set(
        runner,
        state,
        state.primary_target,
        sql=(
            "SELECT tbl.relname||'|'||a.attname||'|'||format_type(a.atttypid,a.atttypmod)||'|'||"
            "COALESCE(pg_get_expr(d.adbin,d.adrelid),'')||'|'||COALESCE(seq.relname,'')||'|'||"
            "COALESCE(owner.relname,'')||'|'||COALESCE(owner_col.attname,'') "
            "FROM pg_class tbl JOIN pg_namespace n ON n.oid=tbl.relnamespace "
            "JOIN pg_attribute a ON a.attrelid=tbl.oid AND a.attname='id' "
            "LEFT JOIN pg_attrdef d ON d.adrelid=tbl.oid AND d.adnum=a.attnum "
            "LEFT JOIN pg_depend dep ON dep.refobjid=tbl.oid AND dep.refobjsubid=a.attnum "
            "AND dep.deptype='a' LEFT JOIN pg_class seq ON seq.oid=dep.objid AND seq.relkind='S' "
            "LEFT JOIN pg_class owner ON owner.oid=dep.refobjid "
            "LEFT JOIN pg_attribute owner_col ON owner_col.attrelid=dep.refobjid AND owner_col.attnum=dep.refobjsubid "
            "WHERE n.nspname='public' AND tbl.relname='canonical_covenant_funding_outpoints' ORDER BY 1;"
        ),
        expected=set(MIGRATION_8_9_SERIAL_SEMANTICS),
        evidence_code="MIGRATED_SERIAL_SEMANTICS_MISMATCH",
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_schema(value: str) -> str:
    lines = [line for line in value.splitlines() if not re.match(r"^\\(?:un)?restrict(?:\s|$)", line)]
    return "\n".join(lines).strip() + "\n"


# Phase 11 compares one deterministic JSON row per catalog object. JSON avoids
# delimiter ambiguity in catalog expressions, while the explicit ORDER BY makes
# byte equality a sound comparison of these catalog-derived identities.
PHASE_11_RELATION_INVENTORY_SQL = """
/* PHASE_11_RELATION_INVENTORY_V1 */
SELECT jsonb_build_array(
         n.nspname,
         c.relname,
         c.relkind::text,
         c.relpersistence::text,
         c.relispartition
       )::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname <> 'information_schema'
  AND n.nspname !~ '^pg_'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'c')
ORDER BY n.nspname, c.relname, c.relkind;
"""


PHASE_11_COLUMN_SEMANTICS_SQL = """
/* PHASE_11_COLUMN_SEMANTICS_V1 */
SELECT jsonb_build_array(
         n.nspname,
         c.relname,
         a.attnum,
         a.attname,
         tn.nspname,
         t.typname,
         format_type(a.atttypid, a.atttypmod),
         a.attnotnull,
         a.attidentity::text,
         a.attgenerated::text,
         pg_get_expr(d.adbin, d.adrelid, false),
         CASE
           WHEN a.attcollation = 0 THEN NULL
           ELSE jsonb_build_array(cn.nspname, coll.collname)
         END
       )::text
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_type t ON t.oid = a.atttypid
JOIN pg_namespace tn ON tn.oid = t.typnamespace
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
LEFT JOIN pg_collation coll ON coll.oid = a.attcollation
LEFT JOIN pg_namespace cn ON cn.oid = coll.collnamespace
WHERE n.nspname <> 'information_schema'
  AND n.nspname !~ '^pg_'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'c')
  AND a.attnum > 0
  AND NOT a.attisdropped
ORDER BY n.nspname, c.relname, a.attnum;
"""


PHASE_11_CONSTRAINT_SEMANTICS_SQL = """
/* PHASE_11_CONSTRAINT_SEMANTICS_V1 */
SELECT jsonb_build_array(
         n.nspname,
         r.relname,
         con.conname,
         con.contype::text,
         COALESCE(
           ARRAY(
             SELECT a.attname::text
             FROM unnest(con.conkey) WITH ORDINALITY AS key(attnum, position)
             JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = key.attnum
             ORDER BY key.position
           ),
           ARRAY[]::text[]
         ),
         rn.nspname,
         rr.relname,
         COALESCE(
           ARRAY(
             SELECT a.attname::text
             FROM unnest(con.confkey) WITH ORDINALITY AS key(attnum, position)
             JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = key.attnum
             ORDER BY key.position
           ),
           ARRAY[]::text[]
         ),
         CASE WHEN con.contype = 'f' THEN con.confdeltype::text END,
         CASE WHEN con.contype = 'f' THEN con.confupdtype::text END,
         CASE WHEN con.contype = 'f' THEN con.confmatchtype::text END,
         con.condeferrable,
         con.condeferred,
         con.convalidated,
         con.connoinherit,
         con.conislocal,
         con.coninhcount,
         pn.nspname,
         pr.relname,
         parent.conname
       )::text
FROM pg_constraint con
JOIN pg_class r ON r.oid = con.conrelid
JOIN pg_namespace n ON n.oid = r.relnamespace
LEFT JOIN pg_class rr ON rr.oid = con.confrelid
LEFT JOIN pg_namespace rn ON rn.oid = rr.relnamespace
LEFT JOIN pg_constraint parent ON parent.oid = con.conparentid
LEFT JOIN pg_class pr ON pr.oid = parent.conrelid
LEFT JOIN pg_namespace pn ON pn.oid = pr.relnamespace
WHERE n.nspname <> 'information_schema'
  AND n.nspname !~ '^pg_'
  AND r.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY n.nspname, r.relname, con.conname;
"""


# A CHECK definition is deparsed by PostgreSQL, installed on an empty temporary
# clone, and deparsed again. This reproduces PostgreSQL's own dump/restore parse
# boundary and yields a stable catalog identity for equivalent ARRAY cast forms.
# No expression is removed or rewritten by Python.
PHASE_11_CHECK_SEMANTICS_SQL = """
/* PHASE_11_CHECK_SEMANTICS_V1 */
BEGIN;
SET LOCAL search_path = pg_catalog, public;
CREATE TEMP TABLE phase_11_check_semantics (
  schema_name text NOT NULL,
  relation_name text NOT NULL,
  constraint_name text NOT NULL,
  canonical_definition text NOT NULL
) ON COMMIT DROP;
DO $phase_11_check$
DECLARE
  item record;
  canonical_definition text;
BEGIN
  FOR item IN
    SELECT con.oid AS constraint_oid,
           n.nspname AS schema_name,
           r.relname AS relation_name,
           con.conname AS constraint_name
    FROM pg_constraint con
    JOIN pg_class r ON r.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = r.relnamespace
    WHERE con.contype = 'c'
      AND n.nspname <> 'information_schema'
      AND n.nspname !~ '^pg_'
      AND r.relkind IN ('r', 'p', 'v', 'm', 'f')
    ORDER BY n.nspname, r.relname, con.conname
  LOOP
    EXECUTE format(
      'CREATE TEMP TABLE pg_temp.phase_11_check_probe (LIKE %I.%I)',
      item.schema_name,
      item.relation_name
    );
    EXECUTE format(
      'ALTER TABLE pg_temp.phase_11_check_probe ADD CONSTRAINT %I %s',
      item.constraint_name,
      pg_get_constraintdef(item.constraint_oid, false)
    );
    SELECT pg_get_constraintdef(probe.oid, false)
      INTO canonical_definition
    FROM pg_constraint probe
    JOIN pg_class probe_relation ON probe_relation.oid = probe.conrelid
    WHERE probe_relation.relnamespace = pg_my_temp_schema()
      AND probe_relation.relname = 'phase_11_check_probe'
      AND probe.conname = item.constraint_name;
    IF canonical_definition IS NULL THEN
      RAISE EXCEPTION 'temporary CHECK constraint identity missing';
    END IF;
    INSERT INTO phase_11_check_semantics
      (schema_name, relation_name, constraint_name, canonical_definition)
    VALUES
      (item.schema_name, item.relation_name, item.constraint_name, canonical_definition);
    DROP TABLE pg_temp.phase_11_check_probe;
  END LOOP;
END
$phase_11_check$;
SELECT jsonb_build_array(
         schema_name,
         relation_name,
         constraint_name,
         canonical_definition
       )::text
FROM phase_11_check_semantics
ORDER BY schema_name, relation_name, constraint_name;
COMMIT;
"""


PHASE_11_INDEX_SEMANTICS_SQL = """
/* PHASE_11_INDEX_SEMANTICS_V1 */
SELECT jsonb_build_array(
         tn.nspname,
         table_relation.relname,
         ins.nspname,
         index_relation.relname,
         access_method.amname,
         index_catalog.indisunique,
         index_catalog.indisprimary,
         index_catalog.indisexclusion,
         index_catalog.indimmediate,
         index_catalog.indisclustered,
         index_catalog.indisreplident,
         index_catalog.indisvalid,
         index_catalog.indisready,
         index_catalog.indislive,
         index_catalog.indnkeyatts,
         index_catalog.indnatts,
         pg_get_indexdef(index_catalog.indexrelid, 0, false),
         pg_get_expr(index_catalog.indpred, index_catalog.indrelid, false),
         constraint_catalog.conname,
         constraint_catalog.contype::text
       )::text
FROM pg_index index_catalog
JOIN pg_class index_relation ON index_relation.oid = index_catalog.indexrelid
JOIN pg_namespace ins ON ins.oid = index_relation.relnamespace
JOIN pg_class table_relation ON table_relation.oid = index_catalog.indrelid
JOIN pg_namespace tn ON tn.oid = table_relation.relnamespace
JOIN pg_am access_method ON access_method.oid = index_relation.relam
LEFT JOIN pg_constraint constraint_catalog
  ON constraint_catalog.conindid = index_catalog.indexrelid
 AND constraint_catalog.contype IN ('p', 'u', 'x')
WHERE tn.nspname <> 'information_schema'
  AND tn.nspname !~ '^pg_'
ORDER BY tn.nspname, table_relation.relname, ins.nspname, index_relation.relname;
"""


PHASE_11_SEQUENCE_SEMANTICS_SQL = """
/* PHASE_11_SEQUENCE_SEMANTICS_V1 */
BEGIN;
CREATE TEMP TABLE phase_11_sequence_state (
  schema_name text NOT NULL,
  sequence_name text NOT NULL,
  last_value text NOT NULL,
  is_called boolean NOT NULL
) ON COMMIT DROP;
DO $phase_11_sequence$
DECLARE
  item record;
  sequence_last_value text;
  sequence_is_called boolean;
BEGIN
  FOR item IN
    SELECT n.nspname AS schema_name, c.relname AS sequence_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'S'
      AND n.nspname <> 'information_schema'
      AND n.nspname !~ '^pg_'
    ORDER BY n.nspname, c.relname
  LOOP
    EXECUTE format(
      'SELECT last_value::text, is_called FROM %I.%I',
      item.schema_name,
      item.sequence_name
    ) INTO sequence_last_value, sequence_is_called;
    INSERT INTO phase_11_sequence_state
      (schema_name, sequence_name, last_value, is_called)
    VALUES
      (item.schema_name, item.sequence_name, sequence_last_value, sequence_is_called);
  END LOOP;
END
$phase_11_sequence$;
SELECT jsonb_build_array(
         n.nspname,
         c.relname,
         format_type(sequence_catalog.seqtypid, NULL),
         sequence_catalog.seqstart,
         sequence_catalog.seqincrement,
         sequence_catalog.seqmax,
         sequence_catalog.seqmin,
         sequence_catalog.seqcache,
         sequence_catalog.seqcycle,
         owned_namespace.nspname,
         owned_relation.relname,
         owned_attribute.attname,
         ownership_dependency.deptype::text,
         sequence_state.last_value,
         sequence_state.is_called
       )::text
FROM pg_sequence sequence_catalog
JOIN pg_class c ON c.oid = sequence_catalog.seqrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN phase_11_sequence_state sequence_state
  ON sequence_state.schema_name = n.nspname
 AND sequence_state.sequence_name = c.relname
LEFT JOIN LATERAL (
  SELECT dependency.refobjid, dependency.refobjsubid, dependency.deptype
  FROM pg_depend dependency
  WHERE dependency.classid = 'pg_class'::regclass
    AND dependency.objid = c.oid
    AND dependency.objsubid = 0
    AND dependency.refclassid = 'pg_class'::regclass
    AND dependency.deptype IN ('a', 'i')
  ORDER BY dependency.deptype, dependency.refobjid, dependency.refobjsubid
  LIMIT 1
) ownership_dependency ON true
LEFT JOIN pg_class owned_relation ON owned_relation.oid = ownership_dependency.refobjid
LEFT JOIN pg_namespace owned_namespace ON owned_namespace.oid = owned_relation.relnamespace
LEFT JOIN pg_attribute owned_attribute
  ON owned_attribute.attrelid = ownership_dependency.refobjid
 AND owned_attribute.attnum = ownership_dependency.refobjsubid
WHERE n.nspname <> 'information_schema'
  AND n.nspname !~ '^pg_'
ORDER BY n.nspname, c.relname;
COMMIT;
"""


PHASE_11_CATALOG_COMPARISONS = (
    (
        PHASE_11_RELATION_INVENTORY_SQL,
        "SOURCE_RELATION_INVENTORY_QUERY_FAILED",
        "RESTORED_RELATION_INVENTORY_QUERY_FAILED",
        "RELATION_INVENTORY_MISMATCH",
    ),
    (
        PHASE_11_COLUMN_SEMANTICS_SQL,
        "SOURCE_COLUMN_SEMANTICS_QUERY_FAILED",
        "RESTORED_COLUMN_SEMANTICS_QUERY_FAILED",
        "COLUMN_SEMANTICS_MISMATCH",
    ),
    (
        PHASE_11_CONSTRAINT_SEMANTICS_SQL,
        "SOURCE_CONSTRAINT_SEMANTICS_QUERY_FAILED",
        "RESTORED_CONSTRAINT_SEMANTICS_QUERY_FAILED",
        "CONSTRAINT_SEMANTICS_MISMATCH",
    ),
    (
        PHASE_11_CHECK_SEMANTICS_SQL,
        "SOURCE_CHECK_SEMANTICS_QUERY_FAILED",
        "RESTORED_CHECK_SEMANTICS_QUERY_FAILED",
        "CHECK_CONSTRAINT_SEMANTICS_MISMATCH",
    ),
    (
        PHASE_11_INDEX_SEMANTICS_SQL,
        "SOURCE_INDEX_SEMANTICS_QUERY_FAILED",
        "RESTORED_INDEX_SEMANTICS_QUERY_FAILED",
        "INDEX_SEMANTICS_MISMATCH",
    ),
    (
        PHASE_11_SEQUENCE_SEMANTICS_SQL,
        "SOURCE_SEQUENCE_SEMANTICS_QUERY_FAILED",
        "RESTORED_SEQUENCE_SEMANTICS_QUERY_FAILED",
        "SEQUENCE_SEMANTICS_MISMATCH",
    ),
)


class RehearsalHarness:
    """Injectable, fail-closed phase orchestrator."""

    def __init__(
        self,
        runner: CommandRunner,
        *,
        monotonic: Callable[[], float] | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.runner = runner
        self.monotonic = monotonic or time.monotonic
        self.token_factory = token_factory or (lambda: secrets.token_hex(16))

    def plan(self) -> dict[str, object]:
        """Return the plan without invoking the runner or reading process state."""

        return load_plan()

    def _phase_00(
        self,
        request: ExecuteRequest,
        plan: Mapping[str, object],
        state_box: dict[str, ExecutionState],
    ) -> PhaseOutcome:
        resolved = validate_execute_request(request)
        state = ExecutionState(resolved=resolved, plan=plan)
        state_box["state"] = state
        verify_local_source_objects(self.runner, resolved)

        guard = WorkspaceGuard.create(resolved.workspace, resolved.temporary_root, str(self.token_factory()))
        state.guard = guard
        guard.assert_no_existing_cluster()

        state.production_snapshot = extract_local_snapshot(
            self.runner,
            resolved,
            guard,
            sha=PRODUCTION_SHA,
            label="production",
        )
        state.staging_snapshot = extract_local_snapshot(
            self.runner,
            resolved,
            guard,
            sha=STAGING_SHA,
            label="staging",
        )

        fixture = resolved.repository / FIXTURE_RELATIVE_PATH
        baseline = plan["synthetic_baseline"]
        if not isinstance(baseline, dict) or not isinstance(baseline.get("fixture_sha256"), str):
            raise PlanContractError("fixture digest missing")
        if not fixture.is_file() or fixture.is_symlink() or _sha256_file(fixture) != baseline["fixture_sha256"]:
            raise SafetyViolation("SYNTHETIC_FIXTURE_DIGEST_MISMATCH")
        inputs = guard.workspace / "inputs"
        inputs.mkdir(mode=0o700)
        state.fixture_copy = inputs / "production_catalog_baseline_v1.sql"
        shutil.copyfile(fixture, state.fixture_copy)
        state.fixture_copy.chmod(0o400)
        if _sha256_file(state.fixture_copy) != baseline["fixture_sha256"]:
            raise SafetyViolation("SYNTHETIC_FIXTURE_COPY_MISMATCH")

        state.jwks_directory = guard.workspace / "jwks"
        create_ephemeral_jwks(state.jwks_directory, self.token_factory)
        return PhaseOutcome("PASS", "PREFLIGHT_COMPLETE", DETAILS["PREFLIGHT_COMPLETE"])

    def _phase_01(self, state: ExecutionState) -> PhaseOutcome:
        if state.guard is None:
            raise SafetyViolation("OWNED_WORKSPACE_REQUIRED")
        state.guard.assert_no_existing_cluster()
        socket_directory = _socket_directory(state)
        log_directory = state.guard.workspace / "log"
        socket_directory.mkdir(mode=0o700)
        log_directory.mkdir(mode=0o700)
        cluster = _cluster_directory(state)
        _checked(
            self.runner,
            [
                str(state.resolved.tools.postgresql["initdb"]),
                "--pgdata",
                str(cluster),
                "--encoding=UTF8",
                "--locale=C",
                "--auth-local=trust",
                "--auth-host=reject",
                "--username",
                REHEARSAL_ROLE,
                "--no-instructions",
            ],
            cwd=state.guard.workspace,
            env=_postgres_environment(state),
            evidence_code="EPHEMERAL_INITDB_FAILED",
            timeout=180,
        )
        if not (cluster / "PG_VERSION").is_file():
            raise CommandFailure("EPHEMERAL_CLUSTER_NOT_CREATED")
        configuration = cluster / "postgresql.conf"
        with configuration.open("a", encoding="utf-8") as handle:
            handle.write("\n# HODLXXI rehearsal V1 isolation\n")
            handle.write("listen_addresses = ''\n")
            handle.write(f"unix_socket_directories = '{socket_directory}'\n")
            handle.write("unix_socket_permissions = 0700\n")
            handle.write(f"port = {REHEARSAL_PORT}\n")
        state.cluster_started = True
        _checked(
            self.runner,
            [
                str(state.resolved.tools.postgresql["pg_ctl"]),
                "--pgdata",
                str(cluster),
                "--log",
                str(log_directory / "postgres.log"),
                "--wait",
                "--timeout",
                "30",
                "start",
            ],
            cwd=state.guard.workspace,
            env=_postgres_environment(state),
            evidence_code="EPHEMERAL_CLUSTER_START_FAILED",
            timeout=60,
        )
        return PhaseOutcome("PASS", "EPHEMERAL_CLUSTER_READY", DETAILS["EPHEMERAL_CLUSTER_READY"])

    def _phase_02(self, state: ExecutionState) -> PhaseOutcome:
        if state.fixture_copy is None:
            raise SafetyViolation("SYNTHETIC_FIXTURE_MISSING")
        state.primary_target, state.restored_target = generate_database_targets(self.token_factory)
        _createdb(self.runner, state, state.primary_target)
        _psql(
            self.runner,
            state,
            state.primary_target,
            file_path=state.fixture_copy,
            evidence_code="SYNTHETIC_BASELINE_LOAD_FAILED",
        )
        _verify_baseline_catalog(self.runner, state)
        return PhaseOutcome("PASS", "SYNTHETIC_BASELINE_READY", DETAILS["SYNTHETIC_BASELINE_READY"])

    def _phase_03(self, state: ExecutionState) -> PhaseOutcome:
        if state.staging_snapshot is None or state.primary_target is None:
            raise SafetyViolation("STAGING_STARTUP_STATE_INCOMPLETE")
        return _run_application_probe(
            self.runner,
            state,
            snapshot=state.staging_snapshot,
            target=state.primary_target,
            mode="startup",
        )

    def _phase_04(self, state: ExecutionState) -> PhaseOutcome:
        if state.staging_snapshot is None or state.primary_target is None:
            raise SafetyViolation("STAGING_AUTH_STATE_INCOMPLETE")
        return _run_application_probe(
            self.runner,
            state,
            snapshot=state.staging_snapshot,
            target=state.primary_target,
            mode="auth",
        )

    def _phase_05(self, state: ExecutionState) -> PhaseOutcome:
        if state.staging_snapshot is None or state.primary_target is None:
            raise SafetyViolation("MIGRATION_STATE_INCOMPLETE")
        for relative in MIGRATIONS:
            migration = state.staging_snapshot / relative
            _psql(
                self.runner,
                state,
                state.primary_target,
                file_path=migration,
                evidence_code="ORDERED_MIGRATION_FAILED",
                timeout=300,
            )
        return PhaseOutcome("PASS", "NINE_MIGRATIONS_APPLIED", DETAILS["NINE_MIGRATIONS_APPLIED"])

    def _phase_06(self, state: ExecutionState) -> PhaseOutcome:
        _verify_migrated_catalog(self.runner, state)
        return PhaseOutcome("PASS", "MIGRATED_CATALOG_VERIFIED", DETAILS["MIGRATED_CATALOG_VERIFIED"])

    def _phase_07(self, state: ExecutionState) -> PhaseOutcome:
        if state.production_snapshot is None or state.primary_target is None:
            raise SafetyViolation("PRODUCTION_STARTUP_STATE_INCOMPLETE")
        return _run_application_probe(
            self.runner,
            state,
            snapshot=state.production_snapshot,
            target=state.primary_target,
            mode="startup",
        )

    def _phase_08(self, state: ExecutionState) -> PhaseOutcome:
        if state.staging_snapshot is None or state.primary_target is None:
            raise SafetyViolation("FINAL_STAGING_PROBE_STATE_INCOMPLETE")
        startup = _run_application_probe(
            self.runner,
            state,
            snapshot=state.staging_snapshot,
            target=state.primary_target,
            mode="startup",
        )
        if startup.status != "PASS":
            return startup
        return _run_application_probe(
            self.runner,
            state,
            snapshot=state.staging_snapshot,
            target=state.primary_target,
            mode="auth",
        )

    def _phase_09(self, state: ExecutionState) -> PhaseOutcome:
        if state.guard is None or state.primary_target is None:
            raise SafetyViolation("BACKUP_STATE_INCOMPLETE")
        artifacts = state.guard.workspace / "artifacts"
        artifacts.mkdir(mode=0o700)
        state.archive_path = artifacts / "rehearsal.dump"
        _checked(
            self.runner,
            [
                str(state.resolved.tools.postgresql["pg_dump"]),
                *_pg_connection_arguments(state),
                "--format=custom",
                "--compress=6",
                "--no-owner",
                "--no-privileges",
                "--file",
                str(state.archive_path),
                "--dbname",
                state.primary_target,
            ],
            cwd=state.guard.workspace,
            env=_postgres_environment(state),
            evidence_code="BACKUP_ARCHIVE_CREATE_FAILED",
            timeout=600,
        )
        if (
            not state.archive_path.is_file()
            or state.archive_path.is_symlink()
            or state.archive_path.stat().st_size == 0
        ):
            raise CommandFailure("BACKUP_ARCHIVE_MISSING")
        state.archive_sha256 = _sha256_file(state.archive_path)
        listing = _checked(
            self.runner,
            [str(state.resolved.tools.postgresql["pg_restore"]), "--list", str(state.archive_path)],
            cwd=state.guard.workspace,
            env=_postgres_environment(state),
            evidence_code="BACKUP_ARCHIVE_LIST_FAILED",
            timeout=120,
        )
        entries = [line for line in listing.stdout.splitlines() if line.strip() and not line.lstrip().startswith(";")]
        if not entries:
            raise CommandFailure("BACKUP_ARCHIVE_EMPTY")
        return PhaseOutcome(
            "PASS",
            "BACKUP_ARCHIVE_VERIFIED",
            DETAILS["BACKUP_ARCHIVE_VERIFIED"],
            artifact_sha256=state.archive_sha256,
        )

    def _phase_10(self, state: ExecutionState) -> PhaseOutcome:
        if (
            state.guard is None
            or state.restored_target is None
            or state.archive_path is None
            or state.archive_sha256 is None
        ):
            raise SafetyViolation("RESTORE_STATE_INCOMPLETE")
        if _sha256_file(state.archive_path) != state.archive_sha256:
            raise CommandFailure("BACKUP_ARCHIVE_CHECKSUM_MISMATCH")
        _createdb(self.runner, state, state.restored_target)
        _checked(
            self.runner,
            [
                str(state.resolved.tools.postgresql["pg_restore"]),
                *_pg_connection_arguments(state),
                "--exit-on-error",
                "--no-owner",
                "--dbname",
                state.restored_target,
                str(state.archive_path),
            ],
            cwd=state.guard.workspace,
            env=_postgres_environment(state),
            evidence_code="SECOND_TARGET_RESTORE_FAILED",
            timeout=900,
        )
        return PhaseOutcome(
            "PASS",
            "RESTORE_COMPLETE",
            DETAILS["RESTORE_COMPLETE"],
            artifact_sha256=state.archive_sha256,
        )

    def _schema_dump(self, state: ExecutionState, target: str) -> CommandResult:
        validate_database_target(target)
        return _checked(
            self.runner,
            [
                str(state.resolved.tools.postgresql["pg_dump"]),
                *_pg_connection_arguments(state),
                "--schema-only",
                "--no-owner",
                "--no-privileges",
                "--no-comments",
                "--dbname",
                target,
            ],
            cwd=state.guard.workspace if state.guard else state.resolved.temporary_root,
            env=_postgres_environment(state),
            evidence_code="NORMALIZED_SCHEMA_DUMP_FAILED",
            timeout=300,
        )

    def _phase_11(self, state: ExecutionState) -> PhaseOutcome:
        if state.primary_target is None or state.restored_target is None or state.staging_snapshot is None:
            raise SafetyViolation("COMPARE_STATE_INCOMPLETE")
        original_schema = _normalized_schema(self._schema_dump(state, state.primary_target).stdout)
        restored_schema = _normalized_schema(self._schema_dump(state, state.restored_target).stdout)

        for sql, source_failure, restored_failure, mismatch in PHASE_11_CATALOG_COMPARISONS:
            original_catalog = _psql(
                self.runner,
                state,
                state.primary_target,
                sql=sql,
                evidence_code=source_failure,
            ).stdout
            restored_catalog = _psql(
                self.runner,
                state,
                state.restored_target,
                sql=sql,
                evidence_code=restored_failure,
            ).stdout
            if original_catalog != restored_catalog:
                raise CommandFailure(mismatch)

        counts_sql = (
            "SELECT count(*) FILTER (WHERE c.relkind IN ('r','p'))||'|'||"
            "count(*) FILTER (WHERE c.relkind='S')||'|'||"
            "count(*) FILTER (WHERE c.relkind IN ('i','I')) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
            "AND n.nspname NOT LIKE 'pg_toast%';"
        )
        original_counts = _psql(
            self.runner,
            state,
            state.primary_target,
            sql=counts_sql,
            evidence_code="SOURCE_OBJECT_COUNT_QUERY_FAILED",
        ).stdout.strip()
        restored_counts = _psql(
            self.runner,
            state,
            state.restored_target,
            sql=counts_sql,
            evidence_code="RESTORED_OBJECT_COUNT_QUERY_FAILED",
        ).stdout.strip()
        if not original_counts or original_counts != restored_counts:
            raise CommandFailure("TABLE_SEQUENCE_INDEX_COUNT_MISMATCH")

        ownership_sql = (
            "SELECT n.nspname||'|'||c.relkind::text||'|'||c.relname||'|'||"
            "CASE WHEN pg_get_userbyid(c.relowner)=current_user THEN 'REHEARSAL_ROLE' ELSE 'OTHER' END "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
            "AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','S','v','m') "
            "ORDER BY n.nspname,c.relkind,c.relname;"
        )
        original_owners = _psql(
            self.runner,
            state,
            state.primary_target,
            sql=ownership_sql,
            evidence_code="SOURCE_OWNERSHIP_QUERY_FAILED",
        ).stdout
        restored_owners = _psql(
            self.runner,
            state,
            state.restored_target,
            sql=ownership_sql,
            evidence_code="RESTORED_OWNERSHIP_QUERY_FAILED",
        ).stdout
        if original_owners != restored_owners:
            raise CommandFailure("RELATION_OWNERSHIP_CATEGORY_MISMATCH")

        baseline = state.plan.get("synthetic_baseline")
        if not isinstance(baseline, dict) or not isinstance(baseline.get("tables"), list):
            raise PlanContractError("baseline catalog missing")
        baseline_tables = {str(item["table"]) for item in baseline["tables"]}
        migrated_tables = _migration_catalog_contract(state.staging_snapshot)[0]
        application_tables = baseline_tables | migrated_tables
        if not application_tables or any(not SAFE_IDENTIFIER.fullmatch(table) for table in application_tables):
            raise PlanContractError("application table contract invalid")
        row_counts_sql = (
            " UNION ALL ".join(
                f"SELECT '{table}' AS table_name,count(*)::text AS row_count FROM {table}"
                for table in sorted(application_tables)
            )
            + " ORDER BY 1;"
        )
        original_row_counts = _psql(
            self.runner,
            state,
            state.primary_target,
            sql=row_counts_sql,
            evidence_code="SOURCE_ROW_COUNT_QUERY_FAILED",
        ).stdout
        restored_row_counts = _psql(
            self.runner,
            state,
            state.restored_target,
            sql=row_counts_sql,
            evidence_code="RESTORED_ROW_COUNT_QUERY_FAILED",
        ).stdout
        if not original_row_counts.strip() or original_row_counts != restored_row_counts:
            raise CommandFailure("PER_TABLE_ROW_COUNT_MISMATCH")

        queryability_sql = """
DO $$
DECLARE relation record; probe integer;
BEGIN
  FOR relation IN
    SELECT n.nspname AS schema_name, c.relname AS relation_name
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind IN ('r','p')
      AND n.nspname NOT IN ('pg_catalog','information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
  LOOP
    EXECUTE format('SELECT 1 FROM %I.%I LIMIT 1', relation.schema_name, relation.relation_name) INTO probe;
  END LOOP;
END
$$;
"""
        _psql(
            self.runner,
            state,
            state.restored_target,
            sql=queryability_sql,
            evidence_code="RESTORED_TABLE_QUERYABILITY_FAILED",
        )
        original_schema_digest = hashlib.sha256(original_schema.encode("utf-8")).hexdigest()
        restored_schema_digest = hashlib.sha256(restored_schema.encode("utf-8")).hexdigest()
        schema_text_status = "EQUAL" if original_schema == restored_schema else "DIFFERENT"
        # The digest retains the raw dump comparison as sanitized diagnostic
        # evidence; schema text status is deliberately not an authority gate.
        schema_digest = hashlib.sha256(
            f"{schema_text_status}|{original_schema_digest}|{restored_schema_digest}".encode("ascii")
        ).hexdigest()
        return PhaseOutcome(
            "PASS",
            "RESTORE_COMPARISON_COMPLETE",
            DETAILS["RESTORE_COMPARISON_COMPLETE"],
            artifact_sha256=schema_digest,
        )

    def _phase_12(self, state: ExecutionState | None) -> PhaseOutcome:
        if state is None or state.guard is None:
            return PhaseOutcome(
                "PASS",
                "CLEANUP_NOT_REQUIRED",
                DETAILS["CLEANUP_NOT_REQUIRED"],
                cleanup_status="NOT_REQUIRED",
            )
        state.guard.assert_owned()
        if state.cluster_started:
            _checked(
                self.runner,
                [
                    str(state.resolved.tools.postgresql["pg_ctl"]),
                    "--pgdata",
                    str(_cluster_directory(state)),
                    "--wait",
                    "--timeout",
                    "30",
                    "--mode",
                    "fast",
                    "stop",
                ],
                cwd=state.guard.workspace,
                env=_postgres_environment(state),
                evidence_code="EPHEMERAL_CLUSTER_STOP_FAILED",
                timeout=60,
            )
            state.cluster_started = False
        guard = state.guard
        guard.cleanup()
        state.guard = None
        return PhaseOutcome(
            "PASS",
            "CLEANUP_COMPLETE",
            DETAILS["CLEANUP_COMPLETE"],
            cleanup_status="COMPLETE",
        )

    def _invoke(self, phase: str, operation: Callable[[], PhaseOutcome]) -> dict[str, object]:
        started = self.monotonic()
        try:
            outcome = operation()
        except SafetyViolation as exc:
            if phase == "REHEARSAL_12_CLEANUP":
                outcome = PhaseOutcome(
                    "FAIL",
                    exc.evidence_code,
                    DETAILS["CLEANUP_FAILED"],
                    cleanup_status="REFUSED_UNOWNED",
                )
            else:
                outcome = PhaseOutcome("BLOCKED", exc.evidence_code, DETAILS["SAFETY_GATE_BLOCKED"], unsupported=True)
        except ProbeUnsupported as exc:
            outcome = PhaseOutcome("BLOCKED", exc.evidence_code, DETAILS["PROBE_BLOCKED"], unsupported=True)
        except CommandFailure as exc:
            if phase == "REHEARSAL_12_CLEANUP":
                outcome = PhaseOutcome(
                    "FAIL",
                    exc.evidence_code,
                    DETAILS["CLEANUP_FAILED"],
                    cleanup_status="FAILED",
                )
            else:
                outcome = PhaseOutcome("FAIL", exc.evidence_code, DETAILS["COMMAND_FAILED"])
        except Exception:
            if phase == "REHEARSAL_12_CLEANUP":
                outcome = PhaseOutcome(
                    "FAIL",
                    "UNEXPECTED_FAILURE",
                    DETAILS["CLEANUP_FAILED"],
                    cleanup_status="FAILED",
                )
            else:
                outcome = PhaseOutcome("FAIL", "UNEXPECTED_FAILURE", DETAILS["UNEXPECTED_FAILURE"])
        duration_ms = max(0, int((self.monotonic() - started) * 1000))
        return _phase_result(phase, outcome, duration_ms)

    def execute(self, request: ExecuteRequest) -> dict[str, object]:
        """Run the separately authorized laboratory workflow through the injected runner."""

        plan = self.plan()
        state_box: dict[str, ExecutionState] = {}
        operations: tuple[Callable[[], PhaseOutcome], ...] = (
            lambda: self._phase_00(request, plan, state_box),
            lambda: self._phase_01(state_box["state"]),
            lambda: self._phase_02(state_box["state"]),
            lambda: self._phase_03(state_box["state"]),
            lambda: self._phase_04(state_box["state"]),
            lambda: self._phase_05(state_box["state"]),
            lambda: self._phase_06(state_box["state"]),
            lambda: self._phase_07(state_box["state"]),
            lambda: self._phase_08(state_box["state"]),
            lambda: self._phase_09(state_box["state"]),
            lambda: self._phase_10(state_box["state"]),
            lambda: self._phase_11(state_box["state"]),
        )
        results: list[dict[str, object]] = []
        prerequisite_failed = False
        workspace_created = False
        cleanup_result: dict[str, object]
        try:
            for phase, operation in zip(PHASES[:12], operations, strict=True):
                if prerequisite_failed:
                    cleanup = "PENDING" if workspace_created else "NOT_REQUIRED"
                    results.append(
                        _phase_result(
                            phase,
                            PhaseOutcome(
                                "BLOCKED",
                                "PREREQUISITE_NOT_PASS",
                                DETAILS["PREREQUISITE_NOT_PASS"],
                                cleanup_status=cleanup,
                                unsupported=True,
                            ),
                            0,
                        )
                    )
                    continue
                result = self._invoke(phase, operation)
                results.append(result)
                workspace_created = state_box.get("state") is not None and state_box["state"].guard is not None
                if result["status"] != "PASS":
                    prerequisite_failed = True
        finally:
            # Cleanup is attempted even for orchestration-level BaseException
            # paths that are deliberately not converted into sanitized phase
            # evidence (for example KeyboardInterrupt or SystemExit).
            cleanup_result = self._invoke(PHASES[12], lambda: self._phase_12(state_box.get("state")))

        results.append(cleanup_result)
        final_cleanup = cleanup_result["cleanup_status"]
        for result in results[:-1]:
            result["cleanup_status"] = final_cleanup

        substantive_statuses = [str(result["status"]) for result in results]
        if "FAIL" in substantive_statuses:
            execution_status = "FAIL"
        elif "BLOCKED" in substantive_statuses:
            execution_status = "BLOCKED"
        else:
            execution_status = "PASS"
        result_phase = _phase_result(
            PHASES[13],
            PhaseOutcome(
                "PASS",
                "SANITIZED_RESULT_EMITTED",
                DETAILS["SANITIZED_RESULT_EMITTED"],
                cleanup_status=str(final_cleanup),
            ),
            0,
        )
        results.append(result_phase)
        result_object: dict[str, object] = {
            "schema": "hodlxxi.production_compatibility_rehearsal_result.v1",
            "plan_version": 1,
            "production_sha": PRODUCTION_SHA,
            "staging_sha": STAGING_SHA,
            "execution_status": execution_status,
            "release_authority": "NONE",
            "phases": results,
            "release_gate_effect": "NONE",
        }
        validate_sanitized_result(result_object)
        return result_object


def validate_sanitized_result(result: Mapping[str, object]) -> None:
    """Ensure result output cannot carry raw runtime or target material."""

    required_top_level = {
        "schema",
        "plan_version",
        "production_sha",
        "staging_sha",
        "execution_status",
        "release_authority",
        "phases",
        "release_gate_effect",
    }
    if set(result) != required_top_level:
        raise ValueError("invalid result top-level shape")
    if result.get("schema") != "hodlxxi.production_compatibility_rehearsal_result.v1":
        raise ValueError("invalid result schema")
    if result.get("plan_version") != 1:
        raise ValueError("invalid result plan version")
    if result.get("production_sha") != PRODUCTION_SHA or result.get("staging_sha") != STAGING_SHA:
        raise ValueError("invalid result source basis")
    if result.get("execution_status") not in {"PASS", "FAIL", "BLOCKED"}:
        raise ValueError("invalid execution status")
    if result.get("release_authority") != "NONE" or result.get("release_gate_effect") != "NONE":
        raise ValueError("result attempted release authority")
    phases = result.get("phases")
    if not isinstance(phases, list) or [item.get("phase") for item in phases if isinstance(item, dict)] != list(PHASES):
        raise ValueError("invalid result phases")
    required_fields = {
        "phase",
        "status",
        "evidence_code",
        "duration_ms",
        "sanitized_detail",
        "artifact_sha256",
        "cleanup_status",
    }
    if any(not isinstance(item, dict) or set(item) != required_fields for item in phases):
        raise ValueError("invalid phase result shape")
    allowed_cleanup = {"COMPLETE", "NOT_REQUIRED", "FAILED", "REFUSED_UNOWNED"}
    fixed_details = set(DETAILS.values())
    for item in phases:
        status = item["status"]
        evidence_code = item["evidence_code"]
        duration_ms = item["duration_ms"]
        artifact_sha256 = item["artifact_sha256"]
        if status not in {"PASS", "FAIL", "BLOCKED"}:
            raise ValueError("invalid phase result status")
        if (
            not isinstance(evidence_code, str)
            or len(evidence_code) > 128
            or not re.fullmatch(r"[A-Z0-9_]+", evidence_code)
        ):
            raise ValueError("invalid phase evidence code")
        if isinstance(duration_ms, bool) or not isinstance(duration_ms, int) or duration_ms < 0:
            raise ValueError("invalid phase duration")
        if item["sanitized_detail"] not in fixed_details:
            raise ValueError("invalid sanitized detail")
        if artifact_sha256 is not None and (
            not isinstance(artifact_sha256, str) or not SHA256_PATTERN.fullmatch(artifact_sha256)
        ):
            raise ValueError("invalid phase artifact digest")
        if item["cleanup_status"] not in allowed_cleanup:
            raise ValueError("invalid cleanup status")
    final_cleanup = phases[12]["cleanup_status"]
    if any(item["cleanup_status"] != final_cleanup for item in phases):
        raise ValueError("inconsistent cleanup status")
    if (
        phases[13]["status"] != "PASS"
        or phases[13]["evidence_code"] != "SANITIZED_RESULT_EMITTED"
        or phases[13]["sanitized_detail"] != DETAILS["SANITIZED_RESULT_EMITTED"]
    ):
        raise ValueError("invalid result emission phase")
    substantive_statuses = {item["status"] for item in phases[:13]}
    expected_execution_status = (
        "FAIL" if "FAIL" in substantive_statuses else "BLOCKED" if "BLOCKED" in substantive_statuses else "PASS"
    )
    if result["execution_status"] != expected_execution_status:
        raise ValueError("execution status does not match phases")
    for path, value in _walk(result):
        if isinstance(value, str):
            if DSN_PATTERN.search(value) or _contains_ip_literal(value) or DATABASE_TARGET_PATTERN.fullmatch(value):
                raise ValueError(f"unsafe result value at {path}")


def _write_explicit_output(path: Path, content: str) -> None:
    target = path.resolve(strict=False)
    if target.exists() or target.is_symlink() or not target.parent.is_dir():
        raise SafetyViolation("OUTPUT_PATH_MUST_BE_NEW")
    if _is_prohibited(target):
        raise SafetyViolation("OUTPUT_PATH_PROHIBITED")
    target.write_text(content, encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    plan_parser = subparsers.add_parser("plan", help="emit the deterministic NOT_RUN plan")
    plan_parser.add_argument("--json", action="store_true", help="emit strict JSON")
    plan_parser.add_argument("--output", type=Path, help="write only to this explicit new path")

    execute_parser = subparsers.add_parser("execute", help="run only in an approved disposable laboratory")
    execute_parser.add_argument("--ack", required=True)
    execute_parser.add_argument("--repository", type=Path, required=True)
    execute_parser.add_argument("--workspace", type=Path, required=True)
    execute_parser.add_argument("--temporary-root", type=Path, required=True)
    execute_parser.add_argument("--production-sha", required=True)
    execute_parser.add_argument("--staging-sha", required=True)
    execute_parser.add_argument("--git-binary", type=Path, required=True)
    execute_parser.add_argument("--python-binary", type=Path, required=True)
    execute_parser.add_argument("--postgresql-binary-directory", type=Path, required=True)
    execute_parser.add_argument("--output", type=Path, help="write the sanitized result to this explicit new path")
    return parser


def main(argv: Sequence[str] | None = None, *, runner: CommandRunner | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ["plan"]
    parser = _build_parser()
    namespace = parser.parse_args(arguments)
    if namespace.command == "plan":
        plan = load_plan()
        if namespace.json:
            rendered = canonical_plan_json(plan)
        else:
            rendered = (
                "\n".join(
                    [
                        "HODLXXI production compatibility rehearsal V1",
                        "execution_status=NOT_RUN",
                        "release_authority=NONE",
                        *[f"{item['phase']}=NOT_RUN" for item in plan["phases"]],
                    ]
                )
                + "\n"
            )
        if namespace.output is not None:
            _write_explicit_output(namespace.output, rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    if namespace.command != "execute":
        parser.error("unknown command")

    # Process state is consulted only after the explicit execute subcommand.
    request = ExecuteRequest(
        acknowledgement=namespace.ack,
        repository=namespace.repository,
        workspace=namespace.workspace,
        temporary_root=namespace.temporary_root,
        production_sha=namespace.production_sha,
        staging_sha=namespace.staging_sha,
        git_binary=namespace.git_binary,
        python_binary=namespace.python_binary,
        postgresql_binary_directory=namespace.postgresql_binary_directory,
        environment_keys=frozenset(os.environ.keys()),
        effective_uid=os.geteuid(),
        output_path=namespace.output,
    )
    harness = RehearsalHarness(runner or SubprocessCommandRunner())
    result = harness.execute(request)
    rendered = json.dumps(result, ensure_ascii=False, indent=2, separators=(",", ": ")) + "\n"
    if namespace.output is not None:
        _write_explicit_output(namespace.output, rendered)
    else:
        sys.stdout.write(rendered)
    return 0 if result["execution_status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
