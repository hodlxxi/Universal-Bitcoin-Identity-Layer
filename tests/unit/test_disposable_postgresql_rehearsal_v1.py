from __future__ import annotations

import ast
import copy
import json
import re
import subprocess
import sys
import tarfile
import textwrap
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tools import production_compatibility_rehearsal_v1 as rehearsal

ROOT = Path(__file__).resolve().parents[2]

EXPECTED_RELATIONAL_CONSTRAINTS = frozenset(
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
        (
            "trusted_covenant_registered_outpoints|f|registration_id|"
            "trusted_covenant_registrations|registration_id|c"
        ),
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
        (
            "canonical_covenant_funding_outpoints|f|funding_set_id|"
            "canonical_covenant_funding_sets|funding_set_id|c"
        ),
    }
)


def phase_11_json_lines(*rows: list[object]) -> str:
    return "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)


PHASE_11_MARKERS = {
    "relation": "PHASE_11_RELATION_INVENTORY_V1",
    "column": "PHASE_11_COLUMN_SEMANTICS_V1",
    "constraint": "PHASE_11_CONSTRAINT_SEMANTICS_V1",
    "check": "PHASE_11_CHECK_SEMANTICS_V1",
    "index": "PHASE_11_INDEX_SEMANTICS_V1",
    "sequence": "PHASE_11_SEQUENCE_SEMANTICS_V1",
}


PHASE_11_CATALOG_OUTPUTS = {
    "relation": phase_11_json_lines(["public", "users", "r", "p", False]),
    "column": phase_11_json_lines(
        [
            "public",
            "users",
            1,
            "id",
            "pg_catalog",
            "varchar",
            "character varying(36)",
            True,
            "",
            "",
            "gen_random_uuid()::text",
            ["pg_catalog", "default"],
        ]
    ),
    "constraint": phase_11_json_lines(
        [
            "public",
            "users",
            "users_pkey",
            "p",
            ["id"],
            None,
            None,
            [],
            None,
            None,
            None,
            False,
            False,
            True,
            False,
            True,
            0,
            None,
            None,
            None,
        ],
        [
            "public",
            "oauth_codes",
            "oauth_codes_user_id_fkey",
            "f",
            ["user_id"],
            "public",
            "users",
            ["id"],
            "a",
            "a",
            "s",
            False,
            False,
            True,
            False,
            True,
            0,
            None,
            None,
            None,
        ],
        [
            "public",
            "action_operations",
            "ck_action_operations_state",
            "c",
            ["state"],
            None,
            None,
            [],
            None,
            None,
            None,
            False,
            False,
            True,
            False,
            True,
            0,
            None,
            None,
            None,
        ],
    ),
    "check": phase_11_json_lines(
        [
            "public",
            "action_operations",
            "ck_action_operations_state",
            "CHECK (((state)::text = ANY (ARRAY[('reserved'::character varying)::text])))",
        ]
    ),
    "index": phase_11_json_lines(
        [
            "public",
            "users",
            "public",
            "idx_user_pubkey",
            "btree",
            False,
            False,
            False,
            True,
            False,
            False,
            True,
            True,
            True,
            1,
            1,
            "CREATE INDEX idx_user_pubkey ON public.users USING btree (pubkey)",
            None,
            None,
            None,
        ]
    ),
    "sequence": phase_11_json_lines(
        [
            "public",
            "canonical_admission_edge_legs_id_seq",
            "bigint",
            1,
            1,
            9223372036854775807,
            1,
            1,
            False,
            "public",
            "canonical_admission_edge_legs",
            "id",
            "a",
            "1",
            False,
        ]
    ),
}


RAW_SOURCE_SCHEMA = """\
CREATE TABLE public.action_operations (state character varying(32));
ALTER TABLE public.action_operations ADD CONSTRAINT ck_action_operations_state
CHECK (((state)::text = ANY ((ARRAY['reserved'::character varying])::text[])));
"""


RAW_RESTORED_SCHEMA = """\
CREATE TABLE public.action_operations (state character varying(32));
ALTER TABLE public.action_operations ADD CONSTRAINT ck_action_operations_state
CHECK (((state)::text = ANY (ARRAY[('reserved'::character varying)::text])));
"""


def changed_catalog_output(category: str, old: str, new: str) -> str:
    value = PHASE_11_CATALOG_OUTPUTS[category]
    assert old in value
    return value.replace(old, new, 1)


def catalog_output_without_line(category: str, position: int) -> str:
    lines = PHASE_11_CATALOG_OUTPUTS[category].splitlines(keepends=True)
    del lines[position]
    return "".join(lines)


def successful_command(stdout: str) -> rehearsal.CommandResult:
    return rehearsal.CommandResult(0, stdout, "")


PHASE_11_FAIL_CLOSED_CASES = (
    (
        "relation missing",
        "relation",
        successful_command(""),
        "RELATION_INVENTORY_MISMATCH",
    ),
    (
        "extra relation",
        "relation",
        successful_command(
            PHASE_11_CATALOG_OUTPUTS["relation"]
            + phase_11_json_lines(["public", "unexpected_relation", "r", "p", False])
        ),
        "RELATION_INVENTORY_MISMATCH",
    ),
    (
        "column missing",
        "column",
        successful_command(""),
        "COLUMN_SEMANTICS_MISMATCH",
    ),
    (
        "column added",
        "column",
        successful_command(
            PHASE_11_CATALOG_OUTPUTS["column"]
            + phase_11_json_lines(
                [
                    "public",
                    "users",
                    2,
                    "unexpected_column",
                    "pg_catalog",
                    "text",
                    "text",
                    False,
                    "",
                    "",
                    None,
                    ["pg_catalog", "default"],
                ]
            )
        ),
        "COLUMN_SEMANTICS_MISMATCH",
    ),
    (
        "column type changed",
        "column",
        successful_command(
            changed_catalog_output("column", '"varchar","character varying(36)"', '"int8","bigint"')
        ),
        "COLUMN_SEMANTICS_MISMATCH",
    ),
    (
        "column nullability changed",
        "column",
        successful_command(changed_catalog_output("column", ',true,"","",', ',false,"","",')),
        "COLUMN_SEMANTICS_MISMATCH",
    ),
    (
        "column default changed",
        "column",
        successful_command(changed_catalog_output("column", "gen_random_uuid()::text", "'changed'::text")),
        "COLUMN_SEMANTICS_MISMATCH",
    ),
    (
        "constraint missing",
        "constraint",
        successful_command(catalog_output_without_line("constraint", 1)),
        "CONSTRAINT_SEMANTICS_MISMATCH",
    ),
    (
        "extra constraint",
        "constraint",
        successful_command(
            PHASE_11_CATALOG_OUTPUTS["constraint"]
            + changed_catalog_output("constraint", "users_pkey", "users_unexpected_key").splitlines(keepends=True)[0]
        ),
        "CONSTRAINT_SEMANTICS_MISMATCH",
    ),
    (
        "foreign key target changed",
        "constraint",
        successful_command(
            changed_catalog_output(
                "constraint",
                '"public","users",["id"],"a","a","s"',
                '"public","oauth_clients",["client_id"],"a","a","s"',
            )
        ),
        "CONSTRAINT_SEMANTICS_MISMATCH",
    ),
    (
        "foreign key delete action changed",
        "constraint",
        successful_command(changed_catalog_output("constraint", '["id"],"a","a","s"', '["id"],"c","a","s"')),
        "CONSTRAINT_SEMANTICS_MISMATCH",
    ),
    (
        "foreign key update action changed",
        "constraint",
        successful_command(changed_catalog_output("constraint", '["id"],"a","a","s"', '["id"],"a","r","s"')),
        "CONSTRAINT_SEMANTICS_MISMATCH",
    ),
    (
        "check expression genuinely changed",
        "check",
        successful_command(changed_catalog_output("check", "reserved", "executing")),
        "CHECK_CONSTRAINT_SEMANTICS_MISMATCH",
    ),
    (
        "explicit index missing",
        "index",
        successful_command(""),
        "INDEX_SEMANTICS_MISMATCH",
    ),
    (
        "explicit index materially changed",
        "index",
        successful_command(changed_catalog_output("index", '"btree",false', '"btree",true')),
        "INDEX_SEMANTICS_MISMATCH",
    ),
    (
        "sequence property changed",
        "sequence",
        successful_command(changed_catalog_output("sequence", '"bigint",1,1,', '"bigint",1,2,')),
        "SEQUENCE_SEMANTICS_MISMATCH",
    ),
    (
        "ownership category changed",
        "ownership",
        successful_command("public|r|users|OTHER\n"),
        "RELATION_OWNERSHIP_CATEGORY_MISMATCH",
    ),
    (
        "table count changed",
        "counts",
        successful_command("11|2|48\n"),
        "TABLE_SEQUENCE_INDEX_COUNT_MISMATCH",
    ),
    (
        "sequence count changed",
        "counts",
        successful_command("12|1|48\n"),
        "TABLE_SEQUENCE_INDEX_COUNT_MISMATCH",
    ),
    (
        "index count changed",
        "counts",
        successful_command("12|2|47\n"),
        "TABLE_SEQUENCE_INDEX_COUNT_MISMATCH",
    ),
    (
        "application row count changed",
        "row_count",
        successful_command("users|999\n"),
        "PER_TABLE_ROW_COUNT_MISMATCH",
    ),
    (
        "restored table cannot be queried",
        "queryability",
        rehearsal.CommandResult(9, "forbidden raw stdout", "forbidden raw stderr"),
        "RESTORED_TABLE_QUERYABILITY_FAILED",
    ),
)


PHASE_11_CATALOG_QUERY_FAILURE_CASES = tuple(
    (side, category, f"{side.upper()}_{label}_QUERY_FAILED")
    for category, label in (
        ("relation", "RELATION_INVENTORY"),
        ("column", "COLUMN_SEMANTICS"),
        ("constraint", "CONSTRAINT_SEMANTICS"),
        ("check", "CHECK_SEMANTICS"),
        ("index", "INDEX_SEMANTICS"),
        ("sequence", "SEQUENCE_SEMANTICS"),
    )
    for side in ("source", "restored")
)


def make_executable(path: Path) -> Path:
    path.write_text("synthetic executable placeholder\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def execute_request(tmp_path: Path, **changes) -> rehearsal.ExecuteRequest:
    pg_directory = tmp_path / "pg-bin"
    pg_directory.mkdir(exist_ok=True)
    for name in rehearsal.POSTGRESQL_TOOLS:
        make_executable(pg_directory / name)
    request = rehearsal.ExecuteRequest(
        acknowledgement=rehearsal.ACKNOWLEDGEMENT,
        repository=ROOT,
        workspace=tmp_path / "workspace",
        temporary_root=tmp_path,
        production_sha=rehearsal.PRODUCTION_SHA,
        staging_sha=rehearsal.STAGING_SHA,
        git_binary=make_executable(tmp_path / "git"),
        python_binary=make_executable(tmp_path / "python"),
        postgresql_binary_directory=pg_directory,
        environment_keys=frozenset(),
        effective_uid=1000,
    )
    return replace(request, **changes)


PROBE_IMPORT_FAILURE_DETAIL = (
    "postgresql://probe-user:probe-password@database.invalid/private "
    "/tmp/private/probe.py credential=probe-secret"
)


def run_probe_with_factory_import(tmp_path: Path, factory_statement: str) -> subprocess.CompletedProcess[str]:
    app_directory = tmp_path / "app"
    app_directory.mkdir()
    (app_directory / "__init__.py").write_text("", encoding="utf-8")
    (app_directory / "utils.py").write_text(
        "def get_rpc_connection():\n"
        "    raise AssertionError('unguarded Bitcoin RPC access')\n",
        encoding="utf-8",
    )
    (tmp_path / "requests.py").write_text(
        textwrap.dedent(
            """
            class Session:
                def request(self, *_args, **_kwargs):
                    raise AssertionError("unguarded HTTP access")

            class Sessions:
                pass

            sessions = Sessions()
            sessions.Session = Session
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "redis.py").write_text(
        textwrap.dedent(
            """
            class ConnectionError(Exception):
                pass

            class Exceptions:
                pass

            exceptions = Exceptions()
            exceptions.ConnectionError = ConnectionError

            class Redis:
                def ping(self):
                    raise AssertionError("unguarded Redis access")

            class Client:
                pass

            client = Client()
            client.Redis = Redis
            """
        ),
        encoding="utf-8",
    )
    factory_source = textwrap.dedent(
        f"""
        import __main__
        import smtplib
        import socket
        import subprocess
        import sys
        import urllib.request

        import app.utils
        import redis
        import requests

        if socket.socket.connect is not __main__.guarded_connect:
            raise RuntimeError("socket connect guard missing")
        if socket.socket.connect_ex is not __main__.guarded_connect_ex:
            raise RuntimeError("socket connect_ex guard missing")
        if socket.socket.sendto is not __main__.guarded_sendto:
            raise RuntimeError("socket sendto guard missing")
        if socket.create_connection is not __main__.blocked_side_effect:
            raise RuntimeError("socket connection guard missing")
        if urllib.request.urlopen is not __main__.blocked_side_effect:
            raise RuntimeError("URL guard missing")
        if smtplib.SMTP is not __main__.blocked_side_effect:
            raise RuntimeError("SMTP guard missing")
        if subprocess.run is not __main__.blocked_side_effect:
            raise RuntimeError("subprocess guard missing")
        if requests.sessions.Session.request is not __main__.blocked_side_effect:
            raise RuntimeError("HTTP guard missing")
        if redis.Redis.ping is not __main__.redis_disabled:
            raise RuntimeError("Redis guard missing")
        if app.utils.get_rpc_connection is not __main__.blocked_side_effect:
            raise RuntimeError("Bitcoin RPC guard missing")

        print({PROBE_IMPORT_FAILURE_DETAIL!r})
        sys.stderr.write(__file__ + " " + {PROBE_IMPORT_FAILURE_DETAIL!r} + "\\n")
        {factory_statement}
        """
    )
    (app_directory / "factory.py").write_text(factory_source, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-c", rehearsal.PROBE_PROGRAM, "startup"],
        cwd=tmp_path,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(tmp_path)},
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def assert_sanitized_probe_failure(
    result: subprocess.CompletedProcess[str],
    *,
    expected_payload: dict[str, str],
    expected_returncode: int,
) -> None:
    assert result.returncode == expected_returncode
    assert result.stderr == ""
    assert len(result.stdout.splitlines()) == 1
    assert json.loads(result.stdout) == expected_payload
    rendered = result.stdout + result.stderr
    for forbidden in (
        "Traceback",
        "ImportError",
        "KeyboardInterrupt",
        "RuntimeError",
        "SystemExit",
        "/tmp/private/probe.py",
        "postgresql://",
        "credential=",
        "probe-password",
        "probe-secret",
        PROBE_IMPORT_FAILURE_DETAIL,
    ):
        assert forbidden not in rendered


class SyntheticProbeFailure(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def probe_function(name: str) -> ast.FunctionDef:
    program = ast.parse(rehearsal.PROBE_PROGRAM)
    return next(
        statement
        for statement in program.body
        if isinstance(statement, ast.FunctionDef) and statement.name == name
    )


def probe_evidence(name: str) -> tuple[str, ...]:
    function = probe_function(name)
    returns = [statement for statement in function.body if isinstance(statement, ast.Return)]
    assert len(returns) == 1
    return tuple(ast.literal_eval(returns[0].value))


def load_probe_browser_fixture(monkeypatch, persist):
    service = SimpleNamespace(persist_verified_browser_subject=persist)
    monkeypatch.setitem(sys.modules, "app.services.canonical_oauth_browser_subject", service)
    program = ast.parse(rehearsal.PROBE_PROGRAM)
    selected = [
        statement
        for statement in program.body
        if (
            isinstance(statement, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "SYNTHETIC_SUBJECT" for target in statement.targets)
        )
        or (isinstance(statement, ast.FunctionDef) and statement.name == "admit_synthetic_browser")
    ]
    namespace = {"require": lambda value, code: value or (_ for _ in ()).throw(SyntheticProbeFailure(code))}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<probe-browser-fixture>", "exec"), namespace)
    return namespace


def test_probe_persists_before_setting_exact_limited_browser_admission(monkeypatch):
    events = []
    browser = {}

    class Client:
        @contextmanager
        def session_transaction(self):
            events.append("session")
            yield browser

    def persist(subject):
        events.append(("persist", subject))
        return subject

    fixture = load_probe_browser_fixture(monkeypatch, persist)
    fixture["admit_synthetic_browser"](Client())

    subject = "ab" * 32
    assert events == [("persist", subject), "session"]
    assert browser == {
        "logged_in_pubkey": subject,
        "login_method": "legacy",
        "access_level": "limited",
    }


def test_probe_persistence_failure_cannot_create_browser_admission(monkeypatch):
    browser = {}

    class Client:
        @contextmanager
        def session_transaction(self):
            yield browser

    def fail_persistence(_subject):
        raise RuntimeError("synthetic persistence unavailable")

    fixture = load_probe_browser_fixture(monkeypatch, fail_persistence)
    with pytest.raises(RuntimeError, match="synthetic persistence unavailable"):
        fixture["admit_synthetic_browser"](Client())
    assert browser == {}


@pytest.mark.parametrize("missing", ["login_method", "access_level"])
def test_incomplete_probe_browser_admission_remains_fail_closed(monkeypatch, missing):
    from app.services.canonical_oauth_browser_subject import resolve_oauth_browser_subject

    subject = "ab" * 32
    browser = {
        "logged_in_pubkey": subject,
        "login_method": "legacy",
        "access_level": "limited",
    }
    browser.pop(missing)
    user = {"id": "synthetic-user", "pubkey": subject, "is_active": True}
    with pytest.raises(ValueError, match="inadmissible browser session"):
        resolve_oauth_browser_subject(
            browser["logged_in_pubkey"],
            browser.get("login_method"),
            browser.get("access_level"),
            get_user_fn=lambda _subject: user,
        )


def test_every_probe_authorization_sequence_establishes_browser_admission_first():
    authorization = probe_function("authorization_code")
    authorization_statements = list(authorization.body)
    authorization_admission_index = next(
        index
        for index, statement in enumerate(authorization_statements)
        if isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "admit_synthetic_browser"
    )
    authorization_request_index = next(
        index
        for index, statement in enumerate(authorization_statements)
        if isinstance(statement, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "response" for target in statement.targets)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Attribute)
        and statement.value.func.attr == "get"
    )
    assert authorization_admission_index < authorization_request_index

    auth_probe_function = probe_function("auth_probe")
    statements = list(auth_probe_function.body)
    admission_index = next(
        index
        for index, statement in enumerate(statements)
        if isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "admit_synthetic_browser"
    )
    first_negative_request = next(
        index
        for index, statement in enumerate(statements)
        if isinstance(statement, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "mismatched" for target in statement.targets)
    )
    assert admission_index < first_negative_request


def id_token_verification_block() -> ast.Try:
    function = probe_function("auth_probe")
    return next(
        statement
        for statement in function.body
        if isinstance(statement, ast.Try)
        and any(
            isinstance(node, ast.Name)
            and node.id == "id_signing_key"
            and isinstance(node.ctx, ast.Store)
            for node in ast.walk(statement)
        )
    )


def make_id_token(
    signing_key: rsa.RSAPrivateKey,
    *,
    issuer: str = "https://rehearsal-issuer.invalid",
    audience: str = "rehearsal-client",
    missing_claim: str | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "exp": now + timedelta(minutes=5),
        "iat": now,
        "iss": issuer,
        "sub": "ab" * 32,
        "aud": audience,
    }
    if missing_claim is not None:
        claims.pop(missing_claim)
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "rehearsal-key"})


def execute_id_token_verification(
    id_token: str,
    signing_key: rsa.RSAPrivateKey,
    *,
    decode_calls: list[dict[str, object]],
    lookup_calls: list[tuple[str, str]],
) -> dict[str, object]:
    def require(value, code):
        if not value:
            raise SyntheticProbeFailure(code)

    def get_key_by_kid(directory, kid):
        lookup_calls.append((directory, kid))
        return signing_key

    def decode(encoded, key, **kwargs):
        decode_calls.append({"encoded": encoded, "key": key, "kwargs": dict(kwargs)})
        return jwt.decode(encoded, key, **kwargs)

    namespace = {
        "ProbeFailure": SyntheticProbeFailure,
        "get_key_by_kid": get_key_by_kid,
        "id_token": id_token,
        "jwt": SimpleNamespace(get_unverified_header=jwt.get_unverified_header, decode=decode),
        "os": SimpleNamespace(
            environ={
                "JWKS_DIR": "/synthetic/rehearsal-jwks",
                "JWT_ISSUER": "https://rehearsal-issuer.invalid",
            }
        ),
        "registration": {"client_id": "rehearsal-client"},
        "require": require,
    }
    module = ast.Module(body=[id_token_verification_block()], type_ignores=[])
    exec(compile(module, "<rehearsal-id-token-verification>", "exec"), namespace)
    return namespace["id_claims"]


class NeverRunner:
    def run(self, *_args, **_kwargs):
        raise AssertionError("runner invoked")


class SuccessfulRehearsalRunner:
    """Filesystem-aware command double for one complete rehearsal."""

    def __init__(
        self,
        *,
        fail_migration_index: int | None = None,
        relational_constraints: set[str] | frozenset[str] | None = None,
        check_semantics: set[str] | frozenset[str] | None = None,
        index_semantics: set[str] | frozenset[str] | None = None,
        serial_semantics: set[str] | frozenset[str] | None = None,
        phase_11_source_results: dict[str, rehearsal.CommandResult] | None = None,
        phase_11_restored_results: dict[str, rehearsal.CommandResult] | None = None,
    ):
        self.calls: list[dict[str, object]] = []
        self.fail_migration_index = fail_migration_index
        self.migration_calls_seen = 0
        self.started_configuration = ""
        self.relational_constraints = (
            rehearsal.MIGRATION_RELATIONAL_CONSTRAINTS
            if relational_constraints is None
            else frozenset(relational_constraints)
        )
        self.index_semantics = (
            rehearsal.MIGRATION_8_9_INDEX_SEMANTICS
            if index_semantics is None
            else frozenset(index_semantics)
        )
        self.check_semantics = (
            rehearsal.MIGRATION_8_9_CHECK_SEMANTICS
            if check_semantics is None
            else frozenset(check_semantics)
        )
        self.serial_semantics = (
            rehearsal.MIGRATION_8_9_SERIAL_SEMANTICS
            if serial_semantics is None
            else frozenset(serial_semantics)
        )
        self.phase_11_source_results = dict(phase_11_source_results or {})
        self.phase_11_restored_results = dict(phase_11_restored_results or {})
        plan = rehearsal.load_plan()
        baseline = plan["synthetic_baseline"]
        assert isinstance(baseline, dict)
        baseline_tables = baseline["tables"]
        assert isinstance(baseline_tables, list)
        self.baseline_table_names = {str(item["table"]) for item in baseline_tables}
        self.baseline_columns = {f"{item['table']}.{column}" for item in baseline_tables for column in item["columns"]}
        self.baseline_constraints = {str(item["primary_key"]) for item in baseline_tables} | {
            str(name) for item in baseline_tables for name in item["foreign_keys"]
        }
        self.baseline_indexes = {str(name) for item in baseline_tables for name in item["indexes"]}
        (
            self.migrated_tables,
            self.migrated_columns,
            _constraints,
            _indexes,
        ) = rehearsal._migration_catalog_contract(ROOT)
        self.named_constraints = rehearsal._migration_named_constraint_contract(ROOT)
        self.check_counts = rehearsal._migration_check_constraint_counts(ROOT)
        self.explicit_indexes = rehearsal._migration_explicit_index_contract(ROOT)

    @staticmethod
    def _lines(values: set[str] | frozenset[str]) -> str:
        return "".join(f"{value}\n" for value in sorted(values))

    @staticmethod
    def _argument_after(argv: tuple[str, ...], flag: str) -> str:
        return argv[argv.index(flag) + 1]

    def _git(self, argv: tuple[str, ...]) -> rehearsal.CommandResult:
        if "status" in argv:
            return rehearsal.CommandResult(0, "", "")
        if "cat-file" in argv:
            return rehearsal.CommandResult(0, "", "")
        if "rev-parse" in argv:
            return rehearsal.CommandResult(0, argv[-1].split("^", 1)[0] + "\n", "")
        if "archive" in argv:
            output_argument = next(item for item in argv if item.startswith("--output="))
            output = Path(output_argument.split("=", 1)[1])
            with tarfile.open(output, mode="w") as archive:
                archive.add(ROOT / "README.md", arcname="README.md", recursive=False)
                if output.name == "staging.tar":
                    for relative in rehearsal.MIGRATIONS:
                        archive.add(ROOT / relative, arcname=relative, recursive=False)
            return rehearsal.CommandResult(0, "", "")
        raise AssertionError(f"unexpected git command: {argv}")

    def _psql(self, argv: tuple[str, ...]) -> rehearsal.CommandResult:
        if "--file" in argv:
            file_path = self._argument_after(argv, "--file")
            if "/migrations/" in file_path:
                self.migration_calls_seen += 1
                if self.fail_migration_index == self.migration_calls_seen:
                    return rehearsal.CommandResult(7, "raw forbidden output", "raw forbidden error")
            return rehearsal.CommandResult(0, "", "")

        sql = self._argument_after(argv, "--command")
        target = self._argument_after(argv, "--dbname")
        restored = target.endswith("_restored")
        if "PHASE_6_CHECK_SEMANTICS_V1" in sql:
            return rehearsal.CommandResult(0, self._lines(self.check_semantics), "")
        if "PHASE_6_INDEX_SEMANTICS_V1" in sql:
            return rehearsal.CommandResult(0, self._lines(self.index_semantics), "")
        for category, marker in PHASE_11_MARKERS.items():
            if marker in sql:
                if restored and category in self.phase_11_restored_results:
                    return self.phase_11_restored_results[category]
                if not restored and category in self.phase_11_source_results:
                    return self.phase_11_source_results[category]
                return rehearsal.CommandResult(0, PHASE_11_CATALOG_OUTPUTS[category], "")
        if "information_schema.tables" in sql:
            values = self.migrated_tables if "action_operations" in sql else self.baseline_table_names
            return rehearsal.CommandResult(0, self._lines(values), "")
        if "information_schema.columns" in sql:
            values = self.migrated_columns if "action_operations" in sql else self.baseline_columns
            return rehearsal.CommandResult(0, self._lines(values), "")
        if sql.startswith("SELECT conname FROM pg_constraint"):
            return rehearsal.CommandResult(0, self._lines(self.baseline_constraints), "")
        if "SELECT r.relname||'|'||c.conname FROM pg_constraint" in sql:
            return rehearsal.CommandResult(0, self._lines(self.named_constraints), "")
        if "unnest(c.conkey)" in sql and "c.contype IN ('p','u','f')" in sql:
            return rehearsal.CommandResult(0, self._lines(self.relational_constraints), "")
        if "count(*)::text FROM pg_constraint" in sql:
            return rehearsal.CommandResult(0, self._lines(self.check_counts), "")
        if "c.contype='c'" in sql and "unnest(c.conkey)" in sql:
            return rehearsal.CommandResult(0, self._lines(self.check_semantics), "")
        if sql.startswith("SELECT indexname FROM pg_indexes"):
            return rehearsal.CommandResult(0, self._lines(self.baseline_indexes), "")
        if "tablename||'|'||indexname" in sql:
            return rehearsal.CommandResult(0, self._lines(self.explicit_indexes), "")
        if "format_type(a.atttypid,a.atttypmod)" in sql:
            return rehearsal.CommandResult(0, self._lines(self.serial_semantics), "")
        if "count(*) FILTER" in sql:
            if restored and "counts" in self.phase_11_restored_results:
                return self.phase_11_restored_results["counts"]
            return rehearsal.CommandResult(0, "12|2|48\n", "")
        if "pg_get_userbyid" in sql:
            if restored and "ownership" in self.phase_11_restored_results:
                return self.phase_11_restored_results["ownership"]
            return rehearsal.CommandResult(0, "public|r|users|REHEARSAL_ROLE\n", "")
        if "AS row_count" in sql:
            if restored and "row_count" in self.phase_11_restored_results:
                return self.phase_11_restored_results["row_count"]
            all_tables = self.baseline_table_names | self.migrated_tables
            values = {f"{table}|{1 if table in self.baseline_table_names else 0}" for table in all_tables}
            return rehearsal.CommandResult(0, self._lines(values), "")
        if sql.lstrip().startswith("DO $$"):
            if restored and "queryability" in self.phase_11_restored_results:
                return self.phase_11_restored_results["queryability"]
            return rehearsal.CommandResult(0, "", "")
        raise AssertionError(f"unexpected psql query: {sql}")

    def run(self, argv, *, cwd, env, input_text=None, timeout=120):
        normalized = tuple(str(item) for item in argv)
        self.calls.append(
            {
                "argv": normalized,
                "cwd": Path(cwd),
                "env": dict(env),
                "input_text": input_text,
                "timeout": timeout,
            }
        )
        command = Path(normalized[0]).name
        if command == "git":
            return self._git(normalized)
        if command == "initdb":
            cluster = Path(self._argument_after(normalized, "--pgdata"))
            cluster.mkdir()
            (cluster / "PG_VERSION").write_text("16\n", encoding="utf-8")
            (cluster / "postgresql.conf").write_text("# synthetic initdb config\n", encoding="utf-8")
            return rehearsal.CommandResult(0, "", "")
        if command == "pg_ctl":
            if normalized[-1] == "start":
                cluster = Path(self._argument_after(normalized, "--pgdata"))
                self.started_configuration = (cluster / "postgresql.conf").read_text(encoding="utf-8")
            return rehearsal.CommandResult(0, "", "")
        if command == "createdb":
            return rehearsal.CommandResult(0, "", "")
        if command == "psql":
            return self._psql(normalized)
        if command == "python":
            mode = normalized[-1]
            evidence = rehearsal.AUTH_PROBE_EVIDENCE if mode == "auth" else rehearsal.STARTUP_PROBE_EVIDENCE
            payload = json.dumps(
                {"status": "PASS", "evidence_codes": list(evidence)},
                sort_keys=True,
                separators=(",", ":"),
            )
            return rehearsal.CommandResult(0, payload + "\n", "")
        if command == "pg_dump":
            if "--file" in normalized:
                archive = Path(self._argument_after(normalized, "--file"))
                archive.write_bytes(b"PGDMP synthetic archive")
                return rehearsal.CommandResult(0, "", "")
            target = self._argument_after(normalized, "--dbname")
            marker = "RESTORED" if target.endswith("_restored") else "PRIMARY"
            semantic_schema = RAW_RESTORED_SCHEMA if target.endswith("_restored") else RAW_SOURCE_SCHEMA
            schema = f"-- synthetic schema\n\\restrict {marker}\n{semantic_schema}\\unrestrict {marker}\n"
            return rehearsal.CommandResult(0, schema, "")
        if command == "pg_restore":
            if "--list" in normalized:
                return rehearsal.CommandResult(0, "; synthetic archive\n1; TABLE public users rehearsal_owner\n", "")
            return rehearsal.CommandResult(0, "", "")
        raise AssertionError(f"unexpected command: {normalized}")


def run_phase_11(tmp_path: Path, runner: SuccessfulRehearsalRunner) -> rehearsal.PhaseOutcome:
    request = execute_request(tmp_path)
    resolved = rehearsal.validate_execute_request(request)
    guard = rehearsal.WorkspaceGuard.create(request.workspace, tmp_path, "phase-11-unit-owner")
    state = rehearsal.ExecutionState(
        resolved=resolved,
        plan=rehearsal.load_plan(),
        guard=guard,
        staging_snapshot=ROOT,
        primary_target="hodlxxi_rehearsal_phase11source",
        restored_target="hodlxxi_rehearsal_phase11source_restored",
    )
    try:
        return rehearsal.RehearsalHarness(runner)._phase_11(state)
    finally:
        guard.cleanup()


def test_phase_11_accepts_catalog_equivalence_when_normalized_pg_dump_text_differs(tmp_path):
    assert rehearsal._normalized_schema(RAW_SOURCE_SCHEMA) != rehearsal._normalized_schema(RAW_RESTORED_SCHEMA)
    runner = SuccessfulRehearsalRunner()

    outcome = run_phase_11(tmp_path, runner)

    assert outcome.status == "PASS"
    assert outcome.evidence_code == "RESTORE_COMPARISON_COMPLETE"
    assert rehearsal.SHA256_PATTERN.fullmatch(str(outcome.artifact_sha256))
    schema_dump_calls = [
        call
        for call in runner.calls
        if Path(call["argv"][0]).name == "pg_dump" and "--schema-only" in call["argv"]
    ]
    assert len(schema_dump_calls) == 2
    ownership_calls = [
        call
        for call in runner.calls
        if "--command" in call["argv"]
        and "pg_get_userbyid" in call["argv"][call["argv"].index("--command") + 1]
    ]
    assert len(ownership_calls) == 2
    assert all(
        "c.relkind::text" in call["argv"][call["argv"].index("--command") + 1]
        for call in ownership_calls
    )


@pytest.mark.parametrize(
    ("_description", "category", "restored_result", "evidence_code"),
    PHASE_11_FAIL_CLOSED_CASES,
    ids=[case[0] for case in PHASE_11_FAIL_CLOSED_CASES],
)
def test_phase_11_semantic_comparison_fails_closed(
    tmp_path,
    _description,
    category,
    restored_result,
    evidence_code,
):
    runner = SuccessfulRehearsalRunner(phase_11_restored_results={category: restored_result})

    with pytest.raises(rehearsal.CommandFailure, match=f"^{evidence_code}$") as caught:
        run_phase_11(tmp_path, runner)

    assert caught.value.evidence_code == evidence_code
    assert "forbidden raw" not in str(caught.value)


@pytest.mark.parametrize(
    ("side", "category", "evidence_code"),
    PHASE_11_CATALOG_QUERY_FAILURE_CASES,
    ids=[f"{case[0]} {case[1]}" for case in PHASE_11_CATALOG_QUERY_FAILURE_CASES],
)
def test_phase_11_catalog_query_failures_use_sanitized_scoped_evidence(
    tmp_path,
    side,
    category,
    evidence_code,
):
    failed = rehearsal.CommandResult(9, "forbidden raw stdout", "forbidden raw stderr")
    source_results = {category: failed} if side == "source" else None
    restored_results = {category: failed} if side == "restored" else None
    runner = SuccessfulRehearsalRunner(
        phase_11_source_results=source_results,
        phase_11_restored_results=restored_results,
    )

    with pytest.raises(rehearsal.CommandFailure, match=f"^{evidence_code}$") as caught:
        run_phase_11(tmp_path, runner)

    assert caught.value.evidence_code == evidence_code
    assert "forbidden raw" not in str(caught.value)


def test_phase_11_catalog_queries_cover_required_semantic_fields():
    relation_sql = rehearsal.PHASE_11_RELATION_INVENTORY_SQL
    assert "n.nspname" in relation_sql
    assert "c.relname" in relation_sql
    assert "c.relkind::text" in relation_sql

    column_sql = rehearsal.PHASE_11_COLUMN_SEMANTICS_SQL
    for field in (
        "a.attnum",
        "a.attname",
        "format_type(a.atttypid, a.atttypmod)",
        "a.attnotnull",
        "a.attidentity::text",
        "a.attgenerated::text",
        "pg_get_expr(d.adbin, d.adrelid, false)",
    ):
        assert field in column_sql

    constraint_sql = rehearsal.PHASE_11_CONSTRAINT_SEMANTICS_SQL
    for field in (
        "con.conname",
        "con.contype::text",
        "unnest(con.conkey) WITH ORDINALITY",
        "unnest(con.confkey) WITH ORDINALITY",
        "con.confdeltype::text",
        "con.confupdtype::text",
        "con.condeferrable",
        "con.condeferred",
        "con.convalidated",
    ):
        assert field in constraint_sql

    index_sql = rehearsal.PHASE_11_INDEX_SEMANTICS_SQL
    for field in (
        "index_catalog.indisunique",
        "index_catalog.indisvalid",
        "pg_get_indexdef(index_catalog.indexrelid, 0, false)",
        "pg_get_expr(index_catalog.indpred, index_catalog.indrelid, false)",
    ):
        assert field in index_sql
    assert "constraint_catalog.contype IN ('p', 'u', 'x')" in index_sql

    sequence_sql = rehearsal.PHASE_11_SEQUENCE_SEMANTICS_SQL
    for field in (
        "sequence_catalog.seqstart",
        "sequence_catalog.seqincrement",
        "sequence_catalog.seqmax",
        "sequence_catalog.seqmin",
        "sequence_catalog.seqcache",
        "sequence_catalog.seqcycle",
        "sequence_state.last_value",
        "sequence_state.is_called",
    ):
        assert field in sequence_sql


def test_phase_11_check_identity_uses_postgresql_reparse_without_regex_rewriting():
    sql = rehearsal.PHASE_11_CHECK_SEMANTICS_SQL
    assert sql.count("pg_get_constraintdef(") == 2
    assert "CREATE TEMP TABLE pg_temp.phase_11_check_probe (LIKE %I.%I)" in sql
    assert "ALTER TABLE pg_temp.phase_11_check_probe ADD CONSTRAINT %I %s" in sql
    assert "con.contype = 'c'" in sql
    assert "canonical_definition" in sql
    assert "regexp" not in sql.casefold()
    assert "replace(" not in sql.casefold()


def test_complete_fourteen_phase_simulation_uses_exact_isolated_commands(tmp_path):
    runner = SuccessfulRehearsalRunner()
    request = execute_request(tmp_path)
    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 1.0,
        token_factory=lambda: "synthetic001",
    ).execute(request)

    assert result["execution_status"] == "PASS"
    assert [item["phase"] for item in result["phases"]] == list(rehearsal.PHASES)
    assert all(item["status"] == "PASS" for item in result["phases"])
    assert all(item["cleanup_status"] == "COMPLETE" for item in result["phases"])
    assert result["phases"][3]["evidence_code"] == "STARTUP_PROBE_COMPLETE"
    assert not request.workspace.exists()
    rehearsal.validate_sanitized_result(result)

    archive_calls = [call for call in runner.calls if "archive" in call["argv"]]
    assert [call["argv"][-1] for call in archive_calls] == [rehearsal.PRODUCTION_SHA, rehearsal.STAGING_SHA]

    probe_calls = [call for call in runner.calls if Path(call["argv"][0]).name == "python"]
    assert [(call["cwd"].name, call["argv"][-1]) for call in probe_calls] == [
        ("staging", "startup"),
        ("staging", "auth"),
        ("production", "startup"),
        ("staging", "startup"),
        ("staging", "auth"),
    ]
    for call in probe_calls:
        assert tuple(call["env"]) == rehearsal.APPLICATION_ENVIRONMENT_KEYS
        generated_runtime_keys = {"DATABASE_URL", "FLASK_SECRET_KEY", "JWKS_DIR"}
        assert set(call["env"]).isdisjoint(rehearsal.INHERITED_RUNTIME_KEYS - generated_runtime_keys)
        assert call["env"]["PYTHONPATH"] == str(call["cwd"])

    migration_calls = [
        call
        for call in runner.calls
        if Path(call["argv"][0]).name == "psql"
        and "--file" in call["argv"]
        and "/migrations/" in call["argv"][call["argv"].index("--file") + 1]
    ]
    applied = ["migrations/" + Path(call["argv"][call["argv"].index("--file") + 1]).name for call in migration_calls]
    assert applied == list(rehearsal.MIGRATIONS)
    assert len(applied) == 9
    assert len(set(applied)) == 9
    flattened = [token for call in runner.calls for token in call["argv"]]
    assert not any("2026-02-10_client_billing.sql" in token for token in flattened)
    assert not any("2026-05-28_nip17_envelopes.sql" in token for token in flattened)

    database_calls = [
        call
        for call in runner.calls
        if Path(call["argv"][0]).name in {"createdb", "psql", "pg_dump", "pg_restore"} and "--dbname" in call["argv"]
    ]
    assert database_calls
    for call in database_calls:
        assert "--host" in call["argv"]
        socket_path = call["argv"][call["argv"].index("--host") + 1]
        assert socket_path == str(request.workspace / "socket")
        assert "--no-password" in call["argv"]
    assert "listen_addresses = ''" in runner.started_configuration
    assert "unix_socket_permissions = 0700" in runner.started_configuration

    created_targets = [call["argv"][-1] for call in runner.calls if Path(call["argv"][0]).name == "createdb"]
    assert len(created_targets) == 2
    assert len(set(created_targets)) == 2
    assert all(rehearsal.DATABASE_TARGET_PATTERN.fullmatch(target) for target in created_targets)
    assert all(target not in {"postgres", "template0", "template1"} for target in created_targets)

    assert any(Path(call["argv"][0]).name == "pg_dump" and "--format=custom" in call["argv"] for call in runner.calls)
    assert any(Path(call["argv"][0]).name == "pg_restore" and "--dbname" in call["argv"] for call in runner.calls)
    assert all(Path(call["argv"][0]).name != "dropdb" for call in runner.calls)
    rendered = json.dumps(result)
    assert str(request.workspace) not in rendered
    assert not any(target in rendered for target in created_targets)
    assert "postgresql://" not in rendered


def test_failure_after_cluster_creation_still_cleans_owned_workspace(tmp_path):
    runner = SuccessfulRehearsalRunner(fail_migration_index=1)
    request = execute_request(tmp_path)
    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 2.0,
        token_factory=lambda: "synthetic002",
    ).execute(request)

    assert result["execution_status"] == "FAIL"
    assert result["phases"][5]["status"] == "FAIL"
    assert result["phases"][5]["evidence_code"] == "ORDERED_MIGRATION_FAILED"
    assert result["phases"][12]["status"] == "PASS"
    assert not request.workspace.exists()
    rendered = json.dumps(result)
    assert "raw forbidden output" not in rendered
    assert "raw forbidden error" not in rendered


@pytest.mark.parametrize("migration_index", [8, 9])
def test_each_new_migration_failure_stops_in_phase_five_and_cleans(tmp_path, migration_index):
    runner = SuccessfulRehearsalRunner(fail_migration_index=migration_index)
    request = execute_request(tmp_path)
    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 2.25,
        token_factory=lambda: f"migration_{migration_index}",
    ).execute(request)

    assert runner.migration_calls_seen == migration_index
    assert result["execution_status"] == "FAIL"
    assert result["phases"][5]["phase"] == "REHEARSAL_05_APPLY_NINE_MIGRATIONS"
    assert result["phases"][5]["evidence_code"] == "ORDERED_MIGRATION_FAILED"
    assert result["phases"][6]["evidence_code"] == "PREREQUISITE_NOT_PASS"
    assert result["phases"][12]["evidence_code"] == "CLEANUP_COMPLETE"
    assert not request.workspace.exists()


def test_outer_finally_cleans_workspace_on_keyboard_interrupt(tmp_path, monkeypatch):
    request = execute_request(tmp_path)
    resolved = rehearsal.validate_execute_request(request)
    harness = rehearsal.RehearsalHarness(NeverRunner(), monotonic=lambda: 3.0)

    def phase_00(_request, plan, state_box):
        state = rehearsal.ExecutionState(resolved=resolved, plan=plan)
        state.guard = rehearsal.WorkspaceGuard.create(request.workspace, tmp_path, "interrupt-owner")
        state_box["state"] = state
        return rehearsal.PhaseOutcome("PASS", "PREFLIGHT_COMPLETE", rehearsal.DETAILS["PREFLIGHT_COMPLETE"])

    monkeypatch.setattr(harness, "_phase_00", phase_00)
    monkeypatch.setattr(harness, "_phase_01", lambda _state: (_ for _ in ()).throw(KeyboardInterrupt()))

    with pytest.raises(KeyboardInterrupt):
        harness.execute(request)
    assert not request.workspace.exists()


def test_unexpected_phase_exception_is_sanitized_and_cleanup_still_runs(tmp_path, monkeypatch):
    runner = SuccessfulRehearsalRunner()
    request = execute_request(tmp_path)
    harness = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 3.5,
        token_factory=lambda: "synthetic003",
    )
    monkeypatch.setattr(
        harness,
        "_phase_05",
        lambda _state: (_ for _ in ()).throw(RuntimeError("forbidden raw exception")),
    )

    result = harness.execute(request)

    assert result["execution_status"] == "FAIL"
    assert result["phases"][5]["status"] == "FAIL"
    assert result["phases"][5]["evidence_code"] == "UNEXPECTED_FAILURE"
    assert result["phases"][12]["status"] == "PASS"
    assert "forbidden raw exception" not in json.dumps(result)
    assert not request.workspace.exists()


def test_workspace_creation_removes_partial_owned_marker_on_unexpected_error(tmp_path, monkeypatch):
    workspace = tmp_path / "partial-workspace"

    def fail_assert_owned(_guard):
        raise RuntimeError("synthetic marker validation failure")

    monkeypatch.setattr(rehearsal.WorkspaceGuard, "assert_owned", fail_assert_owned)
    with pytest.raises(RuntimeError, match="synthetic marker validation failure"):
        rehearsal.WorkspaceGuard.create(workspace, tmp_path, "partial-owner")
    assert not workspace.exists()


def test_migrated_catalog_contract_includes_inline_unique_checks_and_foreign_keys():
    assert rehearsal.MIGRATION_RELATIONAL_CONSTRAINTS == EXPECTED_RELATIONAL_CONSTRAINTS
    assert (
        "canonical_admission_edge_legs|f|edge_id|canonical_admission_edges|edge_id|a"
        in rehearsal.MIGRATION_RELATIONAL_CONSTRAINTS
    )
    assert "action_step_up_challenges|u|nonce|||" in rehearsal.MIGRATION_RELATIONAL_CONSTRAINTS
    assert (
        "trusted_covenant_registered_outpoints|f|registration_id|"
        "trusted_covenant_registrations|registration_id|c" in rehearsal.MIGRATION_RELATIONAL_CONSTRAINTS
    )
    checks = rehearsal._migration_check_constraint_counts(ROOT)
    assert "canonical_admission_edges|23" in checks
    assert "canonical_admission_edge_legs|10" in checks
    indexes = rehearsal._migration_explicit_index_contract(ROOT)
    assert "canonical_admission_edges|uq_admission_edge_effective_child_id" in indexes
    assert "canonical_admission_edge_legs|idx_admission_leg_edge" in indexes
    assert "canonical_root_registration_bindings|11" in checks
    assert "canonical_covenant_funding_sets|11" in checks
    assert "canonical_covenant_funding_outpoints|6" in checks
    assert (
        "canonical_root_registration_bindings|uq_root_registration_binding_effective_root"
        in indexes
    )
    assert "canonical_covenant_funding_sets|uq_funding_set_effective_registration" in indexes
    assert "canonical_covenant_funding_outpoints|idx_funding_outpoint_set" in indexes


def test_phase_06_relational_catalog_sql_casts_contype_and_preserves_shape(tmp_path):
    runner = SuccessfulRehearsalRunner()
    request = execute_request(tmp_path)

    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 3.75,
        token_factory=lambda: "relational_sql",
    ).execute(request)

    assert result["execution_status"] == "PASS"
    assert result["phases"][6]["phase"] == "REHEARSAL_06_VERIFY_MIGRATED_CATALOG"
    assert result["phases"][6]["evidence_code"] == "MIGRATED_CATALOG_VERIFIED"
    relational_calls = [
        call
        for call in runner.calls
        if Path(call["argv"][0]).name == "psql"
        and "--command" in call["argv"]
        and "unnest(c.conkey)" in call["argv"][call["argv"].index("--command") + 1]
        and "c.contype IN ('p','u','f')" in call["argv"][call["argv"].index("--command") + 1]
    ]
    assert len(relational_calls) == 1
    sql = relational_calls[0]["argv"][relational_calls[0]["argv"].index("--command") + 1]
    assert "SELECT r.relname||'|'||c.contype::text||'|'||" in sql
    assert "||c.contype||" not in sql
    assert "CASE WHEN c.contype='f' THEN c.confdeltype::text ELSE '' END" in sql
    assert sql.count("string_agg(a.attname,',' ORDER BY k.ordinality)") == 2
    assert "FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)" in sql
    assert "FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum,ordinality)" in sql
    assert "a.attrelid=c.confrelid AND a.attnum=k.attnum" in sql
    assert "LEFT JOIN pg_class rr ON rr.oid=c.confrelid" in sql
    assert sql.count("c.contype IN ('p','u','f')") == 1
    assert sql.endswith("AND c.contype IN ('p','u','f') ORDER BY 1;")


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_phase_06_relational_catalog_mismatch_remains_fail_closed(tmp_path, mutation):
    actual = set(EXPECTED_RELATIONAL_CONSTRAINTS)
    if mutation == "missing":
        actual.remove("action_operations|p|operation_id|||")
    else:
        actual.add("action_operations|u|unexpected_column|||")
    runner = SuccessfulRehearsalRunner(relational_constraints=actual)
    request = execute_request(tmp_path)

    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 3.875,
        token_factory=lambda: f"relational_{mutation}",
    ).execute(request)

    phase = result["phases"][6]
    assert result["execution_status"] == "FAIL"
    assert phase["phase"] == "REHEARSAL_06_VERIFY_MIGRATED_CATALOG"
    assert phase["status"] == "FAIL"
    assert phase["evidence_code"] == "MIGRATED_RELATIONAL_CONSTRAINT_MISMATCH"
    assert phase["sanitized_detail"] == rehearsal.DETAILS["COMMAND_FAILED"]
    assert result["phases"][7]["evidence_code"] == "PREREQUISITE_NOT_PASS"
    assert result["phases"][12]["evidence_code"] == "CLEANUP_COMPLETE"
    assert not request.workspace.exists()


@pytest.mark.parametrize(
    ("removed", "replacement"),
    [
        ("canonical_root_registration_bindings|p|binding_id|||", None),
        ("canonical_covenant_funding_sets|u|canonical_funding_set_sha256|||", None),
        (
            "canonical_covenant_funding_outpoints|f|funding_set_id|canonical_covenant_funding_sets|funding_set_id|c",
            "canonical_covenant_funding_outpoints|f|funding_set_id|canonical_covenant_funding_sets|funding_set_id|a",
        ),
    ],
)
def test_phase_06_rejects_new_relational_catalog_mutations(tmp_path, removed, replacement):
    actual = set(EXPECTED_RELATIONAL_CONSTRAINTS)
    actual.remove(removed)
    if replacement:
        actual.add(replacement)
    runner = SuccessfulRehearsalRunner(relational_constraints=actual)
    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 3.9,
        token_factory=lambda: "new_relational_mutation",
    ).execute(execute_request(tmp_path))
    assert result["phases"][6]["evidence_code"] == "MIGRATED_RELATIONAL_CONSTRAINT_MISMATCH"


def test_phase_06_rejects_wrong_new_partial_index_predicate(tmp_path):
    actual = set(rehearsal.MIGRATION_8_9_INDEX_SEMANTICS)
    expected = next(item for item in actual if "uq_funding_set_effective_registration" in item)
    actual.remove(expected)
    actual.add(expected.rsplit("|", 1)[0] + "|none")
    runner = SuccessfulRehearsalRunner(index_semantics=actual)
    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 3.95,
        token_factory=lambda: "wrong_partial_predicate",
    ).execute(execute_request(tmp_path))
    assert result["phases"][6]["evidence_code"] == "MIGRATED_INDEX_SEMANTICS_MISMATCH"


@pytest.mark.parametrize("mutation", ["missing", "extra", "renamed"])
def test_phase_06_check_column_sets_remain_fail_closed(tmp_path, mutation):
    actual = set(rehearsal.MIGRATION_8_9_CHECK_SEMANTICS)
    identity = (
        "canonical_covenant_funding_sets|ck_funding_set_participants|"
        "counterparty_xonly_pubkey,subject_xonly_pubkey"
    )
    actual.remove(identity)
    if mutation == "missing":
        actual.add(identity.replace(",subject_xonly_pubkey", ""))
    elif mutation == "extra":
        actual.add(
            identity.replace(
                ",subject_xonly_pubkey",
                ",extra_xonly_pubkey,subject_xonly_pubkey",
            )
        )
    else:
        actual.add(
            identity.replace("counterparty_xonly_pubkey", "renamed_xonly_pubkey")
        )
    runner = SuccessfulRehearsalRunner(check_semantics=actual)
    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 3.96,
        token_factory=lambda: f"{mutation}_check_semantics",
    ).execute(execute_request(tmp_path))
    assert result["phases"][6]["evidence_code"] == "MIGRATED_CHECK_SEMANTICS_MISMATCH"


@pytest.mark.parametrize(
    "columns",
    [
        ("lifecycle_state", "created_at", "effective_at"),
        ("effective_at", "lifecycle_state", "created_at"),
    ],
)
def test_phase_06_check_column_set_canonicalization_is_input_order_independent(columns):
    assert ",".join(sorted(columns)) == "created_at,effective_at,lifecycle_state"


def test_phase_06_expected_check_column_sets_are_lexicographically_canonical():
    for identity in rehearsal.MIGRATION_8_9_CHECK_SEMANTICS:
        columns = identity.rsplit("|", 1)[1].split(",")
        assert columns == sorted(columns)


def test_phase_06_uses_location_normalized_parse_tree_equivalence_for_checks_and_predicates():
    check_sql = rehearsal._migration_8_9_check_semantics_sql(ROOT)
    assert "PHASE_6_CHECK_SEMANTICS_V1" in check_sql
    assert "string_agg(attribute.attname,',' ORDER BY attribute.attname)" in check_sql
    assert "string_agg(attribute.attname,',' ORDER BY key.ordinality)" not in check_sql
    assert "unnest(actual_constraint.conkey) WITH ORDINALITY" not in check_sql
    assert "actual_constraint.conbin=probe_constraint.conbin" not in check_sql
    actual_normalized = rehearsal._normalized_check_tree_sql("actual_constraint.conbin")
    probe_normalized = rehearsal._normalized_check_tree_sql("probe_constraint.conbin")
    assert check_sql.count(actual_normalized) == 1
    assert check_sql.count(probe_normalized) == 1
    assert actual_normalized.replace("actual_constraint", "probe_constraint") == probe_normalized
    assert "ALTER TABLE phase_6_root_checks ADD CONSTRAINT ck_root_registration_binding_lifecycle" in check_sql
    assert "ALTER TABLE phase_6_funding_set_checks ADD CONSTRAINT ck_funding_set_lifecycle" in check_sql
    assert "ALTER TABLE phase_6_funding_outpoint_checks ADD CONSTRAINT ck_funding_outpoint_vout" in check_sql
    assert "pg_get_constraintdef" not in check_sql
    assert "pg_get_expr" not in check_sql

    index_sql = rehearsal.PHASE_6_INDEX_SEMANTICS_SQL
    assert "PHASE_6_INDEX_SEMANTICS_V1" in index_sql
    assert index_sql.count("WHERE lifecycle_state = 'effective'") == 2
    assert "index_catalog.indpred=reference_catalog.indpred" in index_sql
    assert "pg_get_expr" not in index_sql


def test_phase_06_check_tree_normalization_is_exactly_location_only():
    pattern = re.compile(rehearsal.PG_NODE_TREE_LOCATION_PATTERN)
    replacement = rehearsal.PG_NODE_TREE_LOCATION_REPLACEMENT

    def normalize(value: str) -> str:
        return pattern.sub(replacement, value)

    assert normalize(":location 0 :location 42 :location -7}") == (
        ":location -1 :location -1 :location -1}"
    )
    for value in (
        ":location +7 ",
        ":location 7x ",
        ":location --7 ",
        ":location  ",
        ":locations 7 ",
        ":other_location 7 ",
        ":other:location 7 ",
    ):
        assert normalize(value) == value


@pytest.mark.parametrize(
    ("actual", "probe"),
    [
        ("{CONST :constvalue 4 :location 8}", "{CONST :constvalue 4 :location 91}"),
        ("{OPEXPR :opno 96 :location -1}", "{OPEXPR :opno 96 :location 145}"),
    ],
)
def test_phase_06_check_tree_normalization_accepts_only_location_differences(actual, probe):
    pattern = re.compile(rehearsal.PG_NODE_TREE_LOCATION_PATTERN)
    replacement = rehearsal.PG_NODE_TREE_LOCATION_REPLACEMENT
    assert pattern.sub(replacement, actual) == pattern.sub(replacement, probe)


@pytest.mark.parametrize(
    ("actual", "probe"),
    [
        ("{CONST :constvalue 4 :location 8}", "{CONST :constvalue 5 :location 8}"),
        ("{OPEXPR :opno 96 :location 8}", "{OPEXPR :opno 97 :location 8}"),
        ("{VAR :varattno 2 :location 8}", "{VAR :varattno 3 :location 8}"),
        ("{BOOLEXPR :boolop and :location 8}", "{BOOLEXPR :boolop or :location 8}"),
    ],
)
def test_phase_06_check_tree_normalization_preserves_semantic_mutations(actual, probe):
    pattern = re.compile(rehearsal.PG_NODE_TREE_LOCATION_PATTERN)
    replacement = rehearsal.PG_NODE_TREE_LOCATION_REPLACEMENT
    assert pattern.sub(replacement, actual) != pattern.sub(replacement, probe)


@pytest.mark.parametrize("mutation", ["missing", "wrong_owner"])
def test_phase_06_rejects_missing_or_wrongly_owned_bigserial_sequence(tmp_path, mutation):
    actual = set(rehearsal.MIGRATION_8_9_SERIAL_SEMANTICS)
    expected = next(iter(actual))
    if mutation == "missing":
        actual.clear()
    else:
        actual = {expected.rsplit("|", 2)[0] + "|canonical_covenant_funding_sets|funding_set_id"}
    runner = SuccessfulRehearsalRunner(serial_semantics=actual)
    result = rehearsal.RehearsalHarness(
        runner,
        monotonic=lambda: 3.975,
        token_factory=lambda: f"serial_{mutation}",
    ).execute(execute_request(tmp_path))
    assert result["phases"][6]["evidence_code"] == "MIGRATED_SERIAL_SEMANTICS_MISMATCH"


@pytest.mark.parametrize(
    "table",
    [
        "canonical_root_registration_bindings",
        "canonical_covenant_funding_sets",
        "canonical_covenant_funding_outpoints",
    ],
)
def test_phase_11_detects_new_table_catalog_mismatch(tmp_path, table):
    restored = rehearsal.CommandResult(0, phase_11_json_lines(["public", table, "r", "p", False]), "")
    runner = SuccessfulRehearsalRunner(phase_11_restored_results={"relation": restored})
    with pytest.raises(rehearsal.CommandFailure) as failure:
        run_phase_11(tmp_path, runner)
    assert failure.value.evidence_code == "RELATION_INVENTORY_MISMATCH"


@pytest.mark.parametrize(
    "mutation",
    ["extra_raw_output", "path_detail", "credential_detail", "dsn_evidence", "wrong_source"],
)
def test_sanitized_result_validator_rejects_runtime_leak_channels(tmp_path, mutation):
    request = execute_request(tmp_path, acknowledgement="wrong")
    valid = rehearsal.RehearsalHarness(NeverRunner(), monotonic=lambda: 4.0).execute(request)
    result = copy.deepcopy(valid)
    if mutation == "extra_raw_output":
        result["raw_postgresql_output"] = "synthetic server output"
    elif mutation == "path_detail":
        result["phases"][0]["sanitized_detail"] = "/tmp/private/workspace/postgres.log"
    elif mutation == "credential_detail":
        result["phases"][0]["sanitized_detail"] = "password=synthetic-secret"
    elif mutation == "dsn_evidence":
        result["phases"][0]["evidence_code"] = "postgresql://user:password@host/db"
    elif mutation == "wrong_source":
        result["staging_sha"] = "0" * 40
    with pytest.raises(ValueError):
        rehearsal.validate_sanitized_result(result)


def test_database_target_rejects_postgresql_identifier_truncation():
    with pytest.raises(rehearsal.SafetyViolation, match="DATABASE_TARGET_PATTERN_REJECTED"):
        rehearsal.validate_database_target("hodlxxi_rehearsal_" + "a" * 64)


def test_every_inherited_runtime_key_is_refused_before_runner_use(tmp_path):
    request = execute_request(tmp_path)
    for key in rehearsal.INHERITED_RUNTIME_KEYS:
        inherited = replace(request, environment_keys=frozenset({key}))
        with pytest.raises(rehearsal.SafetyViolation, match="INHERITED_RUNTIME_CONFIGURATION_REFUSED"):
            rehearsal.validate_execute_request(inherited)


def test_probe_installs_integration_guards_before_importing_application_factory():
    program = rehearsal.PROBE_PROGRAM
    compile(program, "<production-compatibility-rehearsal-probe>", "exec")
    envelope = program.index("with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):")
    protected_execution = program.index("    try:", envelope)
    factory_import = program.index("from app.factory import create_app")
    factory_classification = program.index("    except ProbeBlocked as exc:", factory_import)
    assert protected_execution < factory_import < factory_classification
    for guard in (
        "socket.socket.connect = guarded_connect",
        "socket.socket.connect_ex = guarded_connect_ex",
        "socket.socket.sendto = guarded_sendto",
        "socket.create_connection = blocked_side_effect",
        "urllib.request.urlopen = blocked_side_effect",
        "smtplib.SMTP = blocked_side_effect",
        "subprocess.run = blocked_side_effect",
        "requests.sessions.Session.request = blocked_side_effect",
        "app.utils.get_rpc_connection = blocked_side_effect",
    ):
        assert program.index(guard) < factory_import
    assert "https://synthetic-client.invalid/callback" in program
    assert "ID_TOKEN_MISSING" in program
    assert 'id_header.get("alg") == "RS256"' in program
    assert 'get_key_by_kid(os.environ["JWKS_DIR"], id_header["kid"])' in program
    assert "id_verification_key = id_signing_key.public_key()" in program
    assert "id_token,\n            id_verification_key," in program
    assert 'algorithms=["RS256"]' in program
    assert 'issuer=os.environ["JWT_ISSUER"]' in program
    assert 'audience=registration["client_id"]' in program
    assert 'options={"require": ["exp", "iat", "iss", "sub", "aud"]}' in program
    assert "/srv/ubid" not in program


def test_rehearsal_id_token_verification_uses_public_key_and_strict_decode_options():
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    id_token = make_id_token(signing_key)
    decode_calls: list[dict[str, object]] = []
    lookup_calls: list[tuple[str, str]] = []

    claims = execute_id_token_verification(
        id_token,
        signing_key,
        decode_calls=decode_calls,
        lookup_calls=lookup_calls,
    )

    assert claims["sub"] == "ab" * 32
    assert lookup_calls == [("/synthetic/rehearsal-jwks", "rehearsal-key")]
    assert len(decode_calls) == 1
    decode_call = decode_calls[0]
    verification_key = decode_call["key"]
    assert isinstance(signing_key, rsa.RSAPrivateKey)
    assert isinstance(verification_key, rsa.RSAPublicKey)
    assert not isinstance(verification_key, rsa.RSAPrivateKey)
    assert verification_key.public_numbers() == signing_key.public_key().public_numbers()
    assert decode_call["encoded"] == id_token
    assert decode_call["kwargs"] == {
        "algorithms": ["RS256"],
        "audience": "rehearsal-client",
        "issuer": "https://rehearsal-issuer.invalid",
        "options": {"require": ["exp", "iat", "iss", "sub", "aud"]},
    }


@pytest.mark.parametrize(
    ("failure", "expected_cause"),
    [
        ("invalid_signature", jwt.InvalidSignatureError),
        ("wrong_issuer", jwt.InvalidIssuerError),
        ("wrong_audience", jwt.InvalidAudienceError),
        ("missing_required_claim", jwt.MissingRequiredClaimError),
    ],
)
def test_rehearsal_id_token_verification_remains_fail_closed(failure, expected_cause):
    verification_signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token_signing_key = verification_signing_key
    token_options = {}
    if failure == "invalid_signature":
        token_signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif failure == "wrong_issuer":
        token_options["issuer"] = "https://wrong-issuer.invalid"
    elif failure == "wrong_audience":
        token_options["audience"] = "wrong-client"
    else:
        token_options["missing_claim"] = "exp"
    id_token = make_id_token(token_signing_key, **token_options)
    decode_calls: list[dict[str, object]] = []
    lookup_calls: list[tuple[str, str]] = []

    with pytest.raises(SyntheticProbeFailure, match="ID_TOKEN_VALIDATION_FAILED") as caught:
        execute_id_token_verification(
            id_token,
            verification_signing_key,
            decode_calls=decode_calls,
            lookup_calls=lookup_calls,
        )

    assert isinstance(caught.value.__cause__, expected_cause)
    assert lookup_calls == [("/synthetic/rehearsal-jwks", "rehearsal-key")]
    assert len(decode_calls) == 1
    assert isinstance(decode_calls[0]["key"], rsa.RSAPublicKey)
    assert decode_calls[0]["kwargs"]["algorithms"] == ["RS256"]


def test_probe_blocked_during_factory_import_emits_sanitized_blocked_envelope(tmp_path):
    result = run_probe_with_factory_import(
        tmp_path,
        'socket.create_connection(("forbidden.invalid", 8332))',
    )
    assert_sanitized_probe_failure(
        result,
        expected_payload={
            "status": "BLOCKED",
            "evidence_code": "EXTERNAL_SIDE_EFFECT_GUARD_TRIGGERED",
        },
        expected_returncode=3,
    )


def test_import_error_during_factory_import_emits_sanitized_blocked_envelope(tmp_path):
    result = run_probe_with_factory_import(
        tmp_path,
        f"raise ImportError({PROBE_IMPORT_FAILURE_DETAIL!r})",
    )
    assert_sanitized_probe_failure(
        result,
        expected_payload={"status": "BLOCKED", "evidence_code": "PROBE_DEPENDENCY_UNAVAILABLE"},
        expected_returncode=3,
    )


def test_ordinary_exception_during_factory_import_emits_sanitized_fail_envelope(tmp_path):
    result = run_probe_with_factory_import(
        tmp_path,
        f"raise RuntimeError({PROBE_IMPORT_FAILURE_DETAIL!r})",
    )
    assert_sanitized_probe_failure(
        result,
        expected_payload={"status": "FAIL", "evidence_code": "UNCLASSIFIED_PROBE_FAILURE"},
        expected_returncode=4,
    )


def test_system_exit_during_factory_import_emits_sanitized_fail_envelope(tmp_path):
    result = run_probe_with_factory_import(
        tmp_path,
        f"raise SystemExit({PROBE_IMPORT_FAILURE_DETAIL!r})",
    )
    assert_sanitized_probe_failure(
        result,
        expected_payload={"status": "FAIL", "evidence_code": "UNCLASSIFIED_PROBE_FAILURE"},
        expected_returncode=4,
    )


def test_keyboard_interrupt_during_factory_import_is_fail_closed(tmp_path):
    result = run_probe_with_factory_import(tmp_path, "raise KeyboardInterrupt()")
    assert_sanitized_probe_failure(
        result,
        expected_payload={"status": "FAIL", "evidence_code": "UNCLASSIFIED_PROBE_FAILURE"},
        expected_returncode=4,
    )


def test_successful_probe_evidence_sequences_remain_exact():
    assert rehearsal.STARTUP_PROBE_EVIDENCE == (
        "APPLICATION_STARTUP",
        "REQUIRED_BLUEPRINT_REGISTRATION",
        "DISPOSABLE_TARGET_QUERYABILITY",
    )
    assert rehearsal.AUTH_PROBE_EVIDENCE == (
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
    assert probe_evidence("startup_probe") == rehearsal.STARTUP_PROBE_EVIDENCE
    assert probe_evidence("auth_probe") == rehearsal.AUTH_PROBE_EVIDENCE
