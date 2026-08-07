from __future__ import annotations

import copy
import json
import subprocess
import sys
import tarfile
import textwrap
from dataclasses import replace
from pathlib import Path

import pytest

from tools import production_compatibility_rehearsal_v1 as rehearsal

ROOT = Path(__file__).resolve().parents[2]


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


class NeverRunner:
    def run(self, *_args, **_kwargs):
        raise AssertionError("runner invoked")


class SuccessfulRehearsalRunner:
    """Filesystem-aware command double for one complete rehearsal."""

    def __init__(self, *, fail_first_migration: bool = False):
        self.calls: list[dict[str, object]] = []
        self.fail_first_migration = fail_first_migration
        self.migration_failure_returned = False
        self.started_configuration = ""
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
            if self.fail_first_migration and not self.migration_failure_returned and "/migrations/" in file_path:
                self.migration_failure_returned = True
                return rehearsal.CommandResult(7, "raw forbidden output", "raw forbidden error")
            return rehearsal.CommandResult(0, "", "")

        sql = self._argument_after(argv, "--command")
        if "information_schema.tables" in sql:
            values = self.migrated_tables if "action_operations" in sql else self.baseline_table_names
            return rehearsal.CommandResult(0, self._lines(values), "")
        if "information_schema.columns" in sql:
            values = self.migrated_columns if "action_operations" in sql else self.baseline_columns
            return rehearsal.CommandResult(0, self._lines(values), "")
        if sql.startswith("SELECT conname FROM pg_constraint"):
            return rehearsal.CommandResult(0, self._lines(self.baseline_constraints), "")
        if "r.relname||'|'||c.conname" in sql:
            return rehearsal.CommandResult(0, self._lines(self.named_constraints), "")
        if "unnest(c.conkey)" in sql:
            return rehearsal.CommandResult(0, self._lines(rehearsal.MIGRATION_RELATIONAL_CONSTRAINTS), "")
        if "count(*)::text FROM pg_constraint" in sql:
            return rehearsal.CommandResult(0, self._lines(self.check_counts), "")
        if sql.startswith("SELECT indexname FROM pg_indexes"):
            return rehearsal.CommandResult(0, self._lines(self.baseline_indexes), "")
        if "tablename||'|'||indexname" in sql:
            return rehearsal.CommandResult(0, self._lines(self.explicit_indexes), "")
        if "count(*) FILTER" in sql:
            return rehearsal.CommandResult(0, "12|2|48\n", "")
        if "pg_get_userbyid" in sql:
            return rehearsal.CommandResult(0, "public|r|users|REHEARSAL_ROLE\n", "")
        if "AS row_count" in sql:
            all_tables = self.baseline_table_names | self.migrated_tables
            values = {f"{table}|{1 if table in self.baseline_table_names else 0}" for table in all_tables}
            return rehearsal.CommandResult(0, self._lines(values), "")
        if sql.lstrip().startswith("DO $$"):
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
            schema = (
                f"-- synthetic schema\n\\restrict {marker}\n"
                f"CREATE TABLE stable (id integer);\n\\unrestrict {marker}\n"
            )
            return rehearsal.CommandResult(0, schema, "")
        if command == "pg_restore":
            if "--list" in normalized:
                return rehearsal.CommandResult(0, "; synthetic archive\n1; TABLE public users rehearsal_owner\n", "")
            return rehearsal.CommandResult(0, "", "")
        raise AssertionError(f"unexpected command: {normalized}")


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
    runner = SuccessfulRehearsalRunner(fail_first_migration=True)
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
    assert 'algorithms=["RS256"]' in program
    assert 'issuer=os.environ["JWT_ISSUER"]' in program
    assert 'audience=registration["client_id"]' in program
    assert "/srv/ubid" not in program


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
