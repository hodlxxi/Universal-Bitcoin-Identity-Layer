from __future__ import annotations

import inspect
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import production_compatibility_rehearsal_v1 as rehearsal

ROOT = Path(__file__).resolve().parents[2]


class FakeRunner:
    def __init__(self, responses=None, *, forbid=False):
        self.responses = list(responses or [])
        self.calls = []
        self.forbid = forbid

    def run(self, argv, *, cwd, env, input_text=None, timeout=120):
        if self.forbid:
            raise AssertionError("runner invoked")
        self.calls.append(
            {
                "argv": tuple(str(item) for item in argv),
                "cwd": Path(cwd),
                "env": dict(env),
                "input_text": input_text,
                "timeout": timeout,
            }
        )
        if self.responses:
            return self.responses.pop(0)
        return rehearsal.CommandResult(0, "", "")


class ExplodingEnvironment:
    def __getitem__(self, _key):
        raise AssertionError("environment value read")

    def get(self, _key, _default=None):
        raise AssertionError("environment value read")

    def keys(self):
        raise AssertionError("environment keys read")

    def __iter__(self):
        raise AssertionError("environment iterated")


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


def source_success_responses():
    return [
        rehearsal.CommandResult(0, "", ""),
        rehearsal.CommandResult(0, "", ""),
        rehearsal.CommandResult(0, rehearsal.PRODUCTION_SHA + "\n", ""),
        rehearsal.CommandResult(0, "", ""),
        rehearsal.CommandResult(0, rehearsal.STAGING_SHA + "\n", ""),
    ]


def test_plan_mode_invokes_no_runner_and_is_deterministic():
    runner = FakeRunner(forbid=True)
    harness = rehearsal.RehearsalHarness(runner)
    first = rehearsal.canonical_plan_json(harness.plan())
    second = rehearsal.canonical_plan_json(harness.plan())
    assert first == second
    assert json.loads(first)["execution_status"] == "NOT_RUN"
    assert runner.calls == []


def test_default_command_is_plan_only_and_invokes_no_runner(capsys):
    runner = FakeRunner(forbid=True)
    assert rehearsal.main([], runner=runner) == 0
    output = capsys.readouterr().out
    assert "execution_status=NOT_RUN" in output
    assert "release_authority=NONE" in output
    assert runner.calls == []


def test_plan_mode_does_not_access_os_environ(monkeypatch):
    monkeypatch.setattr(rehearsal, "os", SimpleNamespace(environ=ExplodingEnvironment()))
    runner = FakeRunner(forbid=True)
    assert rehearsal.RehearsalHarness(runner).plan()["execution_status"] == "NOT_RUN"
    assert rehearsal.canonical_plan_json().endswith("\n")
    assert runner.calls == []


def test_execute_requires_exact_acknowledgement(tmp_path):
    request = execute_request(tmp_path, acknowledgement="almost")
    with pytest.raises(rehearsal.SafetyViolation, match="ACKNOWLEDGEMENT_REQUIRED"):
        rehearsal.validate_execute_request(request)


def test_execute_rejects_root(tmp_path):
    request = execute_request(tmp_path, effective_uid=0)
    with pytest.raises(rehearsal.SafetyViolation, match="ROOT_EXECUTION_REFUSED"):
        rehearsal.validate_execute_request(request)

    invalid_uid = execute_request(tmp_path, effective_uid=-1)
    with pytest.raises(rehearsal.SafetyViolation, match="ROOT_EXECUTION_REFUSED"):
        rehearsal.validate_execute_request(invalid_uid)


@pytest.mark.parametrize("nonempty", [False, True])
def test_execute_rejects_existing_or_nonempty_workspace(tmp_path, nonempty):
    request = execute_request(tmp_path)
    request.workspace.mkdir()
    if nonempty:
        (request.workspace / "preexisting").write_text("not owned", encoding="utf-8")
    with pytest.raises(rehearsal.SafetyViolation, match="WORKSPACE_MUST_NOT_EXIST"):
        rehearsal.validate_execute_request(request)


@pytest.mark.parametrize(
    "protected",
    [Path("/srv/ubid"), Path("/srv/ubid-staging")],
)
def test_execute_rejects_production_and_protected_staging_checkout_paths(tmp_path, protected):
    request = execute_request(tmp_path, repository=protected)
    with pytest.raises(rehearsal.SafetyViolation, match="PROTECTED_REPOSITORY_PATH_REFUSED"):
        rehearsal.validate_execute_request(request)


def test_execute_rejects_existing_postgresql_cluster(tmp_path):
    workspace = tmp_path / "owned"
    guard = rehearsal.WorkspaceGuard.create(workspace, tmp_path, "owner-token")
    cluster = workspace / "cluster"
    cluster.mkdir()
    (cluster / "PG_VERSION").write_text("synthetic\n", encoding="utf-8")
    with pytest.raises(rehearsal.SafetyViolation, match="EXISTING_POSTGRESQL_CLUSTER_REFUSED"):
        guard.assert_no_existing_cluster()
    assert workspace.exists()
    guard.cleanup()


def test_execute_rejects_tcp_and_accepts_only_unix_socket_architecture(tmp_path):
    tcp = execute_request(tmp_path, transport="tcp", listen_addresses="*")
    with pytest.raises(rehearsal.SafetyViolation, match="TCP_POSTGRESQL_REFUSED"):
        rehearsal.validate_execute_request(tcp)
    unix = execute_request(tmp_path)
    resolved = rehearsal.validate_execute_request(unix)
    assert resolved.request.transport == "unix"
    assert resolved.request.listen_addresses == ""


def test_execute_refuses_inherited_database_url(tmp_path):
    request = execute_request(tmp_path, environment_keys=frozenset({"PATH", "DATABASE_URL"}))
    with pytest.raises(rehearsal.SafetyViolation, match="INHERITED_RUNTIME_CONFIGURATION_REFUSED"):
        rehearsal.validate_execute_request(request)


@pytest.mark.parametrize(
    ("dsn", "code"),
    [
        ("postgresql://user:synthetic-password@external.invalid/example", "PASSWORD_BEARING_DSN_REFUSED"),
        ("postgresql://user@external.invalid/example", "EXTERNAL_DSN_REFUSED"),
    ],
)
def test_execute_refuses_password_bearing_and_arbitrary_external_dsns(tmp_path, dsn, code):
    request = execute_request(tmp_path, external_dsn=dsn)
    with pytest.raises(rehearsal.SafetyViolation, match=code):
        rehearsal.validate_execute_request(request)


@pytest.mark.parametrize(
    "target",
    [
        "postgres",
        "template0",
        "template1",
        "hodlxxi_rehearsal_UPPER",
        "hodlxxi_rehearsal_bad-hyphen",
        "production_copy",
    ],
)
def test_database_target_pattern_is_restricted(target):
    with pytest.raises(rehearsal.SafetyViolation):
        rehearsal.validate_database_target(target)
    valid = "hodlxxi_" + "rehearsal_synthetic_v1"
    assert rehearsal.validate_database_target(valid) == valid


def test_database_targets_are_generated_only_by_explicit_execute_helper():
    primary, restored = rehearsal.generate_database_targets(lambda: "synthetic_001")
    assert rehearsal.DATABASE_TARGET_PATTERN.fullmatch(primary)
    assert rehearsal.DATABASE_TARGET_PATTERN.fullmatch(restored)
    assert primary != restored


def test_source_shas_must_exist_locally_and_repository_must_be_clean(tmp_path):
    request = execute_request(tmp_path)
    resolved = rehearsal.validate_execute_request(request)
    runner = FakeRunner(source_success_responses())
    rehearsal.verify_local_source_objects(runner, resolved)
    assert len(runner.calls) == 5

    missing = FakeRunner(
        [
            rehearsal.CommandResult(0, "", ""),
            rehearsal.CommandResult(1, "", "not retained"),
        ]
    )
    with pytest.raises(rehearsal.CommandFailure, match="PRODUCTION_GIT_OBJECT_MISSING"):
        rehearsal.verify_local_source_objects(missing, resolved)

    dirty = FakeRunner([rehearsal.CommandResult(0, " M synthetic", "")])
    with pytest.raises(rehearsal.SafetyViolation, match="SOURCE_REPOSITORY_DIRTY"):
        rehearsal.verify_local_source_objects(dirty, resolved)


def test_source_verification_contains_no_network_clone_command(tmp_path):
    request = execute_request(tmp_path)
    resolved = rehearsal.validate_execute_request(request)
    runner = FakeRunner(source_success_responses())
    rehearsal.verify_local_source_objects(runner, resolved)
    flattened = [token.casefold() for call in runner.calls for token in call["argv"]]
    assert "clone" not in flattened
    assert "fetch" not in flattened
    assert "pull" not in flattened
    assert all(call["env"] and "GIT_TERMINAL_PROMPT" in call["env"] for call in runner.calls)


def test_real_runner_never_uses_shell_true_or_implicit_environment():
    source = inspect.getsource(rehearsal.SubprocessCommandRunner.run)
    assert "shell=True" not in source
    assert "shell=False" in source
    assert "env={" in source


def test_command_output_is_redacted_from_failure_result():
    runner = FakeRunner(
        [
            rehearsal.CommandResult(
                9,
                "postgresql://user:synthetic-password@external.invalid/example",
                "DATABASE_URL=forbidden-value",
            )
        ]
    )
    harness = rehearsal.RehearsalHarness(runner, monotonic=lambda: 1.0)

    def operation():
        rehearsal._checked(
            runner,
            ["synthetic-command"],
            cwd=ROOT,
            env={"LANG": "C"},
            evidence_code="SYNTHETIC_COMMAND_FAILED",
        )
        raise AssertionError("unreachable")

    result = harness._invoke(rehearsal.PHASES[0], operation)
    rendered = json.dumps(result)
    assert result["status"] == "FAIL"
    assert result["evidence_code"] == "SYNTHETIC_COMMAND_FAILED"
    assert "synthetic-password" not in rendered
    assert "forbidden-value" not in rendered
    assert "postgresql://" not in rendered


def test_cleanup_affects_only_marker_owned_workspace(tmp_path):
    workspace = tmp_path / "owned"
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "keep").write_text("keep", encoding="utf-8")
    guard = rehearsal.WorkspaceGuard.create(workspace, tmp_path, "correct-token")
    (workspace / "artifact").write_text("synthetic", encoding="utf-8")

    wrong_guard = rehearsal.WorkspaceGuard(workspace, tmp_path, "wrong-token")
    with pytest.raises(rehearsal.SafetyViolation, match="OWNERSHIP_MARKER_MISMATCH"):
        wrong_guard.cleanup()
    assert workspace.exists()
    assert (unrelated / "keep").read_text(encoding="utf-8") == "keep"

    guard.cleanup()
    assert not workspace.exists()
    assert unrelated.exists()


def test_missing_ownership_marker_removes_cleanup_authority(tmp_path):
    workspace = tmp_path / "owned"
    guard = rehearsal.WorkspaceGuard.create(workspace, tmp_path, "correct-token")
    guard.marker.unlink()
    with pytest.raises(rehearsal.SafetyViolation, match="OWNERSHIP_MARKER_MISSING"):
        guard.cleanup()
    assert workspace.exists()
    workspace.rmdir()


def test_safety_failure_leaves_sanitized_blocked_result_and_stops_prerequisites(tmp_path):
    runner = FakeRunner(forbid=True)
    request = execute_request(tmp_path, acknowledgement="wrong")
    result = rehearsal.RehearsalHarness(runner, monotonic=lambda: 1.0).execute(request)
    assert result["execution_status"] == "BLOCKED"
    assert result["release_authority"] == "NONE"
    assert result["phases"][0]["status"] == "BLOCKED"
    assert all(item["status"] == "BLOCKED" for item in result["phases"][1:12])
    assert result["phases"][12]["status"] == "PASS"
    assert result["phases"][13]["status"] == "PASS"
    assert runner.calls == []
    rehearsal.validate_sanitized_result(result)


def test_unsupported_auth_probe_cannot_be_converted_to_pass(monkeypatch):
    outcome = rehearsal.PhaseOutcome(
        "PASS",
        "AUTH_DEPENDENCY_UNAVAILABLE",
        "forbidden",
        unsupported=True,
    )
    with pytest.raises(ValueError, match="unsupported probe cannot pass"):
        rehearsal._phase_result(rehearsal.PHASES[4], outcome, 0)

    payload = json.dumps(
        {"status": "PASS", "evidence_codes": ["AUTH_DEPENDENCY_UNAVAILABLE"]},
        separators=(",", ":"),
    )
    runner = FakeRunner([rehearsal.CommandResult(0, payload, "")])
    state = SimpleNamespace(
        resolved=SimpleNamespace(tools=SimpleNamespace(python=Path("/synthetic/python"))),
    )
    monkeypatch.setattr(rehearsal, "_application_environment", lambda *_args, **_kwargs: {"LANG": "C"})
    with pytest.raises(rehearsal.CommandFailure, match="PROBE_EVIDENCE_INVALID"):
        rehearsal._run_application_probe(
            runner,
            state,
            snapshot=ROOT,
            target="unused",
            mode="auth",
        )


@pytest.mark.parametrize(
    ("returncode", "expected_status", "expected_evidence", "expected_unsupported"),
    [
        (3, "BLOCKED", "PROBE_PROCESS_BLOCKED", True),
        (4, "FAIL", "PROBE_PROCESS_FAILED", False),
        (-2, "FAIL", "PROBE_PROCESS_FAILED", False),
    ],
)
def test_nonzero_probe_exit_without_stdout_retains_sanitized_process_diagnosis(
    monkeypatch,
    returncode,
    expected_status,
    expected_evidence,
    expected_unsupported,
):
    runner = FakeRunner(
        [
            rehearsal.CommandResult(
                returncode,
                "",
                "Traceback: postgresql://user:password@database.invalid/private",
            )
        ]
    )
    state = SimpleNamespace(
        resolved=SimpleNamespace(tools=SimpleNamespace(python=Path("/synthetic/python"))),
    )
    monkeypatch.setattr(rehearsal, "_application_environment", lambda *_args, **_kwargs: {"LANG": "C"})

    outcome = rehearsal._run_application_probe(
        runner,
        state,
        snapshot=ROOT,
        target="unused",
        mode="startup",
    )

    assert outcome.status == expected_status
    assert outcome.evidence_code == expected_evidence
    assert outcome.unsupported is expected_unsupported
    assert "postgresql://" not in outcome.sanitized_detail
    assert "password" not in outcome.sanitized_detail


def test_zero_probe_exit_without_envelope_remains_fail_closed(monkeypatch):
    runner = FakeRunner([rehearsal.CommandResult(0, "", "")])
    state = SimpleNamespace(
        resolved=SimpleNamespace(tools=SimpleNamespace(python=Path("/synthetic/python"))),
    )
    monkeypatch.setattr(rehearsal, "_application_environment", lambda *_args, **_kwargs: {"LANG": "C"})

    with pytest.raises(rehearsal.CommandFailure, match="PROBE_RESULT_MISSING"):
        rehearsal._run_application_probe(
            runner,
            state,
            snapshot=ROOT,
            target="unused",
            mode="startup",
        )


def test_no_phase_silently_continues_after_prerequisite_failure(tmp_path):
    runner = FakeRunner(forbid=True)
    request = execute_request(tmp_path, production_sha="0" * 40)
    result = rehearsal.RehearsalHarness(runner, monotonic=lambda: 2.0).execute(request)
    for phase in result["phases"][1:12]:
        assert phase["status"] == "BLOCKED"
        assert phase["evidence_code"] == "PREREQUISITE_NOT_PASS"
        assert phase["duration_ms"] == 0
    assert runner.calls == []
