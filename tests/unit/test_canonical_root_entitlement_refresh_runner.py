from pathlib import Path
import builtins
from datetime import datetime, timedelta, timezone
import os
import runpy
import stat
import subprocess
import sys

import pytest

from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import ControllingRegistrationSelectionSource
from app.services.canonical_root_entitlement_policy import evaluate_canonical_root_entitlement
from app.services.canonical_root_entitlement_refresh import (
    REFRESH_CONTRACT_VERSION,
    CanonicalRootEntitlementRefreshMode,
    CanonicalRootEntitlementRefreshOutcome,
    CanonicalRootEntitlementRefreshResult,
)
from app.services.covenant_relation import CovenantRelationReason
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult
import app.services.canonical_root_entitlement_refresh_runner as runner

SUBJECT = "a" * 64
OTHER = "b" * 64
GRAPH = "hodlxxi.crt_membership_graph.v1"
NOW = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)


def refresh_result(mode=CanonicalRootEntitlementRefreshMode.DRY_RUN, *, limited=False, unchanged=False):
    relation = EdgeLocalCovenantRelationResult(
        GRAPH,
        SUBJECT,
        OTHER,
        ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING,
        "00000000-0000-4000-8000-000000000001",
        "1" * 64,
        "00000000-0000-4000-8000-000000000002",
        "2" * 64,
        "00000000-0000-4000-8000-000000000003",
        "3" * 64,
        5,
        1 if limited else 5,
        NOW,
        900000,
        300000,
        0 if limited else 300000,
        not limited,
        CovenantRelationReason.MISSING_OUTGOING if limited else CovenantRelationReason.FULL_RELATION_SATISFIED,
        "4" * 64,
    )
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, relation)
    if mode is CanonicalRootEntitlementRefreshMode.DRY_RUN:
        outcome, evidence, appended = CanonicalRootEntitlementRefreshOutcome.PREVIEW, None, False
    else:
        outcome = (
            CanonicalRootEntitlementRefreshOutcome.UNCHANGED
            if unchanged
            else CanonicalRootEntitlementRefreshOutcome.APPENDED
        )
        appended = not unchanged
        evidence = CurrentEntitlementEvidenceRecord(
            "00000000-0000-4000-8000-000000000010",
            CONTRACT_VERSION,
            SUBJECT,
            decision.identity_class,
            decision.current_full_relation_satisfied,
            decision.evidence_source,
            decision.policy_version,
            decision.source_evidence_sha256,
            NOW,
            NOW + timedelta(seconds=300),
            None,
            NOW,
        )
    return CanonicalRootEntitlementRefreshResult(
        REFRESH_CONTRACT_VERSION,
        mode,
        outcome,
        GRAPH,
        SUBJECT,
        NOW,
        relation,
        decision,
        evidence,
        appended,
    )


def argv(*extra):
    return ["--graph", GRAPH, "--subject", SUBJECT, *extra]


@pytest.mark.parametrize(
    "bad",
    [
        [],
        ["--dry-run"],
        argv("--dry-run", "extra"),
        argv("--dry-run", "--commit"),
        ["--graph", GRAPH, "--graph", GRAPH, "--subject", SUBJECT, "--dry-run"],
        ["--graph", GRAPH, "--subject", SUBJECT.upper(), "--dry-run"],
        argv("--commit"),
        argv("--dry-run", "--lock-directory", "/tmp"),
    ],
)
def test_closed_argument_contract(bad):
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.parse_runner_argv(bad)


def test_argument_validation_precedes_dependency_construction():
    calls = []
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.run(["--commit"], dependency_factory=lambda _mode: calls.append(True))
    assert calls == []


@pytest.mark.parametrize(
    "bad",
    [
        [],
        ["--commit"],
        argv("--dry-run", "extra"),
        argv("--dry-run", "--commit"),
        ["--graph", GRAPH, "--graph", GRAPH, "--subject", SUBJECT, "--dry-run"],
        argv("--unknown", "value", "--dry-run"),
    ],
)
def test_cli_invalid_argv_precedes_every_application_import(monkeypatch, bad, capsys):
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "app" or name.startswith("app."):
            raise AssertionError("application import crossed invalid-argv boundary")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(sys, "argv", ["canonical_root_entitlement_refresh.py", *bad])
    script = Path(__file__).resolve().parents[2] / "scripts" / "canonical_root_entitlement_refresh.py"
    with pytest.raises(SystemExit) as caught:
        runpy.run_path(str(script), run_name="__main__")
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == runner.FAILURE_MESSAGE + "\n"


def test_cli_rejects_valid_looking_non_sequence_before_application_import(monkeypatch, capsys):
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "app" or name.startswith("app."):
            raise AssertionError("application import crossed invalid-argv boundary")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    script = Path(__file__).resolve().parents[2] / "scripts" / "canonical_root_entitlement_refresh.py"
    namespace = runpy.run_path(str(script), run_name="cli_boundary_test")
    assert namespace["main"]((value for value in argv("--dry-run"))) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == runner.FAILURE_MESSAGE + "\n"


def test_cli_sanitizes_ordinary_lazy_import_failure(monkeypatch, capsys):
    real_import = builtins.__import__

    def failing_import(name, *args, **kwargs):
        if name == "app.services.canonical_root_entitlement_refresh_runner":
            raise RuntimeError("private import detail")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", failing_import)
    script = Path(__file__).resolve().parents[2] / "scripts" / "canonical_root_entitlement_refresh.py"
    namespace = runpy.run_path(str(script), run_name="cli_import_failure_test")
    assert namespace["main"](argv("--dry-run")) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == runner.FAILURE_MESSAGE + "\n"


def test_valid_modes_require_explicit_values(tmp_path):
    dry = runner.parse_runner_argv(argv("--dry-run"))
    commit = runner.parse_runner_argv(argv("--commit", "--lock-directory", str(tmp_path)))
    assert dry.mode is CanonicalRootEntitlementRefreshMode.DRY_RUN and dry.lock_directory is None
    assert commit.mode is CanonicalRootEntitlementRefreshMode.COMMIT


@pytest.mark.parametrize("limited", [False, True])
def test_dry_run_executes_once_without_evidence_or_guard(monkeypatch, limited):
    calls = []
    monkeypatch.setattr(
        "app.services.canonical_root_entitlement_refresh.refresh_canonical_root_entitlement",
        lambda graph, subject, **kwargs: calls.append((graph, subject, kwargs)) or refresh_result(limited=limited),
    )
    modes = []
    payload = runner.execute_request(
        runner.parse_runner_argv(argv("--dry-run")),
        dependency_factory=lambda mode: modes.append(mode)
        or {
            "genesis_repository": object(),
            "admission_edge_repository": object(),
            "root_registration_binding_repository": object(),
            "trusted_registration_repository": object(),
            "funding_set_repository": object(),
            "rpc_factory": object(),
        },
        clock=lambda: NOW.replace(microsecond=123456),
    )
    assert modes == [CanonicalRootEntitlementRefreshMode.DRY_RUN] and len(calls) == 1
    assert calls[0][2]["evaluated_at"] == NOW
    assert "execution_guard" not in calls[0][2] and "evidence_repository" not in calls[0][2]
    assert payload["identity_class"] == (IdentityClass.LIMITED if limited else IdentityClass.FULL).value
    assert payload["outcome"] == "preview" and payload["append_performed"] is False


@pytest.mark.parametrize("limited,unchanged", [(False, False), (True, False), (False, True)])
def test_commit_executes_once_and_projects_closed_outcomes(tmp_path, monkeypatch, limited, unchanged):
    calls = []
    monkeypatch.setattr(
        "app.services.canonical_root_entitlement_refresh.refresh_canonical_root_entitlement",
        lambda graph, subject, **kwargs: calls.append(kwargs)
        or refresh_result(CanonicalRootEntitlementRefreshMode.COMMIT, limited=limited, unchanged=unchanged),
    )
    request = runner.parse_runner_argv(argv("--commit", "--lock-directory", str(tmp_path)))
    payload = runner.execute_request(
        request,
        dependency_factory=lambda _mode: {"evidence_repository": object()},
        clock=lambda: NOW,
    )
    assert len(calls) == 1 and type(calls[0]["execution_guard"]) is runner.LinuxSubjectFileExecutionGuard
    assert calls[0]["execution_guard"]._directory_descriptor is None
    assert payload["outcome"] == ("unchanged" if unchanged else "appended")
    assert payload["append_performed"] is (not unchanged)


def test_malformed_nested_result_fails_closed():
    result = refresh_result()
    object.__setattr__(result.edge_local_result, "recognized_outpoint_count", -1)
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.normalized_result(result, runner.parse_runner_argv(argv("--dry-run")))


@pytest.mark.parametrize("field", ["edge_local_result", "decision", "evidence"])
def test_nested_subclasses_fail_closed(field):
    result = refresh_result(
        CanonicalRootEntitlementRefreshMode.COMMIT
        if field == "evidence"
        else CanonicalRootEntitlementRefreshMode.DRY_RUN
    )
    original = getattr(result, field)
    subclass = type("Forged", (type(original),), {})
    forged = object.__new__(subclass)
    for name in type(original).__dataclass_fields__:
        object.__setattr__(forged, name, getattr(original, name))
    object.__setattr__(result, field, forged)
    request = runner.RunnerRequest(GRAPH, SUBJECT, result.mode, "/tmp" if result.evidence else None)
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.normalized_result(result, request)


def test_output_is_deterministic_bounded_and_contains_no_exception_text():
    request = runner.parse_runner_argv(argv("--dry-run"))
    first = runner.normalized_result(refresh_result(), request)
    second = runner.normalized_result(refresh_result(), request)
    assert first == second
    encoded = runner.json.dumps(first, sort_keys=True, separators=(",", ":"))
    assert len(encoded) < 4096 and "password" not in encoded and "traceback" not in encoded


def test_guard_rejects_relative_symlink_non_directory_and_public_directory(tmp_path):
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.LinuxSubjectFileExecutionGuard("relative")
    regular = tmp_path / "regular"
    regular.write_text("x")
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.LinuxSubjectFileExecutionGuard(str(regular))
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.LinuxSubjectFileExecutionGuard(str(link))
    tmp_path.chmod(0o777)
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.LinuxSubjectFileExecutionGuard(str(tmp_path))


@pytest.mark.parametrize("interrupt_type", [KeyboardInterrupt, SystemExit])
def test_guard_construction_preserves_interrupt_when_cleanup_close_fails(tmp_path, monkeypatch, interrupt_type):
    def interrupted_fstat(_descriptor):
        monkeypatch.setattr(runner.os, "close", lambda _fd: (_ for _ in ()).throw(OSError("private")))
        raise interrupt_type()

    monkeypatch.setattr(runner.os, "fstat", interrupted_fstat)
    with pytest.raises(interrupt_type):
        runner.LinuxSubjectFileExecutionGuard(str(tmp_path))


def test_guard_rejects_symlink_and_non_regular_target_and_uses_restrictive_mode(tmp_path):
    guard = runner.LinuxSubjectFileExecutionGuard(str(tmp_path))
    path = Path(guard._path(SUBJECT))
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        with guard.hold(SUBJECT):
            pass
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        with runner.LinuxSubjectFileExecutionGuard(str(tmp_path)).hold(SUBJECT):
            pass
    path.unlink()
    with runner.LinuxSubjectFileExecutionGuard(str(tmp_path)).hold(SUBJECT):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with runner.LinuxSubjectFileExecutionGuard(str(tmp_path)).hold(SUBJECT):
        pass


def test_guard_releases_after_body_failure(tmp_path):
    guard = runner.LinuxSubjectFileExecutionGuard(str(tmp_path))
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable, match="inspect current evidence"):
        with guard.hold(SUBJECT):
            raise RuntimeError("private exception")
    with runner.LinuxSubjectFileExecutionGuard(str(tmp_path)).hold(SUBJECT):
        pass


def test_guard_close_is_idempotent_and_closed_guard_cannot_hold(tmp_path):
    guard = runner.LinuxSubjectFileExecutionGuard(str(tmp_path))
    descriptor = guard._directory_descriptor
    guard.close()
    guard.close()
    with pytest.raises(OSError):
        os.fstat(descriptor)
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        with guard.hold(SUBJECT):
            pass


def test_execute_request_closes_guard_when_orchestrator_fails_before_hold(tmp_path, monkeypatch):
    captured = []

    def reject_before_hold(_graph, _subject, **kwargs):
        captured.append(kwargs["execution_guard"])
        raise ValueError("private dependency rejection")

    monkeypatch.setattr(
        "app.services.canonical_root_entitlement_refresh.refresh_canonical_root_entitlement",
        reject_before_hold,
    )
    request = runner.parse_runner_argv(argv("--commit", "--lock-directory", str(tmp_path)))
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.execute_request(
            request, dependency_factory=lambda _mode: {"evidence_repository": object()}, clock=lambda: NOW
        )
    assert len(captured) == 1 and captured[0]._directory_descriptor is None
    captured[0].close()


def test_execute_request_closes_guard_on_malformed_result(tmp_path, monkeypatch):
    captured = []

    def malformed(_graph, _subject, **kwargs):
        captured.append(kwargs["execution_guard"])
        return object()

    monkeypatch.setattr("app.services.canonical_root_entitlement_refresh.refresh_canonical_root_entitlement", malformed)
    request = runner.parse_runner_argv(argv("--commit", "--lock-directory", str(tmp_path)))
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.execute_request(
            request, dependency_factory=lambda _mode: {"evidence_repository": object()}, clock=lambda: NOW
        )
    assert len(captured) == 1 and captured[0]._directory_descriptor is None


@pytest.mark.parametrize("interrupt_type", [KeyboardInterrupt, SystemExit])
def test_execute_request_closes_guard_and_preserves_orchestrator_interrupt(tmp_path, monkeypatch, interrupt_type):
    captured = []

    def interrupted(_graph, _subject, **kwargs):
        captured.append(kwargs["execution_guard"])
        raise interrupt_type()

    monkeypatch.setattr(
        "app.services.canonical_root_entitlement_refresh.refresh_canonical_root_entitlement", interrupted
    )
    request = runner.parse_runner_argv(argv("--commit", "--lock-directory", str(tmp_path)))
    with pytest.raises(interrupt_type):
        runner.execute_request(
            request, dependency_factory=lambda _mode: {"evidence_repository": object()}, clock=lambda: NOW
        )
    assert len(captured) == 1 and captured[0]._directory_descriptor is None


def test_real_cross_process_contention_without_semaphore(tmp_path):
    child = """
import sys
from app.services.canonical_root_entitlement_refresh_runner import LinuxSubjectFileExecutionGuard
with LinuxSubjectFileExecutionGuard(sys.argv[1]).hold(sys.argv[2]):
    sys.stdout.write('ready\\n'); sys.stdout.flush()
    assert sys.stdin.readline() == 'release\\n'
"""
    process = subprocess.Popen(
        [sys.executable, "-c", child, str(tmp_path), SUBJECT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    try:
        assert process.stdout is not None and process.stdout.readline() == "ready\n"
        guard = runner.LinuxSubjectFileExecutionGuard(str(tmp_path))
        with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
            with guard.hold(SUBJECT):
                pass
        with runner.LinuxSubjectFileExecutionGuard(str(tmp_path)).hold(OTHER):
            pass
        assert process.stdin is not None
        process.stdin.write("release\n")
        process.stdin.flush()
        assert process.wait(timeout=5) == 0
        with runner.LinuxSubjectFileExecutionGuard(str(tmp_path)).hold(SUBJECT):
            pass
    finally:
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), SystemExit()])
def test_interrupts_are_preserved(tmp_path, interrupt):
    guard = runner.LinuxSubjectFileExecutionGuard(str(tmp_path))
    with pytest.raises(type(interrupt)):
        with guard.hold(SUBJECT):
            raise interrupt


def test_unlock_interrupt_still_closes_both_descriptors(tmp_path, monkeypatch):
    guard = runner.LinuxSubjectFileExecutionGuard(str(tmp_path))
    real_flock, real_close = runner.fcntl.flock, runner.os.close
    closed = []

    def flock(fd, operation):
        if operation == runner.fcntl.LOCK_UN:
            raise KeyboardInterrupt()
        return real_flock(fd, operation)

    def close(fd):
        closed.append(fd)
        return real_close(fd)

    monkeypatch.setattr(runner.fcntl, "flock", flock)
    monkeypatch.setattr(runner.os, "close", close)
    with pytest.raises(KeyboardInterrupt):
        with guard.hold(SUBJECT):
            pass
    assert len(closed) == 2 and len(set(closed)) == 2


def test_close_interrupt_still_attempts_remaining_close(tmp_path, monkeypatch):
    guard = runner.LinuxSubjectFileExecutionGuard(str(tmp_path))
    real_close = runner.os.close
    closed = []

    def close(fd):
        closed.append(fd)
        real_close(fd)
        if len(closed) == 1:
            raise SystemExit()

    monkeypatch.setattr(runner.os, "close", close)
    with pytest.raises(SystemExit):
        with guard.hold(SUBJECT):
            pass
    assert len(closed) == 2 and len(set(closed)) == 2


@pytest.mark.parametrize("operation", ["unlock", "close"])
def test_ordinary_release_failure_is_sanitized_and_cleanup_is_attempted(tmp_path, monkeypatch, operation):
    guard = runner.LinuxSubjectFileExecutionGuard(str(tmp_path))
    real_flock, real_close = runner.fcntl.flock, runner.os.close
    unlocks, closes = [], []

    def flock(fd, flags):
        if flags == runner.fcntl.LOCK_UN:
            unlocks.append(fd)
            if operation == "unlock":
                raise OSError("secret unlock detail")
        return real_flock(fd, flags)

    def close(fd):
        closes.append(fd)
        real_close(fd)
        if operation == "close" and len(closes) == 1:
            raise OSError("secret close detail")

    monkeypatch.setattr(runner.fcntl, "flock", flock)
    monkeypatch.setattr(runner.os, "close", close)
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable) as caught:
        with guard.hold(SUBJECT):
            pass
    assert str(caught.value) == runner.AMBIGUOUS_MESSAGE
    assert len(unlocks) == 1 and len(closes) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("recognized_outpoint_count", -1),
        ("observed_block_height", -1),
        ("incoming_sats", runner.MAX_BITCOIN_SATS + 1),
    ],
)
def test_coordinated_invalid_numeric_result_fails_closed(field, value):
    result = refresh_result()
    object.__setattr__(result.edge_local_result, field, value)
    if hasattr(result.decision, field):
        object.__setattr__(result.decision, field, value)
    with pytest.raises(runner.CanonicalRootEntitlementRefreshRunnerUnavailable):
        runner.normalized_result(result, runner.parse_runner_argv(argv("--dry-run")))
