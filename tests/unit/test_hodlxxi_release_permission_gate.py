from __future__ import annotations

import io
import os
import pwd
import stat
import subprocess
from argparse import Namespace
from pathlib import Path

import pytest

from scripts import hodlxxi_release_permission_gate as gate


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=gate.GIT_ENV,
    )


def commit(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def chmod_accessible(path: Path) -> None:
    current = path.resolve()
    stop = Path("/tmp").resolve()
    while True:
        current.chmod(current.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if current == stop or current.parent == current:
            break
        current = current.parent


def make_repo(tmp_path: Path) -> tuple[Path, str, str]:
    chmod_accessible(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test User")
    (repo / "unchanged.txt").write_text("stable\n", encoding="utf-8")
    base = commit(repo, "base")
    (repo / "app").mkdir()
    (repo / "bin").mkdir()
    (repo / "app" / "models.py").write_text("MODEL = 1\n", encoding="utf-8")
    (repo / "app" / "models.py").chmod(0o644)
    (repo / "bin" / "run").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (repo / "bin" / "run").chmod(0o755)
    target = commit(repo, "target")
    for path in [repo, repo / "app", repo / "bin", repo / ".git"]:
        path.chmod(0o755)
    (repo / "app" / "models.py").chmod(0o644)
    (repo / "bin" / "run").chmod(0o755)
    return repo, base, target


@pytest.fixture
def service_user(monkeypatch: pytest.MonkeyPatch) -> str:
    user = gate.ServiceUser(name="svc", uid=65534, gid=65534, groups=frozenset())
    monkeypatch.setattr(gate, "_load_service_user", lambda name: user)
    monkeypatch.setattr(gate, "_run_service_access_probe", lambda _path, _user, _access: True)
    return "svc"


def run_gate(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = gate.main(argv, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


def args(command: str, repo: Path, base: str, target: str, count: int, user: str) -> list[str]:
    return [
        command,
        "--repo",
        str(repo),
        "--base",
        base,
        "--target",
        target,
        "--expected-count",
        str(count),
        "--service-user",
        user,
    ]


def assert_success(code: int, stdout: str, stderr: str) -> None:
    assert code == 0, stderr
    assert "status=PASS" in stdout
    assert "restart_authorized=yes" in stdout
    assert stderr == ""


def assert_failure(code: int, stdout: str, stderr: str) -> None:
    assert code != 0
    assert stdout == ""
    assert "status=FAIL" in stderr
    assert "status=PASS" not in stderr
    assert "restart_authorized=yes" not in stdout + stderr


def manifest(stdout: str) -> str:
    for line in stdout.splitlines():
        if line.startswith("manifest_sha256="):
            return line.split("=", 1)[1]
    raise AssertionError("manifest missing")


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_verify_succeeds_for_correct_0644_and_0755_files(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_success(code, stdout, stderr)
    assert "release_file_count=2" in stdout


def test_verify_detects_0600_and_0700_while_git_remains_clean(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app" / "models.py").chmod(0o600)
    (repo / "bin" / "run").chmod(0o700)
    assert git(repo, "status", "--porcelain").stdout == ""

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "filesystem mode mismatch" in stderr


def test_verify_mode_changes_nothing(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    executable = repo / "bin" / "run"
    data.chmod(0o600)
    executable.chmod(0o700)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert mode(data) == 0o600
    assert mode(executable) == 0o700


def test_repair_maps_0600_to_0644_and_0700_to_0755(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    executable = repo / "bin" / "run"
    data.chmod(0o600)
    executable.chmod(0o700)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_success(code, stdout, stderr)
    assert mode(data) == 0o644
    assert mode(executable) == 0o755


def test_repair_is_idempotent(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app" / "models.py").chmod(0o600)
    (repo / "bin" / "run").chmod(0o700)

    first = run_gate(args("repair", repo, base, target, 2, service_user))
    second = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_success(*first)
    assert_success(*second)
    assert manifest(first[1]) == manifest(second[1])


def test_unchanged_files_retain_original_modes(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    unchanged = repo / "unchanged.txt"
    unchanged.chmod(0o600)
    (repo / "app" / "models.py").chmod(0o600)
    (repo / "bin" / "run").chmod(0o700)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_success(code, stdout, stderr)
    assert mode(unchanged) == 0o600


def test_ownership_changing_operations_are_never_invoked(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app" / "models.py").chmod(0o600)
    (repo / "bin" / "run").chmod(0o700)

    def forbidden_chown(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("chown must not be invoked")

    monkeypatch.setattr(gate.os, "chown", forbidden_chown)
    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_success(code, stdout, stderr)


def test_wrong_head_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    git(repo, "reset", "--hard", base)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "target commit does not equal current HEAD" in stderr


def test_non_ancestor_base_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    git(repo, "checkout", "--orphan", "other")
    git(repo, "rm", "-rf", ".")
    (repo / "other.txt").write_text("other\n", encoding="utf-8")
    other = commit(repo, "other")
    git(repo, "checkout", target)

    code, stdout, stderr = run_gate(args("verify", repo, other, target, 2, service_user))

    assert base != other
    assert_failure(code, stdout, stderr)
    assert "not an ancestor" in stderr


def test_wrong_expected_count_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 1, service_user))

    assert_failure(code, stdout, stderr)
    assert "changed file count mismatch" in stderr


def test_dirty_content_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app" / "models.py").write_text("dirty\n", encoding="utf-8")

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "dirty tracked content" in stderr


@pytest.mark.parametrize("command", ("verify", "repair"))
def test_assume_unchanged_hidden_dirty_content_fails(tmp_path: Path, service_user: str, command: str) -> None:
    repo, base, target = make_repo(tmp_path)
    git(repo, "update-index", "--assume-unchanged", "app/models.py")
    (repo / "app" / "models.py").write_text("hidden dirty\n", encoding="utf-8")
    assert git(repo, "status", "--porcelain").stdout == ""

    code, stdout, stderr = run_gate(args(command, repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "assume-unchanged index entry is not allowed" in stderr
    assert git(repo, "ls-files", "-v", "app/models.py").stdout.startswith("h ")


@pytest.mark.parametrize("command", ("verify", "repair"))
def test_skip_worktree_hidden_dirty_content_fails(tmp_path: Path, service_user: str, command: str) -> None:
    repo, base, target = make_repo(tmp_path)
    git(repo, "update-index", "--skip-worktree", "app/models.py")
    (repo / "app" / "models.py").write_text("hidden dirty\n", encoding="utf-8")
    assert git(repo, "status", "--porcelain").stdout == ""

    code, stdout, stderr = run_gate(args(command, repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "skip-worktree index entry is not allowed" in stderr
    assert git(repo, "ls-files", "-v", "app/models.py").stdout.startswith("S ")


def test_malformed_index_flag_output_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, _base, _target = make_repo(tmp_path)

    monkeypatch.setattr(
        gate,
        "_run_git",
        lambda _repo, git_args, _label, check=True: (
            subprocess.CompletedProcess(git_args, 0, b"H app/models.py", b"")
            if git_args[:3] == ["ls-files", "-z", "-v"]
            else git(repo, *git_args, check=check)
        ),
    )

    with pytest.raises(gate.FailClosed, match="ambiguous Git output for index flag scan"):
        gate._assert_no_hidden_index_flags(repo)


def test_untracked_files_fail(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "untracked.txt").write_text("x\n", encoding="utf-8")

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "unexpected untracked files" in stderr


def test_symlink_git_mode_fails(tmp_path: Path, service_user: str) -> None:
    chmod_accessible(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test User")
    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    base = commit(repo, "base")
    (repo / "link").symlink_to("target")
    target = commit(repo, "target")
    repo.chmod(0o755)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 1, service_user))

    assert_failure(code, stdout, stderr)
    assert "symlink release path is not supported" in stderr


def test_unsupported_git_mode_fails(tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch) -> None:
    chmod_accessible(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test User")
    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    base = commit(repo, "base")
    git(repo, "update-index", "--add", "--cacheinfo", "160000,0123456789012345678901234567890123456789,submodule")
    git(repo, "commit", "-m", "target")
    target = git(repo, "rev-parse", "HEAD").stdout.strip()
    repo.chmod(0o755)
    monkeypatch.setattr(gate, "_assert_clean_worktree", lambda _repo: None)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 1, service_user))

    assert_failure(code, stdout, stderr)
    assert "submodule release path is not supported" in stderr


def test_path_escape_and_malformed_nul_unsafe_input_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    malformed = b":000000 100644 0 1 A\x00../escape\x00"

    monkeypatch.setattr(
        gate,
        "_run_git",
        lambda _repo, git_args, _label, check=True: (
            subprocess.CompletedProcess(git_args, 0, malformed, b"")
            if git_args[:2] == ["diff", "--raw"]
            else git(repo, *git_args, check=check)
        ),
    )

    with pytest.raises(gate.FailClosed, match="unsafe escaping Git path"):
        gate._derive_release_files(repo, base, target)
    with pytest.raises(gate.FailClosed, match="contains NUL"):
        gate._reject_nul("bad\x00input", "operator input")
    monkeypatch.setattr(
        gate,
        "_run_git",
        lambda _repo, git_args, _label, check=True: subprocess.CompletedProcess(
            git_args,
            0,
            malformed.rstrip(b"\x00"),
            b"",
        ),
    )
    with pytest.raises(gate.FailClosed, match="ambiguous Git output"):
        gate._derive_release_files(repo, base, target)


def test_missing_target_files_fail(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app" / "models.py").unlink()
    release_files = gate._derive_release_files(repo, base, target)

    with pytest.raises(gate.FailClosed, match="missing target file"):
        gate._inspect_release_files(repo, release_files)


def test_non_regular_target_files_fail(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app" / "models.py").unlink()
    os.mkfifo(repo / "app" / "models.py")
    release_files = gate._derive_release_files(repo, base, target)

    with pytest.raises(gate.FailClosed, match="non-regular target file"):
        gate._inspect_release_files(repo, release_files)


def test_root_service_user_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, base, target = make_repo(tmp_path)
    root_user = gate.ServiceUser(name="root", uid=0, gid=0, groups=frozenset({0}))

    def fake_root(_name: str) -> gate.ServiceUser:
        if root_user.uid == 0:
            raise gate.FailClosed("root is not an allowed service user")
        return root_user

    monkeypatch.setattr(gate, "_load_service_user", fake_root)
    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, "root"))

    assert_failure(code, stdout, stderr)
    assert "root is not an allowed service user" in stderr


def test_unreadable_service_user_probe_fails(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app").chmod(0o700)

    def fake_probe(path: Path, _user: gate.ServiceUser, access: str) -> bool:
        if path.name == "models.py" and access == "read":
            return False
        return True

    monkeypatch.setattr(gate, "_run_service_access_probe", fake_probe)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "service user cannot read release file" in stderr


def test_non_executable_service_user_probe_fails(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)

    def fake_probe(path: Path, _user: gate.ServiceUser, access: str) -> bool:
        if path.name == "run" and access == "execute":
            return False
        return True

    monkeypatch.setattr(gate, "_run_service_access_probe", fake_probe)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "service user cannot execute release file" in stderr


def test_service_user_probe_unavailable_fails_closed(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)

    def unavailable(_path: Path, _user: gate.ServiceUser, _access: str) -> bool:
        raise gate.ProbeUnavailable("missing probe")

    monkeypatch.setattr(gate, "_run_service_access_probe", unavailable)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "service-user access probe unavailable" in stderr


def test_service_user_probe_invokes_fixed_child_with_exact_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = gate.ServiceUser(name="svc", uid=1234, gid=2345, groups=frozenset({3456, 4567}))
    path = Path("/tmp/exact-release-file")
    state = {"uid": 0, "euid": 0, "gid": 0, "egid": 0, "groups": []}
    identity_calls: list[tuple[str, object]] = []

    def fake_setgroups(groups: list[int]) -> None:
        identity_calls.append(("setgroups", groups))
        state["groups"] = groups

    def fake_setgid(gid: int) -> None:
        identity_calls.append(("setgid", gid))
        state["gid"] = gid
        state["egid"] = gid

    def fake_setuid(uid: int) -> None:
        identity_calls.append(("setuid", uid))
        state["uid"] = uid
        state["euid"] = uid

    def fake_exit(code: int) -> None:
        raise AssertionError(f"probe preexec exited with {code}")

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert cmd == [gate.PROBE_UTILITY, "-I", "-c", gate.PROBE_SCRIPT, "execute", str(path)]
        assert kwargs["check"] is False
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["env"] == gate.PROBE_ENV
        assert kwargs["cwd"] == "/"
        assert kwargs["timeout"] == gate.PROBE_TIMEOUT_SECONDS
        assert kwargs["close_fds"] is True
        assert "shell" not in kwargs
        preexec = kwargs["preexec_fn"]
        assert callable(preexec)
        preexec()
        return subprocess.CompletedProcess(cmd, gate.PROBE_OK)

    monkeypatch.setattr(gate.os, "setgroups", fake_setgroups)
    monkeypatch.setattr(gate.os, "setgid", fake_setgid)
    monkeypatch.setattr(gate.os, "setuid", fake_setuid)
    monkeypatch.setattr(gate.os, "getuid", lambda: state["uid"])
    monkeypatch.setattr(gate.os, "geteuid", lambda: state["euid"])
    monkeypatch.setattr(gate.os, "getgid", lambda: state["gid"])
    monkeypatch.setattr(gate.os, "getegid", lambda: state["egid"])
    monkeypatch.setattr(gate.os, "getgroups", lambda: state["groups"])
    monkeypatch.setattr(gate.os, "_exit", fake_exit)
    monkeypatch.setattr(gate.subprocess, "run", fake_run)

    assert gate._run_service_access_probe(path, user, "execute") is True
    assert identity_calls == [
        ("setgroups", [3456, 4567]),
        ("setgid", 2345),
        ("setuid", 1234),
    ]


def test_no_successful_marker_or_restart_authorization_after_failure(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app" / "models.py").chmod(0o600)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "status=PASS" not in stdout + stderr
    assert "restart_authorized=yes" not in stdout + stderr


def test_manifest_output_is_deterministic(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)

    first = run_gate(args("verify", repo, base, target, 2, service_user))
    second = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_success(*first)
    assert_success(*second)
    assert manifest(first[1]) == manifest(second[1])


def test_real_root_service_user_is_rejected_when_present(tmp_path: Path) -> None:
    repo, base, target = make_repo(tmp_path)
    pwd.getpwnam("root")

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, "root"))

    assert_failure(code, stdout, stderr)
    assert "root is not an allowed service user" in stderr


def test_repair_chmod_failure_blocks_restart(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    (repo / "app" / "models.py").chmod(0o600)

    def failing_fchmod(_fd: int, _mode: int) -> None:
        raise OSError("denied")

    monkeypatch.setattr(gate, "_fchmod_exact", failing_fchmod)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "no restart is authorized" in stderr
    assert mode(repo / "app" / "models.py") == 0o600


@pytest.mark.parametrize("command", ("verify", "repair"))
def test_pre_existing_release_target_hardlink_fails(tmp_path: Path, service_user: str, command: str) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    alias = tmp_path / "outside-alias.py"
    os.link(data, alias)
    data.chmod(0o600)

    code, stdout, stderr = run_gate(args(command, repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "hardlinked target file is not supported" in stderr
    assert mode(data) == 0o600
    assert mode(alias) == 0o600


def test_release_target_hardlink_to_unchanged_tracked_file_fails(tmp_path: Path, service_user: str) -> None:
    chmod_accessible(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test User")
    (repo / "shared.py").write_text("same\n", encoding="utf-8")
    base = commit(repo, "base")
    (repo / "app").mkdir()
    (repo / "app" / "models.py").write_text("same\n", encoding="utf-8")
    target = commit(repo, "target")
    for path in [repo, repo / "app", repo / ".git"]:
        path.chmod(0o755)
    (repo / "app" / "models.py").unlink()
    os.link(repo / "shared.py", repo / "app" / "models.py")
    (repo / "app" / "models.py").chmod(0o600)
    assert git(repo, "status", "--porcelain").stdout == ""

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 1, service_user))

    assert_failure(code, stdout, stderr)
    assert "hardlinked target file is not supported" in stderr
    assert mode(repo / "app" / "models.py") == 0o600
    assert mode(repo / "shared.py") == 0o600


def test_repair_never_fchmods_unchanged_release_modes(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)

    def forbidden_fchmod(_fd: int, _mode: int) -> None:
        raise AssertionError("fchmod must not be called for already-correct modes")

    monkeypatch.setattr(gate, "_fchmod_exact", forbidden_fchmod)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_success(code, stdout, stderr)


def test_final_path_replacement_during_repair_does_not_chmod_replacement(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    data.chmod(0o600)
    real_fchmod = gate._fchmod_exact
    replaced = False

    def replacing_fchmod(fd: int, mode_to_set: int) -> None:
        nonlocal replaced
        if not replaced:
            data.unlink()
            data.write_text("replacement\n", encoding="utf-8")
            data.chmod(0o600)
            replaced = True
        real_fchmod(fd, mode_to_set)

    monkeypatch.setattr(gate, "_fchmod_exact", replacing_fchmod)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "target changed during repair" in stderr
    assert data.read_text(encoding="utf-8") == "replacement\n"
    assert mode(data) == 0o600


def test_parent_path_replacement_during_repair_does_not_chmod_replacement(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    data.chmod(0o600)
    app_dir = repo / "app"
    old_app_dir = repo / "app.old"
    real_fchmod = gate._fchmod_exact
    replaced = False

    def replacing_fchmod(fd: int, mode_to_set: int) -> None:
        nonlocal replaced
        if not replaced:
            app_dir.rename(old_app_dir)
            app_dir.mkdir()
            (app_dir / "models.py").write_text("replacement\n", encoding="utf-8")
            (app_dir / "models.py").chmod(0o600)
            replaced = True
        real_fchmod(fd, mode_to_set)

    monkeypatch.setattr(gate, "_fchmod_exact", replacing_fchmod)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "target path changed during repair" in stderr
    assert data.read_text(encoding="utf-8") == "replacement\n"
    assert mode(data) == 0o600
    assert mode(old_app_dir / "models.py") == 0o644


def test_parent_path_replacement_between_preflight_and_repair_changes_no_modes(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    executable = repo / "bin" / "run"
    data.chmod(0o600)
    executable.chmod(0o700)
    app_dir = repo / "app"
    old_app_dir = repo / "app.old"
    real_inspect = gate._inspect_release_files
    replaced = False

    def replacing_inspect(repo_arg: Path, release_files: list[gate.ReleaseFile]) -> list[gate.ReleaseFile]:
        nonlocal replaced
        inspected = real_inspect(repo_arg, release_files)
        if not replaced:
            app_dir.rename(old_app_dir)
            app_dir.mkdir()
            (app_dir / "models.py").write_text("replacement\n", encoding="utf-8")
            (app_dir / "models.py").chmod(0o600)
            replaced = True
        return inspected

    monkeypatch.setattr(gate, "_inspect_release_files", replacing_inspect)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "target changed before repair" in stderr
    assert data.read_text(encoding="utf-8") == "replacement\n"
    assert mode(data) == 0o600
    assert mode(old_app_dir / "models.py") == 0o600
    assert mode(executable) == 0o700


def test_inode_replacement_between_preflight_and_repair_changes_no_modes(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    executable = repo / "bin" / "run"
    data.chmod(0o600)
    executable.chmod(0o700)
    real_inspect = gate._inspect_release_files
    replaced = False

    def replacing_inspect(repo_arg: Path, release_files: list[gate.ReleaseFile]) -> list[gate.ReleaseFile]:
        nonlocal replaced
        inspected = real_inspect(repo_arg, release_files)
        if not replaced:
            data.unlink()
            data.write_text("replacement\n", encoding="utf-8")
            data.chmod(0o600)
            replaced = True
        return inspected

    monkeypatch.setattr(gate, "_inspect_release_files", replacing_inspect)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "target changed before repair" in stderr
    assert data.read_text(encoding="utf-8") == "replacement\n"
    assert mode(data) == 0o600
    assert mode(executable) == 0o700


def test_partial_fchmod_failure_blocks_restart_and_rerun_is_idempotent(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    executable = repo / "bin" / "run"
    data.chmod(0o600)
    executable.chmod(0o700)
    real_fchmod = gate._fchmod_exact
    calls = 0

    def fail_second_fchmod(fd: int, mode_to_set: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("denied")
        real_fchmod(fd, mode_to_set)

    monkeypatch.setattr(gate, "_fchmod_exact", fail_second_fchmod)

    first = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(*first)
    assert "no restart is authorized" in first[2]
    assert mode(data) == 0o644
    assert mode(executable) == 0o700

    monkeypatch.setattr(gate, "_fchmod_exact", real_fchmod)
    second = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_success(*second)
    assert mode(data) == 0o644
    assert mode(executable) == 0o755


def test_verify_namespace_is_read_only(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    before = git(repo, "rev-parse", "HEAD").stdout
    ns = Namespace(repo=str(repo), base=base, target=target, expected_count=2, service_user=service_user)

    gate._verify(ns)

    assert git(repo, "rev-parse", "HEAD").stdout == before
