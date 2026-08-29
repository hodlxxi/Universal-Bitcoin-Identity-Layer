from __future__ import annotations

import fcntl
import io
import os
import pwd
import stat
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from typing import Callable

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


def git_bytes(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    proc = git(repo, *args, check=check)
    return subprocess.CompletedProcess(
        proc.args,
        proc.returncode,
        proc.stdout.encode("utf-8"),
        proc.stderr.encode("utf-8"),
    )


def commit(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def chmod_accessible(path: Path) -> None:
    current = path.resolve()
    stop = Path("/tmp").resolve()
    while True:
        current_mode = stat.S_IMODE(current.stat().st_mode)
        accessible_mode = current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        if accessible_mode != current_mode:
            current.chmod(accessible_mode)
        if current == stop or current.parent == current:
            break
        current = current.parent


def test_chmod_accessible_skips_already_accessible_ancestor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    already_accessible = tmp_path / "already-accessible"
    needs_execute = already_accessible / "needs-execute"
    already_accessible.mkdir()
    needs_execute.mkdir()
    already_accessible.chmod(0o755)
    needs_execute.chmod(0o7600)
    path_type = type(tmp_path)
    original_chmod = path_type.chmod
    chmod_calls: list[tuple[Path, int]] = []

    def tracked_chmod(path: Path, new_mode: int) -> None:
        if path == already_accessible:
            raise PermissionError("already accessible ancestor must not be chmodded")
        chmod_calls.append((path, new_mode))
        original_chmod(path, new_mode)

    monkeypatch.setattr(path_type, "chmod", tracked_chmod)

    chmod_accessible(needs_execute)

    assert (already_accessible, 0o755) not in chmod_calls
    assert (needs_execute, 0o7711) in chmod_calls
    assert mode(needs_execute) == 0o7711


def make_repo(tmp_path: Path, *, object_format: str | None = None) -> tuple[Path, str, str]:
    chmod_accessible(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    if object_format is None:
        git(repo, "init")
    else:
        init = git(repo, "init", f"--object-format={object_format}", check=False)
        if init.returncode != 0:
            pytest.skip(f"git object format is unavailable: {object_format}")
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
    monkeypatch.setattr(
        gate,
        "_run_bound_service_access_probe",
        lambda _path, _user, _access, _identity: True,
    )
    return "svc"


AUTO_AUTHORIZATION_LOCK_FDS: set[int] = set()


def make_authorization_lock(
    lock_dir: Path,
    *,
    name: str = "authorization.lock",
    mode: int = 0o600,
    inheritable: bool = True,
    locked: bool = True,
) -> tuple[Path, int]:
    path = lock_dir / name
    path.write_text("", encoding="utf-8")
    path.chmod(mode)
    fd = os.open(path, os.O_RDWR)
    os.set_inheritable(fd, inheritable)
    if locked:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return path, fd


def close_authorization_lock(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def can_acquire_authorization_lock(path: Path) -> bool:
    fd = os.open(path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True
    finally:
        os.close(fd)


def _argv_authorization_lock_fd(argv: list[str]) -> int | None:
    try:
        index = argv.index("--authorization-lock-fd")
    except ValueError:
        return None
    try:
        return int(argv[index + 1])
    except (IndexError, ValueError):
        return None


def run_gate(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        code = gate.main(argv, stdout=stdout, stderr=stderr)
        return code, stdout.getvalue(), stderr.getvalue()
    finally:
        fd = _argv_authorization_lock_fd(argv)
        if fd in AUTO_AUTHORIZATION_LOCK_FDS:
            AUTO_AUTHORIZATION_LOCK_FDS.remove(fd)
            close_authorization_lock(fd)


def args(
    command: str,
    repo: Path,
    base: str,
    target: str,
    count: int,
    user: str,
    *,
    authorization_lock_fd: int | None = None,
    authorization_lock_path: Path | str | None = None,
    include_authorization_lock: bool = True,
) -> list[str]:
    argv = [
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
    if not include_authorization_lock:
        return argv
    if authorization_lock_fd is None and authorization_lock_path is None:
        authorization_lock_path, authorization_lock_fd = make_authorization_lock(repo.parent)
        AUTO_AUTHORIZATION_LOCK_FDS.add(authorization_lock_fd)
    if authorization_lock_fd is None or authorization_lock_path is None:
        raise AssertionError("authorization lock fd and path must be supplied together")
    argv.extend(
        [
            "--authorization-lock-fd",
            str(authorization_lock_fd),
            "--authorization-lock-path",
            str(authorization_lock_path),
        ]
    )
    return argv


def assert_success(code: int, stdout: str, stderr: str) -> None:
    assert code == 0, stderr
    assert "status=PASS" in stdout
    assert "lock_bound_authorization=yes" in stdout
    assert "authorization_valid_while_caller_retains_lock_fd=yes" in stdout
    assert "authorization_lock_identity=" in stdout
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


def output_value(stdout: str, key: str) -> str:
    prefix = f"{key}="
    for line in stdout.splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1]
    raise AssertionError(f"{key} missing")


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def mutate_after_final_clean(monkeypatch: pytest.MonkeyPatch, action: Callable[[], None]) -> None:
    real_clean = gate._assert_clean_worktree
    calls = 0

    def clean_then_mutate(repo_arg: Path) -> None:
        nonlocal calls
        real_clean(repo_arg)
        calls += 1
        if calls == 3:
            action()

    monkeypatch.setattr(gate, "_assert_clean_worktree", clean_then_mutate)


def test_valid_inherited_parent_held_authorization_lock(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert_success(code, stdout, stderr)
        lock_stat = lock_path.stat()
        assert output_value(stdout, "authorization_lock_path") == str(lock_path)
        assert output_value(stdout, "authorization_lock_dev") == str(lock_stat.st_dev)
        assert output_value(stdout, "authorization_lock_ino") == str(lock_stat.st_ino)
        assert output_value(stdout, "authorization_lock_identity") == f"{lock_stat.st_dev}:{lock_stat.st_ino}"
    finally:
        close_authorization_lock(lock_fd)


def test_missing_authorization_lock_descriptor_argument_emits_structured_failure(
    tmp_path: Path,
    service_user: str,
) -> None:
    repo, base, target = make_repo(tmp_path)

    code, stdout, stderr = run_gate(
        [
            "verify",
            "--repo",
            str(repo),
            "--base",
            base,
            "--target",
            target,
            "--expected-count",
            "2",
            "--service-user",
            service_user,
            "--authorization-lock-path",
            "/tmp/hodlxxi-unused-parser-test.lock",
        ]
    )

    assert_failure(code, stdout, stderr)
    assert "command=verify" in stderr
    assert "invalid command line:" in stderr
    assert "--authorization-lock-fd" in stderr
    assert "operator_action=do_not_restart" in stderr


def test_closed_authorization_lock_descriptor_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    close_authorization_lock(lock_fd)

    code, stdout, stderr = run_gate(
        args(
            "verify",
            repo,
            base,
            target,
            2,
            service_user,
            authorization_lock_fd=lock_fd,
            authorization_lock_path=lock_path,
        )
    )

    assert_failure(code, stdout, stderr)
    assert "authorization lock descriptor is not open" in stderr


def test_non_inherited_authorization_lock_descriptor_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path, inheritable=False)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock descriptor is not inheritable" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_authorization_lock_descriptor_path_mismatch_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path, name="authorization.lock")
    other_path, other_fd = make_authorization_lock(tmp_path, name="other-authorization.lock")
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=other_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock descriptor/path mismatch" in stderr
    finally:
        close_authorization_lock(lock_fd)
        close_authorization_lock(other_fd)


def test_missing_authorization_lock_path_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    missing_path = tmp_path / "missing-authorization.lock"
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=missing_path,
            )
        )

        assert missing_path != lock_path
        assert_failure(code, stdout, stderr)
        assert "authorization lock path is not available" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_non_normalized_authorization_lock_path_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    non_normalized_path = f"{tmp_path}/./{lock_path.name}"
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=non_normalized_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock path must be absolute and normalized" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_non_regular_authorization_lock_descriptor_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path = tmp_path / "authorization-lock-dir"
    lock_path.mkdir()
    lock_fd = os.open(lock_path, os.O_RDONLY)
    os.set_inheritable(lock_fd, True)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock must be a regular file" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_symlink_authorization_lock_path_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path, name="authorization.lock")
    symlink_path = tmp_path / "authorization-link.lock"
    symlink_path.symlink_to(lock_path)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=symlink_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock path must not be a symlink" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_hardlink_authorization_lock_path_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path, name="authorization.lock")
    os.link(lock_path, tmp_path / "authorization-hardlink.lock")
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock link count must be exactly one" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_unsafe_authorization_lock_mode_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path, mode=0o622)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock must not be group/other writable" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_incorrect_authorization_lock_owner_fails(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    original_euid = os.geteuid()
    monkeypatch.setattr(gate.os, "geteuid", lambda: original_euid + 1)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock must be owned by the effective user" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_competing_authorization_lock_holder_fails(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    holder_path, holder_fd = make_authorization_lock(tmp_path)
    contender_fd = os.open(holder_path, os.O_RDWR)
    os.set_inheritable(contender_fd, True)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=contender_fd,
                authorization_lock_path=holder_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock is already held" in stderr
    finally:
        close_authorization_lock(contender_fd)
        close_authorization_lock(holder_fd)


def test_authorization_lock_is_retained_by_parent_after_gate_exits(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    try:
        result = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert_success(*result)
        assert can_acquire_authorization_lock(lock_path) is False
    finally:
        close_authorization_lock(lock_fd)


def test_subprocess_inherited_lock_handoff_retains_parent_lock_after_gate_exit(
    tmp_path: Path,
    service_user: str,
) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    child = """
import sys
from scripts import hodlxxi_release_permission_gate as gate

gate._load_service_user = lambda name: gate.ServiceUser(name="svc", uid=65534, gid=65534, groups=frozenset())
gate._run_service_access_probe = lambda path, user, access: True
gate._run_bound_service_access_probe = lambda path, user, access, identity: True
raise SystemExit(gate.main(sys.argv[1:]))
""".strip()
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                child,
                *args(
                    "verify",
                    repo,
                    base,
                    target,
                    2,
                    service_user,
                    authorization_lock_fd=lock_fd,
                    authorization_lock_path=lock_path,
                ),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=Path.cwd(),
            pass_fds=(lock_fd,),
        )

        assert_success(proc.returncode, proc.stdout, proc.stderr)
        assert can_acquire_authorization_lock(lock_path) is False
        restart_performed_while_lock_retained = not can_acquire_authorization_lock(lock_path)
        assert restart_performed_while_lock_retained is True
    finally:
        close_authorization_lock(lock_fd)
    assert can_acquire_authorization_lock(lock_path) is True


def test_authorization_is_invalid_after_parent_closes_descriptor(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)

    result = run_gate(
        args(
            "verify",
            repo,
            base,
            target,
            2,
            service_user,
            authorization_lock_fd=lock_fd,
            authorization_lock_path=lock_path,
        )
    )
    close_authorization_lock(lock_fd)

    assert_success(*result)
    assert "authorization_valid_while_caller_retains_lock_fd=yes" in result[1]
    assert can_acquire_authorization_lock(lock_path) is True


def test_authorization_lock_replacement_after_final_clean_fails_without_restart_authorization(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    mutated = False

    def mutate() -> None:
        nonlocal mutated
        lock_path.unlink()
        lock_path.write_text("", encoding="utf-8")
        lock_path.chmod(0o600)
        mutated = True

    mutate_after_final_clean(monkeypatch, mutate)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert mutated
        assert_failure(code, stdout, stderr)
        assert "final authorization lock validation failed" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_authorization_lock_mode_race_after_final_clean_fails_without_restart_authorization(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    mutated = False

    def mutate() -> None:
        nonlocal mutated
        lock_path.chmod(0o622)
        mutated = True

    mutate_after_final_clean(monkeypatch, mutate)
    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert mutated
        assert_failure(code, stdout, stderr)
        assert "final authorization lock validation failed" in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_verify_succeeds_for_correct_0644_and_0755_files(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_success(code, stdout, stderr)
    assert "release_file_count=2" in stdout


def test_verify_succeeds_for_sha256_repository_object_format(tmp_path: Path, service_user: str) -> None:
    repo, base, target = make_repo(tmp_path, object_format="sha256")

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert len(base) == 64
    assert len(target) == 64
    assert_success(code, stdout, stderr)


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
            else git_bytes(repo, *git_args, check=check)
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

    def fake_probe(
        path: Path,
        _user: gate.ServiceUser,
        access: str,
        _identity: gate.FileIdentity,
    ) -> bool:
        if path.name == "models.py" and access == "read":
            return False
        return True

    monkeypatch.setattr(gate, "_run_bound_service_access_probe", fake_probe)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "service user cannot read exact release file" in stderr


def test_non_executable_service_user_probe_fails(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)

    def fake_probe(
        path: Path,
        _user: gate.ServiceUser,
        access: str,
        _identity: gate.FileIdentity,
    ) -> bool:
        if path.name == "run" and access == "execute":
            return False
        return True

    monkeypatch.setattr(gate, "_run_bound_service_access_probe", fake_probe)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "service user cannot execute exact release file" in stderr


def test_service_user_probe_unavailable_fails_closed(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)

    def unavailable(
        _path: Path,
        _user: gate.ServiceUser,
        _access: str,
        _identity: gate.FileIdentity,
    ) -> bool:
        raise gate.ProbeUnavailable("missing probe")

    monkeypatch.setattr(gate, "_run_bound_service_access_probe", unavailable)

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


def test_replacement_between_clean_state_and_descriptor_inspection_fails_closed(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    real_clean = gate._assert_clean_worktree
    replaced = False

    def clean_then_replace(repo_arg: Path) -> None:
        nonlocal replaced
        real_clean(repo_arg)
        if not replaced:
            data.unlink()
            data.write_text("dirty replacement\n", encoding="utf-8")
            data.chmod(0o644)
            replaced = True

    monkeypatch.setattr(gate, "_assert_clean_worktree", clean_then_replace)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert replaced
    assert_failure(code, stdout, stderr)
    assert "target blob mismatch" in stderr


def test_mutation_between_initial_descriptor_hashing_and_access_probe_fails_closed(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    real_assert_blob = gate._assert_target_blob
    mutated = False

    def assert_blob_then_mutate(opened: gate.OpenReleaseFile, object_format: str, context: str) -> None:
        nonlocal mutated
        real_assert_blob(opened, object_format, context)
        if context == "target changed before verification" and opened.release_file.relpath == "app/models.py":
            if not mutated:
                data.write_text("dirty after descriptor hash\n", encoding="utf-8")
                mutated = True

    monkeypatch.setattr(gate, "_assert_target_blob", assert_blob_then_mutate)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert mutated
    assert_failure(code, stdout, stderr)
    assert "dirty tracked content" in stderr


def test_replacement_between_access_probe_and_final_authorization_fails_closed(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    real_service_access = gate._assert_service_access
    replaced = False

    def access_then_replace(
        repo_arg: Path,
        release_files: list[gate.ReleaseFile],
        user: gate.ServiceUser,
    ) -> None:
        nonlocal replaced
        real_service_access(repo_arg, release_files, user)
        if not replaced:
            data.unlink()
            data.write_text("dirty replacement after access\n", encoding="utf-8")
            data.chmod(0o644)
            replaced = True

    monkeypatch.setattr(gate, "_assert_service_access", access_then_replace)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert replaced
    assert_failure(code, stdout, stderr)
    assert "dirty tracked content" in stderr


def test_metadata_change_between_access_probe_and_final_authorization_fails_closed(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    real_service_access = gate._assert_service_access
    changed = False

    def access_then_touch(
        repo_arg: Path,
        release_files: list[gate.ReleaseFile],
        user: gate.ServiceUser,
    ) -> None:
        nonlocal changed
        real_service_access(repo_arg, release_files, user)
        if not changed:
            stat_before = data.stat()
            os.utime(data, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns + 1_000_000_000))
            changed = True

    monkeypatch.setattr(gate, "_assert_service_access", access_then_touch)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert changed
    assert_failure(code, stdout, stderr)
    assert "final target validation failed" in stderr


def test_content_write_after_final_clean_fails_without_restart_authorization(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    mutated = False

    def mutate() -> None:
        nonlocal mutated
        data.write_text("DIRTY = 2\n", encoding="utf-8")
        mutated = True

    mutate_after_final_clean(monkeypatch, mutate)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert mutated
    assert_failure(code, stdout, stderr)
    assert "final target validation failed" in stderr


def test_truncation_after_final_clean_fails_without_restart_authorization(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    mutated = False

    def mutate() -> None:
        nonlocal mutated
        data.write_text("", encoding="utf-8")
        mutated = True

    mutate_after_final_clean(monkeypatch, mutate)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert mutated
    assert_failure(code, stdout, stderr)
    assert "final target validation failed" in stderr


def test_relink_after_final_clean_fails_without_restart_authorization(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    alias = tmp_path / "late-hardlink.py"
    mutated = False

    def mutate() -> None:
        nonlocal mutated
        os.link(data, alias)
        mutated = True

    mutate_after_final_clean(monkeypatch, mutate)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert mutated
    assert_failure(code, stdout, stderr)
    assert "final target validation failed" in stderr


def test_replacement_after_final_clean_fails_without_restart_authorization(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    mutated = False

    def mutate() -> None:
        nonlocal mutated
        data.unlink()
        data.write_text("MODEL = 1\n", encoding="utf-8")
        data.chmod(0o644)
        mutated = True

    mutate_after_final_clean(monkeypatch, mutate)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert mutated
    assert_failure(code, stdout, stderr)
    assert "final target validation failed" in stderr


def test_chmod_after_final_clean_fails_without_restart_authorization(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    mutated = False

    def mutate() -> None:
        nonlocal mutated
        data.chmod(0o600)
        mutated = True

    mutate_after_final_clean(monkeypatch, mutate)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert mutated
    assert_failure(code, stdout, stderr)
    assert "final target validation failed" in stderr


def test_replacement_between_permission_repair_and_final_authorization_fails_closed(
    tmp_path: Path, service_user: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    data.chmod(0o600)
    real_repair_open_files = gate._repair_open_files
    replaced = False

    def repair_then_replace(
        repo_arg: Path,
        open_files: list[gate.OpenReleaseFile],
        object_format: str,
    ) -> None:
        nonlocal replaced
        real_repair_open_files(repo_arg, open_files, object_format)
        if not replaced:
            data.unlink()
            data.write_text("dirty replacement after repair\n", encoding="utf-8")
            data.chmod(0o644)
            replaced = True

    monkeypatch.setattr(gate, "_repair_open_files", repair_then_replace)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert replaced
    assert_failure(code, stdout, stderr)
    assert "dirty tracked content" in stderr
    assert data.read_text(encoding="utf-8") == "dirty replacement after repair\n"


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
    lock_path, lock_fd = make_authorization_lock(tmp_path)
    ns = Namespace(
        repo=str(repo),
        base=base,
        target=target,
        expected_count=2,
        service_user=service_user,
        authorization_lock_fd=lock_fd,
        authorization_lock_path=str(lock_path),
    )

    try:
        gate._verify(ns)
    finally:
        close_authorization_lock(lock_fd)

    assert git(repo, "rev-parse", "HEAD").stdout == before


def test_unsafe_authorization_lock_parent_directory_fails(
    tmp_path: Path,
    service_user: str,
) -> None:
    repo, base, target = make_repo(tmp_path)
    unsafe_parent = tmp_path / "unsafe-lock-parent"
    unsafe_parent.mkdir()
    unsafe_parent.chmod(0o777)
    lock_path, lock_fd = make_authorization_lock(unsafe_parent)

    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=lock_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert ("authorization lock parent must not be group/other writable " "without sticky bit") in stderr
    finally:
        close_authorization_lock(lock_fd)


def test_symlink_authorization_lock_parent_directory_fails(
    tmp_path: Path,
    service_user: str,
) -> None:
    repo, base, target = make_repo(tmp_path)
    real_parent = tmp_path / "real-lock-parent"
    linked_parent = tmp_path / "linked-lock-parent"
    real_parent.mkdir()
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    real_lock_path, lock_fd = make_authorization_lock(real_parent)
    linked_lock_path = linked_parent / real_lock_path.name

    try:
        code, stdout, stderr = run_gate(
            args(
                "verify",
                repo,
                base,
                target,
                2,
                service_user,
                authorization_lock_fd=lock_fd,
                authorization_lock_path=linked_lock_path,
            )
        )

        assert_failure(code, stdout, stderr)
        assert "authorization lock parent must not be a symlink" in stderr
    finally:
        close_authorization_lock(lock_fd)


@pytest.mark.parametrize("dirty_kind", ["tracked", "untracked"])
def test_final_clean_recheck_covers_non_release_paths(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
    dirty_kind: str,
) -> None:
    repo, base, target = make_repo(tmp_path)

    if dirty_kind == "tracked":
        dirty_path = repo / "unchanged.txt"
    else:
        dirty_path = repo / "late-untracked.txt"

    def mutate_non_release_path() -> None:
        dirty_path.write_text("late non-release mutation\n", encoding="utf-8")

    mutate_after_final_clean(monkeypatch, mutate_non_release_path)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert dirty_path.read_text(encoding="utf-8") == "late non-release mutation\n"


def test_run_git_forces_fsmonitor_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(command)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)

    gate._run_git(
        tmp_path,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        "worktree status",
    )

    assert observed == [
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(tmp_path),
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ]
    ]


def test_chmod_after_last_clean_status_fails_without_restart_authorization(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"

    real_clean = gate._assert_clean_worktree
    clean_calls = 0
    mutated = False

    def clean_then_late_chmod(repo_arg: Path) -> None:
        nonlocal clean_calls, mutated

        real_clean(repo_arg)
        clean_calls += 1

        # One preflight clean check plus three final-authorization clean
        # checks. Mutate immediately after the last Git-status observation.
        if clean_calls == 4:
            data.chmod(0o600)
            mutated = True

    monkeypatch.setattr(
        gate,
        "_assert_clean_worktree",
        clean_then_late_chmod,
    )

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert clean_calls >= 4
    assert mutated
    assert_failure(code, stdout, stderr)
    assert "post-status final target validation failed" in stderr
    assert "restart_authorized=yes" not in stdout + stderr
    assert stat.S_IMODE(data.stat().st_mode) == 0o600


def test_same_size_write_after_final_descriptor_hash_fails_closed(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"

    original = data.read_bytes()
    assert original

    replacement = bytearray(original)
    replacement[0] ^= 1
    replacement_bytes = bytes(replacement)

    assert replacement_bytes != original
    assert len(replacement_bytes) == len(original)

    real_assert_target_blob = gate._assert_target_blob
    mutated = False

    def hash_then_mutate(
        opened: gate.OpenReleaseFile,
        object_format: str,
        context: str,
    ) -> None:
        nonlocal mutated

        real_assert_target_blob(opened, object_format, context)

        # Mutate only after the final descriptor hash has consumed the old
        # bytes, but before _revalidate_open_file returns.
        if context == "post-access final target validation failed" and not mutated:
            data.write_bytes(replacement_bytes)
            mutated = True

    monkeypatch.setattr(
        gate,
        "_assert_target_blob",
        hash_then_mutate,
    )

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert mutated
    assert_failure(code, stdout, stderr)
    assert "descriptor changed during target hash" in stderr
    assert "restart_authorized=yes" not in stdout + stderr
    assert data.read_bytes() == replacement_bytes


def test_repair_probe_authority_failure_precedes_fchmod(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    data.chmod(0o600)

    fchmod_called = False

    def authority_failure(
        _path: Path,
        _user: gate.ServiceUser,
        _access: str,
    ) -> bool:
        raise gate.FailClosed("service-user access probe requires effective root")

    def forbidden_fchmod(_fd: int, _mode: int) -> None:
        nonlocal fchmod_called
        fchmod_called = True
        raise AssertionError("repair mutated mode before probe authority preflight")

    monkeypatch.setattr(
        gate,
        "_run_service_access_probe",
        authority_failure,
    )
    monkeypatch.setattr(
        gate,
        "_fchmod_exact",
        forbidden_fchmod,
    )

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "service-user access probe requires effective root" in stderr
    assert not fchmod_called
    assert mode(data) == 0o600
    assert "restart_authorized=yes" not in stdout + stderr


def test_repair_probe_unavailable_precedes_fchmod(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    data.chmod(0o600)

    fchmod_called = False

    def unavailable(
        _path: Path,
        _user: gate.ServiceUser,
        _access: str,
    ) -> bool:
        raise gate.ProbeUnavailable("credential switch unavailable")

    def forbidden_fchmod(_fd: int, _mode: int) -> None:
        nonlocal fchmod_called
        fchmod_called = True
        raise AssertionError("repair mutated mode before probe availability preflight")

    monkeypatch.setattr(
        gate,
        "_run_service_access_probe",
        unavailable,
    )
    monkeypatch.setattr(
        gate,
        "_fchmod_exact",
        forbidden_fchmod,
    )

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "service-user access probe unavailable before repair" in stderr
    assert not fchmod_called
    assert mode(data) == 0o600
    assert "restart_authorized=yes" not in stdout + stderr


def test_repair_execute_probe_unavailable_precedes_fchmod(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    data.chmod(0o600)

    accesses: list[str] = []
    fchmod_called = False

    def probe(
        _path: Path,
        _user: gate.ServiceUser,
        access: str,
    ) -> bool:
        accesses.append(access)
        if access == "read":
            return True
        if access == "execute":
            raise gate.ProbeUnavailable("execute probe unavailable")
        raise AssertionError(f"unexpected probe access: {access}")

    def forbidden_fchmod(_fd: int, _mode: int) -> None:
        nonlocal fchmod_called
        fchmod_called = True
        raise AssertionError("repair mutated mode before execute-probe preflight")

    monkeypatch.setattr(gate, "_run_service_access_probe", probe)
    monkeypatch.setattr(gate, "_fchmod_exact", forbidden_fchmod)

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert accesses == ["read", "execute"]
    assert "service-user access probe unavailable before repair" in stderr
    assert not fchmod_called
    assert mode(data) == 0o600
    assert "restart_authorized=yes" not in stdout + stderr


def test_self_referential_symlink_race_fails_structured(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    mutated = False

    def mutate() -> None:
        nonlocal mutated
        data.unlink()
        data.symlink_to("models.py")
        mutated = True

    mutate_after_final_clean(monkeypatch, mutate)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 2, service_user))

    assert mutated
    assert_failure(code, stdout, stderr)

    # The race may be rejected by descriptor/path identity validation before
    # _release_path() itself is reached. The security contract here is that
    # the swap always becomes a structured fail-closed result, never a
    # traceback or restart authorization.
    assert "status=FAIL" in stderr
    assert "operator_action=do_not_restart" in stderr
    assert "Traceback" not in stderr
    assert "restart_authorized=yes" not in stdout + stderr
    assert data.is_symlink()


def test_self_referential_symlink_resolution_runtimeerror_is_failclosed(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()

    data = repo / "app" / "models.py"
    data.symlink_to("models.py")

    release_file = gate.ReleaseFile(
        path_bytes=b"app/models.py",
        relpath="app/models.py",
        git_mode="100644",
        target_oid="0" * 40,
        expected_mode=0o644,
    )

    with pytest.raises(
        gate.FailClosed,
        match="unsafe escaping target path",
    ):
        gate._release_path(repo, release_file)


def test_gate_git_environment_disables_replacement_objects(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    subprocess.run(
        ["git", "-C", str(repo), "init"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    tracked = repo / "tracked.txt"

    tracked.write_text("original\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(repo), "add", "tracked.txt"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "original"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    original = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()

    tracked.write_text("replacement\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(repo), "add", "tracked.txt"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "replacement"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    replacement = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()

    subprocess.run(
        ["git", "-C", str(repo), "replace", original, replacement],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    normal = subprocess.run(
        ["git", "-C", str(repo), "show", f"{original}:tracked.txt"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert normal.stdout == "replacement\n"

    protected = gate._run_git(
        repo,
        ["show", f"{original}:tracked.txt"],
        "replacement-ref regression",
    )
    assert protected.stdout == b"original\n"

    assert gate.GIT_ENV["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_diff_ignore_submodules_all_cannot_hide_gitlink(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    git(repo, "init")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test User")

    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    base = commit(repo, "base")

    git(
        repo,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{base},vendor/sub",
    )
    git(repo, "commit", "-m", "target")
    target = git(repo, "rev-parse", "HEAD").stdout.strip()

    git(repo, "config", "diff.ignoreSubmodules", "all")

    hidden = git(
        repo,
        "diff",
        "--raw",
        "--full-index",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        base,
        target,
        "--",
    )
    assert hidden.stdout == ""

    with pytest.raises(
        gate.FailClosed,
        match="submodule release path is not supported",
    ):
        gate._derive_release_files(repo, base, target)


def test_bad_expected_count_cli_parse_emits_structured_failure() -> None:
    code, stdout, stderr = run_gate(
        [
            "verify",
            "--repo",
            "/tmp/not-reached",
            "--base",
            "0" * 40,
            "--target",
            "1" * 40,
            "--expected-count",
            "not-a-number",
            "--service-user",
            "svc",
            "--authorization-lock-fd",
            "3",
            "--authorization-lock-path",
            "/tmp/hodlxxi-unused-parser-test.lock",
        ]
    )

    assert_failure(code, stdout, stderr)
    assert "command=verify" in stderr
    assert "invalid command line:" in stderr
    assert "expected count must be a non-negative integer" in stderr
    assert "operator_action=do_not_restart" in stderr


def test_emit_fail_escapes_untrusted_authorization_markers() -> None:
    stderr = io.StringIO()

    gate._emit_fail(
        "verify",
        "bad\rrestart_authorized=yes\nstatus=PASS\x00%=",
        stderr,
    )

    output = stderr.getvalue()

    assert "status=FAIL" in output
    assert "operator_action=do_not_restart" in output
    assert "restart_authorized=yes" not in output
    assert "status=PASS" not in output
    assert "reason=bad%0Drestart_authorized%3Dyes%0Astatus%3DPASS%00%25%3D" in output


def test_symlink_release_path_cannot_inject_restart_authorization(
    tmp_path: Path,
    service_user: str,
) -> None:
    chmod_accessible(tmp_path)

    repo = tmp_path / "repo"
    repo.mkdir()

    git(repo, "init")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test User")

    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    base = commit(repo, "base")

    injected_name = "bad\rrestart_authorized=yes"
    (repo / injected_name).symlink_to("target")
    target = commit(repo, "target")

    repo.chmod(0o755)

    code, stdout, stderr = run_gate(args("verify", repo, base, target, 1, service_user))

    assert_failure(code, stdout, stderr)
    assert "restart_authorized=yes" not in stdout + stderr
    assert "bad%0Drestart_authorized%3Dyes" in stderr


def test_gate_isolated_startup_ignores_worktree_stdlib_shadow(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    source_gate = repo_root / "scripts" / "hodlxxi_release_permission_gate.py"

    first_line = source_gate.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == "#!/usr/bin/python3 -I"

    doc = (repo_root / "docs" / "ops" / "HODLXXI_RELEASE_FILE_PERMISSION_GATE_V1.md").read_text(encoding="utf-8")

    assert "python scripts/hodlxxi_release_permission_gate.py" not in doc
    assert "/usr/bin/python3 -I scripts/hodlxxi_release_permission_gate.py" in doc

    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()

    copied_gate = scripts_dir / "hodlxxi_release_permission_gate.py"
    copied_gate.write_bytes(source_gate.read_bytes())

    marker = tmp_path / "shadow-imported"

    (scripts_dir / "argparse.py").write_text(
        f"open({str(marker)!r}, 'w').write('imported')\n" "raise RuntimeError('worktree argparse shadow imported')\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, "-I", str(copied_gate), "--help"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    assert not marker.exists()


def test_bound_service_probe_script_rejects_replaced_inode(
    tmp_path: Path,
) -> None:
    target = tmp_path / "release-file"
    target.write_text("original\n", encoding="utf-8")
    target.chmod(0o644)

    identity = gate._identity_from_stat(target.lstat())

    identity_args = [
        str(identity.dev),
        str(identity.ino),
        str(identity.uid),
        str(identity.gid),
        str(identity.file_type),
        str(identity.link_count),
        str(identity.fs_mode),
        str(identity.size),
        str(identity.mtime_ns),
        str(identity.ctime_ns),
    ]

    correct = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            gate.BOUND_PROBE_SCRIPT,
            "read",
            str(target),
            *identity_args,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    assert correct.returncode == gate.PROBE_OK

    target.unlink()
    target.write_text("replacement\n", encoding="utf-8")
    target.chmod(0o644)

    replaced = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            gate.BOUND_PROBE_SCRIPT,
            "read",
            str(target),
            *identity_args,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    assert replaced.returncode == gate.PROBE_DENIED


def test_repair_bound_probe_unavailable_precedes_fchmod(
    tmp_path: Path,
    service_user: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, base, target = make_repo(tmp_path)
    data = repo / "app" / "models.py"
    data.chmod(0o600)

    fchmod_called = False

    monkeypatch.setattr(
        gate,
        "_run_service_access_probe",
        lambda _path, _user, _access: True,
    )

    def bound_unavailable(
        _path: Path,
        _user: gate.ServiceUser,
        _access: str,
        _identity: gate.FileIdentity,
    ) -> bool:
        raise gate.ProbeUnavailable("bound credential-switched probe unavailable")

    def forbidden_fchmod(_fd: int, _mode: int) -> None:
        nonlocal fchmod_called
        fchmod_called = True
        raise AssertionError("repair mutated mode before bound-probe preflight")

    monkeypatch.setattr(
        gate,
        "_run_bound_service_access_probe",
        bound_unavailable,
    )
    monkeypatch.setattr(
        gate,
        "_fchmod_exact",
        forbidden_fchmod,
    )

    code, stdout, stderr = run_gate(args("repair", repo, base, target, 2, service_user))

    assert_failure(code, stdout, stderr)
    assert "service-user access probe unavailable before repair" in stderr
    assert not fchmod_called
    assert mode(data) == 0o600
    assert "restart_authorized=yes" not in stdout + stderr


def test_clean_worktree_forces_submodule_dirtiness_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    monkeypatch.setattr(
        gate,
        "_assert_no_hidden_index_flags",
        lambda _repo: None,
    )

    def fake_run_git(
        _repo: Path,
        git_args: list[str],
        _label: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        del check
        calls.append(git_args)
        return subprocess.CompletedProcess(
            git_args,
            0,
            b"",
            b"",
        )

    monkeypatch.setattr(gate, "_run_git", fake_run_git)

    gate._assert_clean_worktree(tmp_path)

    assert calls == [
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ]
    ]


def test_bound_read_probe_contract_performs_actual_read() -> None:
    assert "os.open(" in gate.BOUND_PROBE_SCRIPT and "os.O_RDONLY | os.O_CLOEXEC" in gate.BOUND_PROBE_SCRIPT
    assert "os.read(read_fd, 1)" in gate.BOUND_PROBE_SCRIPT


def test_oversized_authorization_lock_fd_fails_structured(
    tmp_path: Path,
    service_user: str,
) -> None:
    repo, base, target = make_repo(tmp_path)

    lock_path, real_lock_fd = make_authorization_lock(
        tmp_path,
        name="oversized-fd.lock",
    )

    try:
        argv = args(
            "verify",
            repo,
            base,
            target,
            2,
            service_user,
            authorization_lock_fd=2**63,
            authorization_lock_path=lock_path,
        )

        code, stdout, stderr = run_gate(argv)
    finally:
        close_authorization_lock(real_lock_fd)

    assert_failure(code, stdout, stderr)
    assert "authorization lock descriptor is not open" in stderr
    assert "restart_authorized=yes" not in stdout + stderr


def test_resolve_repo_symlink_loop_fails_closed(tmp_path: Path) -> None:
    loop = tmp_path / "repo-loop"
    loop.symlink_to(loop.name)

    with pytest.raises(gate.FailClosed, match="repository does not exist"):
        gate._resolve_repo(str(loop))


def test_resolve_repo_git_toplevel_symlink_loop_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    loop = tmp_path / "top-loop"
    loop.symlink_to(loop.name)

    def fake_run_git(
        _repo: Path,
        git_args: list[str],
        _label: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        del check
        assert git_args == ["rev-parse", "--show-toplevel"]
        return subprocess.CompletedProcess(
            git_args,
            0,
            (str(loop) + "\n").encode(),
            b"",
        )

    monkeypatch.setattr(gate, "_run_git", fake_run_git)

    with pytest.raises(
        gate.FailClosed,
        match="Git repository lookup returned an unsafe path",
    ):
        gate._resolve_repo(str(repo))
