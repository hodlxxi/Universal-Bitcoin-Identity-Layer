#!/usr/bin/env python3
"""HODLXXI release file permission gate V1."""

from __future__ import annotations

import argparse
import grp
import hashlib
import os
import pwd
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TextIO

MARKER = "HODLXXI_RELEASE_FILE_PERMISSION_GATE_V1"
MODE_MAP = {"100644": 0o644, "100755": 0o755}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
INDEX_UPPER_TAGS = {b"H", b"S", b"M", b"R", b"C", b"K", b"?"}
GIT_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "GIT_OPTIONAL_LOCKS": "0",
}
PROBE_UTILITY = "/usr/bin/python3"
PROBE_ENV = {"LC_ALL": "C", "LANG": "C"}
PROBE_TIMEOUT_SECONDS = 5
PROBE_OK = 0
PROBE_DENIED = 10
PROBE_UNAVAILABLE = 70
PROBE_SCRIPT = r"""
import os
import stat
import sys

access = sys.argv[1]
path = sys.argv[2]

if access == "read":
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    except AttributeError:
        raise SystemExit(70)
    try:
        fd = os.open(path, flags)
        try:
            os.read(fd, 1)
        finally:
            os.close(fd)
    except OSError:
        raise SystemExit(10)
    raise SystemExit(0)

if access == "execute":
    try:
        file_stat = os.stat(path, follow_symlinks=False)
    except OSError:
        raise SystemExit(10)
    if not stat.S_ISREG(file_stat.st_mode):
        raise SystemExit(10)
    try:
        allowed = os.access(path, os.X_OK, effective_ids=True)
    except (NotImplementedError, OSError, ValueError):
        raise SystemExit(70)
    raise SystemExit(0 if allowed else 10)

raise SystemExit(70)
""".strip()


class FailClosed(RuntimeError):
    """Expected operator-facing hard failure."""


class ProbeUnavailable(RuntimeError):
    """The credential-switched service-user probe could not run."""


@dataclass(frozen=True)
class ServiceUser:
    name: str
    uid: int
    gid: int
    groups: frozenset[int]


@dataclass(frozen=True)
class FileIdentity:
    dev: int
    ino: int
    uid: int
    gid: int
    file_type: int
    link_count: int
    fs_mode: int


@dataclass(frozen=True)
class ReleaseFile:
    path_bytes: bytes
    relpath: str
    git_mode: str
    expected_mode: int
    identity: FileIdentity | None = None

    @property
    def expected_mode_text(self) -> str:
        return f"{self.expected_mode:04o}"

    @property
    def fs_mode_text(self) -> str:
        if self.identity is None:
            raise FailClosed("internal error: filesystem mode was not inspected")
        return f"{self.identity.fs_mode:04o}"

    @property
    def fs_mode(self) -> int | None:
        return None if self.identity is None else self.identity.fs_mode


@dataclass(frozen=True)
class OpenReleaseFile:
    release_file: ReleaseFile
    path: Path
    fd: int


def _reject_nul(value: str, label: str) -> None:
    if "\x00" in value:
        raise FailClosed(f"{label} contains NUL")


def _safe_int_count(value: str) -> int:
    _reject_nul(value, "expected count")
    try:
        count = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected count must be a non-negative integer") from exc
    if count < 0:
        raise argparse.ArgumentTypeError("expected count must be a non-negative integer")
    return count


def _run_git(repo: Path, args: list[str], label: str, *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            env=GIT_ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FailClosed(f"{label} failed") from exc
    if check and proc.returncode != 0:
        raise FailClosed(f"{label} failed")
    return proc


def _single_line(output: bytes, label: str) -> str:
    if b"\x00" in output:
        raise FailClosed(f"ambiguous Git output for {label}")
    lines = output.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise FailClosed(f"ambiguous Git output for {label}")
    try:
        return lines[0].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FailClosed(f"ambiguous Git output for {label}") from exc


def _resolve_repo(repo_arg: str) -> Path:
    _reject_nul(repo_arg, "repository")
    try:
        repo = Path(repo_arg).resolve(strict=True)
    except OSError as exc:
        raise FailClosed("repository does not exist") from exc
    if not repo.is_dir():
        raise FailClosed("repository is not a directory")
    top = Path(_single_line(_run_git(repo, ["rev-parse", "--show-toplevel"], "Git repository lookup").stdout, "repo"))
    try:
        top = top.resolve(strict=True)
    except OSError as exc:
        raise FailClosed("Git repository lookup returned an unsafe path") from exc
    if top != repo:
        raise FailClosed("repository path must be the exact Git worktree root")
    return repo


def _commit(repo: Path, value: str, label: str) -> str:
    _reject_nul(value, label)
    if value.startswith("-") or not COMMIT_RE.fullmatch(value):
        raise FailClosed(f"{label} must be an exact full lowercase commit id")
    resolved = _single_line(
        _run_git(repo, ["rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}"], f"{label} lookup").stdout,
        label,
    )
    if resolved != value:
        raise FailClosed(f"{label} is not the exact canonical commit id")
    return resolved


def _head(repo: Path) -> str:
    value = _single_line(_run_git(repo, ["rev-parse", "--verify", "HEAD^{commit}"], "HEAD lookup").stdout, "HEAD")
    if not COMMIT_RE.fullmatch(value):
        raise FailClosed("ambiguous Git output for HEAD")
    return value


def _assert_ancestor(repo: Path, base: str, target: str) -> None:
    proc = _run_git(repo, ["merge-base", "--is-ancestor", base, target], "ancestor check", check=False)
    if proc.returncode != 0:
        raise FailClosed("base commit is not an ancestor of target commit")


def _assert_no_hidden_index_flags(repo: Path) -> None:
    proc = _run_git(repo, ["ls-files", "-z", "-v", "--"], "index flag scan")
    output = proc.stdout
    if not output:
        return
    if not output.endswith(b"\x00"):
        raise FailClosed("ambiguous Git output for index flag scan")
    for entry in output[:-1].split(b"\x00"):
        if len(entry) < 3 or entry[1:2] != b" ":
            raise FailClosed("ambiguous Git output for index flag scan")
        tag = entry[:1]
        path_bytes = entry[2:]
        relpath = _validate_git_path(path_bytes)
        if tag in {b"S", b"s"}:
            raise FailClosed(f"skip-worktree index entry is not allowed: {relpath}")
        if b"a" <= tag <= b"z":
            raise FailClosed(f"assume-unchanged index entry is not allowed: {relpath}")
        if tag not in INDEX_UPPER_TAGS:
            raise FailClosed("ambiguous Git output for index flag scan")


def _assert_clean_worktree(repo: Path) -> None:
    _assert_no_hidden_index_flags(repo)
    proc = _run_git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"], "worktree status")
    output = proc.stdout
    if not output:
        return
    if not output.endswith(b"\x00") or len(output) < 4:
        raise FailClosed("ambiguous Git output for worktree status")
    if output.startswith(b"?? "):
        raise FailClosed("unexpected untracked files")
    raise FailClosed("dirty tracked content")


def _validate_git_path(path_bytes: bytes) -> str:
    if not path_bytes:
        raise FailClosed("ambiguous Git output: empty path")
    if b"\x00" in path_bytes:
        raise FailClosed("NUL-unsafe Git path")
    if path_bytes.startswith(b"/"):
        raise FailClosed("unsafe absolute Git path")
    parts = path_bytes.split(b"/")
    if any(part in (b"", b".", b"..") for part in parts):
        raise FailClosed("unsafe escaping Git path")
    relpath = os.fsdecode(path_bytes)
    if os.fsencode(relpath) != path_bytes:
        raise FailClosed("NUL-unsafe Git path")
    return relpath


def _release_path(repo: Path, release_file: ReleaseFile) -> Path:
    path = repo.joinpath(*release_file.relpath.split("/"))
    current = repo
    for part in release_file.relpath.split("/")[:-1]:
        current = current / part
        try:
            st = current.lstat()
        except OSError as exc:
            raise FailClosed(f"missing target parent path: {release_file.relpath}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise FailClosed(f"unsafe symlinked parent path: {release_file.relpath}")
        if not stat.S_ISDIR(st.st_mode):
            raise FailClosed(f"non-directory target parent path: {release_file.relpath}")
    try:
        resolved = path.resolve(strict=False)
        common = os.path.commonpath([str(repo), str(resolved)])
    except (OSError, ValueError) as exc:
        raise FailClosed(f"unsafe escaping target path: {release_file.relpath}") from exc
    if common != str(repo):
        raise FailClosed(f"unsafe escaping target path: {release_file.relpath}")
    return path


def _mode_from_git(raw_mode: bytes, path: str) -> tuple[str, int]:
    try:
        git_mode = raw_mode.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FailClosed("ambiguous Git output for mode") from exc
    if git_mode == "120000":
        raise FailClosed(f"symlink release path is not supported: {path}")
    if git_mode == "160000":
        raise FailClosed(f"submodule release path is not supported: {path}")
    try:
        return git_mode, MODE_MAP[git_mode]
    except KeyError as exc:
        raise FailClosed(f"unsupported Git mode {git_mode}: {path}") from exc


def _derive_release_files(repo: Path, base: str, target: str) -> list[ReleaseFile]:
    proc = _run_git(
        repo,
        ["diff", "--raw", "--full-index", "-z", "--no-renames", "--no-ext-diff", base, target, "--"],
        "release diff",
    )
    output = proc.stdout
    if not output:
        return []
    if not output.endswith(b"\x00"):
        raise FailClosed("ambiguous Git output for release diff")
    chunks = output.split(b"\x00")
    if chunks[-1] != b"":
        raise FailClosed("ambiguous Git output for release diff")
    index = 0
    release_files: list[ReleaseFile] = []
    seen: set[bytes] = set()
    while index < len(chunks) - 1:
        header = chunks[index]
        index += 1
        if not header.startswith(b":"):
            raise FailClosed("ambiguous Git output for release diff")
        fields = header.split()
        if len(fields) != 5:
            raise FailClosed("ambiguous Git output for release diff")
        old_mode = fields[0][1:]
        new_mode = fields[1]
        status_code = fields[4]
        if not old_mode or not new_mode or len(status_code) != 1:
            raise FailClosed("ambiguous Git output for release diff")
        if index >= len(chunks) - 1:
            raise FailClosed("ambiguous Git output for release diff")
        path_bytes = chunks[index]
        index += 1
        relpath = _validate_git_path(path_bytes)
        if status_code == b"D":
            if new_mode != b"000000":
                raise FailClosed("ambiguous Git output for deleted release path")
            continue
        if status_code not in {b"A", b"M", b"T"}:
            raise FailClosed(f"unsupported Git diff status {status_code.decode('ascii', 'replace')}: {relpath}")
        if path_bytes in seen:
            raise FailClosed(f"ambiguous duplicate release path: {relpath}")
        seen.add(path_bytes)
        git_mode, expected_mode = _mode_from_git(new_mode, relpath)
        release_files.append(ReleaseFile(path_bytes, relpath, git_mode, expected_mode))
    return sorted(release_files, key=lambda item: item.path_bytes)


def _load_service_user(name: str) -> ServiceUser:
    _reject_nul(name, "service user")
    if not name:
        raise FailClosed("service user is required")
    try:
        pwent = pwd.getpwnam(name)
    except KeyError as exc:
        raise FailClosed("service user does not exist") from exc
    try:
        group_ids = set(os.getgrouplist(name, pwent.pw_gid))
    except AttributeError:
        group_ids = {pwent.pw_gid}
        for group in grp.getgrall():
            if name in group.gr_mem:
                group_ids.add(group.gr_gid)
    groups = frozenset(group_id for group_id in group_ids if group_id != pwent.pw_gid)
    user = ServiceUser(name=name, uid=pwent.pw_uid, gid=pwent.pw_gid, groups=frozenset(groups))
    if user.uid == 0:
        raise FailClosed("root is not an allowed service user")
    return user


def _service_user_preexec(user: ServiceUser) -> Callable[[], None]:
    groups = tuple(sorted(user.groups))

    def preexec() -> None:
        try:
            os.setgroups(list(groups))
            os.setgid(user.gid)
            os.setuid(user.uid)
            if (
                os.getuid() != user.uid
                or os.geteuid() != user.uid
                or os.getgid() != user.gid
                or os.getegid() != user.gid
                or set(os.getgroups()) != set(groups)
            ):
                os._exit(PROBE_UNAVAILABLE)
        except BaseException:
            os._exit(PROBE_UNAVAILABLE)

    return preexec


def _run_service_access_probe(path: Path, user: ServiceUser, access: str) -> bool:
    if user.uid == 0:
        raise FailClosed("root is not an allowed service user")
    if os.geteuid() != 0:
        raise FailClosed("service-user access probe requires effective root")
    if access not in {"read", "execute"}:
        raise ProbeUnavailable("unknown service-user access probe")
    try:
        proc = subprocess.run(
            [PROBE_UTILITY, "-I", "-c", PROBE_SCRIPT, access, str(path)],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=PROBE_ENV,
            cwd="/",
            timeout=PROBE_TIMEOUT_SECONDS,
            preexec_fn=_service_user_preexec(user),
            close_fds=True,
        )
    except (OSError, ValueError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        raise ProbeUnavailable("service-user access probe failed to run") from exc
    if proc.returncode == PROBE_OK:
        return True
    if proc.returncode == PROBE_DENIED:
        return False
    raise ProbeUnavailable("service-user access probe returned an unavailable result")


def _identity_from_stat(st: os.stat_result) -> FileIdentity:
    return FileIdentity(
        dev=st.st_dev,
        ino=st.st_ino,
        uid=st.st_uid,
        gid=st.st_gid,
        file_type=stat.S_IFMT(st.st_mode),
        link_count=st.st_nlink,
        fs_mode=stat.S_IMODE(st.st_mode),
    )


def _inspected_identity(release_file: ReleaseFile) -> FileIdentity:
    if release_file.identity is None:
        raise FailClosed("internal error: target file was not inspected")
    return release_file.identity


def _assert_single_regular_identity(release_file: ReleaseFile, identity: FileIdentity) -> None:
    if identity.file_type == stat.S_IFLNK:
        raise FailClosed(f"symlink target file is not supported: {release_file.relpath}")
    if identity.file_type != stat.S_IFREG:
        raise FailClosed(f"non-regular target file is not supported: {release_file.relpath}")
    if identity.link_count != 1:
        raise FailClosed(f"hardlinked target file is not supported: {release_file.relpath}")


def _validate_identity_match(
    release_file: ReleaseFile,
    st: os.stat_result,
    context: str,
    *,
    expected_mode: int,
) -> None:
    expected = _inspected_identity(release_file)
    actual = _identity_from_stat(st)
    if (
        actual.dev != expected.dev
        or actual.ino != expected.ino
        or actual.file_type != expected.file_type
        or actual.uid != expected.uid
        or actual.gid != expected.gid
        or actual.link_count != 1
        or actual.link_count != expected.link_count
    ):
        raise FailClosed(f"{context}; no restart is authorized: {release_file.relpath}")
    if actual.file_type != stat.S_IFREG:
        raise FailClosed(f"{context}; no restart is authorized: {release_file.relpath}")
    if actual.fs_mode != expected_mode:
        raise FailClosed(f"{context}; no restart is authorized: {release_file.relpath}")


def _validate_path_identity(repo: Path, release_file: ReleaseFile, context: str, *, expected_mode: int) -> None:
    path = _release_path(repo, release_file)
    try:
        st = path.lstat()
    except OSError as exc:
        raise FailClosed(f"{context}; no restart is authorized: {release_file.relpath}") from exc
    _validate_identity_match(release_file, st, context, expected_mode=expected_mode)


def _inspect_release_files(repo: Path, release_files: list[ReleaseFile]) -> list[ReleaseFile]:
    inspected: list[ReleaseFile] = []
    for release_file in release_files:
        path = _release_path(repo, release_file)
        try:
            st = path.lstat()
        except OSError as exc:
            raise FailClosed(f"missing target file: {release_file.relpath}") from exc
        identity = _identity_from_stat(st)
        _assert_single_regular_identity(release_file, identity)
        inspected.append(
            ReleaseFile(
                path_bytes=release_file.path_bytes,
                relpath=release_file.relpath,
                git_mode=release_file.git_mode,
                expected_mode=release_file.expected_mode,
                identity=identity,
            )
        )
    return inspected


def _assert_modes(release_files: list[ReleaseFile]) -> None:
    for release_file in release_files:
        if release_file.fs_mode != release_file.expected_mode:
            raise FailClosed(
                f"filesystem mode mismatch for {release_file.relpath}: "
                f"git={release_file.git_mode} expected={release_file.expected_mode_text} "
                f"actual={release_file.fs_mode_text}"
            )


def _assert_service_access(repo: Path, release_files: list[ReleaseFile], user: ServiceUser) -> None:
    for release_file in release_files:
        path = _release_path(repo, release_file)
        try:
            can_read = _run_service_access_probe(path, user, "read")
        except ProbeUnavailable as exc:
            raise FailClosed(f"service-user access probe unavailable for {release_file.relpath}") from exc
        if not can_read:
            raise FailClosed(f"service user cannot read release file: {release_file.relpath}")
        if release_file.git_mode == "100755":
            try:
                can_execute = _run_service_access_probe(path, user, "execute")
            except ProbeUnavailable as exc:
                raise FailClosed(f"service-user access probe unavailable for {release_file.relpath}") from exc
            if not can_execute:
                raise FailClosed(f"service user cannot execute release file: {release_file.relpath}")


def _manifest(release_files: list[ReleaseFile]) -> str:
    digest = hashlib.sha256()
    digest.update(MARKER.encode("ascii") + b"\x00")
    for release_file in release_files:
        digest.update(release_file.path_bytes)
        digest.update(b"\x00")
        digest.update(release_file.git_mode.encode("ascii"))
        digest.update(b"\x00")
        digest.update(release_file.fs_mode_text.encode("ascii"))
        digest.update(b"\x00")
    return digest.hexdigest()


def _preflight(args: argparse.Namespace) -> tuple[Path, str, str, str, ServiceUser, list[ReleaseFile]]:
    repo = _resolve_repo(args.repo)
    base = _commit(repo, args.base, "base commit")
    target = _commit(repo, args.target, "target commit")
    head = _head(repo)
    if target != head:
        raise FailClosed("target commit does not equal current HEAD")
    _assert_ancestor(repo, base, target)
    user = _load_service_user(args.service_user)
    if user.uid == 0:
        raise FailClosed("root is not an allowed service user")
    _assert_clean_worktree(repo)
    release_files = _derive_release_files(repo, base, target)
    if len(release_files) != args.expected_count:
        raise FailClosed(f"changed file count mismatch: expected={args.expected_count} actual={len(release_files)}")
    inspected = _inspect_release_files(repo, release_files)
    return repo, base, target, head, user, inspected


def _verify(args: argparse.Namespace) -> dict[str, str]:
    repo, base, target, head, user, release_files = _preflight(args)
    _assert_modes(release_files)
    _assert_service_access(repo, release_files, user)
    return {
        "command": "verify",
        "repo": str(repo),
        "base": base,
        "target": target,
        "head": head,
        "service_user": user.name,
        "expected_count": str(args.expected_count),
        "release_file_count": str(len(release_files)),
        "manifest_sha256": _manifest(release_files),
    }


def _repair_open_flags() -> int:
    try:
        return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    except AttributeError as exc:
        raise FailClosed("no-follow close-on-exec open is unavailable") from exc


def _close_open_files(open_files: list[OpenReleaseFile]) -> OSError | None:
    close_error: OSError | None = None
    while open_files:
        opened = open_files.pop()
        try:
            os.close(opened.fd)
        except OSError as exc:
            if close_error is None:
                close_error = exc
    return close_error


def _open_release_file(repo: Path, release_file: ReleaseFile) -> OpenReleaseFile:
    path = _release_path(repo, release_file)
    fd: int | None = None
    try:
        fd = os.open(path, _repair_open_flags())
        opened = OpenReleaseFile(release_file=release_file, path=path, fd=fd)
        preflight_mode = _inspected_identity(release_file).fs_mode
        _validate_identity_match(
            release_file,
            os.fstat(fd),
            "target changed before repair",
            expected_mode=preflight_mode,
        )
        _validate_path_identity(repo, release_file, "target path changed before repair", expected_mode=preflight_mode)
        return opened
    except OSError as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise FailClosed(f"target open failed before repair; no modes changed: {release_file.relpath}") from exc
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _open_release_files(repo: Path, release_files: list[ReleaseFile]) -> list[OpenReleaseFile]:
    open_files: list[OpenReleaseFile] = []
    try:
        for release_file in release_files:
            open_files.append(_open_release_file(repo, release_file))
    except Exception:
        _close_open_files(open_files)
        raise
    return open_files


def _fchmod_exact(fd: int, mode: int) -> None:
    os.fchmod(fd, mode)


def _repair_open_files(repo: Path, open_files: list[OpenReleaseFile]) -> None:
    for opened in open_files:
        release_file = opened.release_file
        if release_file.fs_mode == release_file.expected_mode:
            continue
        try:
            _fchmod_exact(opened.fd, release_file.expected_mode)
        except OSError as exc:
            raise FailClosed(
                f"mode change failed for {release_file.relpath}; no restart is authorized until repair succeeds"
            ) from exc
        _validate_identity_match(
            release_file,
            os.fstat(opened.fd),
            "target changed during repair",
            expected_mode=release_file.expected_mode,
        )
        _validate_path_identity(
            repo,
            release_file,
            "target path changed during repair",
            expected_mode=release_file.expected_mode,
        )


def _repair(args: argparse.Namespace) -> dict[str, str]:
    repo, _base, _target, _head, _user, release_files = _preflight(args)
    open_files = _open_release_files(repo, release_files)
    try:
        _repair_open_files(repo, open_files)
    finally:
        close_error = _close_open_files(open_files)
    if close_error is not None:
        raise FailClosed("release file descriptor close failed; no restart is authorized") from close_error
    repo, base, target, head, user, checked = _preflight(args)
    _assert_modes(checked)
    _assert_service_access(repo, checked, user)
    return {
        "command": "repair",
        "repo": str(repo),
        "base": base,
        "target": target,
        "head": head,
        "service_user": user.name,
        "expected_count": str(args.expected_count),
        "release_file_count": str(len(checked)),
        "manifest_sha256": _manifest(checked),
    }


def _emit_pass(payload: dict[str, str], stdout: TextIO) -> None:
    print(f"marker={MARKER}", file=stdout)
    print("status=PASS", file=stdout)
    for key in [
        "command",
        "repo",
        "base",
        "target",
        "head",
        "service_user",
        "expected_count",
        "release_file_count",
        "manifest_sha256",
    ]:
        print(f"{key}={payload[key]}", file=stdout)
    print("restart_authorized=yes", file=stdout)


def _emit_fail(command: str, reason: str, stderr: TextIO) -> None:
    reason = reason.replace("\x00", "?").replace("\n", " ")
    print(f"marker={MARKER}", file=stderr)
    print("status=FAIL", file=stderr)
    print(f"command={command}", file=stderr)
    print(f"reason={reason}", file=stderr)
    print("operator_action=do_not_restart", file=stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HODLXXI release file permission gate V1")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "repair"):
        subparser = subparsers.add_parser(name, help=f"{name} release file permissions")
        subparser.add_argument("--repo", required=True, help="Exact Git worktree root to validate")
        subparser.add_argument("--base", required=True, help="Exact full base commit id")
        subparser.add_argument("--target", required=True, help="Exact full target commit id; must equal HEAD")
        subparser.add_argument(
            "--expected-count",
            required=True,
            type=_safe_int_count,
            help="Expected changed-file count",
        )
        subparser.add_argument(
            "--service-user",
            required=True,
            help="Non-root service user that must read release files",
        )
    return parser


def main(argv: list[str] | None = None, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        payload = _verify(args) if args.command == "verify" else _repair(args)
    except FailClosed as exc:
        _emit_fail(args.command, str(exc), stderr)
        return 1
    _emit_pass(payload, stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
