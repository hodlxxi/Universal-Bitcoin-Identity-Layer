#!/usr/bin/python3 -I
"""HODLXXI release file permission gate V1."""

from __future__ import annotations

import argparse
import errno
import fcntl
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
OBJECT_FORMATS = {"sha1": ("sha1", 40), "sha256": ("sha256", 64)}
HASH_CHUNK_SIZE = 1024 * 1024
INDEX_UPPER_TAGS = {b"H", b"S", b"M", b"R", b"C", b"K", b"?"}
GIT_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
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


BOUND_PROBE_SCRIPT = r"""
import os
import stat
import sys

access = sys.argv[1]
path = sys.argv[2]

try:
    expected = tuple(int(value) for value in sys.argv[3:13])
except (TypeError, ValueError):
    raise SystemExit(70)

if len(expected) != 10:
    raise SystemExit(70)

if access not in {"read", "execute"}:
    raise SystemExit(70)

try:
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
except AttributeError:
    raise SystemExit(70)

try:
    fd = os.open(path, flags)
except (FileNotFoundError, PermissionError):
    raise SystemExit(10)
except OSError:
    raise SystemExit(70)

try:
    try:
        st = os.fstat(fd)
    except OSError:
        raise SystemExit(70)

    observed = (
        st.st_dev,
        st.st_ino,
        st.st_uid,
        st.st_gid,
        stat.S_IFMT(st.st_mode),
        st.st_nlink,
        stat.S_IMODE(st.st_mode),
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
    )

    if observed != expected:
        raise SystemExit(10)

    fd_path = f"/proc/self/fd/{fd}"

    if access == "read":
        try:
            read_fd = os.open(
                fd_path,
                os.O_RDONLY | os.O_CLOEXEC,
            )
        except (FileNotFoundError, PermissionError):
            raise SystemExit(10)
        except OSError:
            raise SystemExit(70)

        try:
            try:
                read_stat = os.fstat(read_fd)
            except OSError:
                raise SystemExit(70)

            read_observed = (
                read_stat.st_dev,
                read_stat.st_ino,
                read_stat.st_uid,
                read_stat.st_gid,
                stat.S_IFMT(read_stat.st_mode),
                read_stat.st_nlink,
                stat.S_IMODE(read_stat.st_mode),
                read_stat.st_size,
                read_stat.st_mtime_ns,
                read_stat.st_ctime_ns,
            )

            if read_observed != expected:
                raise SystemExit(10)

            try:
                os.read(read_fd, 1)
            except PermissionError:
                raise SystemExit(10)
            except OSError:
                raise SystemExit(70)

            raise SystemExit(0)
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass

    try:
        allowed = os.access(
            fd_path,
            os.X_OK,
            effective_ids=True,
        )
    except (NotImplementedError, OSError, ValueError):
        raise SystemExit(70)

    raise SystemExit(0 if allowed else 10)
finally:
    try:
        os.close(fd)
    except OSError:
        pass
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
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class ReleaseFile:
    path_bytes: bytes
    relpath: str
    git_mode: str
    target_oid: str
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


@dataclass
class OpenReleaseFile:
    release_file: ReleaseFile
    path: Path
    fd: int


@dataclass(frozen=True)
class AuthorizationLock:
    fd: int
    path: Path
    identity: FileIdentity

    @property
    def identity_text(self) -> str:
        return f"{self.identity.dev}:{self.identity.ino}"


@dataclass(frozen=True)
class Authorization:
    command: str
    repo: Path
    base: str
    target: str
    head: str
    user: ServiceUser
    expected_count: int
    object_format: str
    open_files: list[OpenReleaseFile]
    authorization_lock: AuthorizationLock


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


def _safe_fd(value: str) -> int:
    _reject_nul(value, "authorization lock descriptor")
    try:
        fd = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("authorization lock descriptor must be a non-negative integer") from exc
    if fd < 0:
        raise argparse.ArgumentTypeError("authorization lock descriptor must be a non-negative integer")
    return fd


def _run_git(repo: Path, args: list[str], label: str, *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", str(repo), *args],
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
    except (OSError, RuntimeError) as exc:
        raise FailClosed("repository does not exist") from exc
    if not repo.is_dir():
        raise FailClosed("repository is not a directory")
    top = Path(_single_line(_run_git(repo, ["rev-parse", "--show-toplevel"], "Git repository lookup").stdout, "repo"))
    try:
        top = top.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
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


def _object_format(repo: Path) -> str:
    value = _single_line(
        _run_git(repo, ["rev-parse", "--show-object-format"], "Git object format lookup").stdout, "object format"
    )
    if value not in OBJECT_FORMATS:
        raise FailClosed(f"unsupported Git object format: {value}")
    return value


def _object_oid_length(object_format: str) -> int:
    try:
        return OBJECT_FORMATS[object_format][1]
    except KeyError as exc:
        raise FailClosed(f"unsupported Git object format: {object_format}") from exc


def _validate_object_id(raw_oid: bytes, object_format: str, path: str) -> str:
    try:
        oid = raw_oid.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FailClosed(f"ambiguous target object id for {path}") from exc
    oid_length = _object_oid_length(object_format)
    if not re.fullmatch(f"[0-9a-f]{{{oid_length}}}", oid) or oid == "0" * oid_length:
        raise FailClosed(f"ambiguous target object id for {path}")
    return oid


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
    proc = _run_git(
        repo,
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        "worktree status",
    )
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
    except (OSError, RuntimeError, ValueError) as exc:
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


def _release_files_from_target_tree(
    repo: Path,
    target: str,
    path_bytes_list: list[bytes],
    object_format: str,
) -> list[ReleaseFile]:
    if not path_bytes_list:
        return []
    wanted = set(path_bytes_list)
    found: dict[bytes, ReleaseFile] = {}
    proc = _run_git(repo, ["ls-tree", "-rz", "--full-tree", target], "target tree")
    output = proc.stdout
    if not output:
        raise FailClosed("target tree is missing release paths")
    if not output.endswith(b"\x00"):
        raise FailClosed("ambiguous Git output for target tree")
    for entry in output[:-1].split(b"\x00"):
        try:
            metadata, path_bytes = entry.split(b"\t", 1)
        except ValueError as exc:
            raise FailClosed("ambiguous Git output for target tree") from exc
        if path_bytes not in wanted:
            continue
        fields = metadata.split()
        if len(fields) != 3:
            raise FailClosed("ambiguous Git output for target tree")
        raw_mode, object_type, raw_oid = fields
        relpath = _validate_git_path(path_bytes)
        if path_bytes in found:
            raise FailClosed(f"ambiguous duplicate target tree path: {relpath}")
        git_mode, expected_mode = _mode_from_git(raw_mode, relpath)
        if object_type != b"blob":
            raise FailClosed(f"unsupported Git object type {object_type.decode('ascii', 'replace')}: {relpath}")
        target_oid = _validate_object_id(raw_oid, object_format, relpath)
        found[path_bytes] = ReleaseFile(
            path_bytes=path_bytes,
            relpath=relpath,
            git_mode=git_mode,
            target_oid=target_oid,
            expected_mode=expected_mode,
        )
    missing = wanted.difference(found)
    if missing:
        relpath = _validate_git_path(sorted(missing)[0])
        raise FailClosed(f"target tree is missing release path: {relpath}")
    return sorted(found.values(), key=lambda item: item.path_bytes)


def _derive_release_files(repo: Path, base: str, target: str, object_format: str | None = None) -> list[ReleaseFile]:
    object_format = object_format if object_format is not None else _object_format(repo)
    proc = _run_git(
        repo,
        [
            "diff",
            "--raw",
            "--full-index",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--ignore-submodules=none",
            base,
            target,
            "--",
        ],
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
    release_paths: list[bytes] = []
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
        old_oid = fields[2]
        new_oid = fields[3]
        status_code = fields[4]
        if not old_mode or not new_mode or not old_oid or not new_oid or len(status_code) != 1:
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
        release_paths.append(path_bytes)
    return _release_files_from_target_tree(repo, target, release_paths, object_format)


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


def _run_bound_service_access_probe(
    path: Path,
    user: ServiceUser,
    access: str,
    expected_identity: FileIdentity,
) -> bool:
    if user.uid == 0:
        raise FailClosed("root is not an allowed service user")

    if os.geteuid() != 0:
        raise FailClosed("service-user access probe requires effective root")

    if access not in {"read", "execute"}:
        raise ProbeUnavailable("unknown service-user access probe")

    identity_args = [
        str(expected_identity.dev),
        str(expected_identity.ino),
        str(expected_identity.uid),
        str(expected_identity.gid),
        str(expected_identity.file_type),
        str(expected_identity.link_count),
        str(expected_identity.fs_mode),
        str(expected_identity.size),
        str(expected_identity.mtime_ns),
        str(expected_identity.ctime_ns),
    ]

    try:
        proc = subprocess.run(
            [
                PROBE_UTILITY,
                "-I",
                "-c",
                BOUND_PROBE_SCRIPT,
                access,
                str(path),
                *identity_args,
            ],
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
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        subprocess.TimeoutExpired,
    ) as exc:
        raise ProbeUnavailable("service-user bound access probe failed to run") from exc

    if proc.returncode == PROBE_OK:
        return True

    if proc.returncode == PROBE_DENIED:
        return False

    raise ProbeUnavailable("service-user bound access probe returned an unavailable result")


def _service_probe_execute_target() -> Path:
    try:
        target = Path(PROBE_UTILITY).resolve(strict=True)
        target_stat = target.stat()
    except (OSError, RuntimeError) as exc:
        raise FailClosed(
            "service-user execute probe preflight target unavailable; " "no filesystem mutation is authorized"
        ) from exc

    if not stat.S_ISREG(target_stat.st_mode):
        raise FailClosed(
            "service-user execute probe preflight target is not a regular file; " "no filesystem mutation is authorized"
        )

    return target


def _assert_service_probe_preflight(
    user: ServiceUser,
    release_files: list[ReleaseFile],
) -> None:
    """Prove every required service-user probe works before repair mutates files."""
    read_target = Path("/dev/null")
    execute_required = any(release_file.git_mode == "100755" for release_file in release_files)

    try:
        read_ready = _run_service_access_probe(
            read_target,
            user,
            "read",
        )
        if not read_ready:
            raise FailClosed(
                "service-user read probe preflight denied before repair; " "no filesystem mutation is authorized"
            )

        execute_target: Path | None = None
        if execute_required:
            execute_target = _service_probe_execute_target()
            execute_ready = _run_service_access_probe(
                execute_target,
                user,
                "execute",
            )
            if not execute_ready:
                raise FailClosed(
                    "service-user execute probe preflight denied before repair; " "no filesystem mutation is authorized"
                )

        try:
            read_identity = _identity_from_stat(read_target.lstat())
        except OSError as exc:
            raise ProbeUnavailable("bound read probe preflight identity unavailable") from exc

        bound_read_ready = _run_bound_service_access_probe(
            read_target,
            user,
            "read",
            read_identity,
        )
        if not bound_read_ready:
            raise FailClosed(
                "service-user bound read probe preflight denied before repair; " "no filesystem mutation is authorized"
            )

        if execute_required:
            if execute_target is None:
                raise ProbeUnavailable("bound execute probe preflight target unavailable")

            try:
                execute_identity = _identity_from_stat(execute_target.lstat())
            except OSError as exc:
                raise ProbeUnavailable("bound execute probe preflight identity unavailable") from exc

            bound_execute_ready = _run_bound_service_access_probe(
                execute_target,
                user,
                "execute",
                execute_identity,
            )
            if not bound_execute_ready:
                raise FailClosed(
                    "service-user bound execute probe preflight denied before repair; "
                    "no filesystem mutation is authorized"
                )

    except ProbeUnavailable as exc:
        raise FailClosed(
            "service-user access probe unavailable before repair; " "no filesystem mutation is authorized"
        ) from exc


def _identity_from_stat(st: os.stat_result) -> FileIdentity:
    return FileIdentity(
        dev=st.st_dev,
        ino=st.st_ino,
        uid=st.st_uid,
        gid=st.st_gid,
        file_type=stat.S_IFMT(st.st_mode),
        link_count=st.st_nlink,
        fs_mode=stat.S_IMODE(st.st_mode),
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
        ctime_ns=st.st_ctime_ns,
    )


def _authorization_lock_path(value: str) -> Path:
    _reject_nul(value, "authorization lock path")
    if not value or not os.path.isabs(value) or value.startswith("//") or os.path.normpath(value) != value:
        raise FailClosed("authorization lock path must be absolute and normalized")
    return Path(value)


def _assert_authorization_lock_parent_chain(
    path: Path,
    lock_owner_uid: int,
    context: str,
) -> None:
    trusted_owner_uids = {0, lock_owner_uid}
    current = path.parent

    while True:
        try:
            parent_stat = current.lstat()
        except OSError as exc:
            raise FailClosed(f"{context}: authorization lock parent is not available: {current}") from exc

        parent_identity = _identity_from_stat(parent_stat)
        if parent_identity.file_type == stat.S_IFLNK:
            raise FailClosed(f"{context}: authorization lock parent must not be a symlink: {current}")
        if parent_identity.file_type != stat.S_IFDIR:
            raise FailClosed(f"{context}: authorization lock parent must be a directory: {current}")
        if parent_identity.uid not in trusted_owner_uids:
            raise FailClosed(f"{context}: authorization lock parent owner is not trusted: {current}")
        writable_by_others = parent_identity.fs_mode & (stat.S_IWGRP | stat.S_IWOTH)
        if writable_by_others and not parent_identity.fs_mode & stat.S_ISVTX:
            raise FailClosed(
                f"{context}: authorization lock parent must not be group/other "
                f"writable without sticky bit: {current}"
            )

        if current.parent == current:
            break
        current = current.parent


def _assert_authorization_lock_inheritable(fd: int, context: str) -> None:
    try:
        inheritable = os.get_inheritable(fd)
    except (OSError, OverflowError) as exc:
        raise FailClosed(f"{context}: authorization lock descriptor is not open") from exc
    if not inheritable:
        raise FailClosed(f"{context}: authorization lock descriptor is not inheritable")


def _assert_authorization_lock_stat(identity: FileIdentity, context: str) -> None:
    if identity.file_type == stat.S_IFLNK:
        raise FailClosed(f"{context}: authorization lock path must not be a symlink")
    if identity.file_type != stat.S_IFREG:
        raise FailClosed(f"{context}: authorization lock must be a regular file")
    if identity.link_count != 1:
        raise FailClosed(f"{context}: authorization lock link count must be exactly one")
    if identity.uid != os.geteuid():
        raise FailClosed(f"{context}: authorization lock must be owned by the effective user")
    if identity.fs_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise FailClosed(f"{context}: authorization lock must not be group/other writable")


def _validate_authorization_lock_binding(
    fd: int,
    path: Path,
    context: str,
    *,
    expected: FileIdentity | None = None,
) -> FileIdentity:
    _assert_authorization_lock_inheritable(fd, context)
    try:
        descriptor_stat = os.fstat(fd)
    except OSError as exc:
        raise FailClosed(f"{context}: authorization lock descriptor is not open") from exc
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise FailClosed(f"{context}: authorization lock path is not available") from exc

    descriptor_identity = _identity_from_stat(descriptor_stat)
    path_identity = _identity_from_stat(path_stat)
    _assert_authorization_lock_stat(descriptor_identity, f"{context} descriptor")
    _assert_authorization_lock_stat(path_identity, f"{context} path")
    _assert_authorization_lock_parent_chain(
        path,
        descriptor_identity.uid,
        context,
    )
    if descriptor_identity.dev != path_identity.dev or descriptor_identity.ino != path_identity.ino:
        raise FailClosed(f"{context}: authorization lock descriptor/path mismatch")
    if expected is not None and (descriptor_identity.dev != expected.dev or descriptor_identity.ino != expected.ino):
        raise FailClosed(f"{context}: authorization lock identity changed")
    return descriptor_identity


def _flock_exclusive_nonblocking(fd: int, context: str) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        blocked_errnos = {errno.EACCES, errno.EAGAIN}
        if hasattr(errno, "EWOULDBLOCK"):
            blocked_errnos.add(errno.EWOULDBLOCK)
        if exc.errno in blocked_errnos:
            raise FailClosed(f"{context}: authorization lock is already held") from exc
        raise FailClosed(f"{context}: authorization lock cannot be acquired") from exc


def _authorization_lock_from_args(args: argparse.Namespace) -> AuthorizationLock:
    path = _authorization_lock_path(args.authorization_lock_path)
    identity = _validate_authorization_lock_binding(
        args.authorization_lock_fd,
        path,
        "authorization lock preflight",
    )
    _flock_exclusive_nonblocking(args.authorization_lock_fd, "authorization lock preflight")
    identity = _validate_authorization_lock_binding(
        args.authorization_lock_fd,
        path,
        "authorization lock preflight",
        expected=identity,
    )
    return AuthorizationLock(fd=args.authorization_lock_fd, path=path, identity=identity)


def _revalidate_authorization_lock(lock: AuthorizationLock, context: str) -> None:
    _validate_authorization_lock_binding(lock.fd, lock.path, context, expected=lock.identity)
    _flock_exclusive_nonblocking(lock.fd, context)
    _validate_authorization_lock_binding(lock.fd, lock.path, context, expected=lock.identity)


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
    compare_metadata: bool = True,
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
    if compare_metadata and (
        actual.size != expected.size or actual.mtime_ns != expected.mtime_ns or actual.ctime_ns != expected.ctime_ns
    ):
        raise FailClosed(f"{context}; no restart is authorized: {release_file.relpath}")


def _validate_path_identity(
    repo: Path,
    release_file: ReleaseFile,
    context: str,
    *,
    expected_mode: int,
    compare_metadata: bool = True,
) -> None:
    path = _release_path(repo, release_file)
    try:
        st = path.lstat()
    except OSError as exc:
        raise FailClosed(f"{context}; no restart is authorized: {release_file.relpath}") from exc
    _validate_identity_match(
        release_file,
        st,
        context,
        expected_mode=expected_mode,
        compare_metadata=compare_metadata,
    )


def _git_digest(object_format: str) -> "hashlib._Hash":
    try:
        algorithm = OBJECT_FORMATS[object_format][0]
    except KeyError as exc:
        raise FailClosed(f"unsupported Git object format: {object_format}") from exc
    try:
        return hashlib.new(algorithm, usedforsecurity=False)
    except TypeError:
        return hashlib.new(algorithm)


def _descriptor_blob_oid(fd: int, object_format: str, relpath: str) -> str:
    try:
        st = os.fstat(fd)
        size = st.st_size
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError as exc:
        raise FailClosed(f"target descriptor cannot be hashed; no restart is authorized: {relpath}") from exc
    if size < 0:
        raise FailClosed(f"target descriptor has invalid size; no restart is authorized: {relpath}")
    digest = _git_digest(object_format)
    digest.update(f"blob {size}\0".encode("ascii"))
    remaining = size
    while remaining:
        try:
            chunk = os.read(fd, min(HASH_CHUNK_SIZE, remaining))
        except OSError as exc:
            raise FailClosed(f"target descriptor read failed; no restart is authorized: {relpath}") from exc
        if not chunk:
            raise FailClosed(f"target descriptor truncated during hash; no restart is authorized: {relpath}")
        digest.update(chunk)
        remaining -= len(chunk)
    try:
        extra = os.read(fd, 1)
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError as exc:
        raise FailClosed(f"target descriptor cannot be rechecked; no restart is authorized: {relpath}") from exc
    if extra:
        raise FailClosed(f"target descriptor grew during hash; no restart is authorized: {relpath}")
    return digest.hexdigest()


def _assert_target_blob(opened: OpenReleaseFile, object_format: str, context: str) -> None:
    release_file = opened.release_file
    actual_oid = _descriptor_blob_oid(opened.fd, object_format, release_file.relpath)
    if actual_oid != release_file.target_oid:
        raise FailClosed(f"{context}; target blob mismatch; no restart is authorized: {release_file.relpath}")


def _release_file_with_identity(release_file: ReleaseFile, identity: FileIdentity) -> ReleaseFile:
    return ReleaseFile(
        path_bytes=release_file.path_bytes,
        relpath=release_file.relpath,
        git_mode=release_file.git_mode,
        target_oid=release_file.target_oid,
        expected_mode=release_file.expected_mode,
        identity=identity,
    )


def _release_files_from_open(open_files: list[OpenReleaseFile]) -> list[ReleaseFile]:
    return [opened.release_file for opened in open_files]


def _revalidate_open_file(
    repo: Path,
    opened: OpenReleaseFile,
    object_format: str,
    context: str,
    *,
    expected_mode: int,
    compare_metadata: bool = True,
) -> None:
    release_file = opened.release_file
    try:
        st = os.fstat(opened.fd)
    except OSError as exc:
        raise FailClosed(f"{context}; no restart is authorized: {release_file.relpath}") from exc
    _validate_identity_match(
        release_file,
        st,
        context,
        expected_mode=expected_mode,
        compare_metadata=compare_metadata,
    )
    _validate_path_identity(
        repo,
        release_file,
        f"{context} path binding changed",
        expected_mode=expected_mode,
        compare_metadata=compare_metadata,
    )

    _assert_target_blob(opened, object_format, context)

    # A writer may race with a multi-chunk descriptor hash after bytes have
    # already been consumed. Re-check descriptor metadata and path binding
    # after hashing so size/mtime/ctime/mode/path changes during the read fail
    # closed before authorization can be emitted.
    try:
        post_hash_stat = os.fstat(opened.fd)
    except OSError as exc:
        raise FailClosed(
            f"{context}; descriptor unavailable after target hash; " f"no restart is authorized: {release_file.relpath}"
        ) from exc

    _validate_identity_match(
        release_file,
        post_hash_stat,
        f"{context}; descriptor changed during target hash",
        expected_mode=expected_mode,
        compare_metadata=compare_metadata,
    )
    _validate_path_identity(
        repo,
        release_file,
        f"{context}; path binding changed during target hash",
        expected_mode=expected_mode,
        compare_metadata=compare_metadata,
    )


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
                target_oid=release_file.target_oid,
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


def _assert_service_access(
    repo: Path,
    release_files: list[ReleaseFile],
    user: ServiceUser,
) -> None:
    for release_file in release_files:
        path = _release_path(repo, release_file)
        identity = _inspected_identity(release_file)

        try:
            can_read = _run_bound_service_access_probe(
                path,
                user,
                "read",
                identity,
            )
        except ProbeUnavailable as exc:
            raise FailClosed(f"service-user access probe unavailable for {release_file.relpath}") from exc

        if not can_read:
            raise FailClosed(f"service user cannot read exact release file: {release_file.relpath}")

        if release_file.git_mode == "100755":
            try:
                can_execute = _run_bound_service_access_probe(
                    path,
                    user,
                    "execute",
                    identity,
                )
            except ProbeUnavailable as exc:
                raise FailClosed(f"service-user access probe unavailable for {release_file.relpath}") from exc

            if not can_execute:
                raise FailClosed(f"service user cannot execute exact release file: {release_file.relpath}")


def _manifest(release_files: list[ReleaseFile]) -> str:
    digest = hashlib.sha256()
    digest.update(MARKER.encode("ascii") + b"\x00")
    for release_file in release_files:
        digest.update(release_file.path_bytes)
        digest.update(b"\x00")
        digest.update(release_file.git_mode.encode("ascii"))
        digest.update(b"\x00")
        digest.update(release_file.target_oid.encode("ascii"))
        digest.update(b"\x00")
        digest.update(release_file.fs_mode_text.encode("ascii"))
        digest.update(b"\x00")
    return digest.hexdigest()


def _preflight(args: argparse.Namespace) -> tuple[Path, str, str, str, ServiceUser, str, list[ReleaseFile]]:
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
    object_format = _object_format(repo)
    _assert_clean_worktree(repo)
    release_files = _derive_release_files(repo, base, target, object_format)
    if len(release_files) != args.expected_count:
        raise FailClosed(f"changed file count mismatch: expected={args.expected_count} actual={len(release_files)}")
    inspected = _inspect_release_files(repo, release_files)
    return repo, base, target, head, user, object_format, inspected


def _verify(args: argparse.Namespace) -> Authorization:
    authorization_lock = _authorization_lock_from_args(args)
    repo, base, target, head, user, object_format, release_files = _preflight(args)
    open_files: list[OpenReleaseFile] = []
    try:
        open_files = _open_release_files(repo, release_files, object_format, "verification")
        _assert_modes(_release_files_from_open(open_files))
        _assert_service_access(repo, _release_files_from_open(open_files), user)
        return Authorization(
            command="verify",
            repo=repo,
            base=base,
            target=target,
            head=head,
            user=user,
            expected_count=args.expected_count,
            object_format=object_format,
            open_files=open_files,
            authorization_lock=authorization_lock,
        )
    except Exception:
        _close_open_files(open_files)
        raise


def _release_open_flags() -> int:
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    except AttributeError as exc:
        raise FailClosed("no-follow close-on-exec open is unavailable") from exc
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _repair_open_flags() -> int:
    return _release_open_flags()


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


def _open_release_file(
    repo: Path,
    release_file: ReleaseFile,
    object_format: str,
    phase: str,
) -> OpenReleaseFile:
    path = _release_path(repo, release_file)
    fd: int | None = None
    try:
        fd = os.open(path, _release_open_flags())
        opened = OpenReleaseFile(release_file=release_file, path=path, fd=fd)
        preflight_mode = _inspected_identity(release_file).fs_mode
        _validate_identity_match(
            release_file,
            os.fstat(fd),
            f"target changed before {phase}",
            expected_mode=preflight_mode,
        )
        _validate_path_identity(
            repo,
            release_file,
            f"target path changed before {phase}",
            expected_mode=preflight_mode,
        )
        _assert_target_blob(opened, object_format, f"target changed before {phase}")
        return opened
    except OSError as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise FailClosed(f"target open failed before {phase}; no modes changed: {release_file.relpath}") from exc
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _open_release_files(
    repo: Path,
    release_files: list[ReleaseFile],
    object_format: str,
    phase: str,
) -> list[OpenReleaseFile]:
    open_files: list[OpenReleaseFile] = []
    try:
        for release_file in release_files:
            open_files.append(_open_release_file(repo, release_file, object_format, phase))
    except Exception:
        _close_open_files(open_files)
        raise
    return open_files


def _fchmod_exact(fd: int, mode: int) -> None:
    os.fchmod(fd, mode)


def _repair_open_files(repo: Path, open_files: list[OpenReleaseFile], object_format: str) -> None:
    for opened in open_files:
        release_file = opened.release_file
        if release_file.fs_mode == release_file.expected_mode:
            continue
        _revalidate_open_file(
            repo,
            opened,
            object_format,
            "target changed before repair",
            expected_mode=_inspected_identity(release_file).fs_mode,
        )
        try:
            _fchmod_exact(opened.fd, release_file.expected_mode)
        except OSError as exc:
            raise FailClosed(
                f"mode change failed for {release_file.relpath}; no restart is authorized until repair succeeds"
            ) from exc
        try:
            repaired_stat = os.fstat(opened.fd)
        except OSError as exc:
            raise FailClosed(f"target changed during repair; no restart is authorized: {release_file.relpath}") from exc
        _validate_identity_match(
            release_file,
            repaired_stat,
            "target changed during repair",
            expected_mode=release_file.expected_mode,
            compare_metadata=False,
        )
        _validate_path_identity(
            repo,
            release_file,
            "target path changed during repair",
            expected_mode=release_file.expected_mode,
            compare_metadata=False,
        )
        _assert_target_blob(opened, object_format, "target blob changed during repair")
        opened.release_file = _release_file_with_identity(release_file, _identity_from_stat(repaired_stat))


def _repair(args: argparse.Namespace) -> Authorization:
    authorization_lock = _authorization_lock_from_args(args)
    repo, base, target, head, user, object_format, release_files = _preflight(args)

    # Repair is mutating. Prove that the fixed service-user child probe can
    # actually perform its credential switch before any release-file chmod.
    _assert_service_probe_preflight(user, release_files)

    open_files: list[OpenReleaseFile] = []
    try:
        open_files = _open_release_files(repo, release_files, object_format, "repair")
        _repair_open_files(repo, open_files, object_format)
        _assert_modes(_release_files_from_open(open_files))
        _assert_service_access(repo, _release_files_from_open(open_files), user)
        return Authorization(
            command="repair",
            repo=repo,
            base=base,
            target=target,
            head=head,
            user=user,
            expected_count=args.expected_count,
            object_format=object_format,
            open_files=open_files,
            authorization_lock=authorization_lock,
        )
    except Exception:
        _close_open_files(open_files)
        raise


def _final_authorization_check(authorization: Authorization) -> None:
    head = _head(authorization.repo)
    if head != authorization.target:
        raise FailClosed("target commit does not equal current HEAD")
    _assert_clean_worktree(authorization.repo)
    release_files = _release_files_from_open(authorization.open_files)
    _assert_service_access(authorization.repo, release_files, authorization.user)
    _assert_clean_worktree(authorization.repo)
    for opened in authorization.open_files:
        _revalidate_open_file(
            authorization.repo,
            opened,
            authorization.object_format,
            "final target validation failed",
            expected_mode=opened.release_file.expected_mode,
        )
    _revalidate_authorization_lock(
        authorization.authorization_lock,
        "final authorization lock validation failed",
    )

    # Git status cannot observe every permission-only chmod. After the final
    # whole-worktree cleanliness observation, repeat descriptor/path/mode/blob
    # validation and service-user access checks before emitting authorization.
    _assert_clean_worktree(authorization.repo)

    for opened in authorization.open_files:
        _revalidate_open_file(
            authorization.repo,
            opened,
            authorization.object_format,
            "post-status final target validation failed",
            expected_mode=opened.release_file.expected_mode,
        )

    _assert_service_access(authorization.repo, release_files, authorization.user)

    # Revalidate once more after the access probes so a chmod/path change that
    # races with those probes cannot survive solely because access succeeded.
    for opened in authorization.open_files:
        _revalidate_open_file(
            authorization.repo,
            opened,
            authorization.object_format,
            "post-access final target validation failed",
            expected_mode=opened.release_file.expected_mode,
        )

    _revalidate_authorization_lock(
        authorization.authorization_lock,
        "post-status final authorization lock validation failed",
    )


def _authorization_payload(authorization: Authorization) -> dict[str, str]:
    release_files = _release_files_from_open(authorization.open_files)
    return {
        "command": authorization.command,
        "repo": str(authorization.repo),
        "base": authorization.base,
        "target": authorization.target,
        "head": authorization.head,
        "service_user": authorization.user.name,
        "expected_count": str(authorization.expected_count),
        "release_file_count": str(len(release_files)),
        "manifest_sha256": _manifest(release_files),
        "authorization_lock_path": str(authorization.authorization_lock.path),
        "authorization_lock_dev": str(authorization.authorization_lock.identity.dev),
        "authorization_lock_ino": str(authorization.authorization_lock.identity.ino),
        "authorization_lock_identity": authorization.authorization_lock.identity_text,
    }


def _emit_pass(authorization: Authorization, stdout: TextIO) -> None:
    payload = _authorization_payload(authorization)
    lines = [f"marker={MARKER}", "status=PASS"]
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
        "authorization_lock_path",
        "authorization_lock_dev",
        "authorization_lock_ino",
        "authorization_lock_identity",
    ]:
        lines.append(f"{key}={payload[key]}")
    _final_authorization_check(authorization)
    lines.append("lock_bound_authorization=yes")
    lines.append("authorization_valid_while_caller_retains_lock_fd=yes")
    lines.append("restart_authorized=yes")
    for line in lines:
        print(line, file=stdout)


def _escape_fail_reason(reason: str) -> str:
    escaped: list[str] = []
    for char in reason:
        if char in {"%", "="} or not char.isprintable():
            raw = char.encode("utf-8", errors="backslashreplace")
            escaped.extend(f"%{byte:02X}" for byte in raw)
        else:
            escaped.append(char)
    return "".join(escaped)


def _emit_fail(command: str, reason: str, stderr: TextIO) -> None:
    reason = _escape_fail_reason(reason)
    print(f"marker={MARKER}", file=stderr)
    print("status=FAIL", file=stderr)
    print(f"command={command}", file=stderr)
    print(f"reason={reason}", file=stderr)
    print("operator_action=do_not_restart", file=stderr)


class _FailClosedArgumentParser(argparse.ArgumentParser):
    """Convert CLI denials into the gate's structured fail-closed path."""

    def error(self, message: str) -> None:
        raise FailClosed(f"invalid command line: {message}")


def build_parser() -> argparse.ArgumentParser:
    parser = _FailClosedArgumentParser(description="HODLXXI release file permission gate V1")
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_FailClosedArgumentParser,
    )
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
        subparser.add_argument(
            "--authorization-lock-fd",
            required=True,
            type=_safe_fd,
            help="Inherited caller-owned authorization-lock file descriptor",
        )
        subparser.add_argument(
            "--authorization-lock-path",
            required=True,
            help="Exact absolute normalized authorization lock-file path",
        )
    return parser


def main(
    argv: list[str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    parser = build_parser()

    effective_argv = list(sys.argv[1:] if argv is None else argv)
    command = effective_argv[0] if effective_argv and effective_argv[0] in {"verify", "repair"} else "parse"

    authorization: Authorization | None = None
    try:
        args = parser.parse_args(effective_argv)
        command = args.command
        authorization = _verify(args) if args.command == "verify" else _repair(args)
        _emit_pass(authorization, stdout)
    except FailClosed as exc:
        _emit_fail(command, str(exc), stderr)
        return 1
    finally:
        if authorization is not None:
            _close_open_files(authorization.open_files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
