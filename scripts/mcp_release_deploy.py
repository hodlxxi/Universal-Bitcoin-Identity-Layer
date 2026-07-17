#!/usr/bin/env python3
"""Build, verify, and safely activate immutable HODLXXI MCP sidecar releases."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import time
import tomllib
import zipfile
from pathlib import Path

DEFAULT_SOURCE = Path("/srv/ubid")
DEFAULT_RELEASES = Path("/opt/hodlxxi-mcp/releases")
DEFAULT_CURRENT = Path("/opt/hodlxxi-mcp/current")
DEFAULT_LOCK = Path("/run/lock/hodlxxi-mcp-release.lock")
DEFAULT_DEP_LOCK = Path("packages/hodlxxi_mcp/requirements/mcp-release.lock")
SERVICE_USER = "hodlxxi-mcp"
SERVICE = "hodlxxi-mcp.service"
ENTRY = Path("venv/bin/hodlxxi-mcp-http")
IDENTITY_FILE = "RELEASE_IDENTITY.json"
VERIFY_FILE = "VERIFY.json"
FREEZE_FILE = "INSTALLED_DISTRIBUTIONS.txt"
EXPECTED_NAME = "HODLXXI Read-Only"
EXPECTED_PROTOCOL = "2025-11-25"
EXPECTED_TOOLS = 26
EXPECTED_RESOURCES = 0
EXPECTED_PROMPTS = 0
VERIFY_SCHEMA = "hodlxxi-mcp-release-verification"
VERIFY_SCHEMA_VERSION = 2
HEALTH_TIMEOUT = 30.0
HEALTH_INTERVAL = 1.0

CLEAN_ENV = {
    "HOME": "/tmp",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
}


class FailClosed(RuntimeError):
    pass


class RollbackRecoveryFailed(FailClosed):
    pass


def run(cmd, *, cwd=None, check=True, capture=True, timeout=30, env=None):
    return subprocess.run(
        [str(c) for c in cmd],
        cwd=cwd,
        text=True,
        check=check,
        timeout=timeout,
        env=env,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def git(args, source):
    return run(["git", *args], cwd=source).stdout.strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def package_version(source: Path) -> str:
    data = tomllib.loads((source / "packages/hodlxxi_mcp/pyproject.toml").read_text())
    return data["project"]["version"]


def dependency_lock_path(source: Path, dep_lock: Path) -> Path:
    path = dep_lock if dep_lock.is_absolute() else source / dep_lock
    if not path.is_file() or path.is_symlink():
        raise FailClosed(f"dependency lock is absent or unsafe: {path}")
    text = path.read_text()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "==" not in stripped or any(token in stripped for token in [">=", "<=", "~=", "!=", ">", "<"]):
            raise FailClosed(f"dependency lock contains non-exact requirement: {stripped}")
    return path


def normalize_distribution_name(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def parse_dependency_lock(lock: Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for raw in lock.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        requirement = parts[0]
        hashes = [part.removeprefix("--hash=sha256:") for part in parts[1:] if part.startswith("--hash=sha256:")]
        if len(hashes) != 1 or len(hashes[0]) != 64 or any(c not in "0123456789abcdef" for c in hashes[0]):
            raise FailClosed(f"dependency lock entry must have exactly one valid artifact hash: {line}")
        if "==" not in requirement:
            raise FailClosed(f"dependency lock contains non-exact requirement: {line}")
        name, version = requirement.split("==", 1)
        key = normalize_distribution_name(name)
        if key in entries and entries[key][0] != version:
            raise FailClosed(f"dependency lock has conflicting duplicate entry for {name}")
        if key in entries:
            raise FailClosed(f"dependency lock has duplicate entry for {name}")
        entries[key] = (version, hashes[0])
    if not entries:
        raise FailClosed("dependency lock is empty")
    return entries


def validate_wheelhouse(wheelhouse: str | None, lock: Path) -> Path:
    if not wheelhouse:
        raise FailClosed("--wheelhouse is required for production release builds")
    supplied = Path(wheelhouse)
    try:
        supplied_stat = supplied.lstat()
    except OSError as exc:
        raise FailClosed("wheelhouse must be an existing non-symlink directory") from exc
    if stat.S_ISLNK(supplied_stat.st_mode):
        raise FailClosed("operator-supplied wheelhouse path must not be a symlink")
    root = supplied.resolve(strict=True)
    if not stat.S_ISDIR(supplied_stat.st_mode) or not root.is_dir():
        raise FailClosed("wheelhouse must be an existing non-symlink directory")
    expected_owner = 0 if os.geteuid() == 0 else os.geteuid()
    if supplied_stat.st_uid != expected_owner or supplied_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise FailClosed("wheelhouse has unsafe ownership or permissions")
    children = list(root.iterdir())
    files = [p for p in children if p.is_file() and not p.is_symlink()]
    if not files:
        raise FailClosed("wheelhouse contains no artifacts")
    bad = [p.name for p in children if p.is_symlink() or not p.is_file() or p.suffix != ".whl"]
    if bad:
        raise FailClosed("wheelhouse contains unsupported or unsafe artifacts: " + ", ".join(sorted(bad)[:5]))
    expected = parse_dependency_lock(lock)
    actual: dict[str, tuple[str, str]] = {}
    for artifact in files:
        artifact_stat = artifact.lstat()
        if artifact_stat.st_uid != expected_owner or artifact_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise FailClosed(f"wheelhouse artifact has unsafe ownership or permissions: {artifact.name}")
        try:
            with zipfile.ZipFile(artifact) as wheel:
                metadata_names = [
                    name for name in wheel.namelist() if name.endswith(".dist-info/METADATA") and name.count("/") == 1
                ]
                if len(metadata_names) != 1:
                    raise FailClosed(f"wheel has ambiguous distribution metadata: {artifact.name}")
                metadata = wheel.read(metadata_names[0]).decode("utf-8")
        except (OSError, UnicodeError, zipfile.BadZipFile) as exc:
            raise FailClosed(f"wheel is malformed: {artifact.name}") from exc
        fields = {}
        for line in metadata.splitlines():
            if ": " in line:
                key, value = line.split(": ", 1)
                fields.setdefault(key, value)
        name = normalize_distribution_name(fields.get("Name", ""))
        version = fields.get("Version", "")
        if not name or not version:
            raise FailClosed(f"wheel lacks distribution identity: {artifact.name}")
        if name in actual:
            raise FailClosed(f"wheelhouse has duplicate or ambiguous artifacts for {name}")
        actual[name] = (version, sha256_file(artifact))
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise FailClosed(f"wheelhouse dependency set mismatch (missing={missing}, extra={extra})")
    for name, locked in expected.items():
        if actual[name] != locked:
            raise FailClosed(f"wheelhouse artifact version or hash mismatch for {name}")
    return root


def digest_inputs(source: Path, dep_lock: Path = DEFAULT_DEP_LOCK) -> str:
    lock = dependency_lock_path(source, dep_lock)
    h = hashlib.sha256()
    paths = [
        "packages/hodlxxi_mcp/pyproject.toml",
        "packages/hodlxxi_mcp/README.md",
        "deployment/systemd/hodlxxi-mcp.service",
        str(lock.relative_to(source)),
    ]
    for rel in paths:
        fp = source / rel
        h.update(rel.encode() + b"\0" + fp.read_bytes() + b"\0")
    for fp in sorted((source / "packages/hodlxxi_mcp/src/hodlxxi_mcp").rglob("*")):
        if fp.is_file() and not fp.is_symlink():
            h.update(str(fp.relative_to(source)).encode() + b"\0" + fp.read_bytes() + b"\0")
    return h.hexdigest()


def assert_clean(source: Path, allow_dirty: bool) -> None:
    dirty = git(["status", "--porcelain"], source)
    if dirty and not allow_dirty:
        raise FailClosed("source checkout is dirty; pass --allow-dirty-build only for reviewed local test builds")


def release_path(releases: Path, release_id: str) -> Path:
    if "/" in release_id or "\\" in release_id or release_id in ("", ".", ".."):
        raise FailClosed("unsafe release id")
    return releases / release_id


def require_direct_release_child(path: Path, releases_dir: Path, *, require_exists: bool = True) -> Path:
    releases = releases_dir.resolve(strict=require_exists and releases_dir.exists())
    candidate = path.absolute()
    if require_exists and not candidate.exists():
        raise FailClosed("release directory does not exist")
    if candidate.parent.resolve() != releases:
        raise FailClosed("release must be a direct child of releases-dir")
    if candidate.is_symlink():
        raise FailClosed("release directory must not be a symlink")
    if require_exists and not candidate.is_dir():
        raise FailClosed("release candidate is not a directory")
    return candidate.resolve() if candidate.exists() else candidate


def service_user_ids() -> tuple[int, int]:
    try:
        info = pwd.getpwnam(SERVICE_USER)
    except KeyError as exc:
        raise FailClosed(f"{SERVICE_USER} service user is required for production verification") from exc
    return info.pw_uid, info.pw_gid


def service_user_credentials() -> tuple[int, set[int]]:
    uid, primary_gid = service_user_ids()
    try:
        gids = set(os.getgrouplist(SERVICE_USER, primary_gid))
    except OSError as exc:
        raise FailClosed(f"cannot determine all supplementary groups for {SERVICE_USER}") from exc
    gids.add(primary_gid)
    return uid, gids


def is_writable_by(uid: int, gids: set[int], st_mode: int, st_uid: int, st_gid: int) -> bool:
    if uid == 0:
        return True
    if st_uid == uid and st_mode & stat.S_IWUSR:
        return True
    if st_gid in gids and st_mode & stat.S_IWGRP:
        return True
    return bool(st_mode & stat.S_IWOTH)


def harden_release_permissions(root: Path) -> None:
    root_real = root.resolve()
    for p in [root, *root.rglob("*")]:
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode):
            target = (p.parent / os.readlink(p)).resolve()
            if not (target == root_real or root_real in target.parents):
                raise FailClosed(f"unsafe symlink escapes release: {p}")
            continue
        if stat.S_ISDIR(st.st_mode):
            p.chmod(0o755)
        elif stat.S_ISREG(st.st_mode):
            required_exec = p.relative_to(root) == ENTRY or bool(st.st_mode & stat.S_IXUSR)
            p.chmod(0o755 if required_exec else 0o644)
        else:
            raise FailClosed(f"unsupported release file type: {p}")


def assert_root_owned_not_service_writable(root: Path, *, allow_non_root_owner: bool = False) -> None:
    uid, gids = (
        service_user_credentials() if os.geteuid() == 0 else (os.geteuid(), set(os.getgroups()) | {os.getegid()})
    )
    for p in [root, *root.rglob("*")]:
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode):
            continue
        if not allow_non_root_owner and st.st_uid != 0:
            raise FailClosed(f"release path is not root-owned: {p}")
        if is_writable_by(uid, gids, st.st_mode, st.st_uid, st.st_gid):
            raise FailClosed(f"release path is writable by {SERVICE_USER}: {p}")


def assert_release_accessible_as_service_user(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            continue
        if stat.S_ISDIR(st.st_mode):
            run_as_service_user(["test", "-x", path], timeout=10)
            run_as_service_user(["test", "-r", path], timeout=10)
        elif stat.S_ISREG(st.st_mode):
            run_as_service_user(["test", "-r", path], timeout=10)
        else:
            raise FailClosed(f"unsupported release file type: {path}")


def run_as_service_user(cmd, *, cwd=Path("/tmp"), timeout=30):
    env_args = []
    for key, value in CLEAN_ENV.items():
        env_args.append(f"{key}={value}")
    if os.geteuid() == 0:
        service_user_ids()
        return run(["runuser", "-u", SERVICE_USER, "--", "env", "-i", *env_args, *cmd], cwd=cwd, timeout=timeout)
    return run(cmd, cwd=cwd, timeout=timeout, env=CLEAN_ENV)


def write_installed_manifest(py: Path, target: Path) -> str:
    result = run([py, "-m", "pip", "freeze", "--all"], timeout=60)
    text = "\n".join(sorted(line for line in result.stdout.splitlines() if line.strip())) + "\n"
    target.write_text(text)
    return sha256_text(text)


def build(args):
    os.umask(0o022)
    source = args.source.resolve()
    releases = args.releases_dir.resolve()
    current_path = args.current.absolute()
    lock_path = dependency_lock_path(source, args.dependency_lock)
    parse_dependency_lock(lock_path)
    wheelhouse = validate_wheelhouse(args.wheelhouse, lock_path)
    assert_clean(source, args.allow_dirty_build)
    commit = git(["rev-parse", "HEAD"], source)
    rid = args.release_id or f"{commit[:12]}-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    target = require_direct_release_child(release_path(releases, rid), releases, require_exists=False)
    if current_path.is_symlink() and target == current_path.resolve():
        raise FailClosed("target is active current release")
    if target.exists():
        raise FailClosed(f"release already exists: {target}")
    if args.dry_run:
        print(json.dumps({"dry_run": True, "release_dir": str(target), "source_commit": commit}, indent=2))
        return target
    target.mkdir(parents=True, mode=0o755)
    venv = target / "venv"
    run([sys.executable, "-m", "venv", "--copies", venv], timeout=120)
    pip = venv / "bin/pip"
    py = venv / "bin/python"
    pip_base = [pip, "install", "--require-hashes", "--no-index", "--no-deps", "--find-links", wheelhouse]
    run([*pip_base, "-r", lock_path], timeout=300, capture=not args.verbose)
    built_wheels = target / "built-wheels"
    built_wheels.mkdir(mode=0o755)
    run(
        [
            py,
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--find-links",
            wheelhouse,
            "-w",
            built_wheels,
            str(source / "packages/hodlxxi_mcp"),
        ],
        timeout=300,
        capture=not args.verbose,
    )
    local_wheels = sorted(built_wheels.glob("hodlxxi_mcp-*.whl"))
    if len(local_wheels) != 1:
        raise FailClosed("expected exactly one built hodlxxi-mcp wheel")
    built_wheel = local_wheels[0]
    built_wheel_sha256 = sha256_file(built_wheel)
    local_wheel_lock = built_wheels / "hodlxxi-mcp.lock"
    local_wheel_lock.write_text(f"hodlxxi-mcp @ {built_wheel.as_uri()} --hash=sha256:{built_wheel_sha256}\n")
    run([*pip_base, "-r", local_wheel_lock], timeout=300, capture=not args.verbose)
    run([py, "-m", "pip", "check"], timeout=60)
    freeze_digest = write_installed_manifest(py, target / FREEZE_FILE)
    evidence = {
        "source_commit": commit,
        "package_version": package_version(source),
        "installed_distribution_version": run(
            [py, "-c", 'import importlib.metadata as m; print(m.version("hodlxxi-mcp"))']
        ).stdout.strip(),
        "module_version": run([py, "-c", "import hodlxxi_mcp; print(hodlxxi_mcp.__version__)"]).stdout.strip(),
        "python_version": run([py, "--version"]).stdout.strip(),
        "fastmcp_version": run([py, "-c", "import fastmcp; print(fastmcp.__version__)"]).stdout.strip(),
        "mcp_sdk_version": run([py, "-c", 'import importlib.metadata as m; print(m.version("mcp"))']).stdout.strip(),
        "build_input_digest_sha256": digest_inputs(source, args.dependency_lock),
        "dependency_lock": str(lock_path.relative_to(source)),
        "dependency_lock_sha256": sha256_file(lock_path),
        "installed_distributions_sha256": freeze_digest,
        "built_wheel": str(built_wheel.relative_to(target)),
        "built_wheel_sha256": built_wheel_sha256,
        "build_timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_tree": str(source),
        "release_dir": str(target),
    }
    (target / IDENTITY_FILE).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    harden_release_permissions(target)
    verify_release(
        target,
        source=source,
        current=current_path,
        releases_dir=releases,
        dependency_lock=args.dependency_lock,
        write=True,
    )
    return target


def _server_probe_code(expected_version):
    return f"""
import asyncio
import importlib.metadata as md
import sys
from hodlxxi_mcp import __version__
from hodlxxi_mcp.server import mcp
assert __version__ == {expected_version!r}, (__version__, {expected_version!r})
assert md.version('hodlxxi-mcp') == {expected_version!r}
assert mcp.name == {EXPECTED_NAME!r}
assert mcp.version == {expected_version!r}
async def main():
 t=await mcp.list_tools(); r=await mcp.list_resources(); p=await mcp.list_prompts()
 assert len(t)=={EXPECTED_TOOLS}, len(t)
 assert len(r)=={EXPECTED_RESOURCES}, len(r)
 assert len(p)=={EXPECTED_PROMPTS}, len(p)
asyncio.run(main())
"""


def verify_identity(ident: dict, *, release: Path, source: Path, dep_lock: Path, py: Path) -> None:
    version = package_version(source)
    expected = {
        "source_commit": git(["rev-parse", "HEAD"], source),
        "package_version": version,
        "installed_distribution_version": run(
            [py, "-c", 'import importlib.metadata as m; print(m.version("hodlxxi-mcp"))']
        ).stdout.strip(),
        "module_version": run([py, "-c", "import hodlxxi_mcp; print(hodlxxi_mcp.__version__)"]).stdout.strip(),
        "python_version": run([py, "--version"]).stdout.strip(),
        "fastmcp_version": run([py, "-c", "import fastmcp; print(fastmcp.__version__)"]).stdout.strip(),
        "mcp_sdk_version": run([py, "-c", 'import importlib.metadata as m; print(m.version("mcp"))']).stdout.strip(),
        "build_input_digest_sha256": digest_inputs(source, dep_lock),
        "dependency_lock": str(dependency_lock_path(source, dep_lock).relative_to(source)),
        "dependency_lock_sha256": sha256_file(dependency_lock_path(source, dep_lock)),
        "source_tree": str(source.resolve()),
        "release_dir": str(release.resolve()),
    }
    for key, value in expected.items():
        if ident.get(key) != value:
            raise FailClosed(f"release identity mismatch for {key}")
    if ident.get("package_version") != ident.get("installed_distribution_version"):
        raise FailClosed("installed distribution version does not match package version")
    if ident.get("package_version") != ident.get("module_version"):
        raise FailClosed("module version does not match package version")
    freeze = release / FREEZE_FILE
    if not freeze.is_file() or ident.get("installed_distributions_sha256") != sha256_file(freeze):
        raise FailClosed("installed distribution manifest mismatch")
    built_wheel = release / str(ident.get("built_wheel", ""))
    if release.resolve() not in built_wheel.resolve().parents:
        raise FailClosed("built wheel path escapes release directory")
    if not built_wheel.is_file() or ident.get("built_wheel_sha256") != sha256_file(built_wheel):
        raise FailClosed("built wheel identity mismatch")


def verify_release(release, *, source, current, releases_dir, dependency_lock=DEFAULT_DEP_LOCK, write=False):
    source = source.resolve()
    releases = releases_dir.resolve()
    release = require_direct_release_child(Path(release), releases)
    locked_versions = parse_dependency_lock(dependency_lock_path(source, dependency_lock))
    current_path = Path(current).absolute()
    if current_path.is_symlink() and release == current_path.resolve():
        raise FailClosed("candidate release is already current")
    ident_path = release / IDENTITY_FILE
    if not ident_path.is_file() or ident_path.is_symlink():
        raise FailClosed("missing release identity evidence")
    ident = json.loads(ident_path.read_text())
    py = release / "venv/bin/python"
    entry = release / ENTRY
    if not (entry.is_file() and not entry.is_symlink() and stat.S_IMODE(entry.stat().st_mode) & stat.S_IXUSR):
        raise FailClosed("entrypoint is missing or not executable")
    if os.geteuid() == 0:
        assert_root_owned_not_service_writable(release)
    verify_identity(ident, release=release, source=source, dep_lock=dependency_lock, py=py)
    regenerated_freeze = run([py, "-m", "pip", "freeze", "--all"], timeout=60).stdout
    normalized_freeze = "\n".join(sorted(line for line in regenerated_freeze.splitlines() if line.strip())) + "\n"
    recorded_freeze = (release / FREEZE_FILE).read_text()
    if normalized_freeze != recorded_freeze:
        raise FailClosed("installed distributions manifest does not match regenerated pip freeze")
    installed_versions = {}
    for line in normalized_freeze.splitlines():
        if "==" in line:
            name, version = line.split("==", 1)
            installed_versions[normalize_distribution_name(name)] = version
        elif line.startswith("hodlxxi-mcp @ "):
            installed_versions["hodlxxi-mcp"] = package_version(source)
    expected_versions = {name: version for name, (version, _hash) in locked_versions.items()}
    expected_versions["hodlxxi-mcp"] = package_version(source)
    for name, version in expected_versions.items():
        if installed_versions.get(name) != version:
            raise FailClosed(f"installed distribution mismatch for {name}")
    unexpected = set(installed_versions) - set(expected_versions)
    if unexpected:
        raise FailClosed("unexpected installed distributions: " + ", ".join(sorted(unexpected)[:5]))
    run([py, "-m", "pip", "check"], timeout=60)
    assert_release_accessible_as_service_user(release)
    run_as_service_user(["test", "-x", entry], timeout=10)
    run_as_service_user(["test", "-x", py], timeout=10)
    run_as_service_user(["test", "!", "-w", release], timeout=10)
    run([py, "-c", "import hodlxxi_mcp, hodlxxi_mcp.server, hodlxxi_mcp.http_server"], timeout=30)
    run_as_service_user([py, "-c", "import hodlxxi_mcp, hodlxxi_mcp.server, hodlxxi_mcp.http_server"], timeout=30)
    run([py, "-c", _server_probe_code(package_version(source))], cwd=Path("/tmp"), timeout=30)
    identity_digest = sha256_file(ident_path)
    built_wheel = release / ident["built_wheel"]
    result = {
        "schema": VERIFY_SCHEMA,
        "schema_version": VERIFY_SCHEMA_VERSION,
        "status": "verified",
        "release_dir": str(release),
        "release_identity_path": IDENTITY_FILE,
        "release_identity_sha256": identity_digest,
        "installed_distributions_path": FREEZE_FILE,
        "installed_distributions_sha256": sha256_file(release / FREEZE_FILE),
        "dependency_lock_path": ident["dependency_lock"],
        "dependency_lock_sha256": sha256_file(dependency_lock_path(source, dependency_lock)),
        "built_wheel_path": ident["built_wheel"],
        "built_wheel_sha256": sha256_file(built_wheel),
        "source_commit": git(["rev-parse", "HEAD"], source),
        "verified_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    if write:
        (release / VERIFY_FILE).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2))
    return result


def verify_previous_current(current: Path, releases: Path) -> Path:
    if not current.exists() and not current.is_symlink():
        raise FailClosed("current symlink is missing")
    if not current.is_symlink():
        raise FailClosed("current must be a symlink")
    try:
        previous = current.resolve(strict=True)
    except FileNotFoundError as exc:
        raise FailClosed("current symlink is broken") from exc
    previous = require_direct_release_child(previous, releases)
    entry = previous / ENTRY
    if not (entry.is_file() and os.access(entry, os.X_OK)):
        raise FailClosed("previous release entrypoint is unavailable for rollback")
    return previous


def verify_stored_verification(release: Path) -> None:
    verify_path = release / VERIFY_FILE
    ident_path = release / IDENTITY_FILE
    if not verify_path.is_file() or verify_path.is_symlink():
        raise FailClosed("release has not been previously verified")
    try:
        verify = json.loads(verify_path.read_text())
        ident = json.loads(ident_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise FailClosed("VERIFY.json or RELEASE_IDENTITY.json is malformed") from exc
    expected = {
        "schema": VERIFY_SCHEMA,
        "schema_version": VERIFY_SCHEMA_VERSION,
        "status": "verified",
        "release_dir": str(release),
        "release_identity_path": IDENTITY_FILE,
        "release_identity_sha256": sha256_file(ident_path),
        "installed_distributions_path": FREEZE_FILE,
        "installed_distributions_sha256": sha256_file(release / FREEZE_FILE),
        "dependency_lock_path": ident.get("dependency_lock"),
        "dependency_lock_sha256": ident.get("dependency_lock_sha256"),
        "built_wheel_path": ident.get("built_wheel"),
        "built_wheel_sha256": ident.get("built_wheel_sha256"),
        "source_commit": ident.get("source_commit"),
    }
    for key, value in expected.items():
        if value is None or verify.get(key) != value:
            raise FailClosed(f"VERIFY.json is missing, stale, or differently scoped for {key}")
    wheel = release / str(expected["built_wheel_path"])
    if release.resolve() not in wheel.resolve().parents:
        raise FailClosed("VERIFY.json built wheel path escapes release directory")
    if not wheel.is_file() or sha256_file(wheel) != expected["built_wheel_sha256"]:
        raise FailClosed("VERIFY.json built wheel evidence is stale")


def atomic_point(current: Path, target: Path) -> None:
    tmp = current.with_name(f".{current.name}.tmp-{os.getpid()}")
    try:
        if tmp.exists() or tmp.is_symlink():
            tmp.unlink()
        os.symlink(target, tmp)
        os.replace(tmp, current)
    finally:
        if tmp.exists() or tmp.is_symlink():
            tmp.unlink()


def parse_systemctl_show(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    return fields


def systemctl(args):
    return run(["systemctl", *args], timeout=15)


def listener_ports() -> set[str]:
    if not shutil.which("ss"):
        raise FailClosed("socket listener inspector ss is unavailable")
    result = run(["ss", "-ltnH"], timeout=10)
    return {
        line.split()[3]
        for line in result.stdout.splitlines()
        if len(line.split()) >= 4 and line.split()[3].endswith(":8765")
    }


def assert_loopback_listener() -> None:
    ports = listener_ports()
    if ports != {"127.0.0.1:8765"}:
        raise FailClosed("unexpected MCP listener set: " + ", ".join(sorted(ports)))
    with socket.create_connection(("127.0.0.1", 8765), timeout=3):
        return


def _sdk_smoke_code(expected_version: str | None) -> str:
    return f"""
import anyio
import httpx
import json
from datetime import timedelta
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

EXPECTED_PROTOCOL = {EXPECTED_PROTOCOL!r}
EXPECTED_VERSION = {expected_version!r}

async def collect(session, method, field):
    values = []
    cursor = None
    seen = set()
    for _ in range(100):
        result = await getattr(session, method)(cursor) if cursor else await getattr(session, method)()
        values.extend(getattr(result, field))
        cursor = result.nextCursor
        if not cursor:
            return values
        if cursor in seen:
            raise RuntimeError(f'pagination cursor loop in {{method}}')
        seen.add(cursor)
    raise RuntimeError(f'pagination limit exceeded in {{method}}')

async def main():
    if str(types.LATEST_PROTOCOL_VERSION) != EXPECTED_PROTOCOL:
        raise RuntimeError('candidate MCP SDK does not initialize with required protocol')
    timeout = httpx.Timeout(5.0, read=5.0, write=5.0, connect=3.0, pool=3.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
      with anyio.fail_after(20):
       async with streamable_http_client('http://127.0.0.1:8765/mcp', http_client=client) as streams:
        async with ClientSession(streams[0], streams[1], read_timeout_seconds=timedelta(seconds=5)) as session:
         initialized = await session.initialize()
         info = initialized.serverInfo
         if str(initialized.protocolVersion) != EXPECTED_PROTOCOL:
             raise RuntimeError('protocol mismatch')
         if info.name != {EXPECTED_NAME!r}:
             raise RuntimeError('server name mismatch')
         if EXPECTED_VERSION is not None and info.version != EXPECTED_VERSION:
             raise RuntimeError('server version mismatch')
         tools = await collect(session, 'list_tools', 'tools')
         resources = await collect(session, 'list_resources', 'resources')
         prompts = await collect(session, 'list_prompts', 'prompts')
         names = [tool.name for tool in tools]
         if len(names) != {EXPECTED_TOOLS} or len(set(names)) != {EXPECTED_TOOLS}:
             raise RuntimeError('tool count or uniqueness mismatch')
         if len(resources) != {EXPECTED_RESOURCES} or len(prompts) != {EXPECTED_PROMPTS}:
             raise RuntimeError('resource or prompt count mismatch')
         for name in ('hodlxxi_get_capabilities', 'hodlxxi_get_chain_health', 'hodlxxi_get_reputation'):
             result = await session.call_tool(name, {{}})
             if result.isError:
                 raise RuntimeError(f'{{name}} returned isError=true')
         print(json.dumps({{
             'protocol_version': str(initialized.protocolVersion),
             'server_name': info.name,
             'package_version': info.version,
             'tool_count': len(names),
         }}, sort_keys=True))

anyio.run(main)
"""


def smoke_mcp_protocol(candidate_python: Path, expected_version: str | None = None) -> dict[str, object]:
    try:
        result = run_as_service_user(
            [candidate_python, "-c", _sdk_smoke_code(expected_version)], cwd=Path("/tmp"), timeout=25
        )
        evidence = json.loads(result.stdout.strip())
    except (json.JSONDecodeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise FailClosed(f"official MCP SDK smoke verification failed: {exc}") from exc
    expected = {
        "protocol_version": EXPECTED_PROTOCOL,
        "server_name": EXPECTED_NAME,
        "tool_count": EXPECTED_TOOLS,
    }
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise FailClosed("official MCP SDK smoke evidence has an unexpected shape or value")
    if not isinstance(evidence.get("package_version"), str) or not evidence["package_version"]:
        raise FailClosed("official MCP SDK smoke evidence lacks package version")
    return evidence


def release_version(release: Path) -> str | None:
    identity = release / IDENTITY_FILE
    if not identity.is_file() or identity.is_symlink():
        return None
    try:
        version = json.loads(identity.read_text()).get("package_version")
    except (OSError, json.JSONDecodeError) as exc:
        raise FailClosed("current release identity is malformed") from exc
    if not isinstance(version, str) or not version:
        raise FailClosed("current release identity lacks package version")
    return version


def health_check(
    release: Path,
    *,
    expected_evidence: dict[str, object] | None = None,
    previous_restarts: int | None = None,
    timeout: float = HEALTH_TIMEOUT,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last_error = "not started"
    expected_version = release_version(release)
    while time.monotonic() < deadline:
        try:
            props = parse_systemctl_show(
                systemctl(
                    [
                        "show",
                        SERVICE,
                        "-p",
                        "ActiveState",
                        "-p",
                        "SubState",
                        "-p",
                        "Result",
                        "-p",
                        "NRestarts",
                        "-p",
                        "ExecMainStatus",
                    ]
                ).stdout
            )
            restarts = int(props.get("NRestarts", "0") or "0")
            if props.get("ActiveState") != "active":
                raise FailClosed("ActiveState is not active")
            if props.get("SubState") != "running":
                raise FailClosed("SubState is not running")
            if props.get("Result") != "success":
                raise FailClosed("Result is not success")
            if props.get("ExecMainStatus") != "0":
                raise FailClosed("ExecMainStatus is not 0")
            if previous_restarts is not None and restarts > previous_restarts:
                raise FailClosed("NRestarts increased unexpectedly")
            assert_loopback_listener()
            evidence = smoke_mcp_protocol(release / "venv/bin/python", expected_version)
            evidence["nrestarts"] = restarts
            if expected_evidence is not None and evidence != expected_evidence:
                raise FailClosed("restored service does not match captured pre-switch evidence")
            return evidence
        except Exception as exc:
            last_error = str(exc)
            time.sleep(HEALTH_INTERVAL)
    raise FailClosed(f"service health check failed within startup window: {last_error}")


@contextlib.contextmanager
def deployment_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise FailClosed("deployment lock file is unsafe") from exc
    with os.fdopen(fd, "w") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise FailClosed("deployment lock file has unsafe type or permissions")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise FailClosed("another MCP release operation is already running") from exc
        yield


def activate(args):
    source = args.source.resolve()
    releases = args.releases_dir.resolve()
    current = args.current.absolute()
    release = require_direct_release_child(args.release_dir, releases)
    with deployment_lock(args.lock_file):
        previous = verify_previous_current(current, releases)
        if release == previous:
            raise FailClosed("candidate release is already the previous/current release")
        verify_release(
            release,
            source=source,
            current=current,
            releases_dir=releases,
            dependency_lock=args.dependency_lock,
            write=False,
        )
        verify_stored_verification(release)
        if args.check_only or args.dry_run:
            print(
                json.dumps(
                    {
                        "check_only": args.check_only,
                        "dry_run": args.dry_run,
                        "would_activate": str(release),
                        "previous": str(previous),
                    },
                    indent=2,
                )
            )
            return
        previous_evidence = health_check(previous)
        before = int(previous_evidence["nrestarts"])
        atomic_point(current, release)
        try:
            systemctl(["restart", SERVICE])
            health_check(release, previous_restarts=before)
        except Exception as activation_error:
            rollback_error = None
            try:
                atomic_point(current, previous)
                systemctl(["restart", SERVICE])
                health_check(previous, expected_evidence=previous_evidence)
            except Exception as exc:  # preserve original activation error below
                rollback_error = exc
            if rollback_error is not None:
                raise RollbackRecoveryFailed(
                    f"activation failed ({activation_error}); rollback recovery also failed ({rollback_error})"
                ) from activation_error
            raise FailClosed(
                f"activation failed and rollback recovery succeeded: {activation_error}"
            ) from activation_error


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    p.add_argument("--releases-dir", type=Path, default=DEFAULT_RELEASES)
    p.add_argument("--current", type=Path, default=DEFAULT_CURRENT)
    p.add_argument("--dependency-lock", type=Path, default=DEFAULT_DEP_LOCK)
    p.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK)
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--release-id")
    b.add_argument("--allow-dirty-build", action="store_true")
    b.add_argument("--dry-run", action="store_true")
    b.add_argument("--verbose", action="store_true")
    b.add_argument("--wheelhouse")
    v = sub.add_parser("verify")
    v.add_argument("release_dir", type=Path)
    v.add_argument("--write", action="store_true")
    a = sub.add_parser("activate")
    a.add_argument("release_dir", type=Path)
    a.add_argument("--check-only", action="store_true")
    a.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.cmd == "build":
            with deployment_lock(args.lock_file):
                build(args)
        elif args.cmd == "verify":
            ctx = deployment_lock(args.lock_file) if args.write else contextlib.nullcontext()
            with ctx:
                verify_release(
                    args.release_dir,
                    source=args.source,
                    current=args.current,
                    releases_dir=args.releases_dir,
                    dependency_lock=args.dependency_lock,
                    write=args.write,
                )
        elif args.cmd == "activate":
            activate(args)
    except (FailClosed, subprocess.TimeoutExpired) as exc:
        print(f"FAIL-CLOSED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
