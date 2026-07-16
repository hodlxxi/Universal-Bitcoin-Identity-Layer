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
import urllib.request
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


def parse_dependency_lock(lock: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in lock.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        requirement = line.split(" --hash=", 1)[0].strip()
        if "==" not in requirement:
            raise FailClosed(f"dependency lock contains non-exact requirement: {line}")
        name, version = requirement.split("==", 1)
        key = name.lower().replace("_", "-")
        if key in entries and entries[key] != version:
            raise FailClosed(f"dependency lock has conflicting duplicate entry for {name}")
        if key in entries:
            raise FailClosed(f"dependency lock has duplicate entry for {name}")
        entries[key] = version
    if not entries:
        raise FailClosed("dependency lock is empty")
    return entries


def validate_wheelhouse(wheelhouse: str | None, lock: Path) -> Path:
    if not wheelhouse:
        raise FailClosed("--wheelhouse is required for production release builds")
    root = Path(wheelhouse).resolve()
    if not root.is_dir() or root.is_symlink():
        raise FailClosed("wheelhouse must be an existing non-symlink directory")
    allowed = {".whl", ".tar.gz", ".zip"}
    files = [p for p in root.iterdir() if p.is_file() and not p.is_symlink()]
    if not files:
        raise FailClosed("wheelhouse contains no artifacts")
    bad = [
        p.name
        for p in root.iterdir()
        if p.is_symlink() or (p.is_file() and not any(p.name.endswith(ext) for ext in allowed))
    ]
    if bad:
        raise FailClosed("wheelhouse contains unsupported or unsafe artifacts: " + ", ".join(sorted(bad)[:5]))
    # If hashes are present in the lock, every referenced hash must be present in the wheelhouse.
    expected_hashes = {
        line.split("sha256:", 1)[1].strip() for line in lock.read_text().splitlines() if "--hash=sha256:" in line
    }
    actual_hashes = {sha256_file(p) for p in files}
    missing = expected_hashes - actual_hashes
    if missing:
        raise FailClosed("wheelhouse artifact hash mismatch")
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
    uid, gid = service_user_ids() if os.geteuid() == 0 else (os.geteuid(), os.getegid())
    gids = {gid}
    for p in [root, *root.rglob("*")]:
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode):
            continue
        if not allow_non_root_owner and st.st_uid != 0:
            raise FailClosed(f"release path is not root-owned: {p}")
        if is_writable_by(uid, gids, st.st_mode, st.st_uid, st.st_gid):
            raise FailClosed(f"release path is writable by {SERVICE_USER}: {p}")


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
    pip_base = [pip, "install", "--no-index", "--no-deps", "--find-links", wheelhouse]
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
    run([*pip_base, built_wheel], timeout=300, capture=not args.verbose)
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
    if not built_wheel.is_file() or ident.get("built_wheel_sha256") != sha256_file(built_wheel):
        raise FailClosed("built wheel identity mismatch")


def verify_release(release, *, source, current, releases_dir, dependency_lock=DEFAULT_DEP_LOCK, write=False):
    source = source.resolve()
    releases = releases_dir.resolve()
    release = require_direct_release_child(Path(release), releases)
    parse_dependency_lock(dependency_lock_path(source, dependency_lock))
    harden_release_permissions(release)
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
    required_files = [entry, py, ident_path, release / FREEZE_FILE]
    for path in required_files:
        run_as_service_user(["test", "-r", path], timeout=10)
    run_as_service_user(["test", "-x", entry], timeout=10)
    run_as_service_user(["test", "!", "-w", release], timeout=10)
    run([py, "-c", "import hodlxxi_mcp, hodlxxi_mcp.server, hodlxxi_mcp.http_server"], timeout=30)
    run_as_service_user([py, "-c", "import hodlxxi_mcp, hodlxxi_mcp.server, hodlxxi_mcp.http_server"], timeout=30)
    run([py, "-c", _server_probe_code(package_version(source))], cwd=Path("/tmp"), timeout=30)
    identity_digest = sha256_file(ident_path)
    result = {
        "status": "verified",
        "release_dir": str(release),
        "identity_sha256": identity_digest,
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
    verify = json.loads(verify_path.read_text())
    if verify.get("identity_sha256") != sha256_file(ident_path):
        raise FailClosed("VERIFY.json does not match RELEASE_IDENTITY.json")
    if verify.get("release_dir") != str(release):
        raise FailClosed("VERIFY.json release_dir does not match candidate")


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
    if shutil.which("ss"):
        result = run(["ss", "-ltnH"], timeout=10)
        return {line.split()[3] for line in result.stdout.splitlines() if len(line.split()) >= 4}
    return set()


def assert_loopback_listener() -> None:
    ports = listener_ports()
    if ports and "127.0.0.1:8765" not in ports:
        raise FailClosed("127.0.0.1:8765 listener is absent")
    if "0.0.0.0:8765" in ports or "[::]:8765" in ports or "*:8765" in ports:
        raise FailClosed("unsafe non-loopback MCP listener is present")
    with socket.create_connection(("127.0.0.1", 8765), timeout=3):
        return


def _post_json(method: str, params: dict | None = None, session_id: str | None = None) -> tuple[dict, dict]:
    body = json.dumps({"jsonrpc": "2.0", "id": method, "method": method, "params": params or {}}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if session_id:
        headers["MCP-Session-Id"] = session_id
        headers["MCP-Protocol-Version"] = EXPECTED_PROTOCOL
    req = urllib.request.Request("http://127.0.0.1:8765/mcp", data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as response:
        raw = response.read().decode("utf-8", errors="replace")
        out_headers = dict(response.headers.items())
    if raw.startswith("event:"):
        data_lines = [line.removeprefix("data: ") for line in raw.splitlines() if line.startswith("data:")]
        raw = "\n".join(data_lines)
    return json.loads(raw), out_headers


def smoke_mcp_protocol(expected_version: str) -> None:
    init, headers = _post_json(
        "initialize",
        {
            "protocolVersion": EXPECTED_PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "hodlxxi-release-activator", "version": "1.0.0"},
        },
    )
    result = init.get("result", {})
    info = result.get("serverInfo", {})
    if (
        result.get("protocolVersion") != EXPECTED_PROTOCOL
        or info.get("name") != EXPECTED_NAME
        or info.get("version") != expected_version
    ):
        raise FailClosed("MCP initialize smoke test returned unexpected server identity")
    session = headers.get("Mcp-Session-Id") or headers.get("MCP-Session-Id")
    tools, _ = _post_json("tools/list", session_id=session)
    resources, _ = _post_json("resources/list", session_id=session)
    prompts, _ = _post_json("prompts/list", session_id=session)
    if len(tools.get("result", {}).get("tools", [])) != EXPECTED_TOOLS:
        raise FailClosed("MCP tools/list count mismatch")
    if len(resources.get("result", {}).get("resources", [])) != EXPECTED_RESOURCES:
        raise FailClosed("MCP resources/list count mismatch")
    if len(prompts.get("result", {}).get("prompts", [])) != EXPECTED_PROMPTS:
        raise FailClosed("MCP prompts/list count mismatch")


def health_check(release: Path, *, previous_restarts: int | None = None, timeout: float = HEALTH_TIMEOUT) -> int:
    deadline = time.monotonic() + timeout
    last_error = "not started"
    expected_version = json.loads((release / IDENTITY_FILE).read_text())["package_version"]
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
            smoke_mcp_protocol(expected_version)
            return restarts
        except Exception as exc:
            last_error = str(exc)
            time.sleep(HEALTH_INTERVAL)
    raise FailClosed(f"service health check failed within startup window: {last_error}")


@contextlib.contextmanager
def deployment_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
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
        before = int(
            parse_systemctl_show(systemctl(["show", SERVICE, "-p", "NRestarts"]).stdout).get("NRestarts", "0") or "0"
        )
        atomic_point(current, release)
        try:
            systemctl(["restart", SERVICE])
            health_check(release, previous_restarts=before)
        except Exception as activation_error:
            rollback_error = None
            try:
                atomic_point(current, previous)
                systemctl(["restart", SERVICE])
                health_check(previous)
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
