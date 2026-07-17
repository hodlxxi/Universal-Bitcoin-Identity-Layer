from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from scripts import mcp_release_deploy as deploy

ROOT = Path(__file__).resolve().parents[2]


def fake_release(releases: Path, name: str = "rel", *, version: str = "0.1.1") -> Path:
    rel = releases / name
    (rel / "venv/bin").mkdir(parents=True)
    py = rel / "venv/bin/python"
    py.write_text("#!/bin/sh\nexit 0\n")
    py.chmod(0o755)
    entry = rel / deploy.ENTRY
    entry.write_text("#!/bin/sh\nexit 0\n")
    entry.chmod(0o755)
    freeze = rel / deploy.FREEZE_FILE
    freeze.write_text("hodlxxi-mcp==0.1.1\n")
    wheel_dir = rel / "built-wheels"
    wheel_dir.mkdir()
    built_wheel = wheel_dir / "hodlxxi_mcp-0.1.1-py3-none-any.whl"
    built_wheel.write_bytes(b"fake wheel")
    ident = {
        "source_commit": deploy.git(["rev-parse", "HEAD"], ROOT),
        "package_version": version,
        "installed_distribution_version": version,
        "module_version": version,
        "python_version": "Python 3",
        "fastmcp_version": "3.4.4",
        "mcp_sdk_version": "1.28.1",
        "build_input_digest_sha256": deploy.digest_inputs(ROOT),
        "dependency_lock": str(deploy.DEFAULT_DEP_LOCK),
        "dependency_lock_sha256": deploy.sha256_file(ROOT / deploy.DEFAULT_DEP_LOCK),
        "installed_distributions_sha256": deploy.sha256_file(freeze),
        "built_wheel": str(built_wheel.relative_to(rel)),
        "built_wheel_sha256": deploy.sha256_file(built_wheel),
        "build_timestamp_utc": "2026-01-01T00:00:00+00:00",
        "source_tree": str(ROOT.resolve()),
        "release_dir": str(rel.resolve()),
    }
    ident_path = rel / deploy.IDENTITY_FILE
    ident_path.write_text(json.dumps(ident))
    (rel / deploy.VERIFY_FILE).write_text(
        json.dumps(
            {
                "schema_version": "1",
                "status": "verified",
                "release_dir": str(rel.resolve()),
                "identity_sha256": deploy.sha256_file(ident_path),
                "installed_distributions_sha256": deploy.sha256_file(freeze),
                "dependency_lock_sha256": deploy.sha256_file(ROOT / deploy.DEFAULT_DEP_LOCK),
                "source_commit": deploy.git(["rev-parse", "HEAD"], ROOT),
            }
        )
    )
    return rel


def patch_verify_runtime(monkeypatch):
    monkeypatch.setattr(deploy, "service_user_ids", lambda: (65534, 65534))
    monkeypatch.setattr(deploy, "assert_root_owned_not_service_writable", lambda *a, **k: None)
    monkeypatch.setattr(deploy, "run_as_service_user", lambda *a, **k: None)
    monkeypatch.setattr(
        deploy,
        "run",
        lambda *a, **k: type(
            "R", (), {"stdout": "hodlxxi-mcp==0.1.1\n" if "freeze" in [str(x) for x in a[0]] else "0"}
        )(),
    )
    monkeypatch.setattr(deploy, "verify_identity", lambda *a, **k: None)
    monkeypatch.setattr(deploy, "parse_dependency_lock", lambda *a, **k: {"hodlxxi-mcp": "0.1.1"})


def activate_args(tmp_path: Path, rel: Path, current: Path):
    return type(
        "A",
        (),
        {
            "release_dir": rel,
            "releases_dir": tmp_path / "releases",
            "current": current,
            "source": ROOT,
            "dependency_lock": deploy.DEFAULT_DEP_LOCK,
            "lock_file": tmp_path / "lock",
            "check_only": False,
            "dry_run": False,
        },
    )()


def test_restrictive_caller_umask_artifacts_readable(tmp_path):
    releases = tmp_path / "releases"
    rel = fake_release(releases)
    unreadable = rel / "secretly_unreadable.txt"
    unreadable.write_text("x")
    unreadable.chmod(0o600)
    old = os.umask(0o077)
    try:
        deploy.harden_release_permissions(rel)
    finally:
        os.umask(old)
    assert rel.stat().st_mode & stat.S_IROTH
    assert unreadable.stat().st_mode & stat.S_IROTH
    assert (rel / deploy.ENTRY).stat().st_mode & stat.S_IXOTH
    assert not (unreadable.stat().st_mode & stat.S_IWGRP)
    assert not (unreadable.stat().st_mode & stat.S_IWOTH)


def test_chmod_never_follows_external_symlink(tmp_path):
    releases = tmp_path / "releases"
    rel = fake_release(releases)
    external = tmp_path / "external"
    external.write_text("x")
    external.chmod(0o600)
    (rel / "link").symlink_to(external)
    with pytest.raises(deploy.FailClosed, match="unsafe symlink"):
        deploy.harden_release_permissions(rel)
    assert stat.S_IMODE(external.stat().st_mode) == 0o600


def test_lock_entry_without_hash_rejected(tmp_path):
    lock = tmp_path / "lock"
    lock.write_text("demo==1.0\n")
    with pytest.raises(deploy.FailClosed, match="lacks artifact hash"):
        deploy.parse_dependency_lock(lock)


def test_lock_file_symlink_rejected(tmp_path):
    real = tmp_path / "real.lock"
    real.write_text("demo==1.0 --hash=sha256:" + "0" * 64 + "\n")
    link = tmp_path / "link.lock"
    link.symlink_to(real)
    with pytest.raises(deploy.FailClosed, match="dependency lock"):
        deploy.dependency_lock_path(tmp_path, link)


def test_missing_wheelhouse_fails_before_release_creation(tmp_path):
    lock = ROOT / deploy.DEFAULT_DEP_LOCK
    with pytest.raises(deploy.FailClosed, match="wheelhouse"):
        deploy.validate_wheelhouse(None, lock)


def test_wheel_hash_mismatch_fails(tmp_path):
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "demo-1.0-py3-none-any.whl").write_bytes(b"not expected")
    lock = tmp_path / "lock"
    lock.write_text("demo==1.0 --hash=sha256:" + "0" * 64 + "\n")
    with pytest.raises(deploy.FailClosed, match="hash mismatch"):
        deploy.validate_wheelhouse(str(wheelhouse), lock)


def test_dependency_lock_rejects_duplicate_names(tmp_path):
    lock = tmp_path / "lock"
    lock.write_text("demo==1.0 --hash=sha256:" + "0" * 64 + "\nDemo==1.0 --hash=sha256:" + "1" * 64 + "\n")
    with pytest.raises(deploy.FailClosed, match="duplicate"):
        deploy.parse_dependency_lock(lock)


def test_run_as_service_user_applies_clean_env_after_runuser(monkeypatch):
    monkeypatch.setattr(deploy.os, "geteuid", lambda: 0)
    monkeypatch.setattr(deploy, "service_user_ids", lambda: (100, 100))
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["cwd"] = kwargs.get("cwd")
        return type("R", (), {"stdout": ""})()

    monkeypatch.setattr(deploy, "run", fake_run)
    deploy.run_as_service_user(["python", "-c", "pass"])
    assert seen["cmd"][:5] == ["runuser", "-u", deploy.SERVICE_USER, "--", "env"]
    assert "-i" in seen["cmd"]
    assert seen["cwd"] == Path("/tmp")


def test_actual_temporary_venv_with_copies_passes_symlink_policy(tmp_path):
    venv = tmp_path / "release" / "venv"
    deploy.run([sys.executable, "-m", "venv", "--copies", venv], timeout=120)
    release = tmp_path / "release"
    entry = release / deploy.ENTRY
    entry.write_text("#!/bin/sh\nexit 0\n")
    entry.chmod(0o755)
    deploy.harden_release_permissions(release)
    assert not (venv / "bin" / "python").is_symlink()


def test_incomplete_release_cannot_be_activated(tmp_path):
    releases = tmp_path / "releases"
    rel = releases / "incomplete"
    rel.mkdir(parents=True)
    with pytest.raises(deploy.FailClosed, match="missing release identity"):
        deploy.verify_release(rel, source=ROOT, current=tmp_path / "current", releases_dir=releases)


def test_absent_executable_cannot_be_activated(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    rel = fake_release(releases)
    (rel / deploy.ENTRY).unlink()
    with pytest.raises(deploy.FailClosed, match="entrypoint"):
        deploy.verify_release(rel, source=ROOT, current=tmp_path / "current", releases_dir=releases)


def test_verification_failure_leaves_current_unchanged(tmp_path):
    releases = tmp_path / "releases"
    old = fake_release(releases, "old")
    current = tmp_path / "current"
    current.symlink_to(old)
    rel = releases / "bad"
    rel.mkdir()
    with pytest.raises(deploy.FailClosed):
        deploy.verify_release(rel, source=ROOT, current=current, releases_dir=releases)
    assert current.resolve() == old


def test_atomic_switch_uses_fully_built_target(tmp_path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    current = tmp_path / "current"
    current.symlink_to(old)
    deploy.atomic_point(current, new)
    assert current.is_symlink() and current.resolve() == new
    assert not any(p.name.startswith(".current.tmp") for p in tmp_path.iterdir())


def test_post_switch_health_failure_restores_previous_target(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    old = fake_release(releases, "old")
    rel = fake_release(releases, "new")
    current = tmp_path / "current"
    current.symlink_to(old)
    patch_verify_runtime(monkeypatch)
    monkeypatch.setattr(deploy, "systemctl", lambda *a, **k: type("R", (), {"stdout": "NRestarts=0\n"})())
    calls = []

    def health(release, **kwargs):
        calls.append(release.name)
        if release == rel:
            raise deploy.FailClosed("boom")
        return 0

    monkeypatch.setattr(deploy, "health_check", health)
    with pytest.raises(deploy.FailClosed, match="rollback recovery succeeded"):
        deploy.activate(activate_args(tmp_path, rel, current))
    assert current.resolve() == old
    assert calls == ["new", "old"]


def test_rollback_recovery_failure_is_distinct(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    old = fake_release(releases, "old")
    rel = fake_release(releases, "new")
    current = tmp_path / "current"
    current.symlink_to(old)
    patch_verify_runtime(monkeypatch)
    monkeypatch.setattr(deploy, "systemctl", lambda *a, **k: type("R", (), {"stdout": "NRestarts=0\n"})())
    monkeypatch.setattr(deploy, "health_check", lambda *a, **k: (_ for _ in ()).throw(deploy.FailClosed("bad")))
    with pytest.raises(deploy.RollbackRecoveryFailed):
        deploy.activate(activate_args(tmp_path, rel, current))
    assert current.resolve() == old


def test_source_release_identity_mismatch_fails_closed(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    rel = fake_release(releases)
    patch_verify_runtime(monkeypatch)

    def mismatch(*args, **kwargs):
        raise deploy.FailClosed("release identity mismatch for source_commit")

    monkeypatch.setattr(deploy, "verify_identity", mismatch)
    with pytest.raises(deploy.FailClosed, match="source_commit"):
        deploy.verify_release(rel, source=ROOT, current=tmp_path / "current", releases_dir=releases)


def test_package_version_mismatch_fails_closed(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    rel = fake_release(releases, version="0.1.0")
    patch_verify_runtime(monkeypatch)

    def mismatch(*args, **kwargs):
        raise deploy.FailClosed("release identity mismatch for package_version")

    monkeypatch.setattr(deploy, "verify_identity", mismatch)
    with pytest.raises(deploy.FailClosed, match="package_version"):
        deploy.verify_release(rel, source=ROOT, current=tmp_path / "current", releases_dir=releases)


def test_no_shell_command_injection_through_release_id(tmp_path):
    with pytest.raises(deploy.FailClosed):
        deploy.release_path(tmp_path, "../evil;touch pwned")
    assert not (tmp_path / "pwned").exists()


def test_activate_check_only_does_not_restart_or_write_opt(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    old = fake_release(releases, "old")
    rel = fake_release(releases, "new")
    current = tmp_path / "current"
    current.symlink_to(old)
    patch_verify_runtime(monkeypatch)
    monkeypatch.setattr(deploy, "systemctl", lambda *a, **k: pytest.fail("systemctl must not run"))
    args = activate_args(tmp_path, rel, current)
    args.check_only = True
    deploy.activate(args)
    assert current.resolve() == old


def test_dependency_lock_absence_and_mismatch(tmp_path):
    with pytest.raises(deploy.FailClosed, match="dependency lock"):
        deploy.dependency_lock_path(ROOT, tmp_path / "missing.lock")
    bad = tmp_path / "bad.lock"
    bad.write_text("httpx>=0.27 --hash=sha256:" + "0" * 64 + "\n")
    with pytest.raises(deploy.FailClosed, match="non-exact"):
        deploy.dependency_lock_path(tmp_path, bad)


def test_verify_json_stale_rejected(tmp_path):
    releases = tmp_path / "releases"
    rel = fake_release(releases)
    (rel / deploy.VERIFY_FILE).write_text(json.dumps({"identity_sha256": "bad", "release_dir": str(rel.resolve())}))
    with pytest.raises(deploy.FailClosed, match="VERIFY.json"):
        deploy.verify_stored_verification(rel.resolve())


def test_candidate_outside_and_symlink_rejected(tmp_path):
    releases = tmp_path / "releases"
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(deploy.FailClosed, match="direct child"):
        deploy.require_direct_release_child(outside, releases)
    real = fake_release(releases)
    link = releases / "link"
    link.symlink_to(real)
    with pytest.raises(deploy.FailClosed, match="symlink"):
        deploy.require_direct_release_child(link, releases)


def test_current_symlink_preconditions(tmp_path):
    releases = tmp_path / "releases"
    current = tmp_path / "current"
    with pytest.raises(deploy.FailClosed, match="missing"):
        deploy.verify_previous_current(current, releases)
    current.write_text("not link")
    with pytest.raises(deploy.FailClosed, match="symlink"):
        deploy.verify_previous_current(current, releases)
    current.unlink()
    current.symlink_to(releases / "missing")
    with pytest.raises(deploy.FailClosed, match="broken"):
        deploy.verify_previous_current(current, releases)


def test_candidate_equal_to_previous_rejected(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    old = fake_release(releases, "old")
    current = tmp_path / "current"
    current.symlink_to(old)
    with pytest.raises(deploy.FailClosed, match="previous/current"):
        deploy.activate(activate_args(tmp_path, old, current))


def test_loopback_only_listener_enforcement(monkeypatch):
    monkeypatch.setattr(deploy, "listener_ports", lambda: {"0.0.0.0:8765", "127.0.0.1:8765"})
    with pytest.raises(deploy.FailClosed, match="unexpected MCP listener"):
        deploy.assert_loopback_listener()


def test_nrestarts_increase_rejected(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    rel = fake_release(releases)
    props = "ActiveState=active\nSubState=running\nResult=success\nNRestarts=2\nExecMainStatus=0\n"
    monkeypatch.setattr(deploy, "systemctl", lambda *a, **k: type("R", (), {"stdout": props})())
    monkeypatch.setattr(deploy, "assert_loopback_listener", lambda: None)
    monkeypatch.setattr(deploy, "smoke_mcp_protocol", lambda *a, **k: None)
    with pytest.raises(deploy.FailClosed, match="NRestarts"):
        deploy.health_check(rel, previous_restarts=1, timeout=0.01)


def test_bounded_startup_retries(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    rel = fake_release(releases)
    attempts = {"n": 0}

    def fake_systemctl(*args, **kwargs):
        attempts["n"] += 1
        if attempts["n"] < 2:
            return type("R", (), {"stdout": "ActiveState=activating\nNRestarts=0\n"})()
        return type(
            "R", (), {"stdout": "ActiveState=active\nSubState=running\nResult=success\nNRestarts=0\nExecMainStatus=0\n"}
        )()

    monkeypatch.setattr(deploy, "systemctl", fake_systemctl)
    monkeypatch.setattr(deploy, "assert_loopback_listener", lambda: None)
    monkeypatch.setattr(deploy, "smoke_mcp_protocol", lambda *a, **k: None)
    monkeypatch.setattr(deploy, "HEALTH_INTERVAL", 0)
    assert deploy.health_check(rel, previous_restarts=0, timeout=1) == 0
    assert attempts["n"] == 2


def test_concurrent_activation_lock_refusal(tmp_path):
    lock = tmp_path / "lock"
    with deploy.deployment_lock(lock):
        with pytest.raises(deploy.FailClosed, match="already running"):
            with deploy.deployment_lock(lock):
                pass


def test_subprocess_timeouts():
    with pytest.raises(Exception):
        deploy.run(["python", "-c", "import time; time.sleep(1)"], timeout=0.01)


def test_current_symlink_path_is_not_lost_through_resolve(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    old = fake_release(releases, "old")
    rel = fake_release(releases, "new")
    current = tmp_path / "current"
    current.symlink_to(old)
    patch_verify_runtime(monkeypatch)
    monkeypatch.setattr(deploy, "systemctl", lambda *a, **k: type("R", (), {"stdout": "NRestarts=0\n"})())
    monkeypatch.setattr(deploy, "health_check", lambda *a, **k: 0)
    deploy.activate(activate_args(tmp_path, rel, current))
    assert current.is_symlink()
    assert current.resolve() == rel
