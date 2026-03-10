import json
import os
import re
import subprocess
from pathlib import Path

import pytest

AUDIT_ENV_FLAG = "AUDIT_VPS"
DEFAULT_REPO_PATH = "/srv/ubid"
DEFAULT_ENV_PATH = "/etc/hodlxxi/hodlxxi.env"
DEFAULT_BASE_URL = "https://hodlxxi.com"


def _run(cmd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, shell=True, check=False, text=True, capture_output=True)


def _require_audit_env() -> None:
    if os.getenv(AUDIT_ENV_FLAG) != "1":
        pytest.skip(f"Set {AUDIT_ENV_FLAG}=1 to run VPS audit checks.")


def _redact_env_lines(lines: list[str]) -> list[str]:
    redacted = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if match:
            redacted.append(f"{match.group(1)}=***REDACTED***")
    return redacted


def _assert_success(result: subprocess.CompletedProcess[str], context: str) -> None:
    if result.returncode != 0:
        details = f"{context} failed (rc={result.returncode}). stdout={result.stdout} stderr={result.stderr}"
        raise AssertionError(details)


def _curl(url: str, extra_args: str = "") -> subprocess.CompletedProcess[str]:
    cmd = f"curl -sS {extra_args} {url}"
    return _run(cmd)


def _parse_http_status(response: str) -> int:
    match = re.search(r"HTTP/\S+\s+(\d+)", response)
    if not match:
        raise AssertionError(f"Unable to parse HTTP status from response: {response}")
    return int(match.group(1))


def test_vps_audit_snapshot() -> None:
    _require_audit_env()

    repo_path = os.getenv("AUDIT_REPO_PATH", DEFAULT_REPO_PATH)
    env_path = os.getenv("AUDIT_ENV_PATH", DEFAULT_ENV_PATH)
    base_url = os.getenv("AUDIT_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    repo = Path(repo_path)
    if not repo.exists():
        raise AssertionError(f"Repo path not found: {repo_path}")

    git_status = _run(f"git -C {repo_path} status -sb")
    _assert_success(git_status, "git status")

    git_branch = _run(f"git -C {repo_path} rev-parse --abbrev-ref HEAD")
    _assert_success(git_branch, "git branch")

    git_log = _run(f"git -C {repo_path} log -n 20 --oneline")
    _assert_success(git_log, "git log")

    git_remote = _run(f"git -C {repo_path} remote -v")
    _assert_success(git_remote, "git remote")

    list_dir = _run(f"ls -la {repo_path}")
    _assert_success(list_dir, "repo listing")

    find_docs = _run(
        "find . -maxdepth 3 -iname 'SKILL.md' -o -iname '*.md' | sed -n '1,120p'",
    )
    _assert_success(find_docs, "docs inventory")

    systemctl_status = _run("systemctl status hodlxxi.service --no-pager")
    _assert_success(systemctl_status, "hodlxxi service status")

    journalctl = _run("sudo -n journalctl -u hodlxxi.service -n 200 --no-pager")
    _assert_success(journalctl, "hodlxxi journalctl")

    nginx_test = _run("nginx -t")
    _assert_success(nginx_test, "nginx -t")

    sockets = _run("ss -ltnp | sed -n '1,120p'")
    _assert_success(sockets, "ss -ltnp")

    status_resp = _curl(f"{base_url}/api/public/status")
    _assert_success(status_resp, "public status")

    oauth_docs = _curl(f"{base_url}/oauthx/docs")
    _assert_success(oauth_docs, "oauth docs")

    openid_cfg = _curl(f"{base_url}/.well-known/openid-configuration")
    _assert_success(openid_cfg, "openid configuration")
    openid_data = json.loads(openid_cfg.stdout)
    if "jwks_uri" not in openid_data:
        raise AssertionError("openid-configuration missing jwks_uri")

    jwks_resp = _curl(f"{base_url}/oauth/jwks.json")
    _assert_success(jwks_resp, "jwks")
    jwks_data = json.loads(jwks_resp.stdout)
    if not jwks_data.get("keys"):
        raise AssertionError("JWKS response missing keys")
    if not jwks_data["keys"][0].get("kid"):
        raise AssertionError("JWKS key missing kid")

    bearer_bad = _curl(f"{base_url}/api/demo/protected", "-i -H 'Authorization: Bearer BAD'")
    _assert_success(bearer_bad, "bearer bad request")
    bearer_bad_status = _parse_http_status(bearer_bad.stdout)
    if bearer_bad_status not in {401, 403}:
        raise AssertionError(f"Expected 401/403 for bad bearer token, got {bearer_bad_status}")

    no_auth = _curl(f"{base_url}/api/demo/protected", "-i")
    _assert_success(no_auth, "no auth request")
    no_auth_status = _parse_http_status(no_auth.stdout)
    if no_auth_status not in {401, 403}:
        raise AssertionError(f"Expected 401/403 for no token, got {no_auth_status}")

    env_file = Path(env_path)
    if not env_file.exists():
        raise AssertionError(f"Env file not found: {env_path}")
    env_lines = env_file.read_text(encoding="utf-8").splitlines()
    redacted = _redact_env_lines(env_lines)
    if not redacted:
        raise AssertionError("Env file contained no variables")

    systemd_cat = _run("systemctl cat hodlxxi.service | sed -n '1,220p'")
    _assert_success(systemd_cat, "systemd unit")
