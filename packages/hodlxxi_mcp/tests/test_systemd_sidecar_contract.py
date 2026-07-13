from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
UNIT_PATH = REPOSITORY_ROOT / "deployment" / "systemd" / "hodlxxi-mcp.service"
RUNBOOK_PATH = REPOSITORY_ROOT / "docs" / "ops" / "MCP_SYSTEMD_SIDECAR.md"


def unit_text() -> str:
    return UNIT_PATH.read_text(encoding="utf-8")


def test_unit_uses_separate_dynamic_identity() -> None:
    text = unit_text()

    assert "DynamicUser=yes" in text
    assert "User=hodlxxi-mcp" in text
    assert "Group=hodlxxi-mcp" in text
    assert "User=hodlxxi\n" not in text
    assert "User=root" not in text
    assert "EnvironmentFile=" not in text


def test_unit_uses_fixed_release_entrypoint() -> None:
    text = unit_text()

    assert "WorkingDirectory=/opt/hodlxxi-mcp/current" in text
    assert "ExecStart=/opt/hodlxxi-mcp/current/venv/bin/hodlxxi-mcp-http" in text
    assert "/srv/ubid/venv" not in text
    assert "/srv/ubid-staging/venv" not in text


def test_unit_enforces_local_bind_contract() -> None:
    text = unit_text()

    assert "SocketBindDeny=any" in text
    assert "SocketBindAllow=tcp:8765" in text
    assert "0.0.0.0" not in text
    assert "[::]" not in text


def test_unit_contains_required_hardening() -> None:
    text = unit_text()

    required = {
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "DevicePolicy=closed",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "ProtectHostname=yes",
        "ProtectClock=yes",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "RestrictNamespaces=yes",
        "RestrictRealtime=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "MemoryDenyWriteExecute=yes",
        "RemoveIPC=yes",
        "KeyringMode=private",
        "SystemCallArchitectures=native",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "UMask=0077",
    }

    for directive in required:
        assert directive in text


def test_sensitive_runtime_paths_are_inaccessible() -> None:
    text = unit_text()

    for path in (
        "/srv/ubid",
        "/srv/ubid-staging",
        "/etc/hodlxxi",
        "/var/lib/lnd",
        "/home/lnd",
    ):
        assert f"InaccessiblePaths=-{path}" in text

    assert "ReadWritePaths=" not in text


def test_resource_and_restart_policy_is_bounded() -> None:
    text = unit_text()

    for directive in (
        "Restart=on-failure",
        "RestartSec=5s",
        "TimeoutStartSec=30s",
        "TimeoutStopSec=10s",
        "LimitNOFILE=4096",
        "TasksMax=128",
        "MemoryMax=512M",
        "OOMPolicy=stop",
    ):
        assert directive in text


def test_runbook_preserves_deployment_boundary() -> None:
    text = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert "deployment artifacts only" in text
    assert "separate operator approval" in text
    assert "http://127.0.0.1:8765/mcp" in text
    assert "No nginx route should exist at this stage." in text
    assert "tools/list = 26" in text
