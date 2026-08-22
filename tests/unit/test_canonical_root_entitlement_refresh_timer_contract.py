from configparser import ConfigParser
import json
from pathlib import Path
import re
import shlex


ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "deployment" / "systemd"
DOC = ROOT / "docs" / "CANONICAL_ROOT_ENTITLEMENT_REFRESH_TIMER_V1.md"
MANIFEST = ROOT / "docs" / "data" / "e923_canonical_crt_runtime_bootstrap_v1.json"

PRODUCTION = {
    "stem": "hodlxxi-canonical-root-entitlement-refresh",
    "user": "hodlxxi",
    "group": "hodlxxi",
    "working_directory": "/srv/ubid",
    "environment_file": "/etc/hodlxxi/hodlxxi.env",
    "python": "/srv/ubid/venv/bin/python",
    "script": "/srv/ubid/scripts/canonical_root_entitlement_refresh.py",
    "runtime_directory": "hodlxxi-canonical-root-locks",
}
STAGING = {
    "stem": "ubid-staging-canonical-root-entitlement-refresh",
    "user": "hodlxxi_staging",
    "group": "hodlxxi_staging",
    "working_directory": "/srv/ubid-staging",
    "environment_file": "/etc/hodlxxi-staging/ubid-staging.env",
    "python": "/srv/ubid-staging/venv-staging/bin/python",
    "script": "/srv/ubid-staging/scripts/canonical_root_entitlement_refresh.py",
    "runtime_directory": "ubid-staging-canonical-root-locks",
}

HARDENING = {
    "nonewprivileges": "yes",
    "privatetmp": "yes",
    "privatedevices": "yes",
    "devicepolicy": "closed",
    "protectsystem": "strict",
    "protecthome": "read-only",
    "protectkerneltunables": "yes",
    "protectkernelmodules": "yes",
    "protectkernellogs": "yes",
    "protectcontrolgroups": "yes",
    "restrictnamespaces": "yes",
    "restrictrealtime": "yes",
    "restrictsuidsgid": "yes",
    "lockpersonality": "yes",
    "memorydenywriteexecute": "yes",
    "removeipc": "yes",
    "keyringmode": "private",
    "systemcallarchitectures": "native",
    "capabilityboundingset": "",
    "ambientcapabilities": "",
    "restrictaddressfamilies": "AF_UNIX AF_INET AF_INET6",
    "socketbinddeny": "any",
}


def parse_unit(path):
    parser = ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str.lower
    with path.open(encoding="utf-8") as source:
        parser.read_file(source)
    return parser


def unit_texts():
    paths = [
        SYSTEMD / f"{environment['stem']}.{suffix}"
        for environment in (PRODUCTION, STAGING)
        for suffix in ("service", "timer")
    ]
    return {path: path.read_text(encoding="utf-8") for path in paths}


def test_services_bind_manifest_and_exact_isolated_runtime_contracts():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    graph = manifest["graph_or_protocol_id"]
    subject = manifest["subject_xonly_pubkey"]

    for environment, other in ((PRODUCTION, STAGING), (STAGING, PRODUCTION)):
        path = SYSTEMD / f"{environment['stem']}.service"
        unit = parse_unit(path)
        service = unit["Service"]
        assert "Install" not in unit
        assert service["type"] == "oneshot"
        assert "restart" not in service
        assert service["user"] == environment["user"]
        assert service["group"] == environment["group"]
        assert service["workingdirectory"] == environment["working_directory"]
        assert service["environmentfile"] == environment["environment_file"]
        assert service["environment"] == "PYTHONDONTWRITEBYTECODE=1"
        assert service["umask"] == "0077"
        assert service["timeoutstartsec"].endswith("s")
        assert 0 < int(service["timeoutstartsec"][:-1]) <= 300
        assert service["standardoutput"] == service["standarderror"] == "journal"

        lock_directory = f"/run/{environment['runtime_directory']}"
        assert shlex.split(service["execstart"]) == [
            environment["python"],
            environment["script"],
            "--graph",
            graph,
            "--subject",
            subject,
            "--commit",
            "--lock-directory",
            lock_directory,
        ]
        assert service["runtimeDirectory".lower()] == environment["runtime_directory"]
        assert service["runtimedirectorymode"] == "0700"
        assert service["runtimedirectorypreserve"] == "yes"
        assert service["readwritepaths"] == lock_directory
        assert all(service[key] == value for key, value in HARDENING.items())

        text = path.read_text(encoding="utf-8")
        assert "/bin/sh" not in text and "/bin/bash" not in text
        assert f"User={other['user']}\n" not in text
        assert f"Group={other['group']}\n" not in text
        assert f"WorkingDirectory={other['working_directory']}\n" not in text
        assert f"EnvironmentFile={other['environment_file']}\n" not in text
        assert other["python"] not in text
        assert other["script"] not in text
        assert f"/run/{other['runtime_directory']}" not in text


def test_timers_pair_exactly_and_are_source_only_install_contracts():
    for environment in (PRODUCTION, STAGING):
        unit = parse_unit(SYSTEMD / f"{environment['stem']}.timer")
        assert dict(unit["Timer"]) == {
            "unit": f"{environment['stem']}.service",
            "onbootsec": "30s",
            "onunitinactivesec": "120s",
            "accuracysec": "5s",
            "randomizeddelaysec": "5s",
        }
        assert dict(unit["Install"]) == {"wantedby": "timers.target"}


def test_runtime_assets_embed_no_secrets_activation_or_fallback_authority():
    texts = unit_texts()
    runtime_assets = [*texts.values(), DOC.read_text(encoding="utf-8")]
    combined = "\n".join(runtime_assets)
    all_assets = runtime_assets + [Path(__file__).read_text(encoding="utf-8")]
    fallback_markers = (
        "identity_class=full",
        "identity_class=limited",
        "manual full",
        "manual limited",
        "--dry-run",
    )
    assert all(value not in combined.lower() for value in fallback_markers)

    activation_command = re.compile(
        r"(?im)^\s*(?:systemctl\s+(?:enable|disable|start|stop|restart|reload|daemon-reload)|"
        r"service\s+\S+\s+(?:start|stop|restart|reload))\b"
    )
    secret_assignment = re.compile(
        r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*[^\s\"']+"
    )
    credential_url = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@", re.IGNORECASE)
    pem_private_key = "-----BEGIN " + "PRIVATE KEY-----"
    for text in all_assets:
        assert activation_command.search(text) is None
        assert secret_assignment.search(text) is None
        assert credential_url.search(text) is None
        assert pem_private_key not in text

    assert combined.count("--graph hodlxxi.crt_membership_graph.v1") == 2
    assert combined.count("--subject 3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923") == 2


def test_documentation_covers_operations_growth_and_non_claims():
    text = DOC.read_text(encoding="utf-8").lower()
    required = (
        "300-second ttl",
        "120-second post-completion cadence",
        "fails closed",
        "manual oneshot",
        "at least three successful staging cycles",
        "full and limited social projections",
        "disable the production timer first",
        "then disable the staging timer",
        "about 720 successful refreshes per day",
        "no retention-policy change",
        "no social, oauth, database-schema, policy, bootstrap, or",
        "application change",
        "do not install, enable, start, reload",
    )
    assert all(fragment in text for fragment in required)
    assert text.index("manual oneshot") < text.index("enable only the staging timer")
    assert text.index("enable only the staging timer") < text.index("three successful staging cycles")
    assert text.index("three successful staging cycles") < text.index("production service as a manual oneshot")
