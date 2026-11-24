#!/usr/bin/env python3
"""Read-only isolated paired-preview source/runtime audit.

This audit never deploys, restarts, migrates, signs, imports descriptors,
reads private credentials, or contacts production. It intentionally FAILS
when the candidate checkout does not match the nominated PR HEADs.
"""

import argparse
from pathlib import Path
import re
import subprocess
import sys

SHA = re.compile(r"[a-f0-9]{40}\Z")
DEFAULT_ROOT = "/srv/hxxi-paired-app-3c2b954"
DB_UNIT = "hxxi-paired-827e753-db.service"
UNITS = (
    DB_UNIT,
    "hxxi-paired-3c2b954-ubid-r6.service",
    "hxxi-paired-browser-social-r2.service",
    "hxxi-paired-browser-proxy.service",
    "hxxi-paired-private-transport-r5.service",
    "hxxi-paired-rpc-read-r5.service",
    "hxxi-paired-root-publisher.timer",
)
PROBES = (
    ("UBID_STATUS", "ubid", "https://ubid-preview.hodlxxi.test:9543/api/public/status"),
    ("SOCIAL_MESSAGE_CONFIG", "social", "https://social-preview.hodlxxi.test:9544/auth/messages/config"),
)


def run(args, *, timeout=12):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    return (result.returncode, result.stdout.strip())


def sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def check_source(path, expected):
    if not sha(expected) or not path.is_dir():
        return "FAIL"
    status, found = run(["git", "-C", str(path), "rev-parse", "HEAD"])
    if status != 0 or not sha(found) or found != expected:
        return "FAIL"
    status, dirty = run(["git", "-C", str(path), "status", "--porcelain", "--untracked-files=no"])
    return "PASS" if status == 0 and dirty == "" else "FAIL"


def check_unit(unit):
    status, active = run(["systemctl", "show", unit, "-p", "ActiveState", "--value"])
    return "PASS" if status == 0 and active == "active" else "FAIL"


def check_probe(root, name, origin):
    if name not in ("ubid", "social"):
        return "FAIL"
    cert = root / "browser-proxy" / "ca.crt"
    if not cert.is_file():
        return "FAIL"
    cmd = [
        "curl", "--silent", "--show-error", "--fail", "--location-trusted",
        "--max-time", "5", "--noproxy", "*",
        "--cacert", str(cert),
        "--unix-socket", "/run/hxxi-paired-browser/" + name + ".sock",
        "--output", "/dev/null", "--write-out", "%{http_code}", origin,
    ]
    # Only the status code is surfaced, never a body, URL parameters, or token.
    status, output = run(cmd)
    return "PASS" if status == 0 and output == "200" else "FAIL"


def check_database():
    code, pid = run(["systemctl", "show", DB_UNIT, "-p", "MainPID", "--value"])
    if code != 0 or not pid.isdecimal() or int(pid) <= 1:
        return "FAIL"
    sql = (
        "BEGIN READ ONLY; "
        "SELECT current_database() = 'hodlxxi_browser_preview' "
        "AND current_setting('port') = '55492' "
        "AND current_setting('data_directory') = "
        "'/var/lib/postgresql/16/hxxi-paired-827e753/data'; "
        "ROLLBACK;"
    )
    code, output = run([
        "nsenter", "-t", pid, "-n", "--", "runuser", "-u", "postgres", "--",
        "/usr/lib/postgresql/16/bin/psql", "-X", "-w", "-A", "-t",
        "-v", "ON_ERROR_STOP=1",
        "-h", "/var/lib/postgresql/16/hxxi-paired-827e753",
        "-p", "55492", "-U", "postgres", "-d", "hodlxxi_browser_preview",
        "-c", sql,
    ])
    return "PASS" if code == 0 and output.splitlines().count("t") == 1 else "FAIL"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=DEFAULT_ROOT)
    parser.add_argument("--ubid-head", required=True, help="exact 40-hex PR HEAD")
    parser.add_argument("--social-head", required=True, help="exact 40-hex PR HEAD")
    args = parser.parse_args(argv)
    if not sha(args.ubid_head) or not sha(args.social_head):
        parser.error("both SHA arguments must be full lowercase 40-hex commits")
    root = Path(args.root)
    if not root.is_absolute() or not str(root).startswith("/srv/"):
        parser.error("root must be an absolute preview checkout under /srv")
    results = [
        ("UBID_HEAD_MATCH", check_source(root, args.ubid_head)),
        ("SOCIAL_HEAD_MATCH", check_source(root / "social", args.social_head)),
        ("ISOLATED_PG16_IDENTITY", check_database()),
    ]
    results.extend(("UNIT_" + unit.replace(".", "_").replace("-", "_").upper(), check_unit(unit)) for unit in UNITS)
    results.extend((name, check_probe(root, socket, url)) for name, socket, url in PROBES)
    for name, result in results:
        print(name + "=" + result)
    status = "PASS" if all(result == "PASS" for _, result in results) else "FAIL"
    print("SOURCE_RUNTIME_AUDIT=" + status)
    print("CREDENTIALS_PRINTED=NO")
    print("PRODUCTION_COMMANDS_EXECUTED=NO")
    print("WRITES_EXECUTED=NO")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
