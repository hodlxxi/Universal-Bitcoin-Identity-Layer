#!/usr/bin/env python3
"""Generate an auditable Flask route inventory and flag duplicate path+method ownership."""

from collections import defaultdict
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.factory import create_app

app = create_app()

PUBLIC_WRITE_PATHS = {
    "/agent/request",
    "/agent/message",
    "/api/challenge",
    "/api/verify",
    "/guest_login",
}


def auth_policy(rule, methods):
    path = rule.rule
    if "GET" in methods and methods <= {"GET", "HEAD", "OPTIONS"}:
        return "read/public_or_guarded"
    if path in PUBLIC_WRITE_PATHS or path.startswith("/api/lnurl-auth/"):
        return "public_write_limited"
    return "session_or_token_required"


def main():
    rows = []
    by_method_path = defaultdict(list)

    for rule in app.url_map.iter_rules():
        methods = sorted(m for m in rule.methods if m not in {"HEAD", "OPTIONS"})
        if not methods:
            continue
        endpoint = rule.endpoint
        blueprint = endpoint.split(".", 1)[0] if "." in endpoint else "app"
        row = {
            "methods": methods,
            "path": rule.rule,
            "endpoint": endpoint,
            "blueprint": blueprint,
            "auth_policy": auth_policy(rule, set(methods)),
        }
        rows.append(row)
        for m in methods:
            by_method_path[(m, rule.rule)].append(endpoint)

    duplicates = {f"{m} {p}": owners for (m, p), owners in sorted(by_method_path.items()) if len(owners) > 1}

    out = {
        "route_count": len(rows),
        "routes": sorted(rows, key=lambda r: (r["path"], ",".join(r["methods"]))),
        "duplicates": duplicates,
    }
    print(json.dumps(out, indent=2, sort_keys=False))


if __name__ == "__main__":
    main()
