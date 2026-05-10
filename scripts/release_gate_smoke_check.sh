#!/usr/bin/env bash
# Local/CI helper: validates factory runtime route contract only.
# Does not call staging/production endpoints.

set -euo pipefail

python -m pytest -q tests/unit/test_release_gate_route_contract.py
