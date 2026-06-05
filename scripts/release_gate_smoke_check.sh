#!/usr/bin/env bash
# Local/CI helper: validates factory runtime route contract and local NIP-59
# browser-client safety gates.
# Does not call staging/production endpoints.

set -euo pipefail

python scripts/verify_nip59_release_gate.py
python -m pytest -q tests/unit/test_release_gate_route_contract.py
