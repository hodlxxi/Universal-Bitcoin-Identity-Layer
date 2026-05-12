#!/usr/bin/env bash
set -euo pipefail

# Local-only protocol/docs contract checks. Intentionally no production URLs.
pytest -q tests/unit/test_agent_protocol_docs_contract.py
pytest -q tests/integration/test_agent_surface_machine_readable_contract.py
