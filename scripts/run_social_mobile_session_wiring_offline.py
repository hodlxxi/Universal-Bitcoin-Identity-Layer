"""Run only wiring/schema unit tests, without the shared infrastructure conftest."""

import os
import socket
import sqlite3
import sys
from pathlib import Path

os.environ.clear()
os.environ.update(PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", FLASK_ENV="testing")
sys.dont_write_bytecode = True
root = Path(__file__).resolve().parents[1]
os.chdir(root)
sys.path.insert(0, str(root))


def denied(*args, **kwargs):
    raise AssertionError("offline wiring tests forbid network and database access")


socket.socket.connect = denied
socket.socket.connect_ex = denied
socket.create_connection = denied
socket.getaddrinfo = denied
sqlite3.connect = denied

import pytest  # noqa: E402
import sqlalchemy  # noqa: E402

sqlalchemy.create_engine = denied

raise SystemExit(
    pytest.main(
        [
            "--noconftest",
            "-p",
            "no:cacheprovider",
            "-q",
            "tests/unit/test_social_mobile_session_runtime.py",
            "tests/unit/test_social_session_issuance.py",
            "tests/unit/test_tokens_key_object.py",
            "tests/unit/test_oauth_session_lifecycle.py::test_disabled_by_default",
            "tests/unit/test_oauth_session_lifecycle.py::test_invalid_extension",
            "tests/unit/test_oauth_session_lifecycle.py::test_client_is_explicit_and_bounded",
            "tests/unit/test_oauth_session_lifecycle.py::test_clock_does_not_assume_timezone",
            "tests/unit/test_oauth_session_lifecycle.py::test_browser_identity_fields_are_not_resolver_parameters",
        ]
    )
)
