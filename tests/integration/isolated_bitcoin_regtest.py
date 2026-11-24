"""Explicitly opted-in disposable Core; never connect to an existing wallet/node."""

import hmac
import os
import secrets
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import pytest
from bitcoinrpc.authproxy import AuthServiceProxy


@dataclass
class Regtest:
    endpoint: str = field(repr=False)
    user: str
    password: str = field(repr=False)
    port: int
    directory: str

    def rpc(self, wallet=None):
        suffix = "/wallet/" + quote(wallet, safe="") if wallet is not None else "/"
        return AuthServiceProxy(self.endpoint + suffix, timeout=90)


@pytest.fixture(scope="module")
def regtest():
    binary = os.environ.get("CANON_V2_REGTEST_BINARY")
    if os.environ.get("CANON_V2_REGTEST_ACK") != "1" or not binary:
        pytest.skip("explicit isolated regtest executable/acknowledgement required")
    executable = Path(binary).resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError("regtest_executable_unavailable")
    # Fixed dedicated port; refuse accidental use of a standard serving port.
    port = 18588
    with tempfile.TemporaryDirectory(prefix="hodlxxi-588-regtest-") as directory:
        root = Path(directory)
        user, password = "isolated-regtest", secrets.token_hex(32)
        salt = secrets.token_hex(16)
        password_hmac = hmac.new(
            salt.encode("utf-8"),
            password.encode("utf-8"),
            digestmod="sha256",
        ).hexdigest()
        config = root / "bitcoin.conf"
        config.write_text(
            "regtest=1\nserver=1\nlisten=0\ndnsseed=0\ndiscover=0\n"
            "fallbackfee=0.00001000\nprinttoconsole=0\ndbcache=32\nmaxmempool=20\npar=1\nrpcthreads=2\n"
            f"rpcauth={user}:{salt}${password_hmac}\n[regtest]\nconnect=0\nrpcbind=127.0.0.1\n"
            f"rpcallowip=127.0.0.1\nrpcport={port}\n"
        )
        config.chmod(0o600)
        diagnostic = open(root / "startup.log", "wb")
        process = subprocess.Popen(
            [str(executable), "-datadir=" + directory, "-conf=" + str(config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=diagnostic,
        )
        node = Regtest(f"http://{user}:{password}@127.0.0.1:{port}", user, password, port, directory)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    diagnostic.flush()
                    message = (root / "startup.log").read_text(errors="replace").replace(password, "[redacted]")[-1024:]
                    raise RuntimeError("isolated_regtest_start_failed: " + message)
                try:
                    if node.rpc().getblockchaininfo()["chain"] == "regtest":
                        break
                except Exception:
                    time.sleep(0.1)
            else:
                raise RuntimeError("isolated_regtest_start_timeout")
            # Every mutating RPC below is confined to this new process/datadir.
            node.rpc().createwallet("fixture-funding")
            node.rpc().createwallet("fixture-watch", True, True, "", False, True, False)
            mining = node.rpc("fixture-funding").getnewaddress()
            node.rpc().generatetoaddress(101, mining)
            yield node
        finally:
            diagnostic.close()
            if process.poll() is None:
                try:
                    node.rpc().stop()
                except Exception:
                    process.terminate()
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.fixture
def regtest_environment(regtest, monkeypatch):
    for key, value in {
        "RPC_HOST": "127.0.0.1",
        "RPC_PORT": str(regtest.port),
        "RPC_USER": regtest.user,
        "RPC_PASSWORD": regtest.password,
        "RPC_WALLET": "fixture-watch",
        "CANON_V2_BITCOIN_CHAIN": "regtest",
        "AUTO_SPONSORED_IMPORT_ENABLED": "true",
        "AUTO_SPONSORED_ADMISSION_ENABLED": "true",
        "AUTO_SPONSORED_IMPORT_WATCH_WALLET": "fixture-watch",
    }.items():
        monkeypatch.setenv(key, value)
    return regtest
