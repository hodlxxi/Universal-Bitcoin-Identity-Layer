"""
Minimal stub for AuthServiceProxy to allow imports without python-bitcoinrpc.
This is a temporary workaround for testing without Bitcoin Core RPC.
"""

import json
from typing import Any, Optional


class JSONRPCException(Exception):
    """RPC Exception stub."""
    def __init__(self, error):
        self.error = error
        super().__init__(str(error))


class AuthServiceProxy:
    """
    Minimal stub for Bitcoin Core RPC connection.

    This stub allows the app to import without python-bitcoinrpc installed.
    In production, replace this with the actual python-bitcoinrpc package.
    """

    def __init__(self, service_url: str, timeout: int = 60):
        """
        Initialize RPC connection stub.

        Args:
            service_url: Bitcoin RPC service URL
            timeout: Connection timeout in seconds
        """
        self.service_url = service_url
        self.timeout = timeout
        self._url = service_url

    def __getattr__(self, name: str):
        """
        Return a callable for any RPC method.

        This stub implementation raises NotImplementedError.
        """
        def method_stub(*args, **kwargs):
            raise NotImplementedError(
                f"Bitcoin RPC method '{name}' not available in stub mode. "
                "Install python-bitcoinrpc or configure mocking for tests."
            )
        return method_stub

    def __call__(self, *args, **kwargs):
        """Make the proxy callable."""
        raise NotImplementedError(
            "Bitcoin RPC not available in stub mode. "
            "Install python-bitcoinrpc or configure mocking for tests."
        )
