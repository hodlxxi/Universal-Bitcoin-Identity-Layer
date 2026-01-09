"""
Comprehensive Bitcoin Operation Tests

Tests Bitcoin Core RPC operations:
- Wallet descriptor management
- UTXO verification
- Proof of funds
- Script decoding
- Address derivation
- Balance queries
"""

import json
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

from app.factory import create_app
from app.utils import (
    extract_pubkey_from_op_else,
    extract_pubkey_from_op_if,
    extract_script_from_any_descriptor,
    is_valid_pubkey,
    validate_hex_format,
)


@pytest.fixture
def app():
    """Create test application."""
    test_config = {
        "FLASK_SECRET_KEY": "test_secret",
        "FLASK_ENV": "testing",
        "JWKS_DIR": "/tmp/test_jwks",
        "DATABASE_URL": "sqlite:///:memory:",
        "TESTING": True,
    }
    app = create_app(test_config)
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


import pytest
from unittest.mock import MagicMock

@pytest.fixture
def mock_rpc(monkeypatch, client):
    """Mock Bitcoin Core RPC and patch the symbols actually used by the bitcoin blueprint."""
    import app.utils as utils
    import app.blueprints.bitcoin as btc

    rpc = MagicMock(name='rpc_conn')
    # defaults (override per-test as needed)
    rpc.getblockchaininfo.return_value = {'chain':'main','blocks':800000,'headers':800000,'bestblockhash':'0'*64}
    rpc.getbalance.return_value = 0.0
    rpc.listdescriptors.return_value = {'descriptors': []}
    rpc.listwallets.return_value = []

    monkeypatch.setattr(utils, 'get_rpc_connection', lambda: rpc)
    monkeypatch.setattr(btc, 'get_rpc_connection', lambda: rpc, raising=False)
    return rpc

class TestRPCCommands:
    """Test safe RPC command execution."""

    def test_rpc_getblockchaininfo_success(self, client, mock_rpc):
        """Test successful blockchain info query."""
        mock_rpc.getblockchaininfo.return_value = {
            "chain": "main",
            "blocks": 800000,
            "headers": 800000,
            "bestblockhash": "0" * 64,
        }

        response = client.get("/api/rpc/getblockchaininfo")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "result" in data
        assert data["result"]["chain"] == "main"
        assert data["result"]["blocks"] == 800000

    def test_rpc_getbalance_success(self, client, mock_rpc):
        """Test wallet balance query."""
        mock_rpc.getbalance.return_value = 1.23456789

        response = client.get("/api/rpc/getbalance")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["result"] == 1.23456789

    def test_rpc_dangerous_command_blocked(self, client):
        """Test that dangerous commands are blocked."""
        dangerous_commands = [
            "sendtoaddress",
            "sendmany",
            "sendrawtransaction",
            "walletpassphrase",
            "dumpprivkey",
            "stop",
        ]

        for cmd in dangerous_commands:
            response = client.get(f"/api/rpc/{cmd}")
            assert response.status_code == 403
            data = json.loads(response.data)
            assert "not allowed" in data["error"]

    def test_rpc_connection_failure(self, client, mock_rpc):
        """Test handling of RPC connection failure."""
        mock_rpc.getblockchaininfo.side_effect = ConnectionError("Connection refused")

        response = client.get("/api/rpc/getblockchaininfo")

        assert response.status_code == 500
        data = json.loads(response.data)
        assert "error" in data

    def test_rpc_invalid_command(self, client):
        """Test handling of invalid RPC command."""
        response = client.get("/api/rpc/nonexistent_command")

        assert response.status_code == 403


class TestProofOfFunds:
    """Test proof of funds verification."""

    def test_proof_of_funds_valid_psbt(self, client, mock_rpc):
        """Test valid proof of funds with PSBT."""
        # Mock PSBT with OP_RETURN challenge
        mock_psbt = {
            "tx": {
                "vin": [{"txid": "a" * 64, "vout": 0}],
                "vout": [
                    {
                        "value": 0.0,
                        "scriptPubKey": {
                            "asm": "OP_RETURN test_challenge_12345"
                        },
                    }
                ],
            }
        }

        mock_rpc.decodepsbt.return_value = mock_psbt
        mock_rpc.gettxout.return_value = {
            "value": 1.5,
            "confirmations": 6,
        }

        response = client.post(
            "/api/verify",
            json={"psbt": "cHNidF8...", "challenge": "test_challenge_12345"},
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["verified"] is True
        assert Decimal(data["amount_btc"]) == Decimal("1.5")
        assert data["challenge_verified"] is True

    def test_proof_of_funds_missing_challenge(self, client, mock_rpc):
        """Test PSBT without OP_RETURN challenge."""
        mock_psbt = {
            "tx": {
                "vin": [{"txid": "a" * 64, "vout": 0}],
                "vout": [{"value": 0.01, "scriptPubKey": {"asm": "OP_DUP ..."}}],
            }
        }

        mock_rpc.decodepsbt.return_value = mock_psbt
        mock_rpc.gettxout.return_value = {"value": 1.0}

        response = client.post(
            "/api/verify",
            json={"psbt": "cHNidF8...", "challenge": "test_challenge"},
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["verified"] is False
        assert "challenge not found" in data["error"].lower()

    def test_proof_of_funds_spent_utxo(self, client, mock_rpc):
        """Test PSBT with already spent UTXO."""
        mock_psbt = {
            "tx": {
                "vin": [{"txid": "a" * 64, "vout": 0}],
                "vout": [
                    {"value": 0.0, "scriptPubKey": {"asm": "OP_RETURN challenge"}}
                ],
            }
        }

        mock_rpc.decodepsbt.return_value = mock_psbt
        mock_rpc.gettxout.return_value = None  # UTXO spent

        response = client.post(
            "/api/verify", json={"psbt": "cHNidF8...", "challenge": "challenge"}
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        # Amount should be 0 since UTXO is spent
        assert Decimal(data["amount_btc"]) == Decimal("0")

    def test_proof_of_funds_missing_parameters(self, client):
        """Test proof of funds with missing parameters."""
        response = client.post("/api/verify", json={"psbt": "cHNidF8..."})

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "challenge" in data["error"].lower()


class TestScriptDecoding:
    """Test Bitcoin script decoding."""

    def test_decode_raw_script_success(self, client, mock_rpc):
        """Test successful script decoding."""
        mock_decoded = {
            "asm": "OP_DUP OP_HASH160 abcd... OP_EQUALVERIFY OP_CHECKSIG",
            "type": "pubkeyhash",
            "p2sh": "2N...",
            "segwit": {"asm": "...", "address": "bc1..."},
        }

        mock_rpc.decodescript.return_value = mock_decoded

        response = client.post(
            "/api/decode_raw_script", json={"script": "76a914" + "ab" * 20 + "88ac"}
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["type"] == "pubkeyhash"
        assert "asm" in data

    def test_decode_raw_script_invalid_hex(self, client, mock_rpc):
        """Test script decoding with invalid hex."""
        mock_rpc.decodescript.side_effect = Exception("Invalid hex")

        response = client.post("/api/decode_raw_script", json={"script": "invalid"})

        assert response.status_code == 500

    def test_decode_raw_script_missing_parameter(self, client):
        """Test script decoding without script parameter."""
        response = client.post("/api/decode_raw_script", json={})

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "script" in data["error"].lower()


class TestDescriptorManagement:
    """Test wallet descriptor operations."""

    def test_list_descriptors_success(self, client, mock_rpc):
        """Test listing wallet descriptors."""
        mock_descriptors = {
            "descriptors": [
                {
                    "desc": "wpkh([fingerprint/84'/0'/0']xpub.../0/*)#checksum",
                    "active": True,
                    "range": [0, 1000],
                },
                {
                    "desc": "raw(51210" + "a" * 64 + "51ae)#checksum",
                    "active": True,
                },
            ]
        }

        mock_rpc.listdescriptors.return_value = mock_descriptors

        response = client.get("/api/descriptors")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data["descriptors"]) == 2

    def test_list_descriptors_production_filters_private(self, app, client, mock_rpc):
        """Test that private keys are filtered in production."""
        app.config["APP_CONFIG"]["FLASK_ENV"] = "production"

        mock_descriptors = {
            "descriptors": [
                {"desc": "wpkh([fingerprint]xprv...)#checksum", "active": True}
            ]
        }

        mock_rpc.listdescriptors.return_value = mock_descriptors

        response = client.get("/api/descriptors")

        assert response.status_code == 200
        data = json.loads(response.data)
        # Private key markers should be removed
        assert "xprv" not in str(data)

    def test_list_descriptors_rpc_failure(self, client, mock_rpc):
        """Test descriptor listing with RPC failure."""
        mock_rpc.listdescriptors.side_effect = Exception("RPC error")

        response = client.get("/api/descriptors")

        assert response.status_code == 500


class TestBitcoinUtilities:
    """Test Bitcoin utility functions."""

    def test_extract_script_from_descriptor(self):
        """Test extracting raw script from descriptor."""
        # Plain raw descriptor
        desc1 = "raw(51210aabbcc...51ae)"
        script1 = extract_script_from_any_descriptor(desc1)
        assert script1 == "51210aabbcc...51ae"

        # Wrapped descriptor
        desc2 = "wsh(raw(51210aabbcc...51ae))"
        script2 = extract_script_from_any_descriptor(desc2)
        assert script2 == "51210aabbcc...51ae"

        # No raw script
        desc3 = "wpkh(xpub.../0/*)"
        script3 = extract_script_from_any_descriptor(desc3)
        assert script3 is None

    def test_extract_pubkey_from_op_if(self):
        """Test extracting pubkey from OP_IF branch."""
        asm = f"OP_IF 02{'a'*64} OP_CHECKSIG OP_ELSE OP_RETURN OP_ENDIF"
        pubkey = extract_pubkey_from_op_if(asm)
        assert pubkey == "02" + "a" * 64

    def test_extract_pubkey_from_op_else(self):
        """Test extracting pubkey from OP_ELSE branch."""
        asm = f"OP_IF OP_RETURN OP_ELSE 03{'b'*64} OP_CHECKSIG OP_ENDIF"
        pubkey = extract_pubkey_from_op_else(asm)
        assert pubkey == "03" + "b" * 64

    def test_extract_pubkey_not_found(self):
        """Test pubkey extraction when not present."""
        asm = "OP_IF OP_RETURN OP_ELSE OP_TRUE OP_ENDIF"
        pubkey_if = extract_pubkey_from_op_if(asm)
        pubkey_else = extract_pubkey_from_op_else(asm)

        assert pubkey_if is None
        assert pubkey_else is None

    def test_is_valid_pubkey_hex_compressed(self):
        """Test compressed hex pubkey validation."""
        valid_pubkey = "02" + "a" * 64
        assert is_valid_pubkey(valid_pubkey) is True

    def test_is_valid_pubkey_hex_uncompressed(self):
        """Test uncompressed hex pubkey validation."""
        valid_pubkey = "04" + "a" * 128
        assert is_valid_pubkey(valid_pubkey) is True

    def test_is_valid_pubkey_npub(self):
        """Test npub format validation."""
        valid_npub = "npub1" + "a" * 60
        assert is_valid_pubkey(valid_npub) is True

    def test_is_valid_pubkey_invalid(self):
        """Test invalid pubkey formats."""
        invalid_pubkeys = [
            "",
            "short",
            "zz" * 33,  # Invalid hex
            "npub1abc",  # Too short npub
            "02" + "a" * 63,  # Wrong length
        ]

        for pubkey in invalid_pubkeys:
            assert is_valid_pubkey(pubkey) is False

    def test_validate_hex_format(self):
        """Test hex string validation."""
        assert validate_hex_format("abcd" * 16, 64) is True
        assert validate_hex_format("xyz", 64) is False
        assert validate_hex_format("ab", 4) is False  # Wrong length
        assert validate_hex_format("", 64) is False


class TestBitcoinIntegration:
    """Integration tests with multiple Bitcoin operations."""

    def test_wallet_workflow(self, client, mock_rpc):
        """Test complete wallet workflow."""
        # 1. Get blockchain info
        mock_rpc.getblockchaininfo.return_value = {"chain": "main", "blocks": 800000}
        response1 = client.get("/api/rpc/getblockchaininfo")
        assert response1.status_code == 200

        # 2. List descriptors
        mock_rpc.listdescriptors.return_value = {
            "descriptors": [{"desc": "wpkh(...)", "active": True}]
        }
        response2 = client.get("/api/descriptors")
        assert response2.status_code == 200

        # 3. Get balance
        mock_rpc.getbalance.return_value = 5.0
        response3 = client.get("/api/rpc/getbalance")
        assert response3.status_code == 200
        assert json.loads(response3.data)["result"] == 5.0

    def test_proof_of_funds_full_flow(self, client, mock_rpc):
        """Test full proof of funds verification flow."""
        challenge = "test_challenge_xyz"

        # Decode PSBT
        mock_rpc.decodepsbt.return_value = {
            "tx": {
                "vin": [{"txid": "a" * 64, "vout": 0}],
                "vout": [
                    {"value": 0.0, "scriptPubKey": {"asm": f"OP_RETURN {challenge}"}}
                ],
            }
        }

        # Verify UTXO
        mock_rpc.gettxout.return_value = {"value": 2.5, "confirmations": 10}

        # Submit proof
        response = client.post(
            "/api/verify", json={"psbt": "cHNidF8...", "challenge": challenge}
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["verified"] is True
        assert Decimal(data["amount_btc"]) >= Decimal("2.5")
