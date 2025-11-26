"""
Test Suite for Enhanced PoF System
Tests all Phase 1 functionality
"""

import pytest
import json
import secrets
import time
from unittest.mock import Mock, MagicMock, patch
from pof_enhanced import (
    PoFConfig, PoFDatabase, MembershipVerifier, PSBTVerifier,
    PoFService, PoFException, PoFError, PrivacyLevel
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_db(tmp_path):
    """Create temporary database for testing"""
    db_path = tmp_path / "test_pof.db"
    return PoFDatabase(str(db_path))


@pytest.fixture
def mock_rpc():
    """Mock Bitcoin RPC connection"""
    rpc = Mock()
    
    # Mock decodepsbt response
    rpc.decodepsbt.return_value = {
        "tx": {
            "vout": [
                {
                    "scriptPubKey": {
                        "asm": "OP_RETURN 484f444c5858492d506f463a",
                        "hex": "6a0d484f444c5858492d506f463a"
                    }
                }
            ],
            "vin": [
                {"txid": "abc123", "vout": 0},
                {"txid": "def456", "vout": 1}
            ]
        }
    }
    
    # Mock gettxout (unspent UTXO)
    rpc.gettxout.return_value = {
        "value": 0.01,  # 0.01 BTC = 1,000,000 sats
        "confirmations": 6
    }
    
    return rpc


@pytest.fixture
def mock_membership():
    """Mock membership verifier"""
    verifier = Mock(spec=MembershipVerifier)
    verifier.verify_membership.return_value = (True, "Member verified")
    verifier.get_covenant_settings.return_value = {
        "min_sat": 0,
        "max_ttl": 172800,
        "allowed_privacy_levels": ["aggregate", "threshold", "boolean"]
    }
    return verifier


@pytest.fixture
def psbt_verifier(mock_rpc):
    """Real PSBT verifier with mocked RPC"""
    return PSBTVerifier(lambda: mock_rpc)


@pytest.fixture
def pof_service(temp_db, mock_membership, psbt_verifier):
    """Complete PoF service for testing"""
    return PoFService(temp_db, mock_membership, psbt_verifier, socketio=None)


# ============================================================================
# DATABASE TESTS
# ============================================================================

class TestPoFDatabase:
    
    def test_database_initialization(self, temp_db):
        """Test database is properly initialized with all tables"""
        conn = temp_db._get_connection()
        
        # Check tables exist
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t[0] for t in tables]
        
        assert "pof_attestations" in table_names
        assert "pof_audit_log" in table_names
        assert "pof_challenges" in table_names
        
        # Check indexes exist
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
        index_names = [i[0] for i in indexes]
        
        assert any("idx_attest_expires" in i for i in index_names)
        assert any("idx_audit_timestamp" in i for i in index_names)
        
        conn.close()
    
    def test_store_and_retrieve_attestation(self, temp_db):
        """Test storing and retrieving attestations"""
        pubkey = "test_pubkey_123"
        covenant_id = "test_covenant"
        total_sat = 1000000
        
        # Store
        success = temp_db.store_attestation(
            pubkey, covenant_id, total_sat,
            "psbt", "aggregate", "proof_hash_123",
            int(time.time()) + 86400,
            metadata={"test": "data"}
        )
        assert success
        
        # Retrieve
        attestation = temp_db.get_attestation(pubkey, covenant_id)
        assert attestation is not None
        assert attestation["pubkey"] == pubkey
        assert attestation["total_sat"] == total_sat
        assert attestation["metadata"]["test"] == "data"
    
    def test_attestation_update(self, temp_db):
        """Test updating existing attestation"""
        pubkey = "test_pubkey_456"
        covenant_id = ""
        
        # Store initial
        temp_db.store_attestation(
            pubkey, covenant_id, 500000,
            "psbt", "aggregate", "hash1",
            int(time.time()) + 86400
        )
        
        # Update with new value
        temp_db.store_attestation(
            pubkey, covenant_id, 1000000,
            "psbt", "threshold", "hash2",
            int(time.time()) + 86400
        )
        
        # Verify updated
        attestation = temp_db.get_attestation(pubkey, covenant_id)
        assert attestation["total_sat"] == 1000000
        assert attestation["privacy_level"] == "threshold"
    
    def test_prune_expired_attestations(self, temp_db):
        """Test pruning of expired attestations"""
        now = int(time.time())
        
        # Store expired
        temp_db.store_attestation(
            "expired_pubkey", "", 1000,
            "psbt", "aggregate", "hash_expired",
            now - 3600  # Expired 1 hour ago
        )
        
        # Store valid
        temp_db.store_attestation(
            "valid_pubkey", "", 2000,
            "psbt", "aggregate", "hash_valid",
            now + 3600  # Expires in 1 hour
        )
        
        # Prune
        count = temp_db.prune_expired()
        assert count == 1
        
        # Verify expired is gone
        assert temp_db.get_attestation("expired_pubkey", "") is None
        assert temp_db.get_attestation("valid_pubkey", "") is not None
    
    def test_challenge_storage_and_retrieval(self, temp_db):
        """Test challenge tracking"""
        challenge_id = "test_challenge_123"
        pubkey = "test_pubkey"
        challenge = "HODLXXI-PoF:test:12345"
        expires_at = int(time.time()) + 900
        
        # Store
        success = temp_db.store_challenge(
            challenge_id, pubkey, "", challenge,
            expires_at, "127.0.0.1"
        )
        assert success
        
        # Retrieve
        data = temp_db.get_challenge(challenge_id)
        assert data is not None
        assert data["pubkey"] == pubkey
        assert data["challenge"] == challenge
        assert data["used"] == 0
        
        # Mark as used
        temp_db.mark_challenge_used(challenge_id)
        data = temp_db.get_challenge(challenge_id)
        assert data["used"] == 1
    
    def test_active_challenge_counting(self, temp_db):
        """Test counting active challenges per user"""
        pubkey = "test_pubkey"
        now = int(time.time())
        
        # Create 3 active challenges
        for i in range(3):
            temp_db.store_challenge(
                f"challenge_{i}", pubkey, "",
                f"challenge_text_{i}", now + 900
            )
        
        count = temp_db.count_active_challenges(pubkey)
        assert count == 3
        
        # Mark one as used
        temp_db.mark_challenge_used("challenge_0")
        count = temp_db.count_active_challenges(pubkey)
        assert count == 2
    
    def test_audit_logging(self, temp_db):
        """Test audit log functionality"""
        temp_db.log_audit(
            "test_pubkey",
            "challenge_create",
            True,
            covenant_id="test_covenant",
            challenge_id="test_123",
            ip_address="192.168.1.1",
            metadata={"extra": "info"}
        )
        
        # Query audit log
        conn = temp_db._get_connection()
        logs = conn.execute(
            "SELECT * FROM pof_audit_log WHERE pubkey=?",
            ("test_pubkey",)
        ).fetchall()
        
        assert len(logs) == 1
        log = dict(logs[0])
        assert log["action"] == "challenge_create"
        assert log["success"] == 1
        
        conn.close()


# ============================================================================
# PSBT VERIFIER TESTS
# ============================================================================

class TestPSBTVerifier:
    
    def test_decode_psbt_success(self, psbt_verifier, mock_rpc):
        """Test successful PSBT decoding"""
        psbt = "cHNidP8BAH..."  # Base64 encoded
        result = psbt_verifier.decode_psbt(psbt)
        
        assert "tx" in result
        assert mock_rpc.decodepsbt.called
    
    def test_decode_psbt_too_large(self, psbt_verifier):
        """Test PSBT size limit"""
        large_psbt = "x" * (PoFConfig.MAX_PSBT_B64 + 1)
        
        with pytest.raises(PoFException) as exc:
            psbt_verifier.decode_psbt(large_psbt)
        
        assert exc.value.error_code == PoFError.PSBT_TOO_LARGE
    
    def test_decode_psbt_invalid(self, psbt_verifier, mock_rpc):
        """Test invalid PSBT handling"""
        mock_rpc.decodepsbt.side_effect = Exception("Invalid PSBT")
        
        with pytest.raises(PoFException) as exc:
            psbt_verifier.decode_psbt("invalid_psbt")
        
        assert exc.value.error_code == PoFError.PSBT_DECODE_FAILED
    
    def test_extract_opreturn_asm_format(self, psbt_verifier):
        """Test OP_RETURN extraction from ASM format"""
        challenge = "HODLXXI-PoF:test:123"
        challenge_hex = challenge.encode().hex()
        
        vouts = [{
            "scriptPubKey": {
                "asm": f"OP_RETURN {challenge_hex}"
            }
        }]
        
        result = psbt_verifier.extract_opreturn_challenge(vouts)
        assert result == challenge
    
    def test_extract_opreturn_hex_format(self, psbt_verifier):
        """Test OP_RETURN extraction from hex format"""
        challenge = "HODLXXI-PoF:test:456"
        challenge_hex = challenge.encode().hex()
        
        vouts = [{
            "scriptPubKey": {
                "hex": f"6a{challenge_hex}",  # 0x6a = OP_RETURN
                "asm": ""
            }
        }]
        
        result = psbt_verifier.extract_opreturn_challenge(vouts)
        assert result == challenge
    
    def test_extract_opreturn_missing(self, psbt_verifier):
        """Test missing OP_RETURN"""
        vouts = [{
            "scriptPubKey": {
                "asm": "OP_DUP OP_HASH160 ...",
                "hex": "76a914..."
            }
        }]
        
        result = psbt_verifier.extract_opreturn_challenge(vouts)
        assert result is None
    
    def test_verify_unspent_inputs(self, psbt_verifier, mock_rpc):
        """Test UTXO verification"""
        vins = [
            {"txid": "abc123", "vout": 0},
            {"txid": "def456", "vout": 1}
        ]
        
        total_sat, details = psbt_verifier.verify_unspent_inputs(vins)
        
        # 2 inputs * 0.01 BTC = 2,000,000 sats
        assert total_sat == 2_000_000
        assert len(details) == 2
        assert details[0]["value_sat"] == 1_000_000
        assert details[0]["confirmations"] == 6
    
    def test_verify_unspent_inputs_none_found(self, psbt_verifier, mock_rpc):
        """Test no unspent inputs"""
        mock_rpc.gettxout.return_value = None  # All spent
        
        vins = [{"txid": "abc123", "vout": 0}]
        
        with pytest.raises(PoFException) as exc:
            psbt_verifier.verify_unspent_inputs(vins)
        
        assert exc.value.error_code == PoFError.NO_UNSPENT_INPUTS
    
    def test_verify_psbt_complete_flow(self, psbt_verifier, mock_rpc):
        """Test complete PSBT verification"""
        challenge = "HODLXXI-PoF:test:789"
        challenge_hex = challenge.encode().hex()
        
        # Setup mock response with proper OP_RETURN
        mock_rpc.decodepsbt.return_value = {
            "tx": {
                "vout": [{
                    "scriptPubKey": {
                        "asm": f"OP_RETURN {challenge_hex}",
                        "hex": f"6a{challenge_hex}"
                    }
                }],
                "vin": [{"txid": "abc123", "vout": 0}]
            }
        }
        
        total_sat, details = psbt_verifier.verify_psbt("test_psbt", challenge)
        
        assert total_sat == 1_000_000
        assert len(details) == 1


# ============================================================================
# POF SERVICE TESTS
# ============================================================================

class TestPoFService:
    
    @patch('pof_enhanced.session')
    def test_create_challenge_success(self, mock_session, pof_service):
        """Test successful challenge creation"""
        mock_session.get.return_value = "test_pubkey"
        
        result = pof_service.create_challenge(
            "test_pubkey",
            covenant_id=None,
            ip_address="127.0.0.1"
        )
        
        assert result["ok"] is True
        assert "challenge_id" in result
        assert "challenge" in result
        assert result["expires_in"] == PoFConfig.CHALLENGE_TTL
    
    @patch('pof_enhanced.session')
    def test_create_challenge_membership_denied(self, mock_session, pof_service, mock_membership):
        """Test challenge creation with membership denial"""
        mock_session.get.return_value = "test_pubkey"
        mock_membership.verify_membership.return_value = (False, "Not a member")
        
        with pytest.raises(PoFException) as exc:
            pof_service.create_challenge("test_pubkey")
        
        assert exc.value.error_code == PoFError.MEMBERSHIP_REQUIRED
    
    @patch('pof_enhanced.session')
    def test_create_challenge_rate_limit(self, mock_session, pof_service, temp_db):
        """Test rate limiting on challenge creation"""
        mock_session.get.return_value = "test_pubkey"
        
        # Create max challenges
        for i in range(PoFConfig.MAX_CHALLENGES_PER_USER):
            pof_service.create_challenge("test_pubkey")
        
        # Next one should fail
        with pytest.raises(PoFException) as exc:
            pof_service.create_challenge("test_pubkey")
        
        assert exc.value.error_code == PoFError.RATE_LIMIT_EXCEEDED
    
    @patch('pof_enhanced.session')
    def test_verify_psbt_complete_flow(self, mock_session, pof_service, mock_rpc):
        """Test complete PSBT verification flow"""
        mock_session.get.return_value = "test_pubkey"
        
        # Create challenge
        challenge_result = pof_service.create_challenge("test_pubkey")
        challenge_id = challenge_result["challenge_id"]
        challenge = challenge_result["challenge"]
        
        # Setup mock RPC for verification
        challenge_hex = challenge.encode().hex()
        mock_rpc.decodepsbt.return_value = {
            "tx": {
                "vout": [{
                    "scriptPubKey": {
                        "asm": f"OP_RETURN {challenge_hex}"
                    }
                }],
                "vin": [{"txid": "abc123", "vout": 0}]
            }
        }
        
        # Verify PSBT
        result = pof_service.verify_psbt(
            challenge_id,
            "test_psbt_base64",
            privacy_level="aggregate",
            min_sat=0
        )
        
        assert result["ok"] is True
        assert result["total_sat"] == 1_000_000
        assert result["privacy_level"] == "aggregate"
    
    def test_verify_psbt_invalid_challenge(self, pof_service):
        """Test verification with invalid challenge ID"""
        with pytest.raises(PoFException) as exc:
            pof_service.verify_psbt("nonexistent", "psbt", "aggregate")
        
        assert exc.value.error_code == PoFError.CHALLENGE_NOT_FOUND
    
    @patch('pof_enhanced.session')
    def test_verify_psbt_expired_challenge(self, mock_session, pof_service, temp_db):
        """Test verification with expired challenge"""
        mock_session.get.return_value = "test_pubkey"
        
        # Create expired challenge directly in DB
        challenge_id = "expired_123"
        temp_db.store_challenge(
            challenge_id, "test_pubkey", "",
            "challenge_text",
            int(time.time()) - 100  # Expired
        )
        
        with pytest.raises(PoFException) as exc:
            pof_service.verify_psbt(challenge_id, "psbt", "aggregate")
        
        assert exc.value.error_code == PoFError.CHALLENGE_EXPIRED
    
    @patch('pof_enhanced.session')
    def test_verify_psbt_privacy_levels(self, mock_session, pof_service, mock_rpc):
        """Test different privacy levels"""
        mock_session.get.return_value = "test_pubkey"
        
        for privacy_level in ["aggregate", "threshold", "boolean"]:
            # Create new challenge for each test
            challenge_result = pof_service.create_challenge("test_pubkey")
            challenge_id = challenge_result["challenge_id"]
            challenge = challenge_result["challenge"]
            
            # Setup mock
            challenge_hex = challenge.encode().hex()
            mock_rpc.decodepsbt.return_value = {
                "tx": {
                    "vout": [{
                        "scriptPubKey": {"asm": f"OP_RETURN {challenge_hex}"}
                    }],
                    "vin": [{"txid": "abc", "vout": 0}]
                }
            }
            
            result = pof_service.verify_psbt(
                challenge_id,
                "test_psbt",
                privacy_level=privacy_level,
                min_sat=500000
            )
            
            assert result["ok"] is True
            assert result["privacy_level"] == privacy_level
            
            # Check privacy-specific fields
            if privacy_level == "aggregate":
                assert "total_sat" in result
            elif privacy_level == "threshold":
                assert "meets_threshold" in result
            elif privacy_level == "boolean":
                assert "has_funds" in result
    
    def test_get_status_no_attestation(self, pof_service):
        """Test status check with no attestation"""
        result = pof_service.get_status("nonexistent_pubkey")
        
        assert result["ok"] is True
        assert result["status"] is None
    
    @patch('pof_enhanced.session')
    def test_get_status_with_attestation(self, mock_session, pof_service, temp_db):
        """Test status check with existing attestation"""
        mock_session.get.return_value = "test_pubkey"
        
        # Store attestation
        now = int(time.time())
        temp_db.store_attestation(
            "test_pubkey", "", 1500000,
            "psbt", "aggregate", "hash",
            now + 3600  # Expires in 1 hour
        )
        
        result = pof_service.get_status("test_pubkey")
        
        assert result["ok"] is True
        assert result["status"]["total_sat"] == 1500000
        assert result["status"]["is_valid"] is True
        assert result["status"]["time_remaining"] > 0


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    
    def test_pof_exception_structure(self):
        """Test PoFException structure"""
        exc = PoFException(
            PoFError.INVALID_PUBKEY,
            "Invalid pubkey provided",
            hint="Provide a valid Bitcoin public key",
            details={"received": "invalid"}
        )
        
        error_dict = exc.to_dict()
        
        assert error_dict["ok"] is False
        assert error_dict["error"] == "invalid_pubkey"
        assert error_dict["message"] == "Invalid pubkey provided"
        assert error_dict["hint"] == "Provide a valid Bitcoin public key"
        assert "docs" in error_dict
        assert "support" in error_dict
    
    def test_all_error_codes_defined(self):
        """Test all error codes are properly defined"""
        error_codes = [e.value for e in PoFError]
        
        assert "invalid_pubkey" in error_codes
        assert "membership_required" in error_codes
        assert "challenge_expired" in error_codes
        assert "psbt_too_large" in error_codes
        assert "no_unspent_inputs" in error_codes


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    
    @patch('pof_enhanced.session')
    def test_complete_pof_flow(self, mock_session, pof_service, mock_rpc):
        """Test complete end-to-end PoF flow"""
        mock_session.get.return_value = "integration_test_pubkey"
        pubkey = "integration_test_pubkey"
        
        # 1. Create challenge
        challenge_result = pof_service.create_challenge(pubkey)
        assert challenge_result["ok"] is True
        challenge_id = challenge_result["challenge_id"]
        challenge = challenge_result["challenge"]
        
        # 2. Setup PSBT verification
        challenge_hex = challenge.encode().hex()
        mock_rpc.decodepsbt.return_value = {
            "tx": {
                "vout": [{
                    "scriptPubKey": {"asm": f"OP_RETURN {challenge_hex}"}
                }],
                "vin": [
                    {"txid": "tx1", "vout": 0},
                    {"txid": "tx2", "vout": 1}
                ]
            }
        }
        
        # 3. Verify PSBT
        verify_result = pof_service.verify_psbt(
            challenge_id,
            "test_psbt_base64",
            privacy_level="aggregate"
        )
        assert verify_result["ok"] is True
        assert verify_result["total_sat"] == 2_000_000
        
        # 4. Check status
        status_result = pof_service.get_status(pubkey)
        assert status_result["ok"] is True
        assert status_result["status"]["total_sat"] == 2_000_000
        assert status_result["status"]["is_valid"] is True
        
        # 5. Verify audit trail
        conn = pof_service.db._get_connection()
        audit_count = conn.execute(
            "SELECT COUNT(*) FROM pof_audit_log WHERE pubkey=?",
            (pubkey,)
        ).fetchone()[0]
        assert audit_count >= 2  # At least challenge + verify
        conn.close()


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
