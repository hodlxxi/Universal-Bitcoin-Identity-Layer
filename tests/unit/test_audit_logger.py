"""
Unit tests for audit logging.
"""

from unittest.mock import Mock, call, patch

import pytest

from app.audit_logger import AuditLogger, init_audit_logger


class TestAuditLogger:
    """Test audit logger functionality."""

    @pytest.fixture
    def audit_logger(self):
        """Create an AuditLogger instance for testing."""
        return AuditLogger()

    def test_log_auth_attempt_success(self, audit_logger):
        """Test logging successful authentication attempt."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_auth_attempt(
                user_id="test_user", method="lnurl-auth", success=True, ip_address="192.168.1.1"
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "AUTH_ATTEMPT" in call_args
            assert "user=test_user" in call_args
            assert "method=lnurl-auth" in call_args
            assert "status=SUCCESS" in call_args
            assert "ip=192.168.1.1" in call_args

    def test_log_auth_attempt_failure(self, audit_logger):
        """Test logging failed authentication attempt."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_auth_attempt(user_id="test_user", method="oauth2", success=False, ip_address="192.168.1.1")

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "status=FAILURE" in call_args

    def test_log_token_issued(self, audit_logger):
        """Test logging token issuance."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_token_issued(user_id="test_user", token_type="access_token", scope="openid profile")

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "TOKEN_ISSUED" in call_args
            assert "user=test_user" in call_args
            assert "type=access_token" in call_args
            assert "scope=openid profile" in call_args

    def test_log_token_refresh(self, audit_logger):
        """Test logging token refresh."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_token_refresh(user_id="test_user", success=True)

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "TOKEN_REFRESH" in call_args
            assert "status=SUCCESS" in call_args

    def test_log_api_access(self, audit_logger):
        """Test logging API access."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_api_access(user_id="test_user", endpoint="/api/challenge", method="POST", status_code=200)

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "API_ACCESS" in call_args
            assert "endpoint=/api/challenge" in call_args
            assert "method=POST" in call_args
            assert "status=200" in call_args

    def test_log_rpc_call_success(self, audit_logger):
        """Test logging successful Bitcoin RPC call."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_rpc_call(method="getblockchaininfo", success=True)

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "RPC_CALL" in call_args
            assert "method=getblockchaininfo" in call_args
            assert "status=SUCCESS" in call_args

    def test_log_rpc_call_failure(self, audit_logger):
        """Test logging failed Bitcoin RPC call."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_rpc_call(method="getwalletinfo", success=False, error="Connection refused")

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "status=FAILURE" in call_args
            assert "error=Connection refused" in call_args

    def test_log_security_event(self, audit_logger):
        """Test logging security event."""
        with patch.object(audit_logger.logger, "warning") as mock_warning:
            audit_logger.log_security_event(
                event_type="brute_force", severity="high", details={"ip": "192.168.1.1", "attempts": 10}
            )

            mock_warning.assert_called_once()
            call_args = mock_warning.call_args[0][0]
            assert "SECURITY_EVENT" in call_args
            assert "type=brute_force" in call_args
            assert "severity=high" in call_args

    def test_log_signature_verification(self, audit_logger):
        """Test logging signature verification."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            pubkey = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
            audit_logger.log_signature_verification(pubkey=pubkey, success=True, signature_type="ecdsa")

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "SIG_VERIFY" in call_args
            assert pubkey[:16] in call_args
            assert "type=ecdsa" in call_args
            assert "status=SUCCESS" in call_args

    def test_log_session_created(self, audit_logger):
        """Test logging session creation."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_session_created(session_id="sess_123456", user_id="test_user")

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "SESSION_CREATED" in call_args
            assert "session=sess_123" in call_args  # Truncated
            assert "user=test_user" in call_args

    def test_log_session_destroyed(self, audit_logger):
        """Test logging session destruction."""
        with patch.object(audit_logger.logger, "info") as mock_info:
            audit_logger.log_session_destroyed(session_id="sess_123456", reason="logout")

            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "SESSION_DESTROYED" in call_args
            assert "reason=logout" in call_args

    def test_log_rate_limit_exceeded(self, audit_logger):
        """Test logging rate limit violation."""
        with patch.object(audit_logger.logger, "warning") as mock_warning:
            audit_logger.log_rate_limit_exceeded(ip_address="192.168.1.1", endpoint="/api/challenge")

            mock_warning.assert_called_once()
            call_args = mock_warning.call_args[0][0]
            assert "RATE_LIMIT_EXCEEDED" in call_args
            assert "ip=192.168.1.1" in call_args
            assert "endpoint=/api/challenge" in call_args

    def test_log_error(self, audit_logger):
        """Test logging application error."""
        with patch.object(audit_logger.logger, "error") as mock_error:
            audit_logger.log_error(error_type="ValueError", error_msg="Invalid input", context={"field": "pubkey"})

            mock_error.assert_called_once()
            call_args = mock_error.call_args[0][0]
            assert "ERROR" in call_args
            assert "type=ValueError" in call_args
            assert "msg=Invalid input" in call_args
            assert "context=" in call_args


class TestInitAuditLogger:
    """Test audit logger initialization."""

    def test_init_audit_logger(self):
        """Test that audit logger initializes without errors."""
        init_audit_logger()
        # Should not raise any exceptions
