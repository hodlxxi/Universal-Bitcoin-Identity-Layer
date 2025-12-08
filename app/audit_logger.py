"""
Audit logging for HODLXXI.

This is a basic implementation that logs to Python's logging system.
For production, integrate with structured logging (JSON) and log aggregation systems.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

_logger = logging.getLogger("audit")
_audit_logger = None  # Will be initialized by init_audit_logger


def init_audit_logger():
    """Initialize the audit logger."""
    global _audit_logger

    _logger.setLevel(logging.INFO)

    # Add console handler if not already present
    if not _logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s - AUDIT - %(levelname)s - %(message)s"))
        _logger.addHandler(handler)

    _audit_logger = AuditLogger()

    _logger.info("Audit logger initialized (basic implementation)")
    _logger.warning("⚠️  Basic audit logging active. For production, use structured logging and SIEM integration.")


def get_audit_logger():
    """Get the audit logger instance."""
    global _audit_logger

    if _audit_logger is None:
        init_audit_logger()
    return _audit_logger


class AuditLogger:
    """
    Audit logging interface for security events.

    This basic implementation logs to Python's logging system.
    For production, extend this to support:
    - Structured JSON logs
    - Log streaming to SIEM
    - Tamper-evident log storage
    - Log retention policies
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or _logger

    def log_event(self, event: str, **details: Any) -> None:
        """Generic structured audit event."""

        payload = {"event": event, **details, "timestamp": datetime.utcnow().isoformat()}
        self.logger.info(json.dumps(payload))

    def log_auth_attempt(self, user_id: str, method: str, success: bool, ip_address: Optional[str] = None):
        """Log authentication attempt."""
        status = "SUCCESS" if success else "FAILURE"
        self.logger.info(f"AUTH_ATTEMPT | user={user_id} | method={method} | status={status} | ip={ip_address}")

    def log_token_issued(self, user_id: str, token_type: str, scope: Optional[str] = None):
        """Log token issuance."""
        self.logger.info(f"TOKEN_ISSUED | user={user_id} | type={token_type} | scope={scope}")

    def log_token_refresh(self, user_id: str, success: bool):
        """Log token refresh attempt."""
        status = "SUCCESS" if success else "FAILURE"
        self.logger.info(f"TOKEN_REFRESH | user={user_id} | status={status}")

    def log_api_access(self, user_id: str, endpoint: str, method: str, status_code: int):
        """Log API access."""
        self.logger.info(f"API_ACCESS | user={user_id} | endpoint={endpoint} | method={method} | status={status_code}")

    def log_rpc_call(self, method: str, success: bool, error: Optional[str] = None):
        """Log Bitcoin RPC call."""
        status = "SUCCESS" if success else "FAILURE"
        msg = f"RPC_CALL | method={method} | status={status}"
        if error:
            msg += f" | error={error}"
        self.logger.info(msg)

    def log_security_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Log security event."""
        self.logger.warning(f"SECURITY_EVENT | type={event_type} | severity={severity} | details={details}")

    def log_signature_verification(self, pubkey: str, success: bool, signature_type: str):
        """Log cryptographic signature verification."""
        status = "SUCCESS" if success else "FAILURE"
        self.logger.info(f"SIG_VERIFY | pubkey={pubkey[:16]}... | type={signature_type} | status={status}")

    def log_session_created(self, session_id: str, user_id: str):
        """Log session creation."""
        self.logger.info(f"SESSION_CREATED | session={session_id[:8]}... | user={user_id}")

    def log_session_destroyed(self, session_id: str, reason: str = "logout"):
        """Log session destruction."""
        self.logger.info(f"SESSION_DESTROYED | session={session_id[:8]}... | reason={reason}")

    def log_rate_limit_exceeded(self, ip_address: str, endpoint: str):
        """Log rate limit violation."""
        self.logger.warning(f"RATE_LIMIT_EXCEEDED | ip={ip_address} | endpoint={endpoint}")

    def log_error(self, error_type: str, error_msg: str, context: Optional[Dict[str, Any]] = None):
        """Log application error."""
        msg = f"ERROR | type={error_type} | msg={error_msg}"
        if context:
            msg += f" | context={context}"
        self.logger.error(msg)
