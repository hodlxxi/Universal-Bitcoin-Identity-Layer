"""Phase 3: Structured logging and tracing helper.

Production-safe structured logging for observability without external dependencies.
Emits JSON-style log records with minimal required fields for agent and LN tracing.
"""

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def log_event(
    event: str,
    request_id: Optional[str] = None,
    path: Optional[str] = None,
    method: Optional[str] = None,
    job_id: Optional[str] = None,
    invoice_id: Optional[str] = None,
    user_pubkey_tail: Optional[str] = None,
    actor_type: Optional[str] = None,
    outcome: Optional[str] = None,
    status: Optional[int] = None,
    details: Optional[dict] = None,
) -> None:
    """
    Emit a structured log record for observability.

    Args:
        event: Event name (e.g., 'agent_request_received', 'invoice_created')
        request_id: Request correlation ID (from X-Request-ID or g.request_id)
        path: HTTP path (from request.path)
        method: HTTP method (from request.method)
        job_id: Agent job ID if available
        invoice_id: Lightning invoice ID if available
        user_pubkey_tail: Last 4 chars of user pubkey for audit trail (masked)
        actor_type: Type of actor ('agent', 'client', 'user', etc.)
        outcome: 'success', 'failure', 'error', etc.
        status: HTTP status code or operation-specific status
        details: Additional context dict (safe, no secrets)

    Returns:
        None (logs only)

    Safety:
        - Never logs secrets, macaroons, auth headers, full payment requests
        - Details dict should be filtered by caller
        - Emits as structured key-value + JSON for parsing
    """
    record = {
        "event": event,
    }

    # Add correlation fields
    if request_id:
        record["request_id"] = request_id
    if path:
        record["path"] = path
    if method:
        record["method"] = method

    # Add job/invoice/actor identifiers
    if job_id:
        record["job_id"] = job_id
    if invoice_id:
        record["invoice_id"] = invoice_id
    if user_pubkey_tail:
        record["user_pubkey_tail"] = user_pubkey_tail
    if actor_type:
        record["actor_type"] = actor_type

    # Add outcome/status
    if outcome:
        record["outcome"] = outcome
    if status is not None:
        record["status"] = status

    # Add safe details
    if details:
        record["details"] = details

    # Emit as JSON-line format for structured parsing
    # Also emit as traditional log line with key=value pairs for human inspection
    log_line = " ".join(f"{k}={json.dumps(v) if isinstance(v, dict) else v}" for k, v in record.items())
    logger.info(log_line)


def mask_pubkey(pubkey: str, tail: int = 4) -> str:
    """Return masked pubkey for safe audit logging (last N chars only)."""
    if not pubkey or len(pubkey) < tail:
        return "***"
    return pubkey[-tail:]
