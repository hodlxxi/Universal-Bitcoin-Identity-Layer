"""Lightning Network Payment Integration for HODLXXI"""
import logging
import secrets
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class LightningPaymentError(Exception):
    """Base exception for Lightning payment errors."""

    pass


def create_invoice(amount_sats: int, memo: str, user_pubkey: str, expiry_seconds: int = 3600) -> Tuple[str, str]:
    """Create a Lightning invoice for payment."""
    try:
        invoice_id = f"inv_{secrets.token_urlsafe(16)}"

        # TODO: Wire to your Lightning node here
        # For now, generate stub payment request
        payment_request = f"lnbc{amount_sats}n1p{secrets.token_urlsafe(100)}"

        logger.info(f"Created Lightning invoice: {invoice_id} for {amount_sats} sats")
        return payment_request, invoice_id

    except Exception as e:
        logger.error(f"Failed to create Lightning invoice: {e}", exc_info=True)
        raise LightningPaymentError(f"Could not create invoice: {e}") from e


def check_invoice_paid(invoice_id: str) -> bool:
    """Check if a Lightning invoice has been paid."""
    import os

    # For testing: export TEST_INVOICE_PAID=true
    return os.getenv("TEST_INVOICE_PAID", "false").lower() == "true"


logger.info("Lightning payment module loaded (STUB MODE)")
