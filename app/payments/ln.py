"""Lightning Network Payment Integration for HODLXXI"""

import logging
import base64
import os
import secrets
from typing import Optional, Tuple

import requests

logger = logging.getLogger(__name__)


class LightningPaymentError(Exception):
    """Base exception for Lightning payment errors."""

    pass


def _lnd_headers() -> dict:
    macaroon = os.getenv("LND_MACAROON") or os.getenv("LND_MACAROON_HEX")
    if not macaroon:
        raise LightningPaymentError("Missing LND_MACAROON or LND_MACAROON_HEX for LND REST backend.")
    return {"Grpc-Metadata-macaroon": macaroon}


def _create_invoice_lnd_rest(amount_sats: int, memo: str, expiry_seconds: int) -> Tuple[str, str]:
    base_url = os.getenv("LND_REST_URL", "").rstrip("/")
    if not base_url:
        raise LightningPaymentError("Missing LND_REST_URL for LND REST backend.")

    payload = {"value": int(amount_sats), "memo": memo, "expiry": int(expiry_seconds)}
    resp = requests.post(f"{base_url}/v1/invoices", json=payload, headers=_lnd_headers(), timeout=10)
    if resp.status_code >= 300:
        raise LightningPaymentError(f"LND invoice create failed: {resp.status_code} {resp.text}")

    data = resp.json()
    payment_request = data.get("payment_request")
    invoice_id = data.get("r_hash_str")
    if not invoice_id and data.get("r_hash"):
        # r_hash is base64 bytes; convert to hex string safe for URL paths
        invoice_id = base64.b64decode(data["r_hash"]).hex()
    if not payment_request or not invoice_id:
        raise LightningPaymentError("LND invoice response missing payment_request or r_hash.")
    return payment_request, invoice_id


def create_invoice(amount_sats: int, memo: str, user_pubkey: str, expiry_seconds: int = 3600) -> Tuple[str, str]:
    """Create a Lightning invoice for payment."""
    try:
        backend = os.getenv("LN_BACKEND", "stub").lower()
        if backend == "lnd_rest":
            payment_request, invoice_id = _create_invoice_lnd_rest(amount_sats, memo, expiry_seconds)
        else:
            invoice_id = f"inv_{secrets.token_urlsafe(16)}"
            payment_request = f"lnbc{amount_sats}n1p{secrets.token_urlsafe(100)}"

        logger.info(f"Created Lightning invoice: {invoice_id} for {amount_sats} sats")
        return payment_request, invoice_id

    except Exception as e:
        logger.error(f"Failed to create Lightning invoice: {e}", exc_info=True)
        raise LightningPaymentError(f"Could not create invoice: {e}") from e


def check_invoice_paid(invoice_id: str) -> bool:
    """Check if a Lightning invoice has been paid."""
    backend = os.getenv("LN_BACKEND", "stub").lower()
    if backend == "lnd_rest":
        base_url = os.getenv("LND_REST_URL", "").rstrip("/")
        if not base_url:
            raise LightningPaymentError("Missing LND_REST_URL for LND REST backend.")
        resp = requests.get(f"{base_url}/v1/invoice/{invoice_id}", headers=_lnd_headers(), timeout=10)
        if resp.status_code >= 300:
            raise LightningPaymentError(f"LND invoice lookup failed: {resp.status_code} {resp.text}")
        return bool(resp.json().get("settled"))

    # For testing: export TEST_INVOICE_PAID=true
    return os.getenv("TEST_INVOICE_PAID", "false").lower() == "true"


logger.info("Lightning payment module loaded (stub unless LN_BACKEND is configured)")
