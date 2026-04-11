"""Lightning Network Payment Integration for HODLXXI"""

import base64
import json
import logging
import os
import secrets
import subprocess
from typing import Tuple

import requests

from app.structured_logging import log_event

logger = logging.getLogger(__name__)


class LightningPaymentError(Exception):
    """Base exception for Lightning payment errors."""

    pass


def _assert_not_stub_in_production() -> None:
    env = (os.getenv("FLASK_ENV") or "").lower()
    force_https = os.getenv("FORCE_HTTPS", "").lower() == "true"
    backend = (os.getenv("LN_BACKEND") or "stub").lower()
    test_paid = os.getenv("TEST_INVOICE_PAID", "false").lower() == "true"

    # In prod (or when FORCE_HTTPS), refuse stub/testing modes
    if env == "production" or force_https:
        if backend == "stub" or test_paid:
            logger.error("Lightning backend misconfigured for production (stub/testing enabled).")
            raise LightningPaymentError("Lightning backend misconfigured for production.")


# -----------------------
# LND REST backend
# -----------------------


def _lnd_headers() -> dict:
    macaroon = os.getenv("LND_MACAROON") or os.getenv("LND_MACAROON_HEX")
    if not macaroon:
        raise LightningPaymentError("Missing LND_MACAROON or LND_MACAROON_HEX for LND REST backend.")
    return {"Grpc-Metadata-macaroon": macaroon}


def _create_invoice_lnd_rest(amount_sats: int, memo: str, expiry_seconds: int) -> Tuple[str, str]:
    base_url = (os.getenv("LND_REST_URL") or "").rstrip("/")
    if not base_url:
        raise LightningPaymentError("Missing LND_REST_URL for LND REST backend.")

    payload = {"value": int(amount_sats), "memo": memo, "expiry": int(expiry_seconds)}
    resp = requests.post(f"{base_url}/v1/invoices", json=payload, headers=_lnd_headers(), timeout=15)
    if resp.status_code >= 300:
        log_event(logger, "ln.invoice_create_failed", backend="lnd_rest", outcome="http_error", status=resp.status_code)
        raise LightningPaymentError(f"LND invoice create failed: {resp.status_code}")

    data = resp.json()
    payment_request = data.get("payment_request")
    invoice_id = data.get("r_hash_str")

    if not invoice_id and data.get("r_hash"):
        # r_hash is base64 bytes; convert to hex string safe for URL paths
        invoice_id = base64.b64decode(data["r_hash"]).hex()

    if not payment_request or not invoice_id:
        log_event(logger, "ln.invoice_create_failed", backend="lnd_rest", outcome="missing_fields")
        raise LightningPaymentError("LND invoice response missing payment_request or r_hash.")

    log_event(logger, "ln.invoice_created", backend="lnd_rest", invoice_id=invoice_id, outcome="created")
    return payment_request, invoice_id


def _check_invoice_paid_lnd_rest(invoice_id: str) -> bool:
    base_url = (os.getenv("LND_REST_URL") or "").rstrip("/")
    if not base_url:
        raise LightningPaymentError("Missing LND_REST_URL for LND REST backend.")
    resp = requests.get(f"{base_url}/v1/invoice/{invoice_id}", headers=_lnd_headers(), timeout=15)
    if resp.status_code >= 300:
        log_event(logger, "ln.invoice_lookup_failed", backend="lnd_rest", invoice_id=invoice_id, outcome="http_error", status=resp.status_code)
        raise LightningPaymentError(f"LND invoice lookup failed: {resp.status_code}")

    settled = bool(resp.json().get("settled"))
    log_event(logger, "ln.invoice_lookup_checked", backend="lnd_rest", invoice_id=invoice_id, outcome="paid" if settled else "unpaid")
    return settled


# -----------------------
# LND CLI backend (lncli)
# -----------------------


def _lncli_base_cmd() -> list[str]:
    rpcserver = os.getenv("LND_RPCSERVER") or "127.0.0.1:10009"
    tlscert = os.getenv("LND_TLSCERTPATH")
    macaroon = os.getenv("LND_MACAROONPATH")

    if not tlscert:
        raise LightningPaymentError("Missing LND_TLSCERTPATH for lnd_cli backend.")
    if not macaroon:
        raise LightningPaymentError("Missing LND_MACAROONPATH for lnd_cli backend.")

    cmd = [
        "lncli",
        f"--rpcserver={rpcserver}",
        f"--tlscertpath={tlscert}",
        f"--macaroonpath={macaroon}",
    ]

    # Optional, but harmless if set; if you want it, set LND_NETWORK=mainnet/testnet
    net = (os.getenv("LND_NETWORK") or "").strip()
    if net:
        cmd.append(f"--network={net}")

    return cmd


def _run_lncli(args: list[str], timeout: int = 20) -> dict:
    cmd = _lncli_base_cmd() + args
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        log_event(logger, "ln.lnd_status_fetch_failed", backend="lnd_cli", outcome="timeout")
        raise LightningPaymentError(f"lncli timed out after {timeout}s: {' '.join(cmd)}") from e

    if p.returncode != 0:
        log_event(logger, "ln.lnd_status_fetch_failed", backend="lnd_cli", outcome="command_failed", status=p.returncode)
        err = (p.stderr or p.stdout or "").strip()
        raise LightningPaymentError(f"lncli failed (rc={p.returncode}): {err}")

    out = (p.stdout or "").strip()
    try:
        return json.loads(out) if out else {}
    except json.JSONDecodeError as e:
        raise LightningPaymentError(f"lncli returned non-JSON output: {out[:200]}") from e


def _create_invoice_lnd_cli(amount_sats: int, memo: str, expiry_seconds: int) -> Tuple[str, str]:
    j = _run_lncli(
        ["addinvoice", f"--amt={int(amount_sats)}", f"--memo={memo}", f"--expiry={int(expiry_seconds)}"],
        timeout=30,
    )
    # lncli returns r_hash (hex) + payment_request
    invoice_id = j.get("r_hash")
    payment_request = j.get("payment_request")
    if not invoice_id or not payment_request:
        log_event(logger, "ln.invoice_create_failed", backend="lnd_cli", outcome="missing_fields")
        raise LightningPaymentError("lncli addinvoice missing r_hash or payment_request.")

    log_event(logger, "ln.invoice_created", backend="lnd_cli", invoice_id=invoice_id, outcome="created")
    return payment_request, invoice_id


def _check_invoice_paid_lnd_cli(invoice_id: str) -> bool:
    # invoice_id should be the payment hash (hex) i.e. r_hash
    j = _run_lncli(["lookupinvoice", invoice_id], timeout=20)
    settled = bool(j.get("settled"))
    log_event(logger, "ln.invoice_lookup_checked", backend="lnd_cli", invoice_id=invoice_id, outcome="paid" if settled else "unpaid")
    return settled


# -----------------------
# Public API
# -----------------------


def create_invoice(amount_sats: int, memo: str, user_pubkey: str, expiry_seconds: int = 3600) -> Tuple[str, str]:
    """Create a Lightning invoice for payment."""
    try:
        _assert_not_stub_in_production()
        backend = (os.getenv("LN_BACKEND") or "stub").lower()

        if backend == "lnd_rest":
            payment_request, invoice_id = _create_invoice_lnd_rest(amount_sats, memo, expiry_seconds)
        elif backend == "lnd_cli":
            payment_request, invoice_id = _create_invoice_lnd_cli(amount_sats, memo, expiry_seconds)
        else:
            # stub mode
            invoice_id = secrets.token_bytes(32).hex()  # 64-hex like LND r_hash
            payment_request = f"lnbc{amount_sats}n1p{secrets.token_urlsafe(80)}"

        log_event(logger, "ln.invoice_create", backend=backend, invoice_id=invoice_id, outcome="success", sats=amount_sats)
        return payment_request, invoice_id

    except Exception as e:
        log_event(logger, "ln.invoice_create", backend=(os.getenv("LN_BACKEND") or "stub").lower(), outcome="failure")
        logger.error("Failed to create Lightning invoice: %s", e, exc_info=True)
        raise LightningPaymentError("Could not create invoice") from e


def check_invoice_paid(invoice_id: str) -> bool:
    """Check if a Lightning invoice has been paid."""
    _assert_not_stub_in_production()
    backend = (os.getenv("LN_BACKEND") or "stub").lower()

    if backend == "lnd_rest":
        paid = _check_invoice_paid_lnd_rest(invoice_id)
        log_event(logger, "ln.payment_decision", backend=backend, invoice_id=invoice_id, outcome="paid" if paid else "pending")
        return paid
    if backend == "lnd_cli":
        paid = _check_invoice_paid_lnd_cli(invoice_id)
        log_event(logger, "ln.payment_decision", backend=backend, invoice_id=invoice_id, outcome="paid" if paid else "pending")
        return paid

    # stub/testing
    paid = os.getenv("TEST_INVOICE_PAID", "false").lower() == "true"
    log_event(logger, "ln.payment_decision", backend=backend, invoice_id=invoice_id, outcome="paid" if paid else "pending")
    return paid


logger.info("Lightning payment module loaded (LN_BACKEND decides backend)")
