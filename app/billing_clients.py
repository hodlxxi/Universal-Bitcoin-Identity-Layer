"""
Billing enforcement and Lightning PAYG handling for OAuth client_id.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from functools import wraps
from typing import Optional

from flask import jsonify, request
from sqlalchemy import text

from app.database import session_scope
from app.db_storage import get_oauth_token
from app.payments.ln import check_invoice_paid, create_invoice


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _default_free_quota() -> int:
    return int(os.getenv("HODLXXI_FREE_QUOTA_CALLS", "0"))


def _extract_client_id() -> Optional[str]:
    client_id = getattr(request, "oauth_client_id", None)
    if client_id:
        return client_id

    payload = getattr(request, "oauth_payload", None) or {}
    client_id = payload.get("client_id") or payload.get("azp")
    if client_id:
        return client_id

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token_str = auth_header.split(" ", 1)[1]
    token_data = get_oauth_token(token_str)
    if not token_data:
        return None
    return token_data.get("client_id") or token_data.get("azp")


def _ensure_client_record(db_session, client_id: str) -> None:
    now = _utc_now()
    free_quota = _default_free_quota()
    if db_session.bind.dialect.name == "sqlite":
        db_session.execute(
            text("""
                INSERT OR IGNORE INTO ubid_clients
                    (client_id, payg_enabled, sats_balance, free_quota_remaining, created_at, updated_at, last_quota_reset)
                VALUES (:client_id, TRUE, 0, :free_quota, :now, :now, :now)
                """),
            {"client_id": client_id, "free_quota": free_quota, "now": now},
        )
    else:
        db_session.execute(
            text("""
                INSERT INTO ubid_clients
                    (client_id, payg_enabled, sats_balance, free_quota_remaining, created_at, updated_at, last_quota_reset)
                VALUES (:client_id, TRUE, 0, :free_quota, :now, :now, :now)
                ON CONFLICT (client_id) DO NOTHING
                """),
            {"client_id": client_id, "free_quota": free_quota, "now": now},
        )


def _consume_free_quota(db_session, client_id: str, cost: int) -> bool:
    if cost <= 0:
        return True
    params = {"client_id": client_id, "cost": cost, "now": _utc_now()}
    if db_session.bind.dialect.name == "sqlite":
        result = db_session.execute(
            text("""
                UPDATE ubid_clients
                   SET free_quota_remaining = free_quota_remaining - :cost,
                       updated_at = :now
                 WHERE client_id = :client_id
                   AND free_quota_remaining >= :cost
                """),
            params,
        )
        return result.rowcount > 0
    row = db_session.execute(
        text("""
            UPDATE ubid_clients
               SET free_quota_remaining = free_quota_remaining - :cost,
                   updated_at = :now
             WHERE client_id = :client_id
               AND free_quota_remaining >= :cost
             RETURNING free_quota_remaining
            """),
        params,
    ).fetchone()
    return bool(row)


def _debit_balance(db_session, client_id: str, cost: int) -> bool:
    if cost <= 0:
        return True
    params = {"client_id": client_id, "cost": cost, "now": _utc_now()}
    if db_session.bind.dialect.name == "sqlite":
        result = db_session.execute(
            text("""
                UPDATE ubid_clients
                   SET sats_balance = sats_balance - :cost,
                       updated_at = :now
                 WHERE client_id = :client_id
                   AND sats_balance >= :cost
                """),
            params,
        )
        return result.rowcount > 0
    row = db_session.execute(
        text("""
            UPDATE ubid_clients
               SET sats_balance = sats_balance - :cost,
                   updated_at = :now
             WHERE client_id = :client_id
               AND sats_balance >= :cost
             RETURNING sats_balance
            """),
        params,
    ).fetchone()
    return bool(row)


def _get_balances(db_session, client_id: str) -> tuple[int, int]:
    row = db_session.execute(
        text("""
            SELECT sats_balance, free_quota_remaining
              FROM ubid_clients
             WHERE client_id = :client_id
            """),
        {"client_id": client_id},
    ).fetchone()
    if not row:
        return 0, 0
    return int(row[0] or 0), int(row[1] or 0)


def require_paid_client(cost_sats: int, allow_free: bool = True, free_quota_cost: int = 1):
    """
    Enforce PAYG billing for OAuth client_id.
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_id = _extract_client_id()
            if not client_id:
                return jsonify({"error": "unauthorized", "detail": "Missing client identity"}), 401

            with session_scope() as db_session:
                _ensure_client_record(db_session, client_id)

                if allow_free and free_quota_cost > 0:
                    if _consume_free_quota(db_session, client_id, free_quota_cost):
                        return f(*args, **kwargs)

                if _debit_balance(db_session, client_id, int(cost_sats)):
                    return f(*args, **kwargs)

                balance_sats, free_quota = _get_balances(db_session, client_id)

            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "payment_required",
                        "code": "PAYMENT_REQUIRED",
                        "client_id": client_id,
                        "cost_sats": int(cost_sats),
                        "balance_sats": int(balance_sats),
                        "free_quota_remaining": int(free_quota),
                        "create_invoice_endpoint": "/api/billing/agent/create-invoice",
                        "hint": "Top up via Lightning PAYG",
                    }
                ),
                402,
            )

        return wrapper

    return decorator


def create_client_invoice(client_id: str, amount_sats: int, memo: str) -> dict:
    amount_sats = int(amount_sats)
    payment_request, invoice_id = create_invoice(amount_sats, memo, client_id)
    with session_scope() as db_session:
        _ensure_client_record(db_session, client_id)
        db_session.execute(
            text("""
                INSERT INTO payments_clients
                    (invoice_id, client_id, payment_request, amount_sats, status, created_at)
                VALUES (:invoice_id, :client_id, :payment_request, :amount_sats, 'pending', :now)
                """),
            {
                "invoice_id": invoice_id,
                "client_id": client_id,
                "payment_request": payment_request,
                "amount_sats": amount_sats,
                "now": _utc_now(),
            },
        )
        balance_sats, _free = _get_balances(db_session, client_id)

    return {
        "ok": True,
        "client_id": client_id,
        "invoice_id": invoice_id,
        "payment_request": payment_request,
        "amount_sats": amount_sats,
        "status": "pending",
        "sats_balance": balance_sats,
    }


def check_client_invoice(client_id: str, invoice_id: str) -> dict:
    with session_scope() as db_session:
        payment = db_session.execute(
            text("""
                SELECT amount_sats, status, credited
                  FROM payments_clients
                 WHERE invoice_id = :invoice_id
                   AND client_id = :client_id
                """),
            {"invoice_id": invoice_id, "client_id": client_id},
        ).fetchone()

        if not payment:
            return {"ok": False, "error": "invoice_not_found", "invoice_id": invoice_id, "client_id": client_id}

        amount_sats, status, credited = int(payment[0] or 0), payment[1], bool(payment[2])
        if credited:
            balance_sats, _free = _get_balances(db_session, client_id)
            return {
                "ok": True,
                "paid": True,
                "invoice_id": invoice_id,
                "amount_sats": amount_sats,
                "credited_now": False,
                "sats_balance": balance_sats,
            }

        if not check_invoice_paid(invoice_id):
            return {"ok": True, "paid": False, "invoice_id": invoice_id}

        now = _utc_now()
        params = {"invoice_id": invoice_id, "client_id": client_id, "now": now}
        if db_session.bind.dialect.name == "sqlite":
            db_session.execute(
                text("""
                    UPDATE payments_clients
                       SET status = 'paid',
                           paid_at = :now,
                           credited = TRUE
                     WHERE invoice_id = :invoice_id
                       AND client_id = :client_id
                       AND COALESCE(credited, FALSE) = FALSE
                    """),
                params,
            )
            refreshed = db_session.execute(
                text("""
                    SELECT credited
                      FROM payments_clients
                     WHERE invoice_id = :invoice_id
                       AND client_id = :client_id
                    """),
                params,
            ).fetchone()
            credited_now = bool(refreshed and refreshed[0]) and not credited
        else:
            updated = db_session.execute(
                text("""
                UPDATE payments_clients
                   SET status = 'paid',
                       paid_at = :now,
                       credited = TRUE
                 WHERE invoice_id = :invoice_id
                   AND client_id = :client_id
                   AND COALESCE(credited, FALSE) = FALSE
                 RETURNING amount_sats
                """),
                params,
            ).fetchone()
            credited_now = bool(updated)
        if credited_now:
            db_session.execute(
                text("""
                    UPDATE ubid_clients
                       SET sats_balance = sats_balance + :amount,
                           updated_at = :now
                     WHERE client_id = :client_id
                    """),
                {"amount": amount_sats, "client_id": client_id, "now": now},
            )

        balance_sats, _free = _get_balances(db_session, client_id)

    return {
        "ok": True,
        "paid": True,
        "invoice_id": invoice_id,
        "amount_sats": amount_sats,
        "credited_now": credited_now,
        "sats_balance": balance_sats,
    }
