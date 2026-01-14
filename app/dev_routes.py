"""Developer Dashboard and Billing Routes for HODLXXI"""
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Dict, List

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import text

from app.database import session_scope

logger = logging.getLogger(__name__)

dev_bp = Blueprint("dev", __name__, url_prefix="/dev")

# Plan Configuration
PLANS = {
    "free": {
        "name": "Free",
        "price_sats": 0,
        "price_display": "Free",
        "rate_limit_day": 100,
        "scopes_allowed": ["read_limited"],
        "features": ["100 logins/day", "Basic read-only API", "Community support"],
    },
    "builder": {
        "name": "Builder",
        "price_sats": 1000,
        "price_display": "1,000 sats/month",
        "rate_limit_day": 2000,
        "scopes_allowed": ["read", "covenant_read"],
        "features": ["2,000 logins/day", "Full read API", "Covenant reading", "Email support"],
    },
    "pro": {
        "name": "Pro",
        "price_sats": 5000,
        "price_display": "5,000 sats/month",
        "rate_limit_day": 10000,
        "scopes_allowed": ["read", "write", "covenant_create", "covenant_read"],
        "features": ["10,000 logins/day", "Full API access", "Covenant creation", "Priority support"],
    },
}


def require_login(f):
    """Decorator to require logged-in non-guest user."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_pubkey = session.get("logged_in_pubkey")
        if not user_pubkey:
            return redirect(url_for("login", next=request.url))

        if str(user_pubkey).startswith("guest-"):
            return jsonify({"error": "Guests cannot access developer billing. Please login with a real key."}), 403

        return f(*args, **kwargs)

    return decorated_function


def get_or_create_dev_account(user_pubkey: str) -> Dict:
    """Get or create developer account for user."""
    with session_scope() as db_session:
        result = db_session.execute(
            text("SELECT * FROM dev_accounts WHERE user_pubkey = :pubkey"), {"pubkey": user_pubkey}
        ).fetchone()

        if result:
            return {
                "id": result[0],
                "user_pubkey": result[1],
                "plan": result[2],
                "status": result[3],
                "current_period_start": result[4],
                "current_period_end": result[5],
                "created_at": result[6],
                "updated_at": result[7],
            }

        db_session.execute(
            text(
                "INSERT INTO dev_accounts (user_pubkey, plan, status, created_at) VALUES (:pubkey, 'free', 'active', :now)"
            ),
            {"pubkey": user_pubkey, "now": datetime.now(timezone.utc)},
        )
        db_session.commit()

        result = db_session.execute(
            text("SELECT * FROM dev_accounts WHERE user_pubkey = :pubkey"), {"pubkey": user_pubkey}
        ).fetchone()

        return {
            "id": result[0],
            "user_pubkey": result[1],
            "plan": result[2],
            "status": result[3],
            "current_period_start": result[4],
            "current_period_end": result[5],
            "created_at": result[6],
            "updated_at": result[7],
        }


def get_user_oauth_clients(user_pubkey: str) -> List[Dict]:
    """Get all OAuth clients owned by user."""
    with session_scope() as db_session:
        results = db_session.execute(
            text(
                """
                SELECT client_id, client_name, redirect_uris, grant_types, 
                       response_types, is_active, created_at, plan
                FROM oauth_clients
                WHERE owner_pubkey = :pubkey OR owner_pubkey IS NULL
                ORDER BY created_at DESC
            """
            ),
            {"pubkey": user_pubkey},
        ).fetchall()

        clients = []
        for row in results:
            clients.append(
                {
                    "client_id": row[0],
                    "client_name": row[1],
                    "redirect_uris": row[2],
                    "grant_types": row[3],
                    "response_types": row[4],
                    "is_active": row[5],
                    "created_at": row[6],
                    "plan": row[7] or "free",
                }
            )
        return clients


def get_usage_stats(client_id: str, days: int = 30) -> Dict:
    """Get usage statistics for a client."""
    with session_scope() as db_session:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        token_count = (
            db_session.execute(
                text("SELECT COUNT(*) FROM oauth_tokens WHERE client_id = :client_id AND created_at >= :cutoff"),
                {"client_id": client_id, "cutoff": cutoff_date},
            ).scalar()
            or 0
        )

        code_count = (
            db_session.execute(
                text("SELECT COUNT(*) FROM oauth_codes WHERE client_id = :client_id AND created_at >= :cutoff"),
                {"client_id": client_id, "cutoff": cutoff_date},
            ).scalar()
            or 0
        )

        return {"logins_30d": code_count, "tokens_issued_30d": token_count, "api_calls_30d": token_count}


@dev_bp.route("/dashboard")
@require_login
def dashboard():
    """Developer console dashboard."""
    user_pubkey = session.get("logged_in_pubkey")

    # Ensure dev account exists (required by payments.user_pubkey FK)
    get_or_create_dev_account(user_pubkey)

    try:
        dev_account = get_or_create_dev_account(user_pubkey)
        clients = get_user_oauth_clients(user_pubkey)

        total_logins_30d = 0
        total_api_calls_30d = 0

        for client in clients:
            stats = get_usage_stats(client["client_id"], days=30)
            client["stats"] = stats
            total_logins_30d += stats["logins_30d"]
            total_api_calls_30d += stats["api_calls_30d"]

        current_plan = PLANS.get(dev_account["plan"], PLANS["free"])
        days_until_renewal = None
        if dev_account["current_period_end"]:
            days_until_renewal = (dev_account["current_period_end"] - datetime.now(timezone.utc)).days

        return render_template(
            "dev_dashboard.html",
            user_pubkey=user_pubkey,
            dev_account=dev_account,
            current_plan=current_plan,
            plans=PLANS,
            clients=clients,
            total_logins_30d=total_logins_30d,
            total_api_calls_30d=total_api_calls_30d,
            days_until_renewal=days_until_renewal,
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return f"Error loading dashboard: {e}", 500


@dev_bp.route("/billing/create-invoice", methods=["POST"])
@require_login
def create_invoice_route():
    """Create Lightning invoice for plan upgrade."""
    user_pubkey = session.get("logged_in_pubkey")

    try:
        data = request.get_json()
        plan = data.get("plan")

        if plan not in PLANS:
            return jsonify({"error": "Invalid plan"}), 400

        plan_info = PLANS[plan]
        amount_sats = plan_info["price_sats"]

        if amount_sats == 0:
            return jsonify({"error": "Cannot create invoice for free plan"}), 400

        import secrets

        from app.payments.ln import create_invoice

        invoice_id = f"inv_{secrets.token_urlsafe(16)}"
        payment_request = f"lnbc{amount_sats}n1p{secrets.token_urlsafe(100)}"

        with session_scope() as db_session:
            db_session.execute(
                text(
                    """
                    INSERT INTO payments 
                    (user_pubkey, invoice_id, payment_request, amount_sats, 
                     status, plan, created_at, expires_at)
                    VALUES (:pubkey, :invoice_id, :payment_request, :amount, 
                            'pending', :plan, :now, :expires)
                """
                ),
                {
                    "pubkey": user_pubkey,
                    "invoice_id": invoice_id,
                    "payment_request": payment_request,
                    "amount": amount_sats,
                    "plan": plan,
                    "now": datetime.now(timezone.utc),
                    "expires": datetime.now(timezone.utc) + timedelta(hours=1),
                },
            )
            db_session.commit()

        logger.info(f"Created invoice {invoice_id} for user {user_pubkey[:16]}...")

        return jsonify(
            {
                "ok": True,
                "payment_request": payment_request,
                "invoice_id": invoice_id,
                "amount_sats": amount_sats,
                "plan": plan,
            }
        )
    except Exception as e:
        logger.error(f"Invoice creation error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@dev_bp.route("/billing/check-invoice", methods=["POST"])
@require_login
def check_invoice_route():
    """Check if Lightning invoice has been paid."""
    user_pubkey = session.get("logged_in_pubkey")

    try:
        data = request.get_json()
        invoice_id = data.get("invoice_id")

        if not invoice_id:
            return jsonify({"error": "invoice_id required"}), 400

        from app.payments.ln import check_invoice_paid

        is_paid = check_invoice_paid(invoice_id)

        if is_paid:
            with session_scope() as db_session:
                payment = db_session.execute(
                    text(
                        "SELECT plan, amount_sats, status FROM payments WHERE invoice_id = :invoice_id AND user_pubkey = :pubkey"
                    ),
                    {"invoice_id": invoice_id, "pubkey": user_pubkey},
                ).fetchone()

                if not payment:
                    return jsonify({"error": "Invoice not found"}), 404

                if payment[2] == "paid":
                    return jsonify({"paid": True, "already_processed": True})

                plan = payment[0]
                now = datetime.now(timezone.utc)
                period_end = now + timedelta(days=30)

                db_session.execute(
                    text("UPDATE payments SET status = 'paid', paid_at = :now WHERE invoice_id = :invoice_id"),
                    {"now": now, "invoice_id": invoice_id},
                )

                db_session.execute(
                    text(
                        """
                        UPDATE dev_accounts
                        SET plan = :plan, status = 'active',
                            current_period_start = :start,
                            current_period_end = :end, updated_at = :now
                        WHERE user_pubkey = :pubkey
                    """
                    ),
                    {"plan": plan, "start": now, "end": period_end, "now": now, "pubkey": user_pubkey},
                )

                db_session.execute(
                    text(
                        """
                        INSERT INTO subscriptions
                        (user_pubkey, plan, amount_sats, current_period_start,
                         current_period_end, status, created_at)
                        VALUES (:pubkey, :plan, :amount, :start, :end, 'active', :now)
                    """
                    ),
                    {
                        "pubkey": user_pubkey,
                        "plan": plan,
                        "amount": payment[1],
                        "start": now,
                        "end": period_end,
                        "now": now,
                    },
                )

                db_session.commit()
                logger.info(f"Upgraded user {user_pubkey[:16]}... to {plan} plan")

        return jsonify({"paid": is_paid})
    except Exception as e:
        logger.error(f"Invoice check error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


def get_user_plan(user_pubkey: str) -> str:
    """Get user's current plan."""
    try:
        dev_account = get_or_create_dev_account(user_pubkey)
        return dev_account["plan"]
    except Exception:
        return "free"


def check_plan_allows_scopes(user_pubkey: str, requested_scopes: str) -> tuple:
    """Check if user's plan allows requested scopes."""
    plan = get_user_plan(user_pubkey)
    plan_info = PLANS.get(plan, PLANS["free"])
    allowed_scopes = plan_info["scopes_allowed"]

    requested = [s.strip() for s in requested_scopes.split() if s.strip()]
    disallowed = [s for s in requested if s not in allowed_scopes]

    if disallowed:
        return (False, allowed_scopes, f"Plan '{plan}' does not allow scopes: {', '.join(disallowed)}")

    return (True, allowed_scopes, "OK")


def check_rate_limit(user_pubkey: str, client_id: str) -> tuple:
    """Check if user/client has exceeded rate limit."""
    plan = get_user_plan(user_pubkey)
    plan_info = PLANS.get(plan, PLANS["free"])
    daily_limit = plan_info["rate_limit_day"]

    with session_scope() as db_session:
        today = datetime.now(timezone.utc).date()
        count = (
            db_session.execute(
                text("SELECT COUNT(*) FROM oauth_tokens WHERE client_id = :client_id AND DATE(created_at) = :today"),
                {"client_id": client_id, "today": today},
            ).scalar()
            or 0
        )

    return (count < daily_limit, count, daily_limit)


logger.info("Developer routes loaded")
