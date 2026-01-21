from flask import Blueprint, session, request, jsonify, current_app
import os, uuid, json

bp = Blueprint("account_api_compat", __name__)

def _require_session_json():
    if not session.get("logged_in_pubkey"):
        return jsonify({"ok": False, "error": "not_logged_in"}), 401
    return None

def _get_pg_dsn():
    dsn = (
        os.getenv("DATABASE_URL")
        or os.getenv("SQLALCHEMY_DATABASE_URI")
        or current_app.config.get("DATABASE_URL")
        or current_app.config.get("SQLALCHEMY_DATABASE_URI")
    )
    if not dsn:
        return None
    dsn = dsn.replace("postgresql+psycopg2://", "postgresql://")
    dsn = dsn.replace("postgresql+psycopg://", "postgresql://")
    return dsn

def _pg_connect():
    dsn = _get_pg_dsn()
    if not dsn:
        raise RuntimeError("No DATABASE_URL / SQLALCHEMY_DATABASE_URI found")
    try:
        import psycopg2
        return psycopg2.connect(dsn)
    except Exception:
        import psycopg
        return psycopg.connect(dsn)

def _iso(dt):
    return dt.isoformat() if dt else None

def _rb(cur):
    try:
        cur.connection.rollback()
    except Exception:
        pass

def _fetch_payg_from_users(cur, pk):
    # users.metadata is json in your schema; cast to jsonb for operator support
    cur.execute(
        "select coalesce((metadata::jsonb->>'payg_enabled')::boolean,false) "
        "from users where pubkey=%s limit 1",
        (pk,),
    )
    row = cur.fetchone()
    return bool(row[0]) if row is not None else None

def _upsert_payg_into_users(cur, pk, enabled):
    # If the user row doesn't exist yet, create it (id is varchar(36), so uuid string is perfect)
    new_id = str(uuid.uuid4())
    cur.execute(
        """
        insert into users (id, pubkey, created_at, metadata, is_active)
        values (%s, %s, now(), %s::json, true)
        on conflict (pubkey) do update
        set metadata = (
            coalesce(users.metadata::jsonb,'{}'::jsonb)
            || jsonb_build_object('payg_enabled', %s)
        )::json
        """,
        (new_id, pk, json.dumps({"payg_enabled": enabled}), enabled),
    )

@bp.route("/api/account/summary", methods=["GET"])
def account_summary():
    gate = _require_session_json()
    if gate:
        return gate

    pk = session.get("logged_in_pubkey", "")
    access_level = session.get("access_level")
    guest_label = session.get("guest_label")

    payg_enabled = bool(session.get("payg_enabled", False))
    plan = "free"
    sats_balance = 0
    recent_payments = []

    try:
        with _pg_connect() as conn:
            with conn.cursor() as cur:
                # PAYG flag (users.metadata)
                try:
                    v = _fetch_payg_from_users(cur, pk)
                    if v is not None:
                        payg_enabled = bool(v)
                except Exception as e:
                    _rb(cur)
                    current_app.logger.debug("payg fetch failed: %s", e)

                # Plan heuristic: latest non-null plan in payments
                try:
                    cur.execute(
                        "select plan from payments "
                        "where user_pubkey=%s and plan is not null "
                        "order by created_at desc limit 1",
                        (pk,),
                    )
                    row = cur.fetchone()
                    if row and row[0]:
                        plan = str(row[0])
                except Exception as e:
                    _rb(cur)
                    current_app.logger.debug("plan fetch failed: %s", e)

                # Balance = SUM of paid rows that were actually credited
                cur.execute(
                    "select coalesce(sum(amount_sats),0) "
                    "from payments "
                    "where user_pubkey=%s and status='paid' "
                    "and coalesce((metadata->>'credited')::boolean,false)=true",
                    (pk,),
                )
                sats_balance = int(cur.fetchone()[0] or 0)

                # Recent invoices
                cur.execute(
                    "select invoice_id, amount_sats, status, created_at, paid_at "
                    "from payments "
                    "where user_pubkey=%s "
                    "order by created_at desc "
                    "limit 10",
                    (pk,),
                )
                for invoice_id, amount_sats, status, created_at, paid_at in (cur.fetchall() or []):
                    recent_payments.append({
                        "invoice_id": invoice_id,
                        "amount_sats": int(amount_sats) if amount_sats is not None else None,
                        "status": status,
                        "created_at": _iso(created_at),
                        "paid_at": _iso(paid_at),
                    })

    except Exception as e:
        current_app.logger.warning("account_summary db fallback: %s", e)

    needs_topup = bool(payg_enabled and sats_balance <= 0)

    return jsonify({
        "ok": True,
        "pubkey": pk,
        "access_level": access_level,
        "guest_label": guest_label,
        "plan": plan,
        "sats_balance": sats_balance,
        "payg_enabled": payg_enabled,
        "needs_topup": needs_topup,
        "recent_payments": recent_payments,
    })

@bp.route("/api/account/set-payg", methods=["POST"])
def set_payg():
    gate = _require_session_json()
    if gate:
        return gate

    pk = session.get("logged_in_pubkey", "")
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", False))

    session["payg_enabled"] = enabled

    try:
        with _pg_connect() as conn:
            with conn.cursor() as cur:
                _upsert_payg_into_users(cur, pk, enabled)
    except Exception as e:
        current_app.logger.warning("set_payg persist failed: %s", e)

    return jsonify({"ok": True, "enabled": enabled})
