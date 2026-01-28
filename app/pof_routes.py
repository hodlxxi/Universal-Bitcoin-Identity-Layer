"""
HODLXXI Proof of Funds Routes - Fixed for SQLAlchemy
"""

import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, abort, jsonify, redirect, render_template, request, session, url_for

# Import database session
from app.database import get_session
from app.models import ProofOfFunds, User

# Create blueprint
pof_bp = Blueprint("pof", __name__, url_prefix="/pof")

pof_api_bp = Blueprint("pof_api", __name__, url_prefix="/api/pof")


@pof_api_bp.route("/stats")
def pof_stats_api():
    # POF_FIXES_PLANKTON_STATS_V2: real live stats from DB
    from flask import jsonify
    from sqlalchemy import func

    from app.database import get_session as db_get_session
    from app.models import ProofOfFunds

    db = db_get_session()
    try:
        verified_users = (
            db.query(func.count(func.distinct(ProofOfFunds.user_id))).filter(ProofOfFunds.status == "verified").scalar()
        ) or 0
        total_btc = (
            db.query(func.coalesce(func.sum(ProofOfFunds.total_btc), 0))
            .filter(ProofOfFunds.status == "verified")
            .scalar()
        ) or 0
        addresses_verified = (
            db.query(func.coalesce(func.sum(ProofOfFunds.address_count), 0))
            .filter(ProofOfFunds.status == "verified")
            .scalar()
        ) or 0
    finally:
        try:
            db.close()
        except Exception:
            pass

    return jsonify(
        {
            "verified_users": int(verified_users),
            "total_btc": float(total_btc),
            "addresses_verified": int(addresses_verified),
        }
    )


def login_required(f):
    """Decorator to require authentication"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if ("user_id" not in session) and (not session.get("logged_in_pubkey")):
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# Whale tier thresholds (in BTC)
WHALE_TIERS = [
    {"name": "Shrimp", "min": 0.0, "max": 0.1, "emoji": "🦐", "color": "#94A3B8"},
    {"name": "Crab", "min": 0.1, "max": 1.0, "emoji": "🦀", "color": "#F97316"},
    {"name": "Dolphin", "min": 1.0, "max": 10.0, "emoji": "🐬", "color": "#3B82F6"},
    {"name": "Shark", "min": 10.0, "max": 50.0, "emoji": "🦈", "color": "#8B5CF6"},
    {"name": "Whale", "min": 50.0, "max": 100.0, "emoji": "🐋", "color": "#EC4899"},
    {"name": "Humpback", "min": 100.0, "max": 1000.0, "emoji": "🐳", "color": "#F59E0B"},
    {"name": "Blue Whale", "min": 1000.0, "max": float("inf"), "emoji": "🌊", "color": "#14B8A6"},
]


def get_whale_tier(btc_amount):
    """Determine whale tier based on BTC amount"""
    for tier in WHALE_TIERS:
        if tier["min"] <= btc_amount < tier["max"]:
            return tier
    return WHALE_TIERS[-1]


def format_btc_amount(amount, privacy_level):
    """Format BTC amount based on privacy level"""
    if privacy_level == "boolean":
        return "Verified ✓"
    elif privacy_level == "threshold":
        tier = get_whale_tier(amount)
        return f"{tier['emoji']} {tier['name']}"
    elif privacy_level == "aggregate":
        # POF_FMT_AGGREGATE_V2: avoid showing ~0 BTC for tiny balances
        btc = float(amount or 0.0)
        sats = int(round(btc * 100_000_000))
        if btc < 0.01:
            return f"~{sats:,} sats"
        if btc < 1.0:
            return f"~{btc:.2f} BTC"
        rounded = round(btc / 10) * 10
        return f"~{int(rounded)} BTC"
    elif privacy_level == "exact":
        return f"{amount:.8f} BTC"
    return "Hidden"


@pof_bp.route("/")
def landing():
    """PoF landing page - explain the feature"""
    # POF_FIXES_PLANKTON_STATS_V2: compute live stats for initial render (page can also refresh via API)
    from sqlalchemy import func

    from app.database import get_session as db_get_session
    from app.models import ProofOfFunds

    db = db_get_session()
    try:
        verified_users = (
            db.query(func.count(func.distinct(ProofOfFunds.user_id))).filter(ProofOfFunds.status == "verified").scalar()
        ) or 0
        total_btc = (
            db.query(func.coalesce(func.sum(ProofOfFunds.total_btc), 0))
            .filter(ProofOfFunds.status == "verified")
            .scalar()
        ) or 0
        addresses_verified = (
            db.query(func.coalesce(func.sum(ProofOfFunds.address_count), 0))
            .filter(ProofOfFunds.status == "verified")
            .scalar()
        ) or 0
    finally:
        try:
            db.close()
        except Exception:
            pass

    live_stats = {
        "verified_users": int(verified_users),
        "total_btc": float(total_btc),
        "addresses_verified": int(addresses_verified),
    }
    return render_template("pof/landing.html", live_stats=live_stats)  # POF_FIXES_PLANKTON_STATS_V2


@pof_bp.route("/leaderboard")
def leaderboard():
    # POF_FIXES_PLANKTON_STATS_V2: server-render leaderboard from DB (no JS dependency), with Plankton tier
    from flask import render_template
    from sqlalchemy import func

    from app.database import get_session as db_get_session
    from app.models import ProofOfFunds

    db = db_get_session()
    try:
        rows = (
            db.query(ProofOfFunds)
            .filter(
                ProofOfFunds.status == "verified", ProofOfFunds.privacy_level.in_(["threshold", "aggregate", "exact"])
            )
            .order_by(ProofOfFunds.total_btc.desc(), ProofOfFunds.verified_at.desc())
            .limit(200)
            .all()
        )
    finally:
        try:
            db.close()
        except Exception:
            pass

    def tier_for(btc: float):
        sats = int(round((btc or 0.0) * 100_000_000))
        # Plankton: < 1000 sats
        if sats < 1000:
            return ("Plankton", "🦠")
        # Shrimp: >= 1000 sats but < 0.01 BTC
        if (btc or 0.0) < 0.01:
            return ("Shrimp", "🦐")
        if btc < 0.1:
            return ("Crab", "🦀")
        if btc < 1.0:
            return ("Dolphin", "🐬")
        if btc < 10.0:
            return ("Shark", "🦈")
        return ("Whale", "🐋")

    leaderboard = []
    for i, r in enumerate(rows, start=1):
        btc = float(r.total_btc or 0.0)
        sats = int(round(btc * 100_000_000))
        tier_name, emoji = tier_for(btc)

        # display: sats for tiny PoFs, BTC for larger
        amount_display = f"{sats:,} sats" if btc < 0.0005 else f"{btc:.6f} BTC"

        verified_date = ""
        try:
            verified_date = r.verified_at.date().isoformat() if r.verified_at else ""
        except Exception:
            verified_date = ""

        leaderboard.append(
            {
                "rank": i,
                "tier_name": tier_name,
                "tier": tier_name,
                "emoji": emoji,
                "tier_emoji": emoji,
                "amount_display": amount_display,
                "btc": btc,
                "total_btc": btc,
                "address_count": int(getattr(r, "address_count", 0) or 0),
                "certificate_id": getattr(r, "certificate_id", None),
                "cert": getattr(r, "certificate_id", None),
                "verified_date": verified_date,
                "verified_at": getattr(r, "verified_at", None),
                "privacy_level": getattr(r, "privacy_level", None),
                "user_id": getattr(r, "user_id", None),
            }
        )

    return render_template("pof/leaderboard.html", leaderboard=leaderboard)  # POF_FIXES_PLANKTON_STATS_V2


@pof_bp.route("/certificate/<cert_id>")
def certificate(cert_id):
    # POF_DB_CLOSE_V2: always close db_session
    """Shareable PoF certificate page"""
    db_session = get_session()

    try:
        pof = (
            db_session.query(ProofOfFunds)
            .filter(ProofOfFunds.certificate_id == cert_id, ProofOfFunds.status == "verified")
            .first()
        )

        if not pof:
            abort(404)

        user = db_session.query(User).filter(User.id == pof.user_id).first()
        tier = get_whale_tier(float(pof.total_btc))
        formatted_amount = format_btc_amount(float(pof.total_btc), pof.privacy_level)

        # Generate share URLs
        cert_url = url_for("pof.certificate", cert_id=cert_id, _external=True)
        twitter_text = f"I just verified my Bitcoin holdings on HODLXXI! {tier['emoji']} {tier['name']} status achieved. Proof: {cert_url}"
        twitter_url = f"https://twitter.com/intent/tweet?text={twitter_text}"

        return render_template(
            "pof/certificate.html",
            user=user,
            pof=pof,
            tier=tier,
            formatted_amount=formatted_amount,
            cert_url=cert_url,
            twitter_url=twitter_url,
        )
    except Exception as e:
        print(f"Error in certificate: {e}")
        abort(404)

    finally:
        try:
            db_session.close()
        except Exception:
            pass


@pof_bp.route("/verify")
def verify():
    """Main verification page"""
    return render_template("pof/verify.html", existing_pof=None, whale_tiers=WHALE_TIERS)
