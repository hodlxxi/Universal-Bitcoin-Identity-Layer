"""
HODLXXI Proof of Funds Routes - Fixed for SQLAlchemy
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, abort
from functools import wraps
import hashlib
import secrets
import time
from datetime import datetime, timedelta
import json

# Import database session
from app.database import get_session
from app.models import ProofOfFunds, User

# Create blueprint
pof_bp = Blueprint('pof', __name__, url_prefix='/pof')

pof_api_bp = Blueprint('pof_api', __name__, url_prefix='/api/pof')

@pof_api_bp.route('/stats')
def pof_stats_api():
    """
    Minimal stub JSON stats endpoint.
    Later we can wire it to ProofOfFunds; for now it just proves the route exists.
    """
    return jsonify({
        "ok": True,
        "stats": {
            "total_attestations": 0,
            "active_attestations": 0,
            "unique_pubkeys": 0,
            "biggest_proof_sat": 0,
            "total_active_sat": 0,
            "last_attestation_ts": None,
        },
    })


@pof_api_bp.route('/leaderboard')
def pof_leaderboard_api():
    """
    Minimal stub JSON leaderboard endpoint.
    Later we can return real rows; for now just an empty list.
    """
    return jsonify({
        "ok": True,
        "leaderboard": [],
    })


def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Whale tier thresholds (in BTC)
WHALE_TIERS = [
    {'name': 'Shrimp', 'min': 0.0, 'max': 0.1, 'emoji': '🦐', 'color': '#94A3B8'},
    {'name': 'Crab', 'min': 0.1, 'max': 1.0, 'emoji': '🦀', 'color': '#F97316'},
    {'name': 'Dolphin', 'min': 1.0, 'max': 10.0, 'emoji': '🐬', 'color': '#3B82F6'},
    {'name': 'Shark', 'min': 10.0, 'max': 50.0, 'emoji': '🦈', 'color': '#8B5CF6'},
    {'name': 'Whale', 'min': 50.0, 'max': 100.0, 'emoji': '🐋', 'color': '#EC4899'},
    {'name': 'Humpback', 'min': 100.0, 'max': 1000.0, 'emoji': '🐳', 'color': '#F59E0B'},
    {'name': 'Blue Whale', 'min': 1000.0, 'max': float('inf'), 'emoji': '🌊', 'color': '#14B8A6'}
]

def get_whale_tier(btc_amount):
    """Determine whale tier based on BTC amount"""
    for tier in WHALE_TIERS:
        if tier['min'] <= btc_amount < tier['max']:
            return tier
    return WHALE_TIERS[-1]

def format_btc_amount(amount, privacy_level):
    """Format BTC amount based on privacy level"""
    if privacy_level == 'boolean':
        return "Verified ✓"
    elif privacy_level == 'threshold':
        tier = get_whale_tier(amount)
        return f"{tier['emoji']} {tier['name']}"
    elif privacy_level == 'aggregate':
        rounded = round(amount / 10) * 10
        return f"~{rounded} BTC"
    elif privacy_level == 'exact':
        return f"{amount:.8f} BTC"
    return "Hidden"


@pof_bp.route('/')
def landing():
    """PoF landing page - explain the feature"""
    return render_template('pof/landing.html')


@pof_bp.route('/leaderboard')
def leaderboard():
    """Privacy-preserving leaderboard"""
    db_session = get_session()
    
    try:
        # Only show users who have public privacy levels
        public_pofs = db_session.query(ProofOfFunds).filter(
            ProofOfFunds.status == 'verified',
            ProofOfFunds.privacy_level.in_(['threshold', 'aggregate', 'exact'])
        ).order_by(ProofOfFunds.total_btc.desc()).limit(100).all()
        
        leaderboard_data = []
        for pof in public_pofs:
            user = db_session.query(User).filter(User.id == pof.user_id).first()
            if user:
                tier = get_whale_tier(float(pof.total_btc))
                formatted_amount = format_btc_amount(float(pof.total_btc), pof.privacy_level)
                
                leaderboard_data.append({
                    'user': user,
                    'tier': tier,
                    'formatted_amount': formatted_amount,
                    'verified_at': pof.verified_at,
                    'certificate_id': pof.certificate_id
                })
        
        return render_template('pof/leaderboard.html',
                              leaderboard=leaderboard_data,
                              total_count=len(public_pofs))
    except Exception as e:
        print(f"Error in leaderboard: {e}")
        # Return empty leaderboard on error
        return render_template('pof/leaderboard.html',
                              leaderboard=[],
                              total_count=0)


@pof_bp.route('/certificate/<cert_id>')
def certificate(cert_id):
    """Shareable PoF certificate page"""
    db_session = get_session()
    
    try:
        pof = db_session.query(ProofOfFunds).filter(
            ProofOfFunds.certificate_id == cert_id,
            ProofOfFunds.status == 'verified'
        ).first()
        
        if not pof:
            abort(404)
        
        user = db_session.query(User).filter(User.id == pof.user_id).first()
        tier = get_whale_tier(float(pof.total_btc))
        formatted_amount = format_btc_amount(float(pof.total_btc), pof.privacy_level)
        
        # Generate share URLs
        cert_url = url_for('pof.certificate', cert_id=cert_id, _external=True)
        twitter_text = f"I just verified my Bitcoin holdings on HODLXXI! {tier['emoji']} {tier['name']} status achieved. Proof: {cert_url}"
        twitter_url = f"https://twitter.com/intent/tweet?text={twitter_text}"
        
        return render_template('pof/certificate.html',
                              user=user,
                              pof=pof,
                              tier=tier,
                              formatted_amount=formatted_amount,
                              cert_url=cert_url,
                              twitter_url=twitter_url)
    except Exception as e:
        print(f"Error in certificate: {e}")
        abort(404)


@pof_bp.route('/verify')
@login_required
def verify():
    """Main verification page"""
    return render_template('pof/verify.html', 
                          existing_pof=None,
                          whale_tiers=WHALE_TIERS)
