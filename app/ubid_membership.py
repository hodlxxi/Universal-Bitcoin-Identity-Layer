from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from flask import current_app, redirect, session, url_for

DEFAULT_LOGIN_COST_SATS = 0  # legacy global override (prefer PAYG_ACTION_COSTS)
DEFAULT_TRIAL_DAYS = 7  # initial free trial window (days)
DEFAULT_PAYG_ACTION_COSTS = {"login": 1, "pof": 1, "other": 1}

# In-memory store: pubkey -> UbidUser
_USERS: Dict[str, "UbidUser"] = {}
_PENDING_INVOICES: Dict[str, Dict[str, object]] = {}


@dataclass
class UbidUser:
    """
    In-memory pubkey-based HODLXXI account.

    - pubkey          : primary cryptographic identity
    - plan            : 'free', 'paid', 'admin', 'expired', etc.
    - sats_balance    : for sats-metered login or API usage
    - membership_expires_at : optional expiry for membership
    - payg_enabled    : pay-as-you-go billing
    """

    pubkey: str
    plan: str = "free"
    sats_balance: int = 0
    membership_expires_at: Optional[datetime] = None
    payg_enabled: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login_at: datetime = field(default_factory=datetime.utcnow)

    def is_active_paid(self) -> bool:
        """Return True if user is on a paid/admin plan and not expired."""
        now = datetime.utcnow()
        if self.membership_expires_at and self.membership_expires_at < now:
            return False
        return self.plan in ("paid", "admin")


def ensure_membership_tables():
    """
    Placeholder for compatibility with earlier CLI helpers.
    In this in-memory version there is nothing to create.
    """
    return


def get_user(pubkey: str) -> Optional[UbidUser]:
    """Return an in-memory user for the given pubkey, if present."""
    return _USERS.get(pubkey)


def set_payg(pubkey: str, enabled: bool) -> UbidUser:
    """Enable or disable pay-as-you-go for a user."""
    user = _USERS.get(pubkey)
    if user is None:
        user = UbidUser(pubkey=pubkey)
        _USERS[pubkey] = user
    user.payg_enabled = enabled
    if enabled and user.plan == "free_trial":
        user.plan = "free"
    return user


def add_sats(pubkey: str, amount_sats: int) -> UbidUser:
    """Credit sats to the user's balance."""
    user = _USERS.get(pubkey)
    if user is None:
        user = UbidUser(pubkey=pubkey)
        _USERS[pubkey] = user
    user.sats_balance += max(int(amount_sats), 0)
    return user


def _get_action_costs() -> Dict[str, int]:
    override = current_app.config.get("PAYG_ACTION_COSTS")
    if isinstance(override, dict):
        return {**DEFAULT_PAYG_ACTION_COSTS, **override}
    return DEFAULT_PAYG_ACTION_COSTS


def charge_action(pubkey: str, action: str) -> Tuple[bool, str]:
    """Charge a pay-as-you-go action if enabled. Returns (ok, message)."""
    user = _USERS.get(pubkey)
    if not user or not user.payg_enabled:
        return True, "free"

    costs = _get_action_costs()
    cost = int(costs.get(action, costs.get("other", 0)))
    if cost <= 0:
        return True, "free"

    if user.sats_balance < cost:
        session["needs_topup"] = True
        return False, "insufficient_balance"

    user.sats_balance -= cost
    session.pop("needs_topup", None)
    return True, "charged"


def create_payg_invoice(pubkey: str, amount_sats: int, memo: str) -> Tuple[str, str]:
    """Create a Lightning invoice for pay-as-you-go balance topups."""
    from app.payments.ln import create_invoice

    amount_sats = max(int(amount_sats), 0)
    payment_request, invoice_id = create_invoice(
        amount_sats=amount_sats,
        memo=memo,
        user_pubkey=pubkey,
    )
    _PENDING_INVOICES[invoice_id] = {
        "pubkey": pubkey,
        "amount_sats": amount_sats,
        "created_at": datetime.utcnow(),
    }
    return payment_request, invoice_id


def settle_payg_invoice(invoice_id: str) -> Tuple[bool, Optional[UbidUser]]:
    """Check invoice status and credit the balance if paid."""
    if invoice_id not in _PENDING_INVOICES:
        return False, None

    from app.payments.ln import check_invoice_paid

    if not check_invoice_paid(invoice_id):
        return False, None

    entry = _PENDING_INVOICES.pop(invoice_id)
    user = add_sats(entry["pubkey"], int(entry["amount_sats"]))
    return True, user


def _touch_membership_expiry(user: UbidUser) -> None:
    """
    If user is on free_trial and has no expiry, set one.
    """
    if user.plan == "free_trial" and not user.membership_expires_at:
        days = int(current_app.config.get("TRIAL_DAYS", DEFAULT_TRIAL_DAYS))
        user.membership_expires_at = datetime.utcnow() + timedelta(days=days)


def on_successful_login(pubkey: str) -> UbidUser:
    """
    Call this from ANY place where you've successfully proven a user's pubkey.
    It will:
      * get/create UbidUser for that pubkey (in memory)
      * update last_login_at
      * put user info into session
      * optionally charge sats for the login
    """
    ensure_membership_tables()

    now = datetime.utcnow()

    user = _USERS.get(pubkey)
    if user is None:
        user = UbidUser(pubkey=pubkey, created_at=now, last_login_at=now)
        _touch_membership_expiry(user)
        _USERS[pubkey] = user
    else:
        user.last_login_at = now

    # Put into session
    session["logged_in_pubkey"] = pubkey
    # For this in-memory version, just use pubkey as "user_id"
    session["user_id"] = pubkey
    session["plan"] = user.plan
    session["payg_enabled"] = user.payg_enabled

    # Optional pay-as-you-go login charge
    if user.payg_enabled:
        ok, _ = charge_action(pubkey, "login")
        if not ok:
            session["needs_topup"] = True
    else:
        # Legacy global cost if enabled
        cost = int(current_app.config.get("LOGIN_COST_SATS", DEFAULT_LOGIN_COST_SATS))
        if cost > 0:
            if user.sats_balance < cost:
                # not enough sats; mark for topup
                session["needs_topup"] = True
            else:
                user.sats_balance -= cost
                session.pop("needs_topup", None)

    return user


def require_login() -> Optional[UbidUser]:
    """
    Return current UbidUser or None.
    Used for pages that require *any* authenticated user.
    """
    ensure_membership_tables()

    pubkey = session.get("logged_in_pubkey")
    if not pubkey:
        return None
    return _USERS.get(pubkey)


def require_paid_user():
    """
    Return (user, redirect_response_or_None).

    - If not logged in -> redirect to playground_page.
    - If logged in but not paid -> redirect to upgrade page.
    - If paid/admin -> (user, None).
    """
    ensure_membership_tables()

    user = require_login()
    if user is None:
        # endpoint for /playground is 'playground_page' in your app
        return None, redirect(url_for("playground_page"))

    # update plan if membership expired
    now = datetime.utcnow()
    if user.membership_expires_at and user.membership_expires_at < now:
        if user.plan not in ("admin",):
            user.plan = "expired"

    if not user.is_active_paid():
        return user, redirect(url_for("upgrade"))

    return user, None
