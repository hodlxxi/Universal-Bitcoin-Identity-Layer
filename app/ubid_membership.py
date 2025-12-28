from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict

from flask import current_app, session, redirect, url_for

DEFAULT_LOGIN_COST_SATS = 0          # set >0 via app.config["LOGIN_COST_SATS"] to enable sats-metered login
DEFAULT_TRIAL_DAYS = 7               # initial free trial window (days)

# In-memory store: pubkey -> UbidUser
_USERS: Dict[str, "UbidUser"] = {}


@dataclass
class UbidUser:
    """
    In-memory pubkey-based HODLXXI account.

    - pubkey          : primary cryptographic identity
    - plan            : 'free_trial', 'paid', 'admin', 'expired', etc.
    - sats_balance    : for sats-metered login or API usage
    - membership_expires_at : optional expiry for membership
    """
    pubkey: str
    plan: str = "free_trial"
    sats_balance: int = 0
    membership_expires_at: Optional[datetime] = None
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

    # Optional sats-metered login
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
