"""Factory-owned browser compatibility helpers.

These helpers preserve legacy browser URLs while keeping the implementations
out of app.app so blueprints can remain canonical runtime owners.
"""

from __future__ import annotations

from flask import redirect, render_template, request, session
from jinja2 import TemplateNotFound
from werkzeug.routing import BuildError


def render_upgrade_page():
    if not session.get("logged_in_pubkey"):
        return redirect(f"/login?next={request.path}")

    pk = session.get("logged_in_pubkey") or ""
    short_pk = (pk[:12] + "…") if isinstance(pk, str) and len(pk) > 12 else pk

    return render_template(
        "upgrade.html",
        pubkey=pk,
        short_pk=short_pk,
        access_level=session.get("access_level", "limited"),
        guest_label=session.get("guest_label"),
    )


def render_account_page():
    if not session.get("logged_in_pubkey"):
        return redirect(f"/login?next={request.path}")

    try:
        pk = session.get("logged_in_pubkey") or ""
        short_pk = (pk[:12] + "…") if isinstance(pk, str) and len(pk) > 12 else pk
        return render_template(
            "account.html",
            pubkey=pk,
            short_pk=short_pk,
            access_level=session.get("access_level", "limited"),
            guest_label=session.get("guest_label"),
        )
    except (TemplateNotFound, BuildError) as e:
        pub = session.get("logged_in_pubkey", "")
        lvl = session.get("access_level", "")
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>Account</title></head>"
            "<body style='font-family:system-ui;padding:24px'>"
            "<h1>Account</h1>"
            f"<p><b>pubkey</b>: {pub}</p>"
            f"<p><b>access</b>: {lvl}</p>"
            f"<p style='color:#b00'><b>Template/endpoint issue</b>: {e}</p>"
            "<p>/account route restored. Fix account.html url_for() endpoint names.</p>"
            "</body></html>"
        )


def redirect_explorer():
    return redirect("/home#explorer")


def redirect_onboard():
    return redirect("/home#onboard")


def redirect_oneword():
    # legacy / typo route - keep backwards compatibility
    return redirect("/home")
