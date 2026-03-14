from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for

playground_bp = Blueprint("playground", __name__)
# Compatibility/demo routes only: canonical runtime ownership for /playground remains in app/app.py.


@playground_bp.route("/playground")
def playground():
    """
    Compatibility playground page with auth demos.
    Canonical production handler is app.app.playground; this module is a compatibility/demo surface.
    """
    logged_in_pubkey = session.get("logged_in_pubkey", "")
    access_level = session.get("access_level", "guest")

    issuer = current_app.config.get("PUBLIC_ISSUER") or current_app.config.get("ISSUER") or request.url_root.rstrip("/")

    # which tab to show first: legacy / api / lnurl / oauth / pof
    initial_tab = request.args.get("tab", "legacy")

    return render_template(
        "playground.html",
        logged_in_pubkey=logged_in_pubkey,
        access_level=access_level,
        issuer=issuer,
        initial_tab=initial_tab,
    )


@playground_bp.route("/pof")
@playground_bp.route("/pof/verify")
def pof_entry():
    """
    Compatibility shortcuts that open the PoF tab in playground.
    """
    return redirect(url_for("playground.playground", tab="pof"))


# OPTIONAL: keep your stats/activity demo if you like


@playground_bp.route("/api/playground/stats")
def playground_stats():
    """Demo-only/fake stats for playground UI (non-canonical metrics)."""
    return jsonify(
        {
            "avgAuthTime": "3.2",
            "authsToday": 42,
            "countries": 12,
        }
    )


@playground_bp.route("/api/playground/activity")
def playground_activity():
    """Demo-only/fake activity feed (not production telemetry)."""
    activities = [
        {"user": "user_abc", "action": "verified funds", "location": "Tokyo"},
        {"user": "user_xyz", "action": "logged in via Lightning", "location": "Berlin"},
    ]
    return jsonify({"activities": activities})
