from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    current_app,
)

playground_bp = Blueprint("playground", __name__)


@playground_bp.route("/playground")
def playground():
    """
    Main playground page with all auth demos.
    This is just a UI shell; it talks to existing auth/PoF/LNURL/OAuth APIs.
    """
    logged_in_pubkey = session.get("logged_in_pubkey", "")
    access_level = session.get("access_level", "guest")

    issuer = (
        current_app.config.get("PUBLIC_ISSUER")
        or current_app.config.get("ISSUER")
        or request.url_root.rstrip("/")
    )

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
    Shortcut URLs for Proof-of-Funds that open the PoF tab in the playground.
    """
    return redirect(url_for("playground.playground", tab="pof"))


# OPTIONAL: keep your stats/activity demo if you like

@playground_bp.route("/api/playground/stats")
def playground_stats():
    """Live stats for playground demo UI (fake data for now)."""
    return jsonify(
        {
            "avgAuthTime": "3.2",
            "authsToday": 42,
            "countries": 12,
        }
    )


@playground_bp.route("/api/playground/activity")
def playground_activity():
    """Live activity feed demo."""
    activities = [
        {"user": "user_abc", "action": "verified funds", "location": "Tokyo"},
        {"user": "user_xyz", "action": "logged in via Lightning", "location": "Berlin"},
    ]
    return jsonify({"activities": activities})
