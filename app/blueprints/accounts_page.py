from flask import Blueprint, render_template, session, redirect, url_for

bp = Blueprint("accounts_page", __name__)


@bp.route("/accounts", methods=["GET"])
def accounts():
    if not session.get("logged_in_pubkey"):
        return redirect(url_for("login", next="/accounts"))

    pk = session.get("logged_in_pubkey") or ""
    short_pk = (pk[:12] + "…") if isinstance(pk, str) and len(pk) > 12 else pk

    return render_template(
        "account.html",
        pubkey=pk,
        short_pk=short_pk,
        access_level=session.get("access_level", "limited"),
        guest_label=session.get("guest_label"),
    )
