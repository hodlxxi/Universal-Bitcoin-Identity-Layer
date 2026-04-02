from flask import redirect


def register_browser_routes(app):
    @app.route("/explorer", methods=["GET"], endpoint="explorer_alias")
    def explorer_alias():
        return redirect("/home#explorer")
