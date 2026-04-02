from flask import redirect


def register_browser_routes(app):
    @app.route("/onboard", methods=["GET"], endpoint="onboard_alias")
    def onboard_alias():
        return redirect("/home#onboard")
