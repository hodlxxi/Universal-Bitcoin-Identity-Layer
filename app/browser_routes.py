"""Browser/human-facing route registrations.

Keeps runtime ownership in app.app while isolating browser route handlers.
"""

from __future__ import annotations


def chat():
    from . import app as app_module

    return app_module._browser_chat()


def login():
    from . import app as app_module

    return app_module._browser_login()


def home_page():
    from . import app as app_module

    return app_module._browser_home_page()


def explorer_alias():
    from . import app as app_module

    return app_module._browser_explorer_alias()


def onboard_alias():
    from . import app as app_module

    return app_module._browser_onboard_alias()


def oneword_alias():
    from . import app as app_module

    return app_module._browser_oneword_alias()


def logout():
    from . import app as app_module

    return app_module._browser_logout()


def root_redirect():
    from . import app as app_module

    return app_module._browser_root_redirect()


def playground():
    from . import app as app_module

    return app_module._browser_playground()


def register_browser_routes(app):
    """Register browser/human-facing routes on the shared app runtime."""

    app.add_url_rule("/", view_func=root_redirect, methods=["GET"])
    app.add_url_rule("/login", view_func=login, methods=["GET"])
    app.add_url_rule("/logout", view_func=logout)
    app.add_url_rule("/home", endpoint="home", view_func=home_page, methods=["GET"])
    app.add_url_rule("/app", view_func=chat)
    app.add_url_rule("/explorer", view_func=explorer_alias, methods=["GET"])
    app.add_url_rule("/onboard", view_func=onboard_alias, methods=["GET"])
    app.add_url_rule("/oneword", view_func=oneword_alias, methods=["GET"])
    app.add_url_rule("/playground", view_func=playground, methods=["GET"])
