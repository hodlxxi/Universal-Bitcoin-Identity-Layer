"""Transitional compatibility registration for legacy human/browser routes.

This module intentionally keeps the existing human HTML flow from ``app.app``
while the app moves to a factory-first boot path.
"""

from __future__ import annotations

import importlib
import logging

from flask import Flask

logger = logging.getLogger(__name__)

# Transitional documentation only (do not enforce here):
# these legacy handlers depend on monolith boot wiring in app.app, including
# before_request hooks, session keys, SocketIO globals, and helper modules.
MONOLITH_DEPENDENCIES = (
    "before_request guards/redirects defined in app.app",
    "session keys such as logged_in_pubkey/access_level/guest_label",
    "legacy helper globals and RPC utilities initialized in app.app",
    "SocketIO/chat in-memory globals used by /app",
)


def register_legacy_human_routes(app: Flask) -> None:
    """Register/override human-facing legacy routes on a factory app.

    Behavior-preserving extraction:
    - keep existing paths/templates/session behavior by delegating to app.app
    - avoid touching API/agent/LN/OAuth routes
    """

    # Import safety: explicitly import the legacy module object, not package attrs.
    legacy_app_module = importlib.import_module("app.app")

    def _bind_endpoint(endpoint: str, view_func) -> None:
        if endpoint in app.view_functions:
            app.view_functions[endpoint] = view_func

    def _bind_route_path(route_path: str, view_func) -> None:
        """Bind any existing endpoint currently serving route_path to view_func."""
        for rule in app.url_map.iter_rules():
            if str(rule) == route_path and rule.endpoint in app.view_functions:
                app.view_functions[rule.endpoint] = view_func

    def _route_exists(route_path: str) -> bool:
        return any(str(rule) == route_path for rule in app.url_map.iter_rules())

    def _endpoint_exists(endpoint: str) -> bool:
        return any(rule.endpoint == endpoint for rule in app.url_map.iter_rules())

    def _ensure_route(route_path: str, endpoint: str, view_func, methods=None) -> None:
        if _route_exists(route_path):
            return
        kwargs = {"endpoint": endpoint, "view_func": view_func}
        if methods is not None:
            kwargs["methods"] = methods
        app.add_url_rule(route_path, **kwargs)

    # Prefer path-based rebinding so endpoint renames won't break compatibility.
    _bind_route_path("/", legacy_app_module.root_redirect)
    _bind_route_path("/screensaver", legacy_app_module.screensaver)
    _bind_route_path("/app", legacy_app_module.chat)
    _bind_route_path("/home", legacy_app_module.home_page)
    _bind_route_path("/playground", legacy_app_module.playground)
    _bind_route_path("/account", legacy_app_module.account)
    _bind_route_path("/login", legacy_app_module.login)
    _bind_route_path("/logout", legacy_app_module.logout)

    # Endpoint-name fallbacks for compatibility with known current blueprints.
    _bind_endpoint("ui.index", legacy_app_module.root_redirect)
    _bind_endpoint("ui.screensaver", legacy_app_module.screensaver)
    _bind_endpoint("ui.legacy_chat_route", legacy_app_module.chat)
    _bind_endpoint("ui.home", legacy_app_module.home_page)
    _bind_endpoint("home", legacy_app_module.home_page)
    _bind_endpoint("ui.playground", legacy_app_module.playground)
    _bind_endpoint("ui.legacy_account_route", legacy_app_module.account)
    _bind_endpoint("auth.login", legacy_app_module.login)
    _bind_endpoint("auth.logout", legacy_app_module.logout)

    # Register missing legacy navigation routes directly (no blueprint migration).
    _ensure_route("/explorer", "legacy_explorer_alias", legacy_app_module.explorer_alias)
    _ensure_route("/onboard", "legacy_onboard_alias", legacy_app_module.onboard_alias)
    _ensure_route("/oneword", "legacy_oneword_alias", legacy_app_module.oneword_alias)
    _ensure_route("/upgrade", "legacy_upgrade", legacy_app_module.upgrade, methods=["GET", "POST"])
    _ensure_route("/playground/", "legacy_playground_slash_alias", legacy_app_module.playground_slash_alias)

    # Legacy templates call url_for("home"). Keep explicit endpoint alias intact.
    if not _endpoint_exists("home"):
        app.add_url_rule("/home", endpoint="home", view_func=legacy_app_module.home_page, methods=["GET"])
    if not _endpoint_exists("login"):
        app.add_url_rule("/login", endpoint="login", view_func=legacy_app_module.login, methods=["GET"])
    logger.info("✓ Legacy human routes registered (transitional compatibility)")
