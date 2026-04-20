from __future__ import annotations


def _get_legacy():
    import importlib

    return importlib.import_module("app.app")


def register_legacy_routes(app):
    """
    Safe bridge: re-bind a handful of legacy handlers that still exist in app.app
    so factory-first runtime can serve the old endpoints again.
    """

    bindings = [
        ("/verify_pubkey_and_list", "verify_pubkey_and_list", "verify_pubkey_and_list", ["GET"]),
        ("/export_descriptors", "export_descriptors", "export_descriptors", ["GET"]),
        ("/api/whoami", "api_whoami", "api_whoami", ["GET"]),
        ("/api/public/status", "api_public_status", "api_public_status", ["GET"]),
        ("/api/ui/hide_manifesto", "api_hide_manifesto", "api_hide_manifesto", ["POST"]),
        ("/api/lnd/status", "api_lnd_status", "api_lnd_status", ["GET"]),
        ("/api/pubkey/resolve", "api_pubkey_resolve", "api_pubkey_resolve", ["GET"]),
        ("/import_descriptor", "import_descriptor", "import_descriptor", ["POST"]),
        ("/set_labels_from_zpub", "set_labels_from_zpub", "set_labels_from_zpub", ["POST"]),
        ("/new-index", "new_index_preview", "new_index_preview", ["GET"]),
        ("/docs2", "docs_viewer_v2", "docs_viewer_v2", ["GET"]),
    ]

    existing = {r.rule for r in app.url_map.iter_rules()}

    for rule, endpoint, view_func, methods in bindings:

        # ⚠️ defer legacy import until route is actually called
        def make_lazy_view(func_name):
            def _view(*args, **kwargs):
                import importlib

                legacy = importlib.import_module("app.app")
                return getattr(legacy, func_name)(*args, **kwargs)

            return _view

            def _view(*args, **kwargs):
                import importlib

                legacy = importlib.import_module("app.app")
                return getattr(legacy, func_name)(*args, **kwargs)

            return _view

        if rule in existing:
            continue
        app.add_url_rule(rule, endpoint, make_lazy_view(view_func), methods=methods)
