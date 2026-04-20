from __future__ import annotations


def register_legacy_routes(app):
    """
    Safe bridge: re-bind a handful of legacy handlers that still exist in app.app
    so factory-first runtime can serve the old endpoints again.
    """

    import app.app as legacy

    bindings = [
        ("/verify_pubkey_and_list", "verify_pubkey_and_list", legacy.verify_pubkey_and_list, ["GET"]),
        ("/export_descriptors", "export_descriptors", legacy.export_descriptors, ["GET"]),
        ("/api/whoami", "api_whoami", legacy.api_whoami, ["GET"]),
        ("/api/lnd/status", "api_lnd_status", legacy.api_lnd_status, ["GET"]),
        ("/api/pubkey/resolve", "api_pubkey_resolve", legacy.api_pubkey_resolve, ["GET"]),
        ("/import_descriptor", "import_descriptor", legacy.import_descriptor, ["POST"]),
        ("/set_labels_from_zpub", "set_labels_from_zpub", legacy.set_labels_from_zpub, ["POST"]),
        ("/new-index", "new_index_preview", legacy.new_index_preview, ["GET"]),
        ("/docs2", "docs_viewer_v2", legacy.docs_viewer_v2, ["GET"]),
    ]

    existing = {r.rule for r in app.url_map.iter_rules()}

    for rule, endpoint, view_func, methods in bindings:
        if rule in existing:
            continue
        app.add_url_rule(rule, endpoint, view_func, methods=methods)
