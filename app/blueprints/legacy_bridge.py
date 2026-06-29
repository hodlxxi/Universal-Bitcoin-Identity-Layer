from __future__ import annotations


def _get_legacy():
    import importlib

    return importlib.import_module("app.app")


def _require_full_user_session():
    from flask import jsonify, session

    if not session.get("logged_in_pubkey"):
        return jsonify(error="unauthorized"), 401
    if session.get("access_level") != "full":
        return jsonify(error="forbidden"), 403
    return None


def register_covenant_wallet_routes(app):
    """Register authenticated full-user covenant wallet product routes.

    These routes are distinct from unsafe legacy wallet/API surfaces and do not
    depend on ENABLE_LEGACY_WALLET_ROUTES.
    """

    @app.route("/rpc/<cmd>", methods=["GET"])
    def browser_rpc(cmd):
        guard = _require_full_user_session()
        if guard:
            return guard
        from flask import jsonify, request

        from app.utils import get_rpc_connection

        rpc = get_rpc_connection()
        allowed = {
            "getwalletinfo": lambda: rpc.getwalletinfo(),
            "listdescriptors": lambda: rpc.listdescriptors(),
            "getreceivedbylabel": lambda: rpc.getreceivedbylabel(request.args.get("p", "")),
            "listtransactions": lambda: rpc.listtransactions(),
            "listunspent": lambda: rpc.listunspent(),
            "listreceivedbylabel": lambda: rpc.listreceivedbylabel(),
            "listreceivedbyaddress": lambda: rpc.listreceivedbyaddress(),
            "listaddressgroupings": lambda: rpc.listaddressgroupings(),
            "listlabels": lambda: rpc.listlabels(),
            "getbalance": lambda: rpc.getbalance(),
            "getblockcount": lambda: rpc.getblockcount(),
            "rescanblockchain": lambda: rpc.rescanblockchain(),
        }

        if cmd not in allowed:
            return jsonify({"error": f"Unsupported RPC method `{cmd}`"}), 400

        try:
            return jsonify(allowed[cmd]())
        except Exception:
            import logging

            logging.getLogger(__name__).error("browser_rpc failed", exc_info=True)
            return jsonify({"error": "Internal server error"}), 500

    bindings = [
        ("/export_descriptors", "export_descriptors", "export_descriptors", ["GET"]),
        ("/import_descriptor", "import_descriptor", "import_descriptor", ["POST"]),
        ("/set_labels_from_zpub", "set_labels_from_zpub", "set_labels_from_zpub", ["POST"]),
    ]
    existing = {r.rule for r in app.url_map.iter_rules()}

    for rule, endpoint, view_func, methods in bindings:
        if rule in existing:
            continue

        def make_full_user_view(func_name):
            def _view(*args, **kwargs):
                guard = _require_full_user_session()
                if guard:
                    return guard
                legacy = _get_legacy()
                return getattr(legacy, func_name)(*args, **kwargs)

            return _view

        app.add_url_rule(rule, endpoint, make_full_user_view(view_func), methods=methods)


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
