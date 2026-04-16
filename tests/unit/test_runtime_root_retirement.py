import inspect

from app.factory import create_app


def test_wsgi_is_factory_first():
    import wsgi

    source = inspect.getsource(wsgi)
    assert "from app.factory import create_app" in source
    assert "from app.app import app" not in source


def test_runtime_modules_no_longer_import_app_app():
    import app.socket_handlers as socket_handlers
    import app.stats_routes as stats_routes

    socket_source = inspect.getsource(socket_handlers)
    stats_source = inspect.getsource(stats_routes)

    assert "from app.app import" not in socket_source
    assert "from app.app import" not in stats_source


def test_factory_boot_initializes_socketio_runtime():
    app = create_app()

    socketio = app.extensions.get("socketio")
    assert socketio is not None

    handlers = socketio.server.handlers.get("/", {})
    assert "connect" in handlers
    assert "disconnect" in handlers
    assert "chat:send" in handlers
