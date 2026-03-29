"""WSGI entry point wired to the original Socket.IO runtime instance."""

# Chat/presence handlers are declared with @socketio.on(...) in app/app.py.
# Import both objects from that module so runtime and handler registration
# always share the same Socket.IO instance.
from app.app import app, socketio

# Gunicorn/uWSGI compatibility
application = app

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)
