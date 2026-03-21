"""Canonical WSGI entry point for HODLXXI deployments."""

from app.factory import create_app

app = create_app()
application = app

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
