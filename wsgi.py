"""WSGI entry point for HODLXXI."""

from app.factory import create_app

app = create_app()

# Gunicorn/uWSGI compatibility
application = app

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
