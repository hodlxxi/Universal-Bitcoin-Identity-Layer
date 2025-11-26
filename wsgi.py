"""
WSGI entry point for standalone app.py
"""
from app.app import app

# Gunicorn/uWSGI compatibility
application = app

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
