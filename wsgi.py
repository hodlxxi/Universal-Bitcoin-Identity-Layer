"""
WSGI Entry Point for Universal Bitcoin Identity Layer

This module creates the Flask application using the factory pattern
for production deployment with Gunicorn, uWSGI, or other WSGI servers.
"""

# Option 1: Use new modular factory (recommended)
from app.factory import create_app

app = create_app()

# Option 2: Use legacy monolithic app (deprecated, for backward compatibility)
# from app.app import create_app as legacy_create_app
# app = legacy_create_app()

# Gunicorn/uWSGI compatibility
application = app

if __name__ == "__main__":
    # Development server (DO NOT use in production)
    app.run(host="127.0.0.1", port=5000, debug=False)
