"""
WSGI entry point (staging): factory-based app.
This ensures all blueprints registered in app.factory are active (including Agent UBID).
"""
from app.factory import create_app

app = create_app()

# Gunicorn/uWSGI compatibility
application = app
