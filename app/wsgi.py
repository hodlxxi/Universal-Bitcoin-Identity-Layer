# /srv/ubid/app/wsgi.py

import eventlet
eventlet.monkey_patch()

from app import app  # adjust if your app is created via factory

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    import eventlet.wsgi
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
