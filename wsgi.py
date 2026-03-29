"""WSGI entry point — CORRECT for Flask-SocketIO + Gunicorn"""

from app.app import app, socketio

# ✅ Gunicorn должен видеть Flask app
application = app

# ✅ Локальный запуск (не влияет на gunicorn)
if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000)
