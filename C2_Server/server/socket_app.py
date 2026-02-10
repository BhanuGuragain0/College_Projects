# server/socket_app.py
from flask import Flask
from flask_socketio import SocketIO, emit
from .config import Config
import sqlite3

app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(app)

@socketio.on('connect')
def handle_connect():
    emit('message', {'data': 'Connected to real-time C2 dashboard'})

@socketio.on('request_update')
def handle_request_update():
    # Example: Send updated bots and tasks data
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM bots")
    bots = c.fetchall()
    c.execute("SELECT * FROM tasks")
    tasks = c.fetchall()
    conn.close()
    emit('update', {'bots': bots, 'tasks': tasks})

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5001)
