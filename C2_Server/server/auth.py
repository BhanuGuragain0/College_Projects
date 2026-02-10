# server/auth.py
import os
import datetime
import logging
import jwt
from flask_login import LoginManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .config import Config

login_manager = LoginManager()

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    import sqlite3
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

class AuthManager:
    SECRET_KEY = Config.SECRET_KEY.encode()

    @staticmethod
    def generate_token(user_id):
        payload = {'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
        return jwt.encode(payload, AuthManager.SECRET_KEY, algorithm='HS256')

    @staticmethod
    def verify_token(token):
        try:
            decoded = jwt.decode(token, AuthManager.SECRET_KEY, algorithms=['HS256'])
            return decoded['user_id']
        except jwt.ExpiredSignatureError:
            logging.warning("Token expired.")
            return None
        except jwt.InvalidTokenError:
            logging.error("Invalid token.")
            return None
