# server/models.py
import sqlite3
from .config import Config

DB_NAME = Config.DB_NAME

def init_db():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    # Bots table
    c.execute('''CREATE TABLE IF NOT EXISTS bots
                 (id INTEGER PRIMARY KEY, ip TEXT, os TEXT, last_seen TEXT, group_name TEXT, public_key TEXT)''')
    # Tasks table
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY, bot_id INTEGER, command TEXT, result TEXT, status TEXT)''')
    # Users table (for authentication)
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized.")
