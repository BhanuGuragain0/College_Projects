# server/tasks.py
"""
Celery Tasks for Command Execution

CRITICAL: This module handles bot command execution and result storage.
All results are encrypted before storage and database access uses context managers.
"""

import shlex
import subprocess
import sqlite3
import json
import logging
from datetime import datetime
from celery import Celery
from .config import Config
from .shared_encryption import SecureEncryption

logging.basicConfig(level=logging.INFO)

celery = Celery('tasks', broker=Config.CELERY_BROKER_URL)
celery.conf.update(
    result_backend=Config.CELERY_RESULT_BACKEND,
    result_expires=Config.CELERY_RESULT_EXPIRES,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json'
)

# Encryption instance for task results
encryption = SecureEncryption(Config.ENCRYPTION_KEY)

@celery.task(bind=True, max_retries=3)
def execute_command(self, bot_id, command):
    """
    Execute a command for a given bot and store encrypted result.
    
    IMPORTANT: This task:
    - Validates bot_id before execution
    - Uses subprocess.run with shell=False (safe)
    - Implements proper error handling
    - Encrypts results before storage
    - Uses database context managers
    - Has automatic retry on failure
    
    Args:
        bot_id (int): ID of the bot to execute command on
        command (str): Command string to execute
        
    Returns:
        dict: Result with status, encrypted_result/error
    """
    try:
        # Validate inputs
        if not isinstance(bot_id, int) or bot_id <= 0:
            raise ValueError(f"Invalid bot_id: {bot_id}")
        
        if not isinstance(command, str) or not command.strip():
            raise ValueError("Command cannot be empty")
        
        if len(command) > 10000:
            raise ValueError("Command exceeds maximum length (10000 chars)")
        
        logging.info(f"Executing command for bot {bot_id}: {command[:100]}")
        
        # Check if command is for plugin system
        if command.startswith("plugin:"):
            return _execute_plugin_command(bot_id, command)
        
        # Execute regular system command
        return _execute_system_command(bot_id, command)
        
    except Exception as e:
        logging.error(f"Error executing command for bot {bot_id}: {str(e)}")
        
        # Store error result in database
        try:
            error_result = {
                "error": str(e),
                "status": "error",
                "timestamp": datetime.now().isoformat()
            }
            encrypted_error = encryption.encrypt(json.dumps(error_result))
            
            with sqlite3.connect(Config.DB_NAME) as conn:
                c = conn.cursor()
                c.execute(
                    """INSERT INTO tasks (bot_id, command, result, status) 
                       VALUES (?, ?, ?, ?)""",
                    (bot_id, command, encrypted_error, "failed")
                )
                conn.commit()
        except Exception as db_error:
            logging.error(f"Failed to store error result: {db_error}")
        
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=min(2 ** self.request.retries, 600))

def _execute_system_command(bot_id, command):
    """
    Execute a system command safely using subprocess.
    
    Args:
        bot_id (int): Bot ID for logging
        command (str): Command to execute
        
    Returns:
        dict: Encrypted result stored in database
    """
    try:
        # Parse command safely
        cmd_list = shlex.split(command)
        
        # Execute with timeout
        result = subprocess.run(
            cmd_list,
            shell=False,  # SECURITY: Never use shell=True
            capture_output=True,
            text=True,
            timeout=30
        )
        
        result_data = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "status": "success",
            "timestamp": datetime.now().isoformat()
        }
        result_json = json.dumps(result_data)
        
    except subprocess.TimeoutExpired:
        result_data = {
            "error": "Command execution timeout (30 seconds)",
            "status": "timeout",
            "timestamp": datetime.now().isoformat()
        }
        result_json = json.dumps(result_data)
        
    except ValueError as e:
        result_data = {
            "error": f"Invalid command format: {str(e)}",
            "status": "error",
            "timestamp": datetime.now().isoformat()
        }
        result_json = json.dumps(result_data)
        
    except Exception as e:
        result_data = {
            "error": f"Execution error: {str(e)}",
            "status": "error",
            "timestamp": datetime.now().isoformat()
        }
        result_json = json.dumps(result_data)
    
    # Encrypt result
    try:
        encrypted_result = encryption.encrypt(result_json)
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        encrypted_result = encryption.encrypt(json.dumps({"error": "Encryption failed"}))
    
    # Store in database with context manager
    try:
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            status = result_data.get("status", "completed")
            c.execute(
                """INSERT INTO tasks (bot_id, command, result, status) 
                   VALUES (?, ?, ?, ?)""",
                (bot_id, command, encrypted_result, status)
            )
            conn.commit()
        logging.info(f"Task stored for bot {bot_id} with status: {status}")
    except sqlite3.Error as e:
        logging.error(f"Database error storing task result: {e}")
    
    return {"status": "stored", "encrypted_result": encrypted_result}

def _execute_plugin_command(bot_id, command):
    """
    Execute a plugin command from the plugin system.
    
    Format: plugin:plugin_name args
    """
    try:
        # Parse plugin command
        parts = command.split(":", 1)
        if len(parts) != 2:
            raise ValueError("Invalid plugin command format")
        
        _, plugin_spec = parts
        plugin_parts = plugin_spec.split(None, 1)
        plugin_name = plugin_parts[0]
        plugin_args = plugin_parts[1] if len(plugin_parts) > 1 else ""
        
        # Load plugins
        from .plugins_loader import PLUGINS
        
        if plugin_name not in PLUGINS:
            raise ValueError(f"Plugin '{plugin_name}' not found")
        
        # Execute plugin
        plugin_module = PLUGINS[plugin_name]
        if not hasattr(plugin_module, 'run'):
            raise ValueError(f"Plugin '{plugin_name}' has no 'run' function")
        
        result_data = plugin_module.run({
            "bot_id": bot_id,
            "args": plugin_args
        })
        
        if not isinstance(result_data, dict):
            result_data = {"output": str(result_data), "status": "success"}
        else:
            result_data["status"] = result_data.get("status", "success")
        
        result_data["timestamp"] = datetime.now().isoformat()
        result_json = json.dumps(result_data)
        
    except Exception as e:
        logging.error(f"Plugin execution error: {e}")
        result_data = {
            "error": f"Plugin error: {str(e)}",
            "status": "error",
            "timestamp": datetime.now().isoformat()
        }
        result_json = json.dumps(result_data)
    
    # Encrypt and store
    try:
        encrypted_result = encryption.encrypt(result_json)
    except Exception as e:
        logging.error(f"Encryption failed for plugin result: {e}")
        encrypted_result = encryption.encrypt(json.dumps({"error": "Encryption failed"}))
    
    try:
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            status = result_data.get("status", "completed")
            c.execute(
                """INSERT INTO tasks (bot_id, command, result, status) 
                   VALUES (?, ?, ?, ?)""",
                (bot_id, command, encrypted_result, status)
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error storing plugin result: {e}")
    
    return {"status": "stored", "encrypted_result": encrypted_result}

def get_task_result(task_id, encryption_instance=None):
    """
    Retrieve and decrypt a stored task result.
    
    Args:
        task_id (int): Task ID to retrieve
        encryption_instance: SecureEncryption instance (uses default if None)
        
    Returns:
        dict: Decrypted result or None if not found
    """
    enc = encryption_instance or encryption
    
    try:
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT result FROM tasks WHERE id=?", (task_id,))
            result = c.fetchone()
        
        if not result:
            return None
        
        try:
            decrypted_result = enc.decrypt(result[0])
            return json.loads(decrypted_result)
        except Exception as e:
            logging.error(f"Failed to decrypt task result {task_id}: {e}")
            return None
            
    except Exception as e:
        logging.error(f"Error retrieving task result {task_id}: {e}")
        return None

