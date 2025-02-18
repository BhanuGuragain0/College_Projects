# server/tasks.py
import shlex
from celery import Celery
import sqlite3
import subprocess
import json
import logging
from .config import Config
from .encryption import SecureEncryption

celery = Celery('tasks', broker=Config.CELERY_BROKER_URL)
celery.conf.update(result_backend=Config.CELERY_RESULT_BACKEND)

# Encryption instance for tasks
encryption = SecureEncryption(Config.ENCRYPTION_KEY.encode())

@celery.task(bind=True)
def execute_command(self, bot_id, command):
    try:
        logging.info(f"Executing command: {command} for bot {bot_id}")
        # Allow plugin commands: if command starts with "plugin:" then delegate to a plugin
        if command.startswith("plugin:"):
            plugin_name, _, plugin_args = command.partition(":")[2].partition(" ")
            from .plugins_loader import PLUGINS
            if plugin_name in PLUGINS:
                result = PLUGINS[plugin_name].run({"bot_id": bot_id, "args": plugin_args})
            else:
                result = {"error": f"Plugin {plugin_name} not found."}
            result_json = json.dumps(result)
        else:
            cmd_list = shlex.split(command)
            result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=30)
            result_json = json.dumps({
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            })
        encrypted_result = encryption.encrypt(result_json)
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO tasks (bot_id, command, result, status) VALUES (?, ?, ?, ?)",
                      (bot_id, command, encrypted_result, "completed"))
            conn.commit()
        return encrypted_result
    except Exception as e:
        logging.error(f"Error executing command: {command}. Exception: {str(e)}")
        error_json = json.dumps({"error": str(e)})
        encrypted_error = encryption.encrypt(error_json)
        with sqlite3.connect(Config.DB_NAME) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO tasks (bot_id, command, result, status) VALUES (?, ?, ?, ?)",
                      (bot_id, command, encrypted_error, "failed"))
            conn.commit()
        return encrypted_error
