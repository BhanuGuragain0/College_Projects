# server/task_manager.py
import threading
import sqlite3
import json
import logging
from .config import Config
from .encryption import SecureEncryption

class TaskManager:
    def __init__(self):
        self.tasks = []

    def add_task(self, func, *args):
        task_thread = threading.Thread(target=func, args=args, daemon=True)
        task_thread.start()
        self.tasks.append(task_thread)
        logging.info(f"Task {func.__name__} started.")

    def wait_for_completion(self):
        for task in self.tasks:
            task.join()

def get_task_result(task_id, encryption: SecureEncryption):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT result FROM tasks WHERE id=?", (task_id,))
    result = c.fetchone()
    conn.close()
    if result:
        try:
            decrypted_result = encryption.decrypt(result[0])
            return json.loads(decrypted_result)
        except Exception as e:
            logging.error(f"Error decrypting task result: {e}")
    return None
