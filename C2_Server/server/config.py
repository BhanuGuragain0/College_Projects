# server/config.py
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")
    DB_NAME = os.getenv("DB_NAME", "c2_server.db")
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/var/c2_uploads")
    MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "10485760"))
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "32byteslongsecretkeyhere!!!")
    BOT_CHECKIN_INTERVAL = int(os.getenv("BOT_CHECKIN_INTERVAL", "60"))
    PLUGINS_FOLDER = os.getenv("PLUGINS_FOLDER", "server/plugins")
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "alert@example.com")
