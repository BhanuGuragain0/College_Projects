# server/config.py
import os
import sys
import logging
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

class Config:
    # ===== CRITICAL CONFIGURATION PARAMETERS =====
    
    # Secret key for Flask session management - MUST be set in production
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        logging.error("CRITICAL: SECRET_KEY environment variable not set!")
        sys.exit(1)
    
    # Database configuration
    DB_NAME = os.getenv("DB_NAME", "c2_server.db")
    
    # Redis configuration for Celery task queue
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    
    # File upload configuration
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/tmp/c2_uploads")
    MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "10485760"))  # 10MB default
    
    # ENCRYPTION_KEY - MUST be 32 bytes (256-bit) for AES-256
    # Format: Base64-encoded string (will be decoded at runtime)
    _encryption_key_env = os.getenv("ENCRYPTION_KEY")
    if not _encryption_key_env:
        logging.error("CRITICAL: ENCRYPTION_KEY environment variable not set!")
        logging.error("Generate 32 random bytes: python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())'")
        sys.exit(1)
    
    try:
        import base64
        ENCRYPTION_KEY = base64.b64decode(_encryption_key_env)
        if len(ENCRYPTION_KEY) != 32:
            raise ValueError(f"ENCRYPTION_KEY must decode to 32 bytes, got {len(ENCRYPTION_KEY)}")
    except Exception as e:
        logging.error(f"CRITICAL: Invalid ENCRYPTION_KEY format: {e}")
        sys.exit(1)
    
    # Bot checkin interval (seconds)
    BOT_CHECKIN_INTERVAL = int(os.getenv("BOT_CHECKIN_INTERVAL", "60"))
    
    # Plugin configuration
    PLUGINS_FOLDER = os.getenv("PLUGINS_FOLDER", "server/plugins")
    
    # Alert email for critical events
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "alert@example.com")
    
    # Celery task result cleanup (seconds)
    CELERY_RESULT_EXPIRES = int(os.getenv("CELERY_RESULT_EXPIRES", "3600"))  # 1 hour
    
    # Rate limiting configuration (requests per period)
    RATE_LIMIT_CHECKIN = os.getenv("RATE_LIMIT_CHECKIN", "10 per minute")
    RATE_LIMIT_COMMAND = os.getenv("RATE_LIMIT_COMMAND", "100 per hour")
    RATE_LIMIT_UPLOAD = os.getenv("RATE_LIMIT_UPLOAD", "50 per hour")
    
    @classmethod
    def validate(cls):
        """Validate all critical configuration parameters."""
        required_folders = [cls.UPLOAD_FOLDER, cls.PLUGINS_FOLDER]
        for folder in required_folders:
            if not os.path.exists(folder):
                try:
                    os.makedirs(folder, exist_ok=True)
                    logging.info(f"Created directory: {folder}")
                except Exception as e:
                    logging.error(f"Failed to create directory {folder}: {e}")
                    return False
        return True
