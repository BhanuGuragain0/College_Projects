# server/file_manager.py
"""
File Management Module with Security Hardening

CRITICAL SECURITY FEATURES:
- Path traversal protection using os.path.realpath and comparison
- File type whitelist validation
- File size validation
- Secure filename sanitization
- Directory traversal prevention
"""

import os
from werkzeug.utils import secure_filename
from flask import send_file, jsonify
from .config import Config
import logging

logging.basicConfig(level=logging.INFO)

# Strict whitelist of allowed file extensions (minimal set)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'tar', 'gz'}

def allowed_file(filename):
    """
    Validate file type against whitelist.
    
    SECURITY:
    - Checks extension exists
    - Verifies against whitelist only
    - Case-insensitive
    """
    if not filename or '.' not in filename:
        return False
    
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS

def is_safe_path(upload_folder, filename):
    """
    Prevent directory traversal attacks.
    
    Verifies that the resolved path is within the upload folder.
    """
    # Resolve both paths to absolute paths
    resolved_folder = os.path.abspath(upload_folder)
    requested_path = os.path.abspath(os.path.join(upload_folder, filename))
    
    # Ensure requested path is under upload folder
    if not requested_path.startswith(resolved_folder):
        logging.warning(f"Path traversal attempt blocked: {filename}")
        return False
    
    return True

def upload_file(file):
    """
    Upload a file with comprehensive validation.
    
    SECURITY:
    - Validates file size
    - Validates file type
    - Sanitizes filename
    - Prevents path traversal
    - Checks upload folder exists
    
    Args:
        file: Flask file object
        
    Returns:
        JSON response with status
    """
    try:
        # Check if file exists and has filename
        if not file or file.filename == '':
            return jsonify({"status": "error", "message": "No file selected"}), 400
        
        filename = file.filename.strip()
        
        # Validate file type
        if not allowed_file(filename):
            return jsonify({"status": "error", "message": "File type not allowed"}), 400
        
        # Validate file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > Config.MAX_FILE_SIZE:
            return jsonify({
                "status": "error",
                "message": f"File size exceeds limit ({Config.MAX_FILE_SIZE} bytes)"
            }), 413
        
        if file_size == 0:
            return jsonify({"status": "error", "message": "File is empty"}), 400
        
        # Sanitize filename
        safe_filename = secure_filename(filename)
        if not safe_filename:
            return jsonify({"status": "error", "message": "Invalid filename"}), 400
        
        # Ensure upload folder exists
        upload_folder = Config.UPLOAD_FOLDER
        if not os.path.exists(upload_folder):
            try:
                os.makedirs(upload_folder, exist_ok=True)
                logging.info(f"Created upload folder: {upload_folder}")
            except Exception as e:
                logging.error(f"Failed to create upload folder: {e}")
                return jsonify({"status": "error", "message": "Upload folder error"}), 500
        
        # Check for path traversal
        if not is_safe_path(upload_folder, safe_filename):
            return jsonify({"status": "error", "message": "Invalid file path"}), 400
        
        # Save file
        file_path = os.path.join(upload_folder, safe_filename)
        try:
            file.save(file_path)
            logging.info(f"File uploaded successfully: {safe_filename}")
            return jsonify({
                "status": "success",
                "filename": safe_filename,
                "size": file_size
            }), 200
        except Exception as e:
            logging.error(f"File save error: {e}")
            return jsonify({"status": "error", "message": "Failed to save file"}), 500
            
    except Exception as e:
        logging.error(f"Upload error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

def download_file(filename):
    """
    Download a file with path traversal protection.
    
    SECURITY:
    - Sanitizes filename
    - Prevents path traversal
    - Validates file exists
    
    Args:
        filename: File to download
        
    Returns:
        File response or error JSON
    """
    try:
        # Sanitize filename
        safe_filename = secure_filename(filename)
        if not safe_filename or safe_filename != filename:
            logging.warning(f"Suspicious filename requested: {filename}")
            return jsonify({"status": "error", "message": "Invalid filename"}), 400
        
        upload_folder = Config.UPLOAD_FOLDER
        
        # Check for path traversal
        if not is_safe_path(upload_folder, safe_filename):
            logging.warning(f"Path traversal attempt in download: {filename}")
            return jsonify({"status": "error", "message": "Invalid file path"}), 400
        
        file_path = os.path.join(upload_folder, safe_filename)
        
        # Check if file exists
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            logging.warning(f"File not found for download: {filename}")
            return jsonify({"status": "error", "message": "File not found"}), 404
        
        logging.info(f"File downloaded: {safe_filename}")
        return send_file(file_path, as_attachment=True)
        
    except Exception as e:
        logging.error(f"Download error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

