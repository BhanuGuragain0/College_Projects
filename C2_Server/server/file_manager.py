# server/file_manager.py
import os
from werkzeug.utils import secure_filename
from flask import send_file, jsonify
from .config import Config

def allowed_file(filename):
    allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def upload_file(file):
    if file.content_length > Config.MAX_FILE_SIZE:
        return jsonify({"status": "error", "message": "File size exceeds limit"})
    if not allowed_file(file.filename):
        return jsonify({"status": "error", "message": "File type not allowed"})
    filename = secure_filename(file.filename)
    file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
    file.save(file_path)
    return jsonify({"status": "success", "filename": filename})

def download_file(filename):
    file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
    return send_file(file_path, as_attachment=True)
