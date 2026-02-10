#!/bin/bash
# scripts/deploy.sh
# Deployment script for the C2 server

# Ensure the uploads folder exists
mkdir -p $(python -c "from dotenv import load_dotenv; load_dotenv(); import os; print(os.getenv('UPLOAD_FOLDER'))")

echo "Starting C2 server with Gunicorn..."
# Start the Flask server with Gunicorn
gunicorn -w 4 server.app:app
