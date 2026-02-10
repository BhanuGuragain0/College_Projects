#!/bin/bash
# scripts/setup.sh
# Setup script for the C2 server

echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Initializing database..."
python -m server.models
