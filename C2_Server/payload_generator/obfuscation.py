#!/usr/bin/env python3
"""
Enhanced Obfuscation Utility

This script provides a function to obfuscate a specified Python file using PyArmor.
It verifies the file exists, runs the obfuscation command via subprocess, and logs output.
"""

import os
import subprocess
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def obfuscate_code(file_path):
    """
    Obfuscate the given file using PyArmor.

    Args:
        file_path (str): The path to the Python file to obfuscate.
    """
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return

    try:
        logging.info(f"Starting obfuscation of '{file_path}' with PyArmor...")
        result = subprocess.run(
            ["pyarmor", "obfuscate", file_path],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logging.error(f"Error during obfuscation: {result.stderr}")
        else:
            logging.info("Obfuscation complete.")
    except Exception as e:
        logging.error(f"Exception during obfuscation: {e}")

if __name__ == "__main__":
    # Example usage: obfuscate the bot script
    obfuscate_code("bot/bot.py")
