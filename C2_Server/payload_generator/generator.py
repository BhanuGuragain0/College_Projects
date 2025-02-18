#!/usr/bin/env python3
"""
Enhanced Payload Generator

This script uses PyInstaller to create a one-file executable from your bot script
and then uses PyArmor to obfuscate the resulting bot code.

Ensure that:
  - "bot/bot.py" exists and is the correct path to your bot script.
  - PyInstaller and PyArmor are installed in your environment.
"""

import os
import subprocess
import logging
import PyInstaller.__main__

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def generate_payload():
    try:
        # Step 1: Generate executable with PyInstaller
        logging.info("Starting payload generation with PyInstaller...")
        PyInstaller.__main__.run([
            "bot/bot.py",        # Path to your bot script
            "--onefile",
            "--noconsole",
            "--name=bot"
        ])
        logging.info("PyInstaller payload generation complete.")
        
        # Step 2: Obfuscate the generated bot script with PyArmor
        # Note: Adjust the command if you need to obfuscate a different file.
        logging.info("Starting obfuscation with PyArmor...")
        result = subprocess.run(
            ["pyarmor", "obfuscate", "bot/bot.py"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logging.error(f"PyArmor obfuscation failed: {result.stderr}")
        else:
            logging.info("PyArmor obfuscation complete.")
    except Exception as e:
        logging.error(f"Error generating payload: {e}")

if __name__ == "__main__":
    generate_payload()
