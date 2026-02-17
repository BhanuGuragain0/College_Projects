"""
Payload Templates Package for SecureComm C2

This package contains JSON payload template definitions for various
operational scenarios. Templates are loaded dynamically by the
PayloadTemplateManager in payload_loader.py
"""

from pathlib import Path

# Package directory
PACKAGE_DIR = Path(__file__).parent

# List all available template files
__all__ = [
    "basic_recon",
    "persistence_setup", 
    "credential_harvest",
    "network_pivot",
    "data_exfiltration",
    "windows_recon"
]

# Template file extensions
TEMPLATE_EXTENSION = ".json"

def get_template_path(template_id: str) -> Path:
    """Get the full path to a template file"""
    return PACKAGE_DIR / f"{template_id}{TEMPLATE_EXTENSION}"

def list_available_templates() -> list:
    """List all available template IDs"""
    return [
        f.stem for f in PACKAGE_DIR.glob(f"*{TEMPLATE_EXTENSION}")
        if f.is_file()
    ]
