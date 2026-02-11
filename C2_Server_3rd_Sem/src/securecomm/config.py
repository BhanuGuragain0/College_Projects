"""
SecureComm Configuration
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base Paths
BASE_DIR = Path(__file__).parent.parent.parent
DATA_DIR = BASE_DIR / "data"

# Operational database and audit logs
OPERATIONAL_DB_PATH = Path(os.getenv("SECURECOMM_OP_DB_PATH", DATA_DIR / "operational_db.json"))
AUDIT_LOG_DIR = Path(os.getenv("SECURECOMM_AUDIT_LOG_DIR", DATA_DIR / "logs"))

# PKI Configuration
PKI_PATH = Path(os.getenv("PKI_PATH", DATA_DIR / "pki"))
CA_PATH = PKI_PATH / "ca"
OPERATORS_PATH = PKI_PATH / "operators"
AGENTS_PATH = PKI_PATH / "agents"
CRL_PATH = PKI_PATH / "crl"

# Network Configuration
DEFAULT_PORT = int(os.getenv("NETWORK_PORT", 8443))
DEFAULT_HOST = os.getenv("NETWORK_HOST", "0.0.0.0")

# Cryptography Configuration
SESSION_KEY_ROTATION_COUNT = int(os.getenv("SESSION_KEY_ROTATION_COUNT", 100))
SESSION_KEY_ROTATION_TIME = int(os.getenv("SESSION_KEY_ROTATION_TIME", 3600))  # 1 hour

# Dashboard configuration
DASHBOARD_HOST = os.getenv("SECURECOMM_DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.getenv("SECURECOMM_DASHBOARD_PORT", 8080))
DASHBOARD_REFRESH_SECONDS = int(os.getenv("SECURECOMM_DASHBOARD_REFRESH", 5))
DASHBOARD_TOKEN = os.getenv("SECURECOMM_DASHBOARD_TOKEN", "").strip() if os.getenv("SECURECOMM_DASHBOARD_TOKEN") else None
DASHBOARD_EMBEDDED = os.getenv("SECURECOMM_DASHBOARD_EMBEDDED", "false").lower() in {
    "1",
    "true",
    "yes",
}

# Agent file transfer configuration
AGENT_FILES_DIR = Path(os.getenv("SECURECOMM_AGENT_FILES_DIR", DATA_DIR / "agent_files"))
OPERATOR_FILES_DIR = Path(os.getenv("SECURECOMM_OPERATOR_FILES_DIR", DATA_DIR / "operator_files"))
MAX_TRANSFER_BYTES = int(os.getenv("SECURECOMM_MAX_TRANSFER_BYTES", 65536))
MAX_TRANSFER_PAYLOAD = int(os.getenv("SECURECOMM_MAX_TRANSFER_PAYLOAD", MAX_TRANSFER_BYTES * 2))

# Exec allowlist configuration
EXEC_ALLOWLIST = [
    cmd.strip()
    for cmd in os.getenv(
        "SECURECOMM_EXEC_ALLOWLIST",
        "echo,whoami,hostname,id,uname,uptime,pwd,ls",
    ).split(",")
    if cmd.strip()
]
EXEC_TIMEOUT = int(os.getenv("SECURECOMM_EXEC_TIMEOUT", 5))
EXEC_MAX_OUTPUT_BYTES = int(os.getenv("SECURECOMM_EXEC_MAX_OUTPUT_BYTES", 4096))

# Persistence policy (explicit opt-in)
PERSISTENCE_ALLOWED = os.getenv("SECURECOMM_ENABLE_PERSISTENCE", "false").lower() in {"1", "true", "yes"}
