"""
SecureComm - Red Team Encrypted C2 Framework
Military-grade encryption for ethical hacking operations

Author: Shadow Junior (Bhanu Guragain)
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Shadow Junior"

from .pki_manager import PKIManager
from .crypto_engine import CryptoEngine
from .operator import OperatorConsole
from .agent import SecureAgent

__all__ = [
    'PKIManager',
    'CryptoEngine',
    'OperatorConsole',
    'SecureAgent'
]
