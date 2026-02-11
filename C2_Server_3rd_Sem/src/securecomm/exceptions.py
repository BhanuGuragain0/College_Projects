"""
SecureComm Custom Exceptions

Comprehensive exception hierarchy for SecureComm framework.
All exceptions inherit from SecureCommError for consistent handling.

Author: SecureComm Team
Version: 2.0.0
"""

from __future__ import annotations
from typing import Optional


class SecureCommError(Exception):
    """
    Base exception for all SecureComm errors.
    
    All other SecureComm exceptions inherit from this class,
    allowing callers to catch all framework errors with:
        try:
            ...
        except SecureCommError as e:
            handle_error(e)
    """
    
    def __init__(self, message: str, details: Optional[dict] = None):
        """
        Initialize SecureCommError.
        
        Args:
            message: Human-readable error message
            details: Optional dict with additional error context
        """
        self.message = message
        self.details = details or {}
        super().__init__(message)


class AuthenticationError(SecureCommError):
    """
    Raised when authentication fails.
    
    Raised when:
    - Certificate validation fails
    - Token is invalid or expired
    - Signature verification fails
    - Credentials are incorrect
    """
    pass


class AuthorizationError(SecureCommError):
    """
    Raised when authorization check fails.
    
    Raised when:
    - Operator lacks required permissions
    - Agent is not authorized for operation
    - Role-based access control denies action
    """
    pass


class ValidationError(SecureCommError):
    """
    Raised when input validation fails.
    
    Raised when:
    - Input parameters are invalid
    - Command type is not whitelisted
    - File path contains traversal attempts
    - Payload format is incorrect
    """
    pass


class CryptographicError(SecureCommError):
    """
    Raised when cryptographic operation fails.
    
    Raised when:
    - Encryption/decryption fails
    - Key generation fails
    - Signature verification fails
    - Key derivation fails
    - ECDH key exchange fails
    """
    pass


class NetworkError(SecureCommError):
    """
    Raised when network operation fails.
    
    Raised when:
    - Socket operation fails
    - TLS handshake fails
    - Connection timeout
    - Peer connection lost
    - Message framing error
    """
    pass


class PersistenceError(SecureCommError):
    """
    Raised when persistence operation fails.
    
    Raised when:
    - Persistence installation fails
    - Registry/cron operations fail
    - Persistence cleanup fails
    - OS-specific operations fail
    """
    pass


class FileTransferError(SecureCommError):
    """
    Raised during file upload/download.
    
    Raised when:
    - File size exceeds limits
    - Checksum validation fails
    - Path resolution fails
    - File I/O fails
    - Permission denied
    """
    pass


class SessionError(SecureCommError):
    """
    Raised when session management fails.
    
    Raised when:
    - Session creation fails
    - Session key derivation fails
    - Key rotation fails
    - Session not found
    - Session expired
    """
    pass


class CommandExecutionError(SecureCommError):
    """
    Raised during command execution.
    
    Raised when:
    - Command execution times out
    - Command fails with error
    - Process launch fails
    - Command validation fails
    """
    pass


class PKIError(SecureCommError):
    """
    Raised during PKI operations.
    
    Raised when:
    - Certificate generation fails
    - Certificate validation fails
    - CA operations fail
    - CRL operations fail
    - Certificate loading fails
    """
    pass


class StealthError(SecureCommError):
    """
    Raised when stealth/evasion fails.
    
    Raised when:
    - Debugger detection triggers
    - Sandbox detection triggers
    - Anti-analysis fails
    - Stealth check fails
    """
    pass


class DatabaseError(SecureCommError):
    """
    Raised during database operations.
    
    Raised when:
    - Database I/O fails
    - JSON deserialization fails
    - Record creation fails
    - Data corruption detected
    """
    pass


class ConfigurationError(SecureCommError):
    """
    Raised when configuration is invalid.
    
    Raised when:
    - Required configuration missing
    - Configuration values invalid
    - Environment variables not set
    - Configuration file corrupted
    """
    pass


class RateLimitError(SecureCommError):
    """
    Raised when rate limit exceeded.
    
    Raised when:
    - Request rate exceeds limit
    - Agent command rate exceeds limit
    - Replay attack detected
    - Too many failed attempts
    """
    pass


def raise_if_invalid(condition: bool, exception_class: type[SecureCommError], 
                     message: str, details: Optional[dict] = None) -> None:
    """
    Raise exception if condition is True.
    
    Helper function for cleaner conditional exception raising.
    
    Args:
        condition: If True, exception is raised
        exception_class: Exception class to raise
        message: Exception message
        details: Additional error context
    
    Example:
        >>> raise_if_invalid(len(key) != 32, ValidationError, 
        ...                  "Key must be 32 bytes")
    """
    if condition:
        raise exception_class(message, details)
