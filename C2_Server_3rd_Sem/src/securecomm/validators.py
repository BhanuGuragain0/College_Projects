"""
SecureComm Input Validation

Comprehensive input validation with whitelist enforcement
and security-focused checks.

Author: SecureComm Team
Version: 1.0.0
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional, Set, Dict, Any
import re
from .exceptions import ValidationError


class InputValidator:
    """Comprehensive input validation system."""
    
    # Whitelist of allowed command types
    ALLOWED_COMMAND_TYPES: Set[str] = {
        'exec', 'upload', 'download', 'persist', 
        'rotate', 'scan', 'heartbeat'
    }
    
    # Whitelist of allowed command properties
    ALLOWED_COMMAND_PROPS: Set[str] = {
        'type', 'payload', 'path', 'timeout', 'priority'
    }
    
    # Agent ID pattern (alphanumeric, underscore, hyphen, period)
    AGENT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
    
    # File path pattern (prevent directory traversal)
    PATH_TRAVERSAL_PATTERNS = {'..', '///', '\\\\', '~', '$'}
    
    @staticmethod
    def validate_agent_id(agent_id: str, max_length: int = 128) -> str:
        """
        Validate agent ID format.
        
        Args:
            agent_id: Agent identifier string
            max_length: Maximum allowed length
        
        Returns:
            Validated agent ID (trimmed)
        
        Raises:
            ValidationError: If agent_id is invalid
        """
        if not isinstance(agent_id, str):
            raise ValidationError(
                f"Agent ID must be string, got {type(agent_id).__name__}",
                {"type": type(agent_id).__name__}
            )
        
        agent_id = agent_id.strip()
        
        if not agent_id:
            raise ValidationError("Agent ID cannot be empty")
        
        if len(agent_id) > max_length:
            raise ValidationError(
                f"Agent ID exceeds {max_length} characters",
                {"length": len(agent_id), "max": max_length}
            )
        
        # Whitelist safe characters
        if not InputValidator.AGENT_ID_PATTERN.match(agent_id):
            raise ValidationError(
                f"Agent ID contains invalid characters: {agent_id}. "
                f"Allowed: alphanumeric, underscore, hyphen, period"
            )
        
        return agent_id
    
    @staticmethod
    def validate_command_type(cmd_type: str) -> str:
        """
        Validate command type against whitelist.
        
        Args:
            cmd_type: Command type string
        
        Returns:
            Validated command type (lowercase)
        
        Raises:
            ValidationError: If cmd_type not in whitelist
        """
        if not isinstance(cmd_type, str):
            raise ValidationError(f"Command type must be string")
        
        cmd_type = cmd_type.strip().lower()
        
        if not cmd_type:
            raise ValidationError("Command type cannot be empty")
        
        if cmd_type not in InputValidator.ALLOWED_COMMAND_TYPES:
            raise ValidationError(
                f"Invalid command type: {cmd_type}. "
                f"Allowed: {', '.join(InputValidator.ALLOWED_COMMAND_TYPES)}",
                {"requested": cmd_type, "allowed": list(InputValidator.ALLOWED_COMMAND_TYPES)}
            )
        
        return cmd_type
    
    @staticmethod
    def validate_file_path(filepath: str, max_length: int = 1024) -> Path:
        """
        Validate file path with security checks.
        
        Prevents:
        - Directory traversal (..)
        - Absolute paths (/)
        - Home directory (~)
        - Environment variables ($)
        - UNC paths (///)
        
        Args:
            filepath: File path string
            max_length: Maximum path length
        
        Returns:
            Validated Path object
        
        Raises:
            ValidationError: If path is invalid or suspicious
        """
        if not isinstance(filepath, str):
            raise ValidationError("File path must be string")
        
        filepath = filepath.strip()
        
        if not filepath:
            raise ValidationError("File path cannot be empty")
        
        if len(filepath) > max_length:
            raise ValidationError(
                f"File path exceeds {max_length} characters",
                {"length": len(filepath), "max": max_length}
            )
        
        # Check for path traversal attempts
        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            if pattern in filepath:
                raise ValidationError(
                    f"Path traversal detected (contains '{pattern}'): {filepath}"
                )
        
        # Reject absolute paths
        if filepath.startswith('/') or filepath.startswith('\\'):
            raise ValidationError(f"Absolute paths not allowed: {filepath}")
        
        # Reject null bytes
        if '\x00' in filepath:
            raise ValidationError("Path contains null bytes")
        
        try:
            path = Path(filepath).resolve()
        except (ValueError, OSError) as e:
            raise ValidationError(f"Invalid path: {e}")
        
        return path
    
    @staticmethod
    def validate_command_payload(payload: str, max_length: int = 4096) -> str:
        """
        Validate command payload.
        
        Args:
            payload: Command payload string
            max_length: Maximum payload length
        
        Returns:
            Validated payload (trimmed)
        
        Raises:
            ValidationError: If payload is invalid
        """
        if not isinstance(payload, str):
            raise ValidationError("Payload must be string")
        
        if len(payload) > max_length:
            raise ValidationError(
                f"Payload exceeds {max_length} characters",
                {"length": len(payload), "max": max_length}
            )
        
        # Reject null bytes
        if '\x00' in payload:
            raise ValidationError("Payload contains null bytes")
        
        # Reject control characters (except tab, newline, carriage return)
        for i, char in enumerate(payload):
            if ord(char) < 32 and char not in '\t\n\r':
                raise ValidationError(
                    f"Payload contains control character at position {i}"
                )
        
        return payload
    
    @staticmethod
    def validate_token(token: str, min_length: int = 32) -> str:
        """
        Validate authentication token.
        
        Args:
            token: Token string
            min_length: Minimum token length
        
        Returns:
            Validated token (trimmed)
        
        Raises:
            ValidationError: If token invalid
        """
        if not isinstance(token, str):
            raise ValidationError("Token must be string")
        
        token = token.strip()
        
        if not token:
            raise ValidationError("Token cannot be empty")
        
        if len(token) < min_length:
            raise ValidationError(
                f"Token too short (minimum {min_length} characters)"
            )
        
        # Token should only contain alphanumeric and safe characters
        if not re.match(r'^[a-zA-Z0-9._-]+$', token):
            raise ValidationError("Token contains invalid characters")
        
        return token
    
    @staticmethod
    def validate_hostname(hostname: str, max_length: int = 253) -> str:
        """
        Validate hostname or IP address.
        
        Args:
            hostname: Hostname or IP string
            max_length: Maximum hostname length
        
        Returns:
            Validated hostname (trimmed)
        
        Raises:
            ValidationError: If hostname invalid
        """
        if not isinstance(hostname, str):
            raise ValidationError("Hostname must be string")
        
        hostname = hostname.strip().lower()
        
        if not hostname:
            raise ValidationError("Hostname cannot be empty")
        
        if len(hostname) > max_length:
            raise ValidationError(f"Hostname exceeds {max_length} characters")
        
        # Reject localhost for remote connections
        if hostname in ('localhost', '127.0.0.1', '::1'):
            raise ValidationError("Cannot connect to localhost")
        
        return hostname
    
    @staticmethod
    def validate_port(port: int, allow_privileged: bool = False) -> int:
        """
        Validate port number.
        
        Args:
            port: Port number
            allow_privileged: Allow ports < 1024 (default: False)
        
        Returns:
            Validated port number
        
        Raises:
            ValidationError: If port invalid
        """
        if not isinstance(port, int):
            raise ValidationError(f"Port must be integer, got {type(port).__name__}")
        
        if port < 1 or port > 65535:
            raise ValidationError(
                f"Port out of range (1-65535): {port}",
                {"port": port, "min": 1, "max": 65535}
            )
        
        if port < 1024 and not allow_privileged:
            raise ValidationError(
                f"Privileged port (< 1024) not allowed: {port}"
            )
        
        return port
    
    @staticmethod
    def validate_timeout(timeout: int, min_seconds: int = 1, 
                        max_seconds: int = 3600) -> int:
        """
        Validate timeout value.
        
        Args:
            timeout: Timeout in seconds
            min_seconds: Minimum allowed timeout
            max_seconds: Maximum allowed timeout
        
        Returns:
            Validated timeout
        
        Raises:
            ValidationError: If timeout invalid
        """
        if not isinstance(timeout, int):
            raise ValidationError("Timeout must be integer")
        
        if timeout < min_seconds:
            raise ValidationError(
                f"Timeout too low (minimum {min_seconds}s): {timeout}s"
            )
        
        if timeout > max_seconds:
            raise ValidationError(
                f"Timeout too high (maximum {max_seconds}s): {timeout}s"
            )
        
        return timeout


def validate_json_structure(data: Any, schema: Dict[str, Any]) -> None:
    """
    Validate JSON data against schema.
    
    Args:
        data: JSON data to validate
        schema: Validation schema
    
    Raises:
        ValidationError: If data invalid
    
    Example:
        >>> schema = {
        ...     'type': 'dict',
        ...     'fields': {
        ...         'agent_id': {'type': 'string', 'required': True},
        ...         'timeout': {'type': 'int', 'required': False}
        ...     }
        ... }
    """
    if not isinstance(data, dict):
        raise ValidationError("Data must be dictionary")
    
    required_fields = [
        name for name, field in schema.get('fields', {}).items()
        if field.get('required', False)
    ]
    
    for field in required_fields:
        if field not in data:
            raise ValidationError(f"Required field missing: {field}")
