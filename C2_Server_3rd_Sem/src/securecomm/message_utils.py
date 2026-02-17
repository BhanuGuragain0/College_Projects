"""
Message utilities for SecureComm academic workflows.
Provides canonical JSON encoding and signature payload helpers.
"""

from __future__ import annotations

import json
from typing import Iterable, Mapping

COMMAND_SIGNATURE_FIELDS = (
    "task_id",
    "operator_id",
    "type",
    "payload",
    "nonce",
    "timestamp",
)

RESPONSE_SIGNATURE_FIELDS = (
    "task_id",
    "agent_id",
    "status",
    "result",
    "nonce",
    "timestamp",
)

CHECKIN_SIGNATURE_FIELDS = (
    "agent_id",
    "nonce",
    "timestamp",
)

HANDSHAKE_SIGNATURE_FIELDS = (
    "agent_id",
    "ecdh_public_key",
    "nonce",
    "timestamp",
)

ROTATION_REQUEST_SIGNATURE_FIELDS = (
    "rotation_id",
    "operator_id",
    "agent_id",
    "ecdh_public_key",
    "nonce",
    "timestamp",
)

ROTATION_RESPONSE_SIGNATURE_FIELDS = (
    "rotation_id",
    "agent_id",
    "ecdh_public_key",
    "nonce",
    "timestamp",
)


def canonical_json(data: Mapping[str, object]) -> bytes:
    """Serialize data in a deterministic JSON format for signing."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def signature_payload(data: Mapping[str, object], fields: Iterable[str]) -> bytes:
    """Build canonical JSON from selected fields for signing/verification."""
    payload = {field: data[field] for field in fields}
    return canonical_json(payload)


def create_message(
    msg_type: str,
    payload: dict,
    agent_id: str | None = None,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict:
    """Create a standardized message envelope for secure communication.
    
    Args:
        msg_type: Message type (e.g., 'command', 'response', 'beacon')
        payload: Message payload data
        agent_id: Optional agent identifier
        timestamp: Optional ISO timestamp (generated if not provided)
        nonce: Optional nonce (generated if not provided)
    
    Returns:
        Standardized message dictionary
    """
    import secrets
    from datetime import datetime, timezone
    
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    
    if nonce is None:
        nonce = secrets.token_hex(16)
    
    message = {
        "version": "3.0",
        "type": msg_type,
        "timestamp": timestamp,
        "nonce": nonce,
        "payload": payload,
    }
    
    if agent_id:
        message["agent_id"] = agent_id
    
    return message


def parse_message(data: bytes | str) -> dict:
    """Parse a message from bytes or string.
    
    Args:
        data: Raw message data (JSON bytes or string)
    
    Returns:
        Parsed message dictionary
    
    Raises:
        ValueError: If message format is invalid
    """
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        
        message = json.loads(data)
        
        # Validate required fields
        if not isinstance(message, dict):
            raise ValueError("Message must be a JSON object")
        
        if "type" not in message:
            raise ValueError("Message missing required 'type' field")
        
        return message
    
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
    except Exception as e:
        raise ValueError(f"Message parsing failed: {e}")
