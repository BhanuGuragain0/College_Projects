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
