"""
SecureComm command handler for authenticated operator-agent workflows.

Academic/ethical use only.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .auth_gateway import AuthGateway, AuthToken
from .config import MAX_TRANSFER_PAYLOAD
from .crypto_engine import CryptoEngine
from .message_utils import (
    COMMAND_SIGNATURE_FIELDS,
    HANDSHAKE_SIGNATURE_FIELDS,
    RESPONSE_SIGNATURE_FIELDS,
    ROTATION_REQUEST_SIGNATURE_FIELDS,
    ROTATION_RESPONSE_SIGNATURE_FIELDS,
    canonical_json,
    signature_payload,
)
from .operational_db import AgentRecord, CommandRecord, OperationalDatabase
from .security import SecurityModule, SecurityError
from .session import SessionManager

CertificateValidator = Callable[[x509.Certificate], None]


@dataclass
class RotationState:
    agent_id: str
    crypto: CryptoEngine
    requested_at: datetime


class CommandHandler:
    """Handle authenticated SecureComm command workflows."""

    def __init__(
        self,
        operator_id: str,
        operator_signing_key: ed25519.Ed25519PrivateKey,
        sessions: SessionManager,
        security: SecurityModule,
        operational_db: OperationalDatabase,
        audit_logger: Optional[object] = None,
        auth_gateway: Optional[AuthGateway] = None,
        certificate_validator: Optional[CertificateValidator] = None,
    ) -> None:
        self.operator_id = operator_id
        self._operator_signing_key = operator_signing_key
        self.sessions = sessions
        self.security = security
        self.operational_db = operational_db
        self.auth_gateway = auth_gateway
        self.certificate_validator = certificate_validator
        self._logger = logging.getLogger(__name__)
        self._audit = audit_logger
        self._agent_certificates: Dict[str, x509.Certificate] = {}
        self._agent_public_keys: Dict[str, ed25519.Ed25519PublicKey] = {}
        self._pending_rotations: Dict[str, RotationState] = {}
        self._crypto = CryptoEngine()

    def handle_handshake(
        self,
        payload: Dict[str, object],
        peer_certificate: x509.Certificate,
        client_address: Tuple[str, int],
    ) -> Tuple[str, Dict[str, object]]:
        """Validate handshake, create a session, and return response payload."""
        self._validate_certificate(peer_certificate)
        self.security.validate_handshake(payload)
        agent_id = str(payload.get("agent_id", ""))
        if not agent_id:
            raise ValueError("Handshake missing agent_id")
        cn = peer_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn != agent_id:
            raise ValueError("Agent ID does not match certificate CN")
        self._require_fields(payload, HANDSHAKE_SIGNATURE_FIELDS)
        self._validate_nonce_timestamp(payload)
        self._verify_signature(
            payload,
            payload.get("signature"),
            peer_certificate.public_key(),
            HANDSHAKE_SIGNATURE_FIELDS,
            "handshake",
        )
        agent_public_key_bytes = self._decode_hex_field(payload, "ecdh_public_key", 64)
        session_key, operator_public = self._derive_session_key(agent_public_key_bytes)
        self.sessions.create_session(agent_id, session_key, ecdh_public=agent_public_key_bytes)
        fingerprint = self._certificate_fingerprint(peer_certificate)
        subject = peer_certificate.subject.rfc4514_string()
        now = datetime.now(timezone.utc)
        self.operational_db.register_agent(
            AgentRecord(
                agent_id=agent_id,
                ip_address=client_address[0],
                status="connected",
                connected_at=now,
                last_seen=now,
                certificate_fingerprint=fingerprint,
                certificate_subject=subject,
            )
        )
        self._agent_certificates[agent_id] = peer_certificate
        self._agent_public_keys[agent_id] = peer_certificate.public_key()
        response = {
            "agent_id": agent_id,
            "ecdh_public_key": operator_public.hex(),
            "nonce": self._crypto.generate_nonce(),
            "timestamp": int(time.time()),
        }
        response_signature = self._sign_payload(response, HANDSHAKE_SIGNATURE_FIELDS)
        response["signature"] = response_signature.hex()
        if self._audit:
            self._audit.log_connection(
                agent_id,
                "handshake",
                {"ip": client_address[0], "fingerprint": fingerprint},
            )
        return agent_id, response

    def create_command_payload(
        self,
        agent_id: str,
        cmd_type: str,
        payload: str,
        auth_token: Optional[str] = None,
    ) -> Dict[str, object]:
        """Build a signed, encrypted command payload for an agent."""
        session = self.sessions.get_session(agent_id)
        if not session:
            raise ValueError(f"No active session for agent {agent_id}")
        self._validate_operator_token(auth_token)
        is_transfer = cmd_type in {"upload", "download"}
        max_length = MAX_TRANSFER_PAYLOAD if is_transfer else 4096
        sanitized_payload = self.security.sanitize_input(
            payload,
            max_length=max_length,
            allow_binary=is_transfer,
        )
        task_id = uuid.uuid4().hex
        command = {
            "task_id": task_id,
            "operator_id": self.operator_id,
            "agent_id": agent_id,
            "type": cmd_type,
            "payload": sanitized_payload,
            "nonce": self._crypto.generate_nonce(),
            "timestamp": int(time.time()),
        }
        signature = self._sign_payload(command, COMMAND_SIGNATURE_FIELDS)
        command["signature"] = signature.hex()
        encrypted = self._crypto.encrypt_message(canonical_json(command), session.session_key)
        self.sessions.record_command(agent_id, command["nonce"])
        self.operational_db.record_command(
            CommandRecord(
                task_id=task_id,
                operator_id=self.operator_id,
                agent_id=agent_id,
                command_type=cmd_type,
                payload=sanitized_payload,
                nonce=command["nonce"],
                timestamp=command["timestamp"],
                signature=signature.hex(),
            )
        )
        if self._audit:
            self._audit.log_command(
                agent_id=agent_id,
                cmd_type=cmd_type,
                payload=sanitized_payload,
                task_id=task_id,
                operator_id=self.operator_id,
            )
        return {"task_id": task_id, "encrypted_command": encrypted.hex()}

    def handle_command_response(self, agent_id: str, payload: Dict[str, object]) -> Dict[str, object]:
        """Decrypt and verify a command response from an agent."""
        session = self.sessions.get_session(agent_id)
        if not session:
            raise ValueError(f"No active session for agent {agent_id}")
        encrypted_response = self._decode_hex_field(payload, "encrypted_response")
        decrypted = self._crypto.decrypt_message(encrypted_response, session.session_key)
        response = self._json_load(decrypted)
        self.security.validate_response(response)
        self._require_fields(response, RESPONSE_SIGNATURE_FIELDS)
        if str(response.get("agent_id")) != agent_id:
            raise ValueError("Agent ID mismatch in response")
        self._validate_nonce_timestamp(response)
        public_key = self._agent_public_keys.get(agent_id)
        if not public_key:
            raise ValueError(f"Missing public key for agent {agent_id}")
        self._verify_signature(
            response,
            response.get("signature"),
            public_key,
            RESPONSE_SIGNATURE_FIELDS,
            "response",
        )
        task_id = str(response["task_id"])
        status = str(response.get("status", "unknown"))
        self.operational_db.record_response(task_id, response, status)
        if self._audit:
            self._audit.log_command_result(
                task_id=task_id,
                agent_id=agent_id,
                status=status,
                result=response,
                operator_id=self.operator_id,
            )
        return response

    def create_rotation_request(self, agent_id: str, auth_token: Optional[str] = None) -> Dict[str, object]:
        """Create a signed key rotation request for an agent."""
        session = self.sessions.get_session(agent_id)
        if not session:
            raise ValueError(f"No active session for agent {agent_id}")
        self._validate_operator_token(auth_token)
        rotation_crypto = CryptoEngine()
        rotation_crypto.generate_ecdh_keypair()
        operator_public = rotation_crypto.serialize_ecdh_public_key()
        rotation_id = uuid.uuid4().hex
        request = {
            "rotation_id": rotation_id,
            "operator_id": self.operator_id,
            "agent_id": agent_id,
            "ecdh_public_key": operator_public.hex(),
            "nonce": self._crypto.generate_nonce(),
            "timestamp": int(time.time()),
        }
        signature = self._sign_payload(request, ROTATION_REQUEST_SIGNATURE_FIELDS)
        request["signature"] = signature.hex()
        self._pending_rotations[rotation_id] = RotationState(
            agent_id=agent_id,
            crypto=rotation_crypto,
            requested_at=datetime.now(timezone.utc),
        )
        return request

    def handle_rotation_response(self, agent_id: str, payload: Dict[str, object]) -> None:
        """Handle agent key rotation response and update session key."""
        self.security.validate_rotation_response(payload)
        self._require_fields(payload, ROTATION_RESPONSE_SIGNATURE_FIELDS)
        if str(payload.get("agent_id")) != agent_id:
            raise ValueError("Agent ID mismatch in rotation response")
        self._validate_nonce_timestamp(payload)
        public_key = self._agent_public_keys.get(agent_id)
        if not public_key:
            raise ValueError(f"Missing public key for agent {agent_id}")
        self._verify_signature(
            payload,
            payload.get("signature"),
            public_key,
            ROTATION_RESPONSE_SIGNATURE_FIELDS,
            "rotation_response",
        )
        rotation_id = str(payload["rotation_id"])
        state = self._pending_rotations.pop(rotation_id, None)
        if not state:
            raise ValueError("Unknown rotation_id")
        if state.agent_id != agent_id:
            raise ValueError("Rotation agent mismatch")
        agent_public = self._decode_hex_field(payload, "ecdh_public_key", 64)
        new_session_key = state.crypto.perform_key_exchange(agent_public)
        new_session_key = state.crypto.derive_session_key(new_session_key)
        self.sessions.update_session_key(agent_id, new_session_key, new_ecdh_public=agent_public)

    def handle_heartbeat(self, agent_id: str, payload: Dict[str, object]) -> None:
        """Update agent status on heartbeat."""
        try:
            self.security.check_rate_limit(agent_id)
        except SecurityError as exc:
            self._log_security_event("rate_limit", {"agent_id": agent_id, "error": str(exc)})
            raise
        timestamp = payload.get("timestamp")
        if not isinstance(timestamp, int) or timestamp <= 0:
            raise ValueError("Invalid heartbeat timestamp")
        if str(payload.get("agent_id", "")) != agent_id:
            raise ValueError("Heartbeat agent mismatch")
        self.operational_db.update_agent_status(agent_id, "active", datetime.now(timezone.utc))

    def handle_disconnect(self, agent_id: str) -> None:
        """Mark agent as disconnected."""
        self.operational_db.update_agent_status(agent_id, "disconnected", datetime.now(timezone.utc))

    def _validate_operator_token(self, auth_token: Optional[str]) -> Optional[AuthToken]:
        if not self.auth_gateway:
            return None
        if not auth_token:
            raise ValueError("Authentication token required")
        token = self.auth_gateway.validate_token(auth_token)
        if token.operator_id != self.operator_id:
            raise ValueError("Token operator mismatch")
        return token

    def _validate_certificate(self, certificate: x509.Certificate) -> None:
        if not self.certificate_validator:
            raise ValueError("Certificate validator is required for agent authentication")
        self.certificate_validator(certificate)

    def _derive_session_key(self, agent_public_key: bytes) -> Tuple[bytes, bytes]:
        crypto = CryptoEngine()
        crypto.generate_ecdh_keypair()
        operator_public = crypto.serialize_ecdh_public_key()
        shared_secret = crypto.perform_key_exchange(agent_public_key)
        session_key = crypto.derive_session_key(shared_secret)
        return session_key, operator_public

    def _require_fields(self, payload: Dict[str, object], fields: Tuple[str, ...]) -> None:
        missing = [field for field in fields if field not in payload]
        if missing:
            raise ValueError(f"Missing fields: {', '.join(missing)}")

    def _validate_nonce_timestamp(self, payload: Dict[str, object]) -> None:
        nonce = payload.get("nonce")
        timestamp = payload.get("timestamp")
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("Invalid nonce")
        if not isinstance(timestamp, int) or timestamp <= 0:
            raise ValueError("Invalid timestamp")
        self.security.validate_nonce(nonce, timestamp)

    def _sign_payload(self, payload: Dict[str, object], fields: Tuple[str, ...]) -> bytes:
        data = signature_payload(payload, fields)
        return self._crypto.sign_data(data, self._operator_signing_key)

    def _verify_signature(
        self,
        payload: Dict[str, object],
        signature_hex: Optional[object],
        public_key: ed25519.Ed25519PublicKey,
        fields: Tuple[str, ...],
        context: str,
    ) -> None:
        if not isinstance(signature_hex, str):
            raise ValueError(f"Missing signature for {context}")
        signature = bytes.fromhex(signature_hex)
        data = signature_payload(payload, fields)
        if not self._crypto.verify_signature(data, signature, public_key):
            raise ValueError(f"Invalid signature for {context}")

    def _decode_hex_field(self, payload: Dict[str, object], field: str, length: Optional[int] = None) -> bytes:
        value = payload.get(field)
        if not isinstance(value, str):
            raise ValueError(f"Invalid {field}")
        if length and len(value) != length:
            raise ValueError(f"Invalid {field} length")
        return bytes.fromhex(value)

    def _certificate_fingerprint(self, certificate: x509.Certificate) -> str:
        cert_bytes = certificate.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_bytes).hexdigest()

    def _json_load(self, payload: bytes) -> Dict[str, object]:
        import json

        return json.loads(payload.decode("utf-8"))

    def _log_security_event(self, event_type: str, details: Dict[str, object]) -> None:
        if self._audit:
            self._audit.log_security_event(event_type, details)
        else:
            self._logger.warning("Security event %s: %s", event_type, details)
