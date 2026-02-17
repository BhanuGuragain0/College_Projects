"""
Identity & Access Authentication Gateway for SecureComm (academic scope).
Issues short-lived HMAC-signed tokens after X.509 validation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .message_utils import canonical_json

if TYPE_CHECKING:
    from .pki_manager import PKIManager

CertificateValidator = Callable[[x509.Certificate], None]


@dataclass(frozen=True)
class AuthToken:
    """Represents an issued authentication token."""

    token: str
    operator_id: str
    issued_at: datetime
    expires_at: datetime
    issuer: str


class AuthGateway:
    """
    Academic authentication gateway issuing HMAC-signed bearer tokens.

    Security:
    - Validates X.509 certificates against a trusted CA.
    - Enforces CN/operator identity binding.
    - Issues short-lived tokens with HMAC-SHA256 integrity.
    """

    def __init__(
        self,
        ca_certificate: x509.Certificate,
        token_ttl_seconds: int = 900,
        issuer: str = "SecureCommAuth",
        certificate_validator: Optional[CertificateValidator] = None,
        audit_logger: Optional[object] = None,
        pki_manager: Optional["PKIManager"] = None,
    ) -> None:
        self._ca_certificate = ca_certificate
        self._token_ttl = token_ttl_seconds
        self._issuer = issuer
        self._certificate_validator = certificate_validator
        self._pki_manager = pki_manager
        self._secret = secrets.token_bytes(32)
        self._active_tokens: dict[str, AuthToken] = {}
        self._logger = logging.getLogger(__name__)
        self._audit = audit_logger

    def authenticate(self, operator_id: str, certificate: x509.Certificate) -> AuthToken:
        """Validate operator certificate and issue a signed token."""
        try:
            self._validate_certificate(operator_id, certificate)
        except Exception as exc:
            self._log_security_event(
                "auth_failed",
                {"operator_id": operator_id, "reason": str(exc)},
            )
            raise
        token = self._issue_token(operator_id)
        self._active_tokens[token.token] = token
        self._logger.info("✅ Issued auth token for %s", operator_id)
        return token

    def validate_token(self, token: str) -> AuthToken:
        """Validate token integrity and expiry."""
        try:
            payload = self._decode_token(token)
        except Exception as exc:
            self._log_security_event("token_invalid", {"reason": str(exc)})
            raise
        if token not in self._active_tokens:
            self._log_security_event("token_invalid", {"reason": "token_not_recognized"})
            raise ValueError("Token not recognized")
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        if now >= expires_at:
            self._log_security_event(
                "token_invalid",
                {"reason": "token_expired", "operator_id": payload.get("sub")},
            )
            raise ValueError("Token expired")
        stored = self._active_tokens[token]
        return stored

    def revoke_token(self, token: str) -> None:
        """Invalidate a token."""
        if token in self._active_tokens:
            del self._active_tokens[token]
            self._logger.info("🔒 Token revoked")

    def _issue_token(self, operator_id: str) -> AuthToken:
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(seconds=self._token_ttl)
        payload = {
            "sub": operator_id,
            "iss": self._issuer,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": secrets.token_hex(16),
        }
        payload_bytes = canonical_json(payload)
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii")
        signature = hmac.new(self._secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        token = f"{payload_b64}.{signature}"
        return AuthToken(
            token=token,
            operator_id=operator_id,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer=self._issuer,
        )

    def _decode_token(self, token: str) -> dict:
        try:
            payload_b64, signature = token.split(".", 1)
        except ValueError as exc:
            raise ValueError("Invalid token format") from exc
        expected = hmac.new(self._secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Invalid token signature")
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        return json_load_bytes(payload_bytes)

    def _validate_certificate(self, operator_id: str, certificate: x509.Certificate) -> None:
        """Validate operator certificate using unified validation method"""
        if self._certificate_validator:
            # Legacy validator for custom validation
            self._certificate_validator(certificate)
        else:
            # Use unified validation method from PKI manager
            if self._pki_manager:
                self._pki_manager.validate_certificate_unified(
                    certificate,
                    self._ca_certificate,
                    expected_cn=operator_id,
                    expected_type="operator",
                    require_db_registration=False
                )
            else:
                # Fallback: basic signature validation
                self._validate_certificate_signature(certificate)

    def _validate_certificate_signature(self, certificate: x509.Certificate) -> None:
        """Basic certificate signature validation (fallback)"""
        now = datetime.now(timezone.utc)
        if now < certificate.not_valid_before.replace(tzinfo=timezone.utc) or now > certificate.not_valid_after.replace(tzinfo=timezone.utc):
            raise ValueError("Certificate expired or not yet valid")
        ca_public_key = self._ca_certificate.public_key()
        ca_public_key.verify(certificate.signature, certificate.tbs_certificate_bytes)

    def _log_security_event(self, event_type: str, details: dict) -> None:
        if self._audit:
            try:
                self._audit.log_security_event(event_type, details)
            except Exception:
                pass
        self._logger.warning("Auth security event %s: %s", event_type, details)


def json_load_bytes(payload: bytes) -> dict:
    """Minimal JSON loader with strict UTF-8 decoding."""
    return json_load_str(payload.decode("utf-8"))


def json_load_str(payload: str) -> dict:
    import json

    return json.loads(payload)
