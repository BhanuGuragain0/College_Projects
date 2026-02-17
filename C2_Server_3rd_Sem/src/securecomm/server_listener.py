"""
SecureComm server listener for authenticated agent connections.

Academic/ethical use only.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519

from .auth_gateway import AuthGateway
from .command_handler import CommandHandler
from .crypto_engine import CryptoEngine
from .network import (
    NetworkManager,
    MSG_TYPE_COMMAND,
    MSG_TYPE_HANDSHAKE,
    MSG_TYPE_HEARTBEAT,
    MSG_TYPE_KEY_ROTATION,
    MSG_TYPE_RESPONSE,
)
from .operational_db import OperationalDatabase
from .pki_manager import PKIManager
from .security import SecurityModule
from .session import SessionManager


class SecureCommServer:
    """TLS listener that authenticates agents and handles SecureComm workflows."""

    def __init__(
        self,
        operator_id: str,
        host: str,
        port: int,
        cert_path: str,
        key_path: str,
        ca_cert_path: str,
        operator_signing_key: Optional[ed25519.Ed25519PrivateKey] = None,
        operator_key_password: Optional[bytes] = None,
        operational_db: Optional[OperationalDatabase] = None,
        sessions: Optional[SessionManager] = None,
        security: Optional[SecurityModule] = None,
        auth_gateway: Optional[AuthGateway] = None,
        audit_logger: Optional[object] = None,
        pki_path: Optional[str] = None,
    ) -> None:
        self.operator_id = operator_id
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path

        self._logger = logging.getLogger(__name__)
        self._crypto = CryptoEngine()
        self.network = NetworkManager(cert_path, key_path, ca_cert_path)
        self.sessions = sessions or SessionManager()
        self.security = security or SecurityModule()
        self.operational_db = operational_db or OperationalDatabase()
        self.auth_gateway = auth_gateway
        self.audit_logger = audit_logger
        self._server_socket = None
        self._running = False
        
        # Thread pool to manage concurrent agent connections (prevents unlimited thread creation)
        self._thread_pool = ThreadPoolExecutor(
            max_workers=100,
            thread_name_prefix="agent_handler_"
        )

        self._operator_signing_key = operator_signing_key or self._load_operator_signing_key(
            operator_key_password
        )
        self._ca_certificate = self._load_ca_certificate()
        self._pki_manager = PKIManager(pki_path=self._resolve_pki_path(pki_path))
        self.command_handler = CommandHandler(
            operator_id=self.operator_id,
            operator_signing_key=self._operator_signing_key,
            sessions=self.sessions,
            security=self.security,
            operational_db=self.operational_db,
            audit_logger=self.audit_logger,
            auth_gateway=self.auth_gateway,
            certificate_validator=self._validate_agent_certificate,
        )

    def start(self) -> None:
        """Start the TLS listener."""
        if self._running:
            return
        self._server_socket = self.network.create_server(self.host, self.port)
        self._server_socket.settimeout(1.0)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        self._logger.info("✅ SecureComm server listening on %s:%s", self.host, self.port)

    def stop(self) -> None:
        """Stop the TLS listener and close active connections."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:  # pragma: no cover - best effort shutdown
                pass
        for agent_id in list(self.network.connections.keys()):
            self.disconnect_agent(agent_id)
        
        # Shutdown thread pool gracefully
        self._thread_pool.shutdown(wait=True)
        self._logger.info("Thread pool shutdown complete")

    def send_command(self, agent_id: str, cmd_type: str, payload: str, auth_token: Optional[str] = None) -> str:
        """Send a signed command to an agent and return the task_id."""
        message = self.command_handler.create_command_payload(
            agent_id=agent_id,
            cmd_type=cmd_type,
            payload=payload,
            auth_token=auth_token,
        )
        sock = self.network.get_connection(agent_id)
        if not sock:
            raise ValueError(f"No active connection for agent {agent_id}")
        self.network.send_message(sock, MSG_TYPE_COMMAND, message)
        return str(message["task_id"])

    def request_key_rotation(self, agent_id: str, auth_token: Optional[str] = None) -> str:
        """Initiate session key rotation with an agent."""
        request = self.command_handler.create_rotation_request(agent_id, auth_token)
        sock = self.network.get_connection(agent_id)
        if not sock:
            raise ValueError(f"No active connection for agent {agent_id}")
        self.network.send_message(sock, MSG_TYPE_KEY_ROTATION, request)
        return str(request["rotation_id"])

    def disconnect_agent(self, agent_id: str) -> None:
        """Disconnect an agent and clear session state."""
        self.command_handler.handle_disconnect(agent_id)
        self.sessions.remove_session(agent_id)
        self.network.remove_connection(agent_id)

    def _accept_loop(self) -> None:
        while self._running and self._server_socket:
            try:
                client_socket, address = self._server_socket.accept()
            except Exception:
                continue
            # Submit connection handling to thread pool instead of unbounded thread creation
            self._thread_pool.submit(
                self._handle_connection,
                client_socket,
                address,
            )

    def _handle_connection(self, client_socket, address: Tuple[str, int]) -> None:
        agent_id = None
        try:
            peer_cert = self.network.get_peer_certificate(client_socket)
            if not peer_cert:
                self._logger.error("❌ Missing client certificate from %s", address)
                client_socket.close()
                return
            message = self.network.receive_message(client_socket)
            if not message:
                return
            msg_type, payload = message
            if msg_type != MSG_TYPE_HANDSHAKE:
                raise ValueError("First message must be handshake")
            agent_id, response = self.command_handler.handle_handshake(payload, peer_cert, address)
            self.network.register_connection(agent_id, client_socket)
            self.network.send_message(client_socket, MSG_TYPE_HANDSHAKE, response)
            while self._running:
                message = self.network.receive_message(client_socket)
                if not message:
                    break
                msg_type, payload = message
                self._refresh_agent_state(agent_id)
                if msg_type == MSG_TYPE_RESPONSE:
                    self.command_handler.handle_command_response(agent_id, payload)
                elif msg_type == MSG_TYPE_KEY_ROTATION:
                    self.command_handler.handle_rotation_response(agent_id, payload)
                elif msg_type == MSG_TYPE_HEARTBEAT:
                    self.command_handler.handle_heartbeat(agent_id, payload)
                elif msg_type == MSG_TYPE_HANDSHAKE:
                    raise ValueError("Unexpected handshake after session established")
                else:
                    self._logger.warning("Unhandled message type %s from %s", msg_type, agent_id)
        except Exception as exc:
            self._logger.error("❌ Connection error from %s: %s", address, exc)
        finally:
            if agent_id:
                self.disconnect_agent(agent_id)
            try:
                client_socket.close()
            except Exception:
                pass

    def _refresh_agent_state(self, agent_id: str) -> None:
        self.operational_db.update_agent_status(agent_id, "active")

    def _load_operator_signing_key(self, password: Optional[bytes]) -> ed25519.Ed25519PrivateKey:
        key_bytes = Path(self.key_path).read_bytes()
        return self._crypto.load_signing_private_key(key_bytes, password=password)

    def _load_ca_certificate(self) -> x509.Certificate:
        cert_bytes = Path(self.ca_cert_path).read_bytes()
        return x509.load_pem_x509_certificate(cert_bytes, default_backend())

    def _resolve_pki_path(self, pki_path: Optional[str]) -> str:
        if pki_path:
            return pki_path
        ca_path = Path(self.ca_cert_path)
        if len(ca_path.parents) >= 2:
            return str(ca_path.parents[1])
        return str(ca_path.parent)

    def _validate_agent_certificate(self, certificate: x509.Certificate) -> None:
        """Validate agent certificate using unified validation method"""
        self._pki_manager.validate_certificate_unified(
            certificate,
            self._ca_certificate,
            expected_type="agent",
            require_db_registration=True
        )
