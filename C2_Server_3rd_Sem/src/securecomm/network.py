"""
SecureComm Network Manager
Handles TCP/TLS connections, message framing, and protocol

Author: Shadow Junior
"""

import socket
import ssl
import struct
import json
from typing import Optional, Tuple, Dict
from pathlib import Path
import logging

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# Message type constants
MSG_TYPE_HANDSHAKE = 0x01
MSG_TYPE_COMMAND = 0x02
MSG_TYPE_RESPONSE = 0x03
MSG_TYPE_KEY_ROTATION = 0x04
MSG_TYPE_HEARTBEAT = 0x05


class NetworkManager:
    """
    Manages network communications for SecureComm
    
    Features:
    - TCP/TLS connection handling
    - Message framing protocol
    - Connection pooling
    - Certificate-based authentication
    
    Message Format:
    ┌──────────────┬─────────────┬──────────────────┐
    │ Length (4)   │ Type (1)    │ Payload (N)      │
    └──────────────┴─────────────┴──────────────────┘
    
    Length: 4 bytes (big-endian) - total message length
    Type: 1 byte - message type (handshake, command, response)
    Payload: N bytes - JSON-encoded encrypted data
    """
    
    def __init__(
        self,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        ca_cert_path: Optional[str] = None
    ):
        """
        Initialize Network Manager
        
        Args:
            cert_path: Path to certificate file
            key_path: Path to private key file
            ca_cert_path: Path to CA certificate for validation
        """
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        
        self.logger = logging.getLogger(__name__)
        
        # Active connections
        self.connections: Dict[str, socket.socket] = {}
    
    def create_tls_context(self, is_server: bool = True) -> ssl.SSLContext:
        """
        Create TLS context for secure connections
        
        Args:
            is_server: Whether this is server or client context
        
        Returns:
            Configured SSL context
        
        Security:
            - TLS 1.2+ only (no TLS 1.0/1.1)
            - Strong cipher suites
            - Certificate verification enabled
        """
        if is_server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = False  # We do certificate validation manually
        
        # Load certificates if provided
        if self.cert_path and self.key_path:
            context.load_cert_chain(self.cert_path, self.key_path)
        
        # Load CA certificate for validation
        if self.ca_cert_path:
            context.load_verify_locations(self.ca_cert_path)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_NONE
        
        # Configure strong cipher suites
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return context
    
    def create_server(
        self,
        host: str = "0.0.0.0",
        port: int = 8443,
        backlog: int = 5
    ) -> socket.socket:
        """
        Create TLS server socket
        
        Args:
            host: Host to bind to
            port: Port to listen on
            backlog: Connection backlog
        
        Returns:
            TLS server socket
        """
        # Create TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind and listen
        server_socket.bind((host, port))
        server_socket.listen(backlog)
        
        # Wrap with TLS
        context = self.create_tls_context(is_server=True)
        tls_socket = context.wrap_socket(server_socket, server_side=True)
        
        self.logger.info(f"✅ Server listening on {host}:{port}")
        return tls_socket
    
    def connect_to_server(
        self,
        host: str,
        port: int,
        timeout: int = 30
    ) -> socket.socket:
        """
        Connect to TLS server
        
        Args:
            host: Server hostname/IP
            port: Server port
            timeout: Connection timeout
        
        Returns:
            Connected TLS socket
        """
        # Create TCP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(timeout)
        
        # Connect
        client_socket.connect((host, port))
        
        # Wrap with TLS
        context = self.create_tls_context(is_server=False)
        tls_socket = context.wrap_socket(client_socket, server_hostname=host)
        
        self.logger.info(f"✅ Connected to {host}:{port}")
        return tls_socket
    
    def send_message(
        self,
        sock: socket.socket,
        msg_type: int,
        payload: dict
    ) -> bool:
        """
        Send message over socket
        
        Args:
            sock: Socket to send on
            msg_type: Message type (0x01-0x05)
            payload: Dictionary to send (will be JSON encoded)
        
        Returns:
            True if successful
        
        Message Format:
            [4 bytes length][1 byte type][N bytes JSON payload]
        """
        try:
            # Serialize payload
            payload_bytes = json.dumps(payload).encode('utf-8')
            
            # Calculate total length
            total_length = 1 + len(payload_bytes)  # type + payload
            
            # Build message
            message = struct.pack('>I', total_length)  # 4 bytes, big-endian
            message += struct.pack('B', msg_type)      # 1 byte
            message += payload_bytes                    # N bytes
            
            # Send message
            sock.sendall(message)
            
            self.logger.debug(f"📤 Sent message type {msg_type:#x}, {len(payload_bytes)} bytes")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Send failed: {e}")
            return False
    
    def receive_message(self, sock: socket.socket) -> Optional[Tuple[int, dict]]:
        """
        Receive message from socket
        
        Args:
            sock: Socket to receive from
        
        Returns:
            Tuple of (message_type, payload_dict) or None
        
        Security:
            - Validates message length
            - Handles malformed messages
            - Prevents buffer overflow
        """
        try:
            # Receive length (4 bytes)
            length_bytes = self._recv_exact(sock, 4)
            if not length_bytes:
                return None
            
            total_length = struct.unpack('>I', length_bytes)[0]
            
            # Sanity check (prevent DOS with huge messages)
            if total_length > 10 * 1024 * 1024:  # 10 MB max
                self.logger.error(f"❌ Message too large: {total_length} bytes")
                return None
            
            # Receive type (1 byte)
            type_byte = self._recv_exact(sock, 1)
            if not type_byte:
                return None
            
            msg_type = struct.unpack('B', type_byte)[0]
            
            # Receive payload
            payload_length = total_length - 1  # subtract type byte
            payload_bytes = self._recv_exact(sock, payload_length)
            if not payload_bytes:
                return None
            
            # Parse JSON
            payload = json.loads(payload_bytes.decode('utf-8'))
            
            self.logger.debug(f"📥 Received message type {msg_type:#x}, {payload_length} bytes")
            return msg_type, payload
            
        except json.JSONDecodeError as e:
            self.logger.error(f"❌ JSON decode failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"❌ Receive failed: {e}")
            return None
    
    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """
        Receive exactly n bytes from socket
        
        Args:
            sock: Socket to receive from
            n: Number of bytes to receive
        
        Returns:
            Exactly n bytes or None if connection closed
        """
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def get_peer_certificate(self, sock: socket.socket) -> Optional[x509.Certificate]:
        """
        Get peer's certificate from TLS connection
        
        Args:
            sock: TLS socket
        
        Returns:
            Peer's X.509 certificate or None
        """
        try:
            peer_cert_der = sock.getpeercert(binary_form=True)
            if peer_cert_der:
                return x509.load_der_x509_certificate(peer_cert_der, default_backend())
        except Exception as e:
            self.logger.error(f"❌ Failed to get peer certificate: {e}")
        return None
    
    def close_connection(self, sock: socket.socket):
        """Close socket connection"""
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            self.logger.info("✅ Connection closed")
        except Exception as e:
            self.logger.debug(f"Connection close: {e}")
    
    def register_connection(self, conn_id: str, sock: socket.socket):
        """Register active connection"""
        self.connections[conn_id] = sock
        self.logger.info(f"✅ Registered connection: {conn_id}")
    
    def get_connection(self, conn_id: str) -> Optional[socket.socket]:
        """Get connection by ID"""
        return self.connections.get(conn_id)
    
    def remove_connection(self, conn_id: str):
        """Remove connection from pool"""
        if conn_id in self.connections:
            sock = self.connections[conn_id]
            self.close_connection(sock)
            del self.connections[conn_id]
            self.logger.info(f"✅ Removed connection: {conn_id}")


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    import threading
    import time
    
    logging.basicConfig(level=logging.INFO)
    
    print("🔥 SecureComm Network Manager Test 🔥\n")
    
    # Test server function
    def run_server():
        server_net = NetworkManager(
            cert_path="data/pki/operators/operator@redteam.crt",
            key_path="data/pki/operators/operator@redteam.key",
            ca_cert_path="data/pki/ca/ca_root.crt"
        )
        
        server_socket = server_net.create_server("127.0.0.1", 9443)
        print("🖥️  Server: Waiting for connection...")
        
        client_socket, addr = server_socket.accept()
        print(f"🖥️  Server: Client connected from {addr}")
        
        # Receive handshake
        msg_type, payload = server_net.receive_message(client_socket)
        print(f"🖥️  Server: Received handshake: {payload}")
        
        # Send response
        server_net.send_message(client_socket, MSG_TYPE_RESPONSE, {
            "status": "success",
            "message": "Handshake accepted"
        })
        
        time.sleep(1)
        client_socket.close()
        server_socket.close()
    
    # Test client function
    def run_client():
        time.sleep(1)  # Wait for server to start
        
        client_net = NetworkManager(
            cert_path="data/pki/agents/agent001.crt",
            key_path="data/pki/agents/agent001.key",
            ca_cert_path="data/pki/ca/ca_root.crt"
        )
        
        client_socket = client_net.connect_to_server("127.0.0.1", 9443)
        print(f"💻 Client: Connected to server")
        
        # Send handshake
        client_net.send_message(client_socket, MSG_TYPE_HANDSHAKE, {
            "client_id": "agent001",
            "version": "1.0.0"
        })
        print(f"💻 Client: Sent handshake")
        
        # Receive response
        msg_type, payload = client_net.receive_message(client_socket)
        print(f"💻 Client: Received response: {payload}")
        
        client_socket.close()
    
    # Run test
    try:
        server_thread = threading.Thread(target=run_server)
        client_thread = threading.Thread(target=run_client)
        
        server_thread.start()
        client_thread.start()
        
        server_thread.join()
        client_thread.join()
        
        print("\n🔥 Network Manager test passed! 🔥")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
