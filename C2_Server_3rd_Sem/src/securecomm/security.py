"""
SecureComm Security Module
Implements attack prevention: MITM, Replay, Rate Limiting

Author: Shadow Junior
"""

import time
import hashlib
import threading
from typing import Dict, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class SecurityModule:
    """
    Security module for attack prevention and input validation
    
    Features:
    - MITM prevention (certificate pinning)
    - Replay attack prevention (nonce + timestamp)
    - Rate limiting
    - Input validation and sanitization
    """
    
    def __init__(
        self,
        replay_window: int = 300,      # 5 minutes
        rate_limit_window: int = 60,   # 1 minute
        rate_limit_max: int = 100      # 100 requests per window
    ):
        """
        Initialize Security Module
        
        Args:
            replay_window: Time window for replay protection (seconds)
            rate_limit_window: Time window for rate limiting (seconds)
            rate_limit_max: Max requests per window
        """
        self.replay_window = replay_window
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max = rate_limit_max
        
        # Certificate pinning
        self.pinned_certs: Dict[str, str] = {}  # agent_id -> cert_fingerprint
        
        # Replay protection
        self.nonce_cache: Dict[str, int] = {}  # nonce -> timestamp
        
        # Rate limiting
        self.rate_limit_data: Dict[str, list] = defaultdict(list)  # agent_id -> [timestamps]
        self.rate_limit_lock = threading.Lock()  # Thread safety for rate limiting
        
        self.logger = logging.getLogger(__name__)
    
    # ==================== CERTIFICATE PINNING (MITM PREVENTION) ====================
    
    def pin_certificate(self, agent_id: str, certificate: x509.Certificate):
        """
        Pin certificate to prevent MITM attacks
        
        Args:
            agent_id: Agent identifier
            certificate: X.509 certificate to pin
        
        Security:
            - Prevents certificate substitution
            - Detects MITM attempts
            - Trust On First Use (TOFU) model
        """
        fingerprint = self._get_cert_fingerprint(certificate)
        self.pinned_certs[agent_id] = fingerprint
        self.logger.info(f"📌 Pinned certificate for {agent_id}: {fingerprint[:16]}...")
    
    def validate_pinned_certificate(
        self,
        agent_id: str,
        certificate: x509.Certificate
    ) -> bool:
        """
        Validate certificate against pinned fingerprint
        
        Args:
            agent_id: Agent identifier
            certificate: Certificate to validate
        
        Returns:
            True if valid
        
        Raises:
            SecurityError: If certificate mismatch (possible MITM)
        """
        fingerprint = self._get_cert_fingerprint(certificate)
        
        if agent_id not in self.pinned_certs:
            # First connection - pin the certificate
            self.pin_certificate(agent_id, certificate)
            return True
        
        pinned_fingerprint = self.pinned_certs[agent_id]
        
        if fingerprint != pinned_fingerprint:
            self.logger.error(f"🚨 MITM ATTACK DETECTED for {agent_id}")
            self.logger.error(f"   Expected: {pinned_fingerprint[:16]}...")
            self.logger.error(f"   Got:      {fingerprint[:16]}...")
            raise SecurityError(f"Certificate mismatch - possible MITM attack")
        
        self.logger.debug(f"✅ Certificate validated for {agent_id}")
        return True
    
    def _get_cert_fingerprint(self, certificate: x509.Certificate) -> str:
        """
        Calculate certificate SHA-256 fingerprint
        
        Args:
            certificate: X.509 certificate
        
        Returns:
            Hex-encoded SHA-256 fingerprint
        """
        cert_bytes = certificate.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_bytes).hexdigest()
    
    def unpin_certificate(self, agent_id: str):
        """Remove certificate pin for agent"""
        if agent_id in self.pinned_certs:
            del self.pinned_certs[agent_id]
            self.logger.info(f"📌 Unpinned certificate for {agent_id}")
    
    # ==================== REPLAY ATTACK PREVENTION ====================
    
    def validate_nonce(self, nonce: str, timestamp: int) -> bool:
        """
        Validate nonce and timestamp for replay protection
        
        Args:
            nonce: Unique nonce string
            timestamp: Unix timestamp (seconds)
        
        Returns:
            True if valid
        
        Raises:
            SecurityError: If replay attack detected or timestamp invalid
        
        Security:
            - Nonces must be unique
            - Timestamps must be within acceptable window
            - Prevents replay attacks
        """
        current_time = int(time.time())
        
        # Check timestamp is within acceptable window
        time_diff = abs(current_time - timestamp)
        if time_diff > self.replay_window:
            self.logger.warning(f"⚠️  Timestamp outside window: {time_diff}s")
            raise SecurityError(f"Timestamp outside acceptable window ({self.replay_window}s)")
        
        # Check nonce hasn't been seen before
        if nonce in self.nonce_cache:
            self.logger.warning(f"🚨 REPLAY ATTACK DETECTED: nonce {nonce[:16]}... reused")
            raise SecurityError("Replay attack detected - nonce reused")
        
        # Store nonce with timestamp
        self.nonce_cache[nonce] = timestamp
        
        # Cleanup old nonces
        self._cleanup_nonces()
        
        return True
    
    def _cleanup_nonces(self):
        """
        Remove expired nonces from cache
        
        Security:
            - Prevents memory exhaustion
            - Maintains only recent nonces
        """
        current_time = int(time.time())
        cutoff_time = current_time - self.replay_window
        
        # Remove expired nonces
        expired = [n for n, t in self.nonce_cache.items() if t < cutoff_time]
        for nonce in expired:
            del self.nonce_cache[nonce]
        
        if expired:
            self.logger.debug(f"🧹 Cleaned up {len(expired)} expired nonces")
    
    def get_nonce_cache_size(self) -> int:
        """Get current nonce cache size"""
        return len(self.nonce_cache)
    
    # ==================== RATE LIMITING ====================
    
    def check_rate_limit(self, agent_id: str) -> bool:
        """
        Check if agent has exceeded rate limit
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            True if within limit
        
        Raises:
            SecurityError: If rate limit exceeded
        
        Security:
            - Prevents DOS attacks
            - Limits request frequency per agent
            - Thread-safe concurrent access
        """
        with self.rate_limit_lock:
            current_time = time.time()
            cutoff_time = current_time - self.rate_limit_window
            
            # Get agent's request history
            timestamps = self.rate_limit_data[agent_id]
            
            # Remove old timestamps
            timestamps = [t for t in timestamps if t > cutoff_time]
            self.rate_limit_data[agent_id] = timestamps
            
            # Check if limit exceeded
            if len(timestamps) >= self.rate_limit_max:
                self.logger.warning(f"⚠️  Rate limit exceeded for {agent_id}: {len(timestamps)} requests")
                raise SecurityError(f"Rate limit exceeded: {len(timestamps)}/{self.rate_limit_max}")
            
            # Record this request
            timestamps.append(current_time)
            
            return True
    
    def get_rate_limit_status(self, agent_id: str) -> Dict:
        """
        Get rate limit status for agent
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Dictionary with rate limit statistics
        """
        with self.rate_limit_lock:
            current_time = time.time()
            cutoff_time = current_time - self.rate_limit_window
            
            timestamps = self.rate_limit_data.get(agent_id, [])
            recent_timestamps = [t for t in timestamps if t > cutoff_time]
            
            return {
                "agent_id": agent_id,
                "requests_in_window": len(recent_timestamps),
                "limit": self.rate_limit_max,
                "window_seconds": self.rate_limit_window,
                "percentage_used": (len(recent_timestamps) / self.rate_limit_max) * 100
            }

    def _validate_hex_string(self, value: str, expected_length: int, field: str) -> None:
        if not isinstance(value, str) or len(value) != expected_length:
            raise SecurityError(f"Invalid {field} format")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise SecurityError(f"Invalid {field} hex encoding") from exc
    
    def reset_rate_limit(self, agent_id: str):
        """Reset rate limit for agent"""
        with self.rate_limit_lock:
            if agent_id in self.rate_limit_data:
                del self.rate_limit_data[agent_id]
                self.logger.info(f"🔄 Reset rate limit for {agent_id}")
    
    # ==================== INPUT VALIDATION ====================
    
    def validate_command(self, command: Dict) -> bool:
        """
        Validate command structure and content
        
        Args:
            command: Command dictionary
        
        Returns:
            True if valid
        
        Raises:
            SecurityError: If validation fails
        
        Security:
            - Validates required fields
            - Checks command types
            - Prevents injection attacks
        """
        required_fields = ['task_id', 'operator_id', 'agent_id', 'type', 'payload', 'nonce', 'timestamp', 'signature']
        
        # Check required fields
        for field in required_fields:
            if field not in command:
                raise SecurityError(f"Missing required field: {field}")
        
        # Validate command type
        valid_types = ['exec', 'upload', 'download', 'sleep', 'exit', 'persist', 'status']
        if command['type'] not in valid_types:
            raise SecurityError(f"Invalid command type: {command['type']}")

        allow_empty_payload = command['type'] in {'persist', 'exit', 'status'}

        for field in ['task_id', 'operator_id', 'agent_id', 'type', 'payload']:
            if not isinstance(command[field], str):
                raise SecurityError(f"Invalid {field}")
            if field != 'payload' and not command[field]:
                raise SecurityError(f"Invalid {field}")
            if field == 'payload' and not allow_empty_payload and not command[field]:
                raise SecurityError("Invalid payload")
        
        # Validate nonce format (64 hex characters)
        nonce = command['nonce']
        self._validate_hex_string(nonce, 64, "nonce")
        
        # Validate timestamp
        timestamp = command['timestamp']
        if not isinstance(timestamp, int) or timestamp <= 0:
            raise SecurityError("Invalid timestamp")

        self._validate_hex_string(command['signature'], 128, "signature")
        
        return True

    def validate_response(self, response: Dict) -> bool:
        """Validate response structure and content."""
        required_fields = ['task_id', 'agent_id', 'status', 'result', 'nonce', 'timestamp', 'signature']
        for field in required_fields:
            if field not in response:
                raise SecurityError(f"Missing required field: {field}")

        for field in ['task_id', 'agent_id', 'status']:
            if not isinstance(response[field], str) or not response[field]:
                raise SecurityError(f"Invalid {field}")

        nonce = response['nonce']
        self._validate_hex_string(nonce, 64, "nonce")

        timestamp = response['timestamp']
        if not isinstance(timestamp, int) or timestamp <= 0:
            raise SecurityError("Invalid timestamp")

        self._validate_hex_string(response['signature'], 128, "signature")
        return True

    def validate_handshake(self, payload: Dict) -> bool:
        """Validate signed handshake payload structure."""
        required_fields = ['agent_id', 'ecdh_public_key', 'nonce', 'timestamp', 'signature']
        for field in required_fields:
            if field not in payload:
                raise SecurityError(f"Missing required field: {field}")
        if not isinstance(payload['agent_id'], str) or not payload['agent_id']:
            raise SecurityError("Invalid agent_id")
        self._validate_hex_string(payload['ecdh_public_key'], 64, "ecdh_public_key")
        self._validate_hex_string(payload['nonce'], 64, "nonce")
        timestamp = payload['timestamp']
        if not isinstance(timestamp, int) or timestamp <= 0:
            raise SecurityError("Invalid timestamp")
        self._validate_hex_string(payload['signature'], 128, "signature")
        return True

    def validate_rotation_request(self, payload: Dict) -> bool:
        """Validate rotation request payload structure."""
        required_fields = ['rotation_id', 'operator_id', 'agent_id', 'ecdh_public_key', 'nonce', 'timestamp', 'signature']
        for field in required_fields:
            if field not in payload:
                raise SecurityError(f"Missing required field: {field}")
        for field in ['rotation_id', 'operator_id', 'agent_id']:
            if not isinstance(payload[field], str) or not payload[field]:
                raise SecurityError(f"Invalid {field}")
        self._validate_hex_string(payload['ecdh_public_key'], 64, "ecdh_public_key")
        self._validate_hex_string(payload['nonce'], 64, "nonce")
        timestamp = payload['timestamp']
        if not isinstance(timestamp, int) or timestamp <= 0:
            raise SecurityError("Invalid timestamp")
        self._validate_hex_string(payload['signature'], 128, "signature")
        return True

    def validate_rotation_response(self, payload: Dict) -> bool:
        """Validate rotation response payload structure."""
        required_fields = ['rotation_id', 'agent_id', 'ecdh_public_key', 'nonce', 'timestamp', 'signature']
        for field in required_fields:
            if field not in payload:
                raise SecurityError(f"Missing required field: {field}")
        for field in ['rotation_id', 'agent_id']:
            if not isinstance(payload[field], str) or not payload[field]:
                raise SecurityError(f"Invalid {field}")
        self._validate_hex_string(payload['ecdh_public_key'], 64, "ecdh_public_key")
        self._validate_hex_string(payload['nonce'], 64, "nonce")
        timestamp = payload['timestamp']
        if not isinstance(timestamp, int) or timestamp <= 0:
            raise SecurityError("Invalid timestamp")
        self._validate_hex_string(payload['signature'], 128, "signature")
        return True
    
    def sanitize_input(self, data: str, max_length: int = 4096, allow_binary: bool = False) -> str:
        """
        Sanitize input data
        
        Args:
            data: Input string to sanitize
            max_length: Maximum allowed length
            allow_binary: Skip dangerous pattern checks for binary payloads
        
        Returns:
            Sanitized string
        
        Raises:
            SecurityError: If validation fails
        """
        # Check length
        if len(data) > max_length:
            raise SecurityError(f"Input too long: {len(data)} > {max_length}")
        
        # Remove null bytes
        data = data.replace('\x00', '')
        
        if not allow_binary:
            # Check for dangerous patterns (basic)
            dangerous_patterns = ['rm -rf /', ':(){ :|:& };:', 'dd if=']
            for pattern in dangerous_patterns:
                if pattern in data:
                    raise SecurityError(f"Dangerous pattern detected: {pattern}")
        
        return data
    
    # ==================== UTILITY FUNCTIONS ====================
    
    def get_security_stats(self) -> Dict:
        """
        Get security module statistics
        
        Returns:
            Dictionary with security statistics
        """
        return {
            "pinned_certificates": len(self.pinned_certs),
            "nonce_cache_size": len(self.nonce_cache),
            "rate_limited_agents": len(self.rate_limit_data),
            "replay_window_seconds": self.replay_window,
            "rate_limit_max": self.rate_limit_max,
            "rate_limit_window_seconds": self.rate_limit_window
        }


class SecurityError(Exception):
    """Security-related exception"""
    pass


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    import secrets
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    logging.basicConfig(level=logging.INFO)
    
    print("🔥 SecureComm Security Module Test 🔥\n")
    
    security = SecurityModule(
        replay_window=300,
        rate_limit_window=60,
        rate_limit_max=10
    )
    
    print("1. Certificate Pinning Test (MITM Prevention)")
    print("-" * 50)
    
    # Simulate certificate pinning (we'll use a mock)
    class MockCert:
        def public_bytes(self, encoding):
            return b"mock_certificate_data"
    
    agent_id = "agent001"
    cert1 = MockCert()
    
    # First connection - pin certificate
    security.pin_certificate(agent_id, cert1)
    
    # Validate same certificate
    try:
        security.validate_pinned_certificate(agent_id, cert1)
        print("✅ Certificate validation passed")
    except SecurityError as e:
        print(f"❌ {e}")
    
    # Try different certificate (simulate MITM)
    class DifferentMockCert:
        def public_bytes(self, encoding):
            return b"different_certificate_data"
    
    cert2 = DifferentMockCert()
    try:
        security.validate_pinned_certificate(agent_id, cert2)
        print("❌ MITM attack should have been detected!")
    except SecurityError as e:
        print(f"✅ MITM detected: {e}")
    
    print("\n2. Replay Attack Prevention")
    print("-" * 50)
    
    nonce1 = secrets.token_hex(32)
    timestamp1 = int(time.time())
    
    # Valid nonce
    try:
        security.validate_nonce(nonce1, timestamp1)
        print(f"✅ Nonce accepted: {nonce1[:16]}...")
    except SecurityError as e:
        print(f"❌ {e}")
    
    # Replay attack
    try:
        security.validate_nonce(nonce1, timestamp1)  # Same nonce
        print(f"❌ Replay should have been detected!")
    except SecurityError as e:
        print(f"✅ Replay blocked: {e}")
    
    # Old timestamp
    old_timestamp = int(time.time()) - 400  # 6.7 minutes ago (> 5 minute window)
    try:
        security.validate_nonce(secrets.token_hex(32), old_timestamp)
        print(f"❌ Old timestamp should have been rejected!")
    except SecurityError as e:
        print(f"✅ Old timestamp blocked: {e}")
    
    print("\n3. Rate Limiting Test")
    print("-" * 50)
    
    agent_id = "agent002"
    
    # Send requests up to limit
    for i in range(10):
        try:
            security.check_rate_limit(agent_id)
        except SecurityError:
            pass
    
    status = security.get_rate_limit_status(agent_id)
    print(f"Requests: {status['requests_in_window']}/{status['limit']}")
    print(f"Usage: {status['percentage_used']:.1f}%")
    
    # Exceed limit
    try:
        security.check_rate_limit(agent_id)
        print(f"❌ Rate limit should have been exceeded!")
    except SecurityError as e:
        print(f"✅ Rate limit enforced: {e}")
    
    print("\n4. Input Validation Test")
    print("-" * 50)
    
    # Valid command
    valid_command = {
        'type': 'exec',
        'payload': 'whoami',
        'nonce': secrets.token_hex(32),
        'timestamp': int(time.time()),
        'signature': b'fake_signature'
    }
    
    try:
        security.validate_command(valid_command)
        print("✅ Valid command accepted")
    except SecurityError as e:
        print(f"❌ {e}")
    
    # Invalid command (missing field)
    invalid_command = {
        'type': 'exec',
        'payload': 'whoami'
        # Missing nonce, timestamp, signature
    }
    
    try:
        security.validate_command(invalid_command)
        print(f"❌ Invalid command should have been rejected!")
    except SecurityError as e:
        print(f"✅ Invalid command rejected: {e}")
    
    # Dangerous input
    try:
        dangerous = "rm -rf / --no-preserve-root"
        security.sanitize_input(dangerous)
        print(f"❌ Dangerous input should have been rejected!")
    except SecurityError as e:
        print(f"✅ Dangerous input blocked: {e}")
    
    print("\n5. Security Statistics")
    print("-" * 50)
    
    stats = security.get_security_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n🔥 Security Module test completed! 🔥")
