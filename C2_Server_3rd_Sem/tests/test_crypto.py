"""
Unit Tests for PKI Manager and Crypto Engine
Comprehensive testing of cryptographic operations

Author: Shadow Junior
"""

import pytest
import os
import secrets
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, rsa
from cryptography.hazmat.primitives import serialization

# Import modules to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securecomm.pki_manager import PKIManager
from securecomm.crypto_engine import CryptoEngine


# ==================== FIXTURES ====================

@pytest.fixture
def temp_pki_dir(tmp_path):
    """Create temporary PKI directory"""
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    return str(pki_dir)


@pytest.fixture
def pki_manager(temp_pki_dir):
    """Create PKI Manager instance"""
    return PKIManager(temp_pki_dir)


@pytest.fixture
def crypto_engine():
    """Create Crypto Engine instance"""
    return CryptoEngine()


@pytest.fixture
def ca_setup(pki_manager):
    """Setup CA certificate and key"""
    ca_cert, ca_key = pki_manager.generate_root_ca("Test CA")
    return ca_cert, ca_key, pki_manager


# ==================== PKI MANAGER TESTS ====================

class TestPKIManager:
    """Test PKI Manager functionality"""
    
    def test_initialization(self, pki_manager):
        """Test PKI Manager initializes correctly"""
        assert pki_manager.pki_path.exists()
        assert pki_manager.ca_path.exists()
        assert pki_manager.operators_path.exists()
        assert pki_manager.agents_path.exists()
        assert pki_manager.crl_path.exists()
    
    def test_generate_key_pair(self, pki_manager):
        """Test Ed25519 key pair generation"""
        private_key, public_key = pki_manager.generate_key_pair()
        
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)
        assert isinstance(public_key, ed25519.Ed25519PublicKey)
        
        # Verify keys are related
        assert private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ) == public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def test_generate_root_ca(self, pki_manager):
        """Test root CA generation"""
        ca_cert, ca_key = pki_manager.generate_root_ca("Test Root CA", validity_days=365)
        
        # Verify certificate properties
        assert isinstance(ca_cert, x509.Certificate)
        assert isinstance(ca_key, ed25519.Ed25519PrivateKey)
        
        # Check certificate is self-signed
        assert ca_cert.issuer == ca_cert.subject
        
        # Check CA flag
        basic_constraints = ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        
        # Check validity period
        assert ca_cert.not_valid_before_utc <= datetime.now(timezone.utc)
        assert ca_cert.not_valid_after_utc > datetime.now(timezone.utc)
    
    def test_create_csr(self, pki_manager):
        """Test CSR creation"""
        private_key, _ = pki_manager.generate_key_pair()
        csr = pki_manager.create_csr(private_key, "operator@test.com")
        
        assert isinstance(csr, x509.CertificateSigningRequest)
        
        # Verify subject
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == "operator@test.com"
    
    def test_sign_csr(self, ca_setup):
        """Test CSR signing"""
        ca_cert, ca_key, pki_manager = ca_setup
        
        # Create CSR
        user_key, _ = pki_manager.generate_key_pair()
        csr = pki_manager.create_csr(user_key, "test_operator")
        
        # Sign CSR
        cert = pki_manager.sign_csr(csr, ca_cert, ca_key, validity_days=365, cert_type="operator")
        
        assert isinstance(cert, x509.Certificate)
        assert cert.issuer == ca_cert.subject
        assert cert.subject == csr.subject
        
        # Verify certificate is in database
        certs = pki_manager.list_certificates()
        assert len(certs) == 1
        assert certs[0]["common_name"] == "test_operator"
    
    def test_validate_certificate(self, ca_setup):
        """Test certificate validation"""
        ca_cert, ca_key, pki_manager = ca_setup
        
        # Issue certificate
        cert, _ = pki_manager.issue_certificate("test_user", cert_type="operator")
        
        # Validate certificate
        is_valid = pki_manager.validate_certificate(cert, ca_cert)
        assert is_valid is True
    
    def test_validate_expired_certificate(self, ca_setup):
        """Test expired certificate is rejected"""
        ca_cert, ca_key, pki_manager = ca_setup
        
        # Issue certificate with -1 day validity (already expired)
        user_key, _ = pki_manager.generate_key_pair()
        csr = pki_manager.create_csr(user_key, "expired_user")
        
        # Manually create expired certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=10))
            .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))
            .sign(ca_key, algorithm=None)
        )
        
        # Validation should fail
        with pytest.raises(ValueError, match="expired"):
            pki_manager.validate_certificate(cert, ca_cert)
    
    def test_revoke_certificate(self, ca_setup):
        """Test certificate revocation"""
        ca_cert, ca_key, pki_manager = ca_setup
        
        # Issue certificate
        cert, _ = pki_manager.issue_certificate("revoke_test", cert_type="operator")
        serial = str(cert.serial_number)
        
        # Revoke certificate
        pki_manager.revoke_certificate(serial, "key_compromise")
        
        # Check revocation status
        assert pki_manager.is_revoked(serial) is True
        
        # Validation should fail for revoked certificate
        with pytest.raises(ValueError, match="revoked"):
            pki_manager.validate_certificate(cert, ca_cert)
    
    def test_issue_certificate(self, ca_setup):
        """Test complete certificate issuance workflow"""
        ca_cert, ca_key, pki_manager = ca_setup
        
        cert, private_key = pki_manager.issue_certificate("full_workflow_test", cert_type="agent")
        
        assert isinstance(cert, x509.Certificate)
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)
        
        # Verify certificate is valid
        is_valid = pki_manager.validate_certificate(cert, ca_cert)
        assert is_valid is True
    
    def test_list_certificates(self, ca_setup):
        """Test certificate listing"""
        ca_cert, ca_key, pki_manager = ca_setup
        
        # Issue multiple certificates
        pki_manager.issue_certificate("operator1", cert_type="operator")
        pki_manager.issue_certificate("operator2", cert_type="operator")
        pki_manager.issue_certificate("agent1", cert_type="agent")
        
        # List all certificates
        all_certs = pki_manager.list_certificates()
        assert len(all_certs) == 3
        
        # List only operators
        operators = pki_manager.list_certificates(cert_type="operator")
        assert len(operators) == 2
        
        # List only agents
        agents = pki_manager.list_certificates(cert_type="agent")
        assert len(agents) == 1


# ==================== CRYPTO ENGINE TESTS ====================

class TestCryptoEngine:
    """Test Crypto Engine functionality"""
    
    def test_ecdh_key_generation(self, crypto_engine):
        """Test ECDH key pair generation"""
        private_key, public_key = crypto_engine.generate_ecdh_keypair()
        
        assert isinstance(private_key, x25519.X25519PrivateKey)
        assert isinstance(public_key, x25519.X25519PublicKey)
        assert crypto_engine.ecdh_private_key == private_key
        assert crypto_engine.ecdh_public_key == public_key
    
    def test_ecdh_key_exchange(self):
        """Test ECDH key exchange produces same shared secret"""
        alice = CryptoEngine()
        bob = CryptoEngine()
        
        # Generate keys
        alice.generate_ecdh_keypair()
        bob.generate_ecdh_keypair()
        
        # Serialize public keys
        alice_public = alice.serialize_ecdh_public_key()
        bob_public = bob.serialize_ecdh_public_key()
        
        # Perform key exchange
        alice_shared = alice.perform_key_exchange(bob_public)
        bob_shared = bob.perform_key_exchange(alice_public)
        
        # Shared secrets should match
        assert alice_shared == bob_shared
        assert len(alice_shared) == 32  # 256 bits
    
    def test_session_key_derivation(self, crypto_engine):
        """Test HKDF session key derivation"""
        shared_secret = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)
        
        session_key = crypto_engine.derive_session_key(shared_secret, salt)
        
        assert len(session_key) == 32  # 256 bits for AES-256
        assert crypto_engine.session_key == session_key
        
        # Same inputs should produce same output
        crypto_engine2 = CryptoEngine()
        session_key2 = crypto_engine2.derive_session_key(shared_secret, salt)
        assert session_key == session_key2
    
    def test_aes_gcm_encryption_decryption(self, crypto_engine):
        """Test AES-256-GCM encryption and decryption"""
        plaintext = b"This is a secret message for testing"
        session_key = secrets.token_bytes(32)
        
        # Encrypt
        ciphertext = crypto_engine.encrypt_message(plaintext, session_key)
        
        # Verify ciphertext format: nonce(12) + encrypted_data + tag(16)
        assert len(ciphertext) >= 12 + len(plaintext) + 16
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = crypto_engine.decrypt_message(ciphertext, session_key)
        
        assert decrypted == plaintext
    
    def test_aes_gcm_tamper_detection(self, crypto_engine):
        """Test AES-GCM detects tampering"""
        plaintext = b"Original message"
        session_key = secrets.token_bytes(32)
        
        ciphertext = crypto_engine.encrypt_message(plaintext, session_key)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[20] ^= 0xFF  # Flip bits in middle of ciphertext
        
        # Decryption should fail
        with pytest.raises(ValueError, match="tampering"):
            crypto_engine.decrypt_message(bytes(tampered), session_key)
    
    def test_aes_gcm_unique_nonces(self, crypto_engine):
        """Test AES-GCM generates unique nonces"""
        plaintext = b"Same message encrypted twice"
        session_key = secrets.token_bytes(32)
        
        ciphertext1 = crypto_engine.encrypt_message(plaintext, session_key)
        ciphertext2 = crypto_engine.encrypt_message(plaintext, session_key)
        
        # Ciphertexts should be different (different nonces)
        assert ciphertext1 != ciphertext2
        
        # But both should decrypt to same plaintext
        assert crypto_engine.decrypt_message(ciphertext1, session_key) == plaintext
        assert crypto_engine.decrypt_message(ciphertext2, session_key) == plaintext
    
    def test_ed25519_signing_verification(self, crypto_engine):
        """Test Ed25519 signature generation and verification"""
        private_key, public_key = crypto_engine.generate_signing_keypair()
        data = b"Data to sign"
        
        # Sign data
        signature = crypto_engine.sign_data(data, private_key)
        
        assert len(signature) == 64  # Ed25519 signatures are 64 bytes
        
        # Verify signature
        is_valid = crypto_engine.verify_signature(data, signature, public_key)
        assert is_valid is True
    
    def test_ed25519_invalid_signature(self, crypto_engine):
        """Test Ed25519 rejects invalid signatures"""
        private_key, public_key = crypto_engine.generate_signing_keypair()
        data = b"Original data"
        
        signature = crypto_engine.sign_data(data, private_key)
        
        # Try to verify with tampered data
        tampered_data = b"Modified data"
        is_valid = crypto_engine.verify_signature(tampered_data, signature, public_key)
        assert is_valid is False
    
    def test_ed25519_wrong_public_key(self, crypto_engine):
        """Test Ed25519 rejects signature with wrong public key"""
        private_key1, _ = crypto_engine.generate_signing_keypair()
        _, public_key2 = crypto_engine.generate_signing_keypair()
        
        data = b"Signed data"
        signature = crypto_engine.sign_data(data, private_key1)
        
        # Verification with wrong public key should fail
        is_valid = crypto_engine.verify_signature(data, signature, public_key2)
        assert is_valid is False
    
    def test_hybrid_encryption_decryption(self):
        """Test hybrid encryption (ECDH + AES-GCM)"""
        alice = CryptoEngine()
        bob = CryptoEngine()
        
        # Bob generates keys
        bob.generate_ecdh_keypair()
        bob_public = bob.serialize_ecdh_public_key()
        
        # Alice encrypts message for Bob
        plaintext = b"Secret message from Alice to Bob"
        alice_public, encrypted = alice.hybrid_encrypt(plaintext, bob_public)
        
        # Bob decrypts message
        decrypted = bob.hybrid_decrypt(alice_public, encrypted)
        
        assert decrypted == plaintext
    
    def test_session_key_rotation(self):
        """Test session key rotation for Perfect Forward Secrecy"""
        alice = CryptoEngine()
        bob = CryptoEngine()
        
        # Initial key exchange
        alice.generate_ecdh_keypair()
        bob.generate_ecdh_keypair()
        
        alice_pub1 = alice.serialize_ecdh_public_key()
        bob_pub1 = bob.serialize_ecdh_public_key()
        
        alice_shared1 = alice.perform_key_exchange(bob_pub1)
        bob_shared1 = bob.perform_key_exchange(alice_pub1)
        
        alice_session1 = alice.derive_session_key(alice_shared1)
        bob_session1 = bob.derive_session_key(bob_shared1)
        
        # Rotate keys
        bob.generate_ecdh_keypair()
        bob_pub2 = bob.serialize_ecdh_public_key()
        
        alice_session2 = alice.rotate_session_key(bob_pub2)
        bob_shared2 = bob.perform_key_exchange(alice.serialize_ecdh_public_key())
        bob_session2 = bob.derive_session_key(bob_shared2)
        
        # New session keys should be different
        assert alice_session1 != alice_session2
        assert bob_session1 != bob_session2
        
        # But Alice and Bob should have matching new keys
        assert alice_session2 == bob_session2
    
    def test_hash_data(self, crypto_engine):
        """Test data hashing with different algorithms"""
        data = b"Data to hash"
        
        # SHA-256
        hash_sha256 = crypto_engine.hash_data(data, "sha256")
        assert len(hash_sha256) == 32
        
        # SHA-512
        hash_sha512 = crypto_engine.hash_data(data, "sha512")
        assert len(hash_sha512) == 64
        
        # BLAKE2b
        hash_blake2b = crypto_engine.hash_data(data, "blake2b")
        assert len(hash_blake2b) == 64
        
        # Same data should produce same hash
        hash2 = crypto_engine.hash_data(data, "sha256")
        assert hash_sha256 == hash2
    
    def test_generate_nonce(self, crypto_engine):
        """Test nonce generation for replay protection"""
        nonce1 = crypto_engine.generate_nonce()
        nonce2 = crypto_engine.generate_nonce()
        
        # Nonces should be 64 characters (32 bytes hex)
        assert len(nonce1) == 64
        assert len(nonce2) == 64
        
        # Nonces should be unique
        assert nonce1 != nonce2
    
    def test_clear_session_key(self, crypto_engine):
        """Test secure session key clearing"""
        session_key = secrets.token_bytes(32)
        crypto_engine.session_key = session_key
        
        crypto_engine.clear_session_key()
        
        assert crypto_engine.session_key is None
    
    def test_rsa_key_generation(self, crypto_engine):
        """Test RSA-4096 key pair generation"""
        private_key, public_key = crypto_engine.generate_rsa_keypair()
        
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert private_key.key_size == 4096
        assert public_key.key_size == 4096
        
    def test_rsa_encryption_decryption(self, crypto_engine):
        """Test RSA-OAEP encryption and decryption"""
        private_key, public_key = crypto_engine.generate_rsa_keypair(key_size=2048)  # Smaller key for speed
        plaintext = b"RSA Secret Message"
        
        # Encrypt
        ciphertext = crypto_engine.rsa_encrypt(plaintext, public_key)
        assert len(ciphertext) == 256  # 2048 bits = 256 bytes
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = crypto_engine.rsa_decrypt(ciphertext, private_key)
        assert decrypted == plaintext

    def test_rsa_encryption_large_payload_fail(self, crypto_engine):
        """Test RSA fails for payload larger than key size"""
        private_key, public_key = crypto_engine.generate_rsa_keypair(key_size=2048)
        # Max payload for 2048-bit RSA-OAEP-SHA256 is 2048/8 - 2*32 - 2 = 190 bytes
        large_payload = b"X" * 300
        
        with pytest.raises(ValueError):
             crypto_engine.rsa_encrypt(large_payload, public_key)
             
    def test_constant_time_compare(self, crypto_engine):
        """Test constant time comparison util"""
        a = b"secret_token_123"
        b = b"secret_token_123"
        c = b"wrong_token_456"
        
        assert crypto_engine.constant_time_compare(a, b) is True
        assert crypto_engine.constant_time_compare(a, c) is False
        
    def test_derive_key_generic(self, crypto_engine):
        """Test generic HKDF key derivation"""
        master = b"master_secret"
        salt = b"random_salt"
        info = b"context"
        
        key1 = crypto_engine.derive_key(master, salt, info, length=64)
        key2 = crypto_engine.derive_key(master, salt, info, length=64)
        key3 = crypto_engine.derive_key(master, b"diff_salt", info, length=64)
        
        assert len(key1) == 64
        assert key1 == key2  # Deterministic
        assert key1 != key3  # Different salt = different key


# ==================== INTEGRATION TESTS ====================

class TestIntegration:
    """Integration tests combining PKI and Crypto"""
    
    def test_complete_secure_channel_setup(self, ca_setup):
        """Test complete secure channel establishment"""
        ca_cert, ca_key, pki_manager = ca_setup
        
        # Issue certificates for operator and agent
        operator_cert, operator_key = pki_manager.issue_certificate("operator1", "operator")
        agent_cert, agent_key = pki_manager.issue_certificate("agent1", "agent")
        
        # Initialize crypto engines
        operator_crypto = CryptoEngine()
        agent_crypto = CryptoEngine()
        
        # Generate ECDH keys for key exchange
        operator_crypto.generate_ecdh_keypair()
        agent_crypto.generate_ecdh_keypair()
        
        # Exchange public keys
        operator_public = operator_crypto.serialize_ecdh_public_key()
        agent_public = agent_crypto.serialize_ecdh_public_key()
        
        # Perform key exchange
        operator_shared = operator_crypto.perform_key_exchange(agent_public)
        agent_shared = agent_crypto.perform_key_exchange(operator_public)
        
        # Derive session keys
        operator_session = operator_crypto.derive_session_key(operator_shared)
        agent_session = agent_crypto.derive_session_key(agent_shared)
        
        # Verify session keys match
        assert operator_session == agent_session
        
        # Test encrypted communication
        command = b"exec whoami"
        encrypted_command = operator_crypto.encrypt_message(command)
        decrypted_command = agent_crypto.decrypt_message(encrypted_command)
        
        assert decrypted_command == command
    
    def test_signed_and_encrypted_message(self, ca_setup):
        """Test message that is both signed and encrypted"""
        ca_cert, ca_key, pki_manager = ca_setup
        
        # Setup operator
        operator_cert, operator_signing_key = pki_manager.issue_certificate("operator", "operator")
        operator_crypto = CryptoEngine()
        operator_crypto.generate_ecdh_keypair()
        
        # Setup agent
        agent_cert, agent_signing_key = pki_manager.issue_certificate("agent", "agent")
        agent_crypto = CryptoEngine()
        agent_crypto.generate_ecdh_keypair()
        
        # Establish session
        op_pub = operator_crypto.serialize_ecdh_public_key()
        ag_pub = agent_crypto.serialize_ecdh_public_key()
        
        op_shared = operator_crypto.perform_key_exchange(ag_pub)
        ag_shared = agent_crypto.perform_key_exchange(op_pub)
        
        operator_crypto.derive_session_key(op_shared)
        agent_crypto.derive_session_key(ag_shared)
        
        # Operator creates signed command
        command = b"execute: ls -la"
        signature = operator_crypto.sign_data(command, operator_signing_key)
        
        # Package: command + signature
        package = command + b"|SIGNATURE|" + signature
        
        # Encrypt package
        encrypted_package = operator_crypto.encrypt_message(package)
        
        # Agent receives and decrypts
        decrypted_package = agent_crypto.decrypt_message(encrypted_package)
        
        # Extract command and signature
        parts = decrypted_package.split(b"|SIGNATURE|")
        received_command = parts[0]
        received_signature = parts[1]
        
        # Verify signature
        operator_public_key = operator_signing_key.public_key()
        is_valid = agent_crypto.verify_signature(received_command, received_signature, operator_public_key)
        
        assert is_valid is True
        assert received_command == command


# ==================== PERFORMANCE TESTS ====================

class TestPerformance:
    """Performance benchmarking tests"""
    
    def test_encryption_speed(self, crypto_engine, benchmark):
        """Benchmark encryption speed"""
        data = b"X" * 1024  # 1KB payload
        session_key = secrets.token_bytes(32)
        
        result = benchmark(crypto_engine.encrypt_message, data, session_key)
        assert len(result) > len(data)
    
    def test_decryption_speed(self, crypto_engine, benchmark):
        """Benchmark decryption speed"""
        data = b"X" * 1024
        session_key = secrets.token_bytes(32)
        ciphertext = crypto_engine.encrypt_message(data, session_key)
        
        result = benchmark(crypto_engine.decrypt_message, ciphertext, session_key)
        assert result == data
    
    def test_signature_generation_speed(self, crypto_engine, benchmark):
        """Benchmark signature generation speed"""
        private_key, _ = crypto_engine.generate_signing_keypair()
        data = b"Data to sign" * 10
        
        signature = benchmark(crypto_engine.sign_data, data, private_key)
        assert len(signature) == 64
    
    def test_signature_verification_speed(self, crypto_engine, benchmark):
        """Benchmark signature verification speed"""
        private_key, public_key = crypto_engine.generate_signing_keypair()
        data = b"Data to verify" * 10
        signature = crypto_engine.sign_data(data, private_key)
        
        result = benchmark(crypto_engine.verify_signature, data, signature, public_key)
        assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
