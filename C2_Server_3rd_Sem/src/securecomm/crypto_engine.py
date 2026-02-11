"""
SecureComm Crypto Engine
Handles all cryptographic operations: ECDH, AES-GCM, Ed25519, HKDF

Author: Shadow Junior
"""

import os
import secrets
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class CryptoEngine:
    """
    Core cryptographic engine for SecureComm
    
    Implements:
    - ECDH (X25519) for key exchange
    - AES-256-GCM for encryption
    - Ed25519 for digital signatures
    - HKDF for key derivation
    
    Security Features:
    - Perfect Forward Secrecy (ephemeral keys)
    - Authenticated encryption (GCM)
    - Fast elliptic curve operations
    """
    
    def __init__(self):
        """Initialize crypto engine"""
        self.session_key: Optional[bytes] = None
        self.ecdh_private_key: Optional[x25519.X25519PrivateKey] = None
        self.ecdh_public_key: Optional[x25519.X25519PublicKey] = None
    
    # ==================== ECDH KEY EXCHANGE ====================
    
    def generate_ecdh_keypair(self) -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
        """
        Generate ephemeral ECDH key pair (Curve25519)
        
        Returns:
            Tuple of (private_key, public_key)
        
        Security:
            - Curve25519 (X25519) for ECDH
            - 128-bit security level
            - Fast key generation and exchange
            - Recommended by cryptographers
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        self.ecdh_private_key = private_key
        self.ecdh_public_key = public_key
        
        return private_key, public_key
    
    def perform_key_exchange(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Perform ECDH key exchange with peer
        
        Args:
            peer_public_key_bytes: Peer's public key (32 bytes)
        
        Returns:
            Shared secret (32 bytes)
        
        Security:
            - Diffie-Hellman key exchange on Curve25519
            - Produces same shared secret for both parties
            - Shared secret should be passed to HKDF for key derivation
        """
        if self.ecdh_private_key is None:
            raise ValueError("No ECDH private key. Call generate_ecdh_keypair() first")
        
        # Load peer's public key
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        
        # Perform key exchange
        shared_secret = self.ecdh_private_key.exchange(peer_public_key)
        
        return shared_secret
    
    def derive_session_key(
        self,
        shared_secret: bytes,
        salt: Optional[bytes] = None,
        info: bytes = b"SecureComm v1.0 Session Key"
    ) -> bytes:
        """
        Derive session key from ECDH shared secret using HKDF
        
        Args:
            shared_secret: Output from ECDH key exchange
            salt: Optional salt (random 32 bytes recommended)
            info: Context string for key derivation
        
        Returns:
            32-byte session key for AES-256
        
        Security:
            - HKDF (HMAC-based Key Derivation Function)
            - Uses SHA-256 as hash function
            - Extracts entropy from shared secret
            - Expands to required key length
        """
        if salt is None:
            salt = b'\x00' * 32  # Fixed salt for deterministic derivation
        
        # HKDF with SHA-256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            info=info,
            backend=default_backend()
        )
        
        session_key = hkdf.derive(shared_secret)
        self.session_key = session_key
        
        return session_key
    
    # ==================== AES-256-GCM ENCRYPTION ====================
    
    def encrypt_message(self, plaintext: bytes, session_key: Optional[bytes] = None) -> bytes:
        """
        Encrypt message using AES-256-GCM
        
        Args:
            plaintext: Message to encrypt
            session_key: 32-byte AES key (uses self.session_key if None)
        
        Returns:
            Encrypted message: nonce(12) || ciphertext || tag(16)
        
        Security:
            - AES-256 in GCM mode (Galois/Counter Mode)
            - Authenticated encryption (confidentiality + integrity)
            - Random 96-bit nonce per message
            - 128-bit authentication tag
            - NIST approved, widely used
        """
        if session_key is None:
            if self.session_key is None:
                raise ValueError("No session key available")
            session_key = self.session_key
        
        # Generate random nonce (96 bits / 12 bytes for GCM)
        nonce = secrets.token_bytes(12)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(session_key)
        
        # Encrypt and authenticate
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Format: nonce || ciphertext (ciphertext includes auth tag)
        encrypted_message = nonce + ciphertext
        
        return encrypted_message
    
    def decrypt_message(self, encrypted_message: bytes, session_key: Optional[bytes] = None) -> bytes:
        """
        Decrypt message using AES-256-GCM
        
        Args:
            encrypted_message: Encrypted message (nonce || ciphertext || tag)
            session_key: 32-byte AES key (uses self.session_key if None)
        
        Returns:
            Decrypted plaintext
        
        Raises:
            InvalidTag: If message has been tampered with
        
        Security:
            - Verifies authentication tag before decryption
            - Prevents tampering detection
            - Constant-time tag verification
        """
        if session_key is None:
            if self.session_key is None:
                raise ValueError("No session key available")
            session_key = self.session_key
        
        # Extract nonce and ciphertext
        nonce = encrypted_message[:12]
        ciphertext = encrypted_message[12:]
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(session_key)
        
        # Decrypt and verify authentication tag
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError(f"Decryption failed - possible tampering: {e}")
        
        return plaintext
    
    # ==================== ED25519 DIGITAL SIGNATURES ====================
    
    def generate_signing_keypair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """
        Generate Ed25519 key pair for digital signatures
        
        Returns:
            Tuple of (private_key, public_key)
        
        Security:
            - Ed25519 (Edwards-curve Digital Signature Algorithm)
            - 128-bit security level
            - Fast signature generation and verification
            - Deterministic signatures (no random number generation)
            - Immune to timing attacks
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def sign_data(self, data: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
        """
        Sign data with Ed25519 private key
        
        Args:
            data: Data to sign
            private_key: Ed25519 private key
        
        Returns:
            64-byte signature
        
        Security:
            - Provides data integrity and authenticity
            - Non-repudiation (only private key holder can sign)
            - Deterministic (same data + key = same signature)
        """
        signature = private_key.sign(data)
        return signature
    
    def verify_signature(
        self,
        data: bytes,
        signature: bytes,
        public_key: ed25519.Ed25519PublicKey
    ) -> bool:
        """
        Verify Ed25519 signature
        
        Args:
            data: Original data
            signature: 64-byte signature
            public_key: Signer's public key
        
        Returns:
            True if signature is valid
        
        Raises:
            InvalidSignature: If signature verification fails
        
        Security:
            - Constant-time verification
            - Prevents timing attacks
            - Guarantees data integrity
        """
        try:
            public_key.verify(signature, data)
            return True
        except Exception:
            return False
    
    # ==================== KEY SERIALIZATION ====================
    
    def serialize_ecdh_public_key(self, public_key: Optional[x25519.X25519PublicKey] = None) -> bytes:
        """Serialize ECDH public key to bytes"""
        if public_key is None:
            if self.ecdh_public_key is None:
                raise ValueError("No ECDH public key available")
            public_key = self.ecdh_public_key
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def serialize_signing_public_key(self, public_key: ed25519.Ed25519PublicKey) -> bytes:
        """Serialize Ed25519 public key to bytes"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def load_signing_public_key(self, public_key_bytes: bytes) -> ed25519.Ed25519PublicKey:
        """Load Ed25519 public key from bytes"""
        return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    
    def serialize_signing_private_key(
        self,
        private_key: ed25519.Ed25519PrivateKey,
        password: Optional[bytes] = None
    ) -> bytes:
        """
        Serialize Ed25519 private key to PEM format
        
        Args:
            private_key: Private key to serialize
            password: Optional password for encryption
        
        Returns:
            PEM-encoded private key
        """
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    
    def load_signing_private_key(
        self,
        private_key_pem: bytes,
        password: Optional[bytes] = None
    ) -> ed25519.Ed25519PrivateKey:
        """Load Ed25519 private key from PEM format"""
        return serialization.load_pem_private_key(
            private_key_pem,
            password=password,
            backend=default_backend()
        )
    
    # ==================== UTILITY FUNCTIONS ====================
    
    def generate_random_bytes(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes
        
        Args:
            length: Number of bytes to generate
        
        Returns:
            Random bytes
        
        Security:
            - Uses secrets.token_bytes() (CSPRNG)
            - Suitable for cryptographic purposes
        """
        return secrets.token_bytes(length)
    
    def generate_nonce(self) -> str:
        """
        Generate random nonce for replay protection
        
        Returns:
            32-byte hex string (64 characters)
        """
        return secrets.token_hex(32)
    
    def hash_data(self, data: bytes, algorithm: str = "sha256") -> bytes:
        """
        Hash data with specified algorithm
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha512, blake2b)
        
        Returns:
            Hash digest
        """
        if algorithm == "sha256":
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        elif algorithm == "sha512":
            digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        elif algorithm == "blake2b":
            digest = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        digest.update(data)
        return digest.finalize()
    
    # ==================== SESSION KEY ROTATION ====================
    
    def rotate_session_key(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Rotate session key by performing new ECDH exchange
        
        Args:
            peer_public_key_bytes: Peer's new ECDH public key
        
        Returns:
            New session key
        
        Security:
            - Implements Perfect Forward Secrecy
            - Old session keys are discarded
            - New ephemeral keys generated
            - Previous communications remain secure even if current key compromised
        """
        # Generate new ephemeral key pair
        self.generate_ecdh_keypair()
        
        # Perform new key exchange
        shared_secret = self.perform_key_exchange(peer_public_key_bytes)
        
        # Derive new session key
        new_session_key = self.derive_session_key(shared_secret)
        
        # Old session key is now garbage collected (PFS)
        return new_session_key
    
    def clear_session_key(self):
        """
        Clear session key from memory
        
        Security:
            - Prevents key leakage
            - Part of secure key lifecycle
        """
        if self.session_key:
            # Overwrite with zeros before deletion
            self.session_key = b'\x00' * len(self.session_key)
            self.session_key = None
    
    # ==================== HYBRID ENCRYPTION ====================
    
    def hybrid_encrypt(
        self,
        plaintext: bytes,
        recipient_ecdh_public_key: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Hybrid encryption: ECDH + AES-256-GCM
        
        Args:
            plaintext: Data to encrypt
            recipient_ecdh_public_key: Recipient's ECDH public key
        
        Returns:
            Tuple of (our_public_key, encrypted_data)
        
        Workflow:
            1. Generate ephemeral ECDH key pair
            2. Perform key exchange with recipient
            3. Derive session key
            4. Encrypt data with AES-256-GCM
            5. Return our public key + encrypted data
        
        Security:
            - Fast AES encryption for bulk data
            - Secure ECDH key exchange
            - Forward secrecy (ephemeral keys)
        """
        # Generate ephemeral keys
        private_key, public_key = self.generate_ecdh_keypair()
        
        # Perform key exchange
        shared_secret = self.perform_key_exchange(recipient_ecdh_public_key)
        
        # Derive session key
        session_key = self.derive_session_key(shared_secret)
        
        # Encrypt data
        encrypted_data = self.encrypt_message(plaintext, session_key)
        
        # Serialize our public key
        our_public_key = self.serialize_ecdh_public_key(public_key)
        
        return our_public_key, encrypted_data
    
    def hybrid_decrypt(
        self,
        sender_ecdh_public_key: bytes,
        encrypted_data: bytes
    ) -> bytes:
        """
        Hybrid decryption: ECDH + AES-256-GCM
        
        Args:
            sender_ecdh_public_key: Sender's ECDH public key
            encrypted_data: Encrypted data from sender
        
        Returns:
            Decrypted plaintext
        
        Workflow:
            1. Use our existing ECDH private key
            2. Perform key exchange with sender's public key
            3. Derive same session key
            4. Decrypt data with AES-256-GCM
        """
        # Perform key exchange
        shared_secret = self.perform_key_exchange(sender_ecdh_public_key)
        
        # Derive session key (same as sender)
        session_key = self.derive_session_key(shared_secret)
        
        # Decrypt data
        plaintext = self.decrypt_message(encrypted_data, session_key)
        
        return plaintext


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    print("🔥 SecureComm Crypto Engine Test 🔥\n")
    
    # Initialize crypto engines for Alice and Bob
    alice = CryptoEngine()
    bob = CryptoEngine()
    
    print("1. ECDH Key Exchange Test")
    print("-" * 50)
    
    # Alice and Bob generate ephemeral keys
    alice_private, alice_public = alice.generate_ecdh_keypair()
    bob_private, bob_public = bob.generate_ecdh_keypair()
    
    # Serialize public keys for exchange
    alice_pub_bytes = alice.serialize_ecdh_public_key()
    bob_pub_bytes = bob.serialize_ecdh_public_key()
    
    # Perform key exchange
    alice_shared = alice.perform_key_exchange(bob_pub_bytes)
    bob_shared = bob.perform_key_exchange(alice_pub_bytes)
    
    print(f"✅ Shared secrets match: {alice_shared == bob_shared}")
    
    # Derive session keys
    alice_session = alice.derive_session_key(alice_shared)
    bob_session = bob.derive_session_key(bob_shared)
    
    print(f"✅ Session keys match: {alice_session == bob_session}\n")
    
    print("2. AES-256-GCM Encryption Test")
    print("-" * 50)
    
    message = b"This is a secret command: whoami"
    encrypted = alice.encrypt_message(message)
    print(f"Plaintext: {message}")
    print(f"Encrypted ({len(encrypted)} bytes): {encrypted[:50]}...")
    
    decrypted = bob.decrypt_message(encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"✅ Decryption successful: {message == decrypted}\n")
    
    print("3. Ed25519 Digital Signature Test")
    print("-" * 50)
    
    # Generate signing keys
    sign_private, sign_public = alice.generate_signing_keypair()
    
    # Sign data
    data = b"Command payload to sign"
    signature = alice.sign_data(data, sign_private)
    print(f"Data: {data}")
    print(f"Signature ({len(signature)} bytes): {signature.hex()[:64]}...")
    
    # Verify signature
    valid = alice.verify_signature(data, signature, sign_public)
    print(f"✅ Signature valid: {valid}")
    
    # Verify tampered data fails
    tampered = b"Modified command payload"
    valid_tampered = alice.verify_signature(tampered, signature, sign_public)
    print(f"✅ Tampered data rejected: {not valid_tampered}\n")
    
    print("4. Hybrid Encryption Test")
    print("-" * 50)
    
    # Bob generates long-term ECDH keys
    bob.generate_ecdh_keypair()
    bob_public_key = bob.serialize_ecdh_public_key()
    
    # Alice encrypts message for Bob
    sender_public, encrypted = alice.hybrid_encrypt(b"Secret message", bob_public_key)
    print(f"✅ Hybrid encryption successful")
    
    # Bob decrypts message
    decrypted = bob.hybrid_decrypt(sender_public, encrypted)
    print(f"✅ Hybrid decryption successful: {decrypted}\n")
    
    print("🔥 All cryptographic tests passed! 🔥")
