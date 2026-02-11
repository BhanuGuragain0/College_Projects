"""
Shared Encryption Module (server/shared/encryption.py)

This module provides centralized AES-256-GCM encryption for both
bot and server components to eliminate duplication and ensure
consistent cryptographic implementation across the system.

IMPORTANT: This module should be imported by both bot and server
to maintain unified encryption standards.
"""

import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SecureEncryption:
    """
    Provides AES-256-GCM authenticated encryption.
    
    CRITICAL: This class is used for encrypting sensitive data
    including bot commands and results. DO NOT modify algorithm
    or serialization format without careful consideration of
    backward compatibility.
    
    Attributes:
        key (bytes): 32-byte key for AES-256
        backend: Cryptographic backend instance
    """
    
    def __init__(self, key: bytes):
        """
        Initialize encryption instance with AES-256 key.
        
        Args:
            key (bytes): Must be exactly 32 bytes for AES-256
            
        Raises:
            ValueError: If key is not exactly 32 bytes
            TypeError: If key is not bytes
        """
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key)} bytes")
        
        self.key = key
        self.backend = default_backend()
        logging.debug("SecureEncryption initialized successfully")

    def encrypt(self, data: str) -> str:
        """
        Encrypt a message string using AES-256-GCM.
        
        Format: Base64(nonce || tag || ciphertext)
        - nonce: 12 bytes (96-bit for GCM)
        - tag: 16 bytes (128-bit authentication tag)
        - ciphertext: Variable length
        
        Args:
            data (str): Plaintext string to encrypt
            
        Returns:
            str: Base64-encoded encrypted data
            
        Raises:
            ValueError: If data is not a string
            Exception: On cryptographic failure
        """
        if not isinstance(data, str):
            raise ValueError(f"Data must be string, got {type(data).__name__}")
        
        try:
            nonce = os.urandom(12)  # 12-byte nonce for GCM (96-bit)
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            
            # Concatenate nonce + tag + ciphertext and Base64 encode
            encrypted_data = nonce + encryptor.tag + ciphertext
            encoded = base64.b64encode(encrypted_data).decode('ascii')
            logging.debug(f"Encryption successful: {len(data)} bytes -> {len(encoded)} bytes")
            return encoded
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            raise

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt a Base64-encoded ciphertext using AES-256-GCM.
        
        Expects format: Base64(nonce || tag || ciphertext)
        
        Args:
            encrypted_data (str): Base64-encoded encrypted data
            
        Returns:
            str: Decrypted plaintext string
            
        Raises:
            ValueError: If data format is invalid
            cryptography.hazmat.primitives.ciphers.InvalidTag: If authentication fails
            Exception: On cryptographic failure
        """
        if not isinstance(encrypted_data, str):
            raise ValueError(f"Encrypted data must be string, got {type(encrypted_data).__name__}")
        
        try:
            data = base64.b64decode(encrypted_data)
            
            # Verify minimum length: 12 (nonce) + 16 (tag) + at least 1 byte ciphertext
            if len(data) < 29:
                raise ValueError(f"Encrypted data too short: {len(data)} bytes")
            
            nonce = data[:12]           # First 12 bytes: nonce
            tag = data[12:28]           # Next 16 bytes: tag
            ciphertext = data[28:]      # Remaining: ciphertext
            
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            result = decrypted.decode('utf-8')
            logging.debug(f"Decryption successful: {len(encrypted_data)} bytes -> {len(result)} bytes")
            return result
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            raise

    def __repr__(self):
        """Return string representation for debugging (not showing key)."""
        return f"<SecureEncryption(AES-256-GCM, key_size={len(self.key)*8}bits)>"
