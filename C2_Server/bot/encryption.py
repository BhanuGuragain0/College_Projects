# bot/encryption.py
"""
Bot-side Encryption Module

NOTE: This module is maintained for backward compatibility.
In production, consider importing from shared_encryption module instead:
    from server.shared_encryption import SecureEncryption

Both implementations are identical to ensure bot-server communication consistency.
"""

import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO)

class SecureEncryption:
    """
    Bot-side AES-256-GCM encryption implementation.
    
    IMPORTANT: This class must remain synchronized with server/shared_encryption.py
    to ensure bot-server communication doesn't fail due to encryption mismatches.
    
    Format: Base64(nonce || tag || ciphertext)
    - nonce: 12 bytes (96-bit for GCM)
    - tag: 16 bytes (128-bit authentication tag)
    - ciphertext: Variable length
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
        logging.debug("SecureEncryption initialized")

    def encrypt(self, data: str) -> str:
        """
        Encrypt plaintext using AES-256-GCM.
        
        Args:
            data (str): Plaintext string
            
        Returns:
            str: Base64-encoded ciphertext (nonce || tag || ciphertext)
        """
        if not isinstance(data, str):
            raise ValueError(f"Data must be string, got {type(data).__name__}")
        
        try:
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            
            # Concatenate nonce + tag + ciphertext
            encrypted_data = nonce + encryptor.tag + ciphertext
            return base64.b64encode(encrypted_data).decode('ascii')
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            raise

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt AES-256-GCM ciphertext.
        
        Args:
            encrypted_data (str): Base64-encoded ciphertext
            
        Returns:
            str: Decrypted plaintext
        """
        if not isinstance(encrypted_data, str):
            raise ValueError(f"Encrypted data must be string, got {type(encrypted_data).__name__}")
        
        try:
            data = base64.b64decode(encrypted_data)
            
            if len(data) < 29:  # 12 (nonce) + 16 (tag) + 1 (min ciphertext)
                raise ValueError(f"Invalid encrypted data length: {len(data)} bytes")
            
            nonce = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted.decode('utf-8')
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            raise

    def __repr__(self):
        return f"<SecureEncryption(AES-256-GCM, key_size={len(self.key)*8}bits)>"

