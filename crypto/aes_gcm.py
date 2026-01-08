"""
AES-GCM Encryption Module
Implements AES-256-GCM symmetric encryption for data payload protection.
Uses wolfssl Python bindings for all cryptographic operations.
"""

import os
import secrets
from typing import Tuple, Optional
from dataclasses import dataclass

try:
    from wolfssl.ciphers import AesGcm
    from wolfssl.hashes import Sha256, HmacSha256
except ImportError:
    raise ImportError(
        "wolfssl library is required for AES-GCM support. "
        "Install it with: pip install wolfssl"
    )


@dataclass
class EncryptedPayload:
    """Represents an encrypted payload with all necessary components."""
    nonce: bytes
    ciphertext: bytes
    tag: bytes  # GCM authentication tag is included in ciphertext
    
    def to_bytes(self) -> bytes:
        """
        Serialize to bytes for transmission.
        Format: NONCE_LEN(1) + NONCE + CIPHERTEXT (includes tag)
        """
        data = bytearray()
        data.append(len(self.nonce))
        data.extend(self.nonce)
        data.extend(self.ciphertext)
        return bytes(data)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedPayload':
        """
        Deserialize from bytes.
        
        Args:
            data: Serialized encrypted payload
            
        Returns:
            EncryptedPayload instance
        """
        if len(data) < 2:
            raise ValueError("Invalid encrypted payload: too short")
        
        nonce_len = data[0]
        if len(data) < 1 + nonce_len + 16:  # At least nonce + tag
            raise ValueError("Invalid encrypted payload: insufficient data")
        
        nonce = data[1:1 + nonce_len]
        ciphertext = data[1 + nonce_len:]
        
        return cls(nonce=nonce, ciphertext=ciphertext, tag=b'')


class AESGCMCipher:
    """
    AES-256-GCM cipher for encrypting and decrypting data payloads.
    Uses 256-bit keys and 96-bit (12-byte) nonces as recommended.
    """
    
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    TAG_SIZE = 16  # 128 bits
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize the cipher.
        
        Args:
            key: 256-bit encryption key. If None, must be set later.
        """
        self._key: Optional[bytes] = None
        self._cipher: Optional[AesGcm] = None
        
        if key is not None:
            self.set_key(key)
    
    def set_key(self, key: bytes) -> None:
        """
        Set the encryption key.
        
        Args:
            key: 256-bit (32-byte) encryption key
            
        Raises:
            ValueError: If key is not 32 bytes
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        
        self._key = key
        self._cipher = AesGcm(key)
    
    def _generate_nonce(self) -> bytes:
        """
        Generate a cryptographically secure random nonce.
        
        Returns:
            12-byte random nonce
        """
        return secrets.token_bytes(self.NONCE_SIZE)
    
    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> EncryptedPayload:
        """
        Encrypt plaintext using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Optional additional authenticated data (AAD)
            
        Returns:
            EncryptedPayload containing nonce and ciphertext
            
        Raises:
            ValueError: If key not set
        """
        if self._cipher is None:
            raise ValueError("Encryption key not set")
        
        nonce = self._generate_nonce()
        
        # wolfcrypt AesGcm.encrypt returns ciphertext + tag
        auth_tag = bytearray(self.TAG_SIZE)
        ciphertext = self._cipher.encrypt(plaintext, nonce, associated_data or b'', auth_tag)
        
        # Concatenate ciphertext and tag
        ciphertext_with_tag = ciphertext + bytes(auth_tag)
        
        return EncryptedPayload(
            nonce=nonce,
            ciphertext=ciphertext_with_tag,
            tag=b''  # Tag is included in ciphertext
        )
    
    def decrypt(self, payload: EncryptedPayload, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM.
        
        Args:
            payload: EncryptedPayload to decrypt
            associated_data: Optional additional authenticated data (AAD)
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If key not set or decryption fails
        """
        if self._cipher is None:
            raise ValueError("Encryption key not set")
        
        try:
            # Split ciphertext and tag
            if len(payload.ciphertext) < self.TAG_SIZE:
                raise ValueError("Ciphertext too short")
            
            ciphertext = payload.ciphertext[:-self.TAG_SIZE]
            auth_tag = payload.ciphertext[-self.TAG_SIZE:]
            
            # Decrypt
            plaintext = self._cipher.decrypt(
                ciphertext,
                payload.nonce,
                associated_data or b'',
                auth_tag
            )
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def encrypt_bytes(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt and return serialized bytes ready for transmission.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Optional AAD
            
        Returns:
            Serialized encrypted payload bytes
        """
        payload = self.encrypt(plaintext, associated_data)
        return payload.to_bytes()
    
    def decrypt_bytes(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt from serialized bytes.
        
        Args:
            data: Serialized encrypted payload
            associated_data: Optional AAD
            
        Returns:
            Decrypted plaintext
        """
        payload = EncryptedPayload.from_bytes(data)
        return self.decrypt(payload, associated_data)
    
    @staticmethod
    def derive_key_from_shared_secret(shared_secret: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Derive an AES-256 key from a shared secret using HMAC-based KDF.
        
        Args:
            shared_secret: Shared secret from key exchange
            salt: Optional salt for KDF
            
        Returns:
            32-byte derived key
        """
        if salt is None:
            salt = b'bunnytunnel-transport-v1'
        
        # Use HMAC-SHA256 for key derivation
        hmac = HmacSha256(salt)
        hmac.update(shared_secret)
        hmac.update(b'aes-gcm-key')
        derived = hmac.digest()
        
        return derived[:AESGCMCipher.KEY_SIZE]
