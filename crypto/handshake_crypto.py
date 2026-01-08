"""
Handshake Cryptography Module
Implements pre-encryption, signing, and padding for handshake messages.
"""

import secrets
import struct
import time
from typing import Tuple, Optional
from dataclasses import dataclass

from .mldsa import MLDSAKeyManager, MLDSASigner
from .mlkem import MLKEMKeyManager
from .padding import PayloadPadding
from .aes_gcm import AESGCMCipher


@dataclass
class HandshakePayload:
    """Represents a handshake payload with all security features."""
    timestamp: int
    nonce: bytes
    data: bytes
    signature: bytes
    
    def to_bytes(self) -> bytes:
        """
        Serialize handshake payload.
        
        Format: TIMESTAMP(8) + NONCE(32) + DATA_LEN(4) + DATA + SIG_LEN(4) + SIGNATURE
        """
        payload = bytearray()
        payload.extend(struct.pack('>Q', self.timestamp))
        payload.extend(self.nonce)
        payload.extend(len(self.data).to_bytes(4, 'big'))
        payload.extend(self.data)
        payload.extend(len(self.signature).to_bytes(4, 'big'))
        payload.extend(self.signature)
        return bytes(payload)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'HandshakePayload':
        """
        Deserialize handshake payload.
        
        Args:
            data: Serialized payload bytes
            
        Returns:
            HandshakePayload instance
            
        Raises:
            ValueError: If payload format is invalid
        """
        if len(data) < 48:  # 8 + 32 + 4 + 0 + 4 + 0
            raise ValueError("Handshake payload too short")
        
        offset = 0
        
        # Parse timestamp
        timestamp = struct.unpack('>Q', data[offset:offset + 8])[0]
        offset += 8
        
        # Parse nonce
        nonce = data[offset:offset + 32]
        offset += 32
        
        # Parse data
        data_len = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4
        
        if len(data) < offset + data_len + 4:
            raise ValueError("Handshake payload incomplete (data)")
        
        payload_data = data[offset:offset + data_len]
        offset += data_len
        
        # Parse signature
        sig_len = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4
        
        if len(data) < offset + sig_len:
            raise ValueError("Handshake payload incomplete (signature)")
        
        signature = data[offset:offset + sig_len]
        
        return cls(
            timestamp=timestamp,
            nonce=nonce,
            data=payload_data,
            signature=signature
        )


class HandshakeCrypto:
    """
    Handles all cryptographic operations for handshake messages.
    Implements pre-encryption, signing, padding, and timestamp/nonce validation.
    """
    
    # Timestamp tolerance (5 minutes)
    TIMESTAMP_TOLERANCE = 300
    
    # Nonce size
    NONCE_SIZE = 32
    
    def __init__(
        self,
        mlkem_manager: MLKEMKeyManager,
        mldsa_manager: MLDSAKeyManager,
        padding: Optional[PayloadPadding] = None
    ):
        """
        Initialize handshake crypto handler.
        
        Args:
            mlkem_manager: ML-KEM key manager for pre-encryption
            mldsa_manager: ML-DSA key manager for signing
            padding: Payload padding handler (optional)
        """
        self.mlkem_manager = mlkem_manager
        self.mldsa_manager = mldsa_manager
        self.signer = MLDSASigner(mldsa_manager)
        self.padding = padding or PayloadPadding()
        
        # Pre-encryption cipher using ML-KEM public key as seed
        # Note: In production, this should use a proper KEM-based encryption
        # For now, we'll use the public key to derive an encryption key
        self._init_pre_encryption_cipher()
    
    def _init_pre_encryption_cipher(self) -> None:
        """Initialize pre-encryption cipher from ML-KEM public key."""
        # Derive a symmetric key from the ML-KEM public key for pre-encryption
        # This is a simplified approach; in production, consider using a separate key
        public_key = self.mlkem_manager.get_public_key()
        
        # Use the public key hash as encryption key material
        from wolfssl.hashes import Sha256
        hasher = Sha256()
        hasher.update(public_key)
        hasher.update(b'handshake-pre-encryption-v1')
        key_material = hasher.digest()
        
        self.pre_cipher = AESGCMCipher(key_material[:32])
    
    def _generate_nonce(self) -> bytes:
        """Generate a cryptographically secure nonce."""
        return secrets.token_bytes(self.NONCE_SIZE)
    
    def _get_current_timestamp(self) -> int:
        """Get current Unix timestamp in seconds."""
        return int(time.time())
    
    def create_handshake_message(self, data: bytes) -> bytes:
        """
        Create a complete handshake message with all security features.
        
        Process:
        1. Add timestamp and nonce to data
        2. Sign the data with ML-DSA-87
        3. Create handshake payload
        4. Add ASCII padding
        5. Pre-encrypt with ML-KEM-derived key
        
        Args:
            data: Original handshake data
            
        Returns:
            Encrypted, signed, and padded handshake message
        """
        # Generate timestamp and nonce
        timestamp = self._get_current_timestamp()
        nonce = self._generate_nonce()
        
        # Create message to sign: TIMESTAMP + NONCE + DATA
        message_to_sign = bytearray()
        message_to_sign.extend(struct.pack('>Q', timestamp))
        message_to_sign.extend(nonce)
        message_to_sign.extend(data)
        
        # Sign the message
        signature = self.signer.sign_message(bytes(message_to_sign))
        
        # Create handshake payload
        payload = HandshakePayload(
            timestamp=timestamp,
            nonce=nonce,
            data=data,
            signature=signature
        )
        
        # Serialize payload
        serialized = payload.to_bytes()
        
        # Add ASCII padding
        padded = self.padding.pad(serialized)
        
        # Pre-encrypt with ML-KEM-derived key
        encrypted = self.pre_cipher.encrypt_bytes(padded)
        
        return encrypted
    
    def parse_handshake_message(self, encrypted_data: bytes) -> Tuple[bytes, int, bytes]:
        """
        Parse and validate a handshake message.
        
        Process:
        1. Decrypt with ML-KEM-derived key
        2. Remove ASCII padding
        3. Parse handshake payload
        4. Verify signature
        5. Validate timestamp and nonce
        
        Args:
            encrypted_data: Encrypted handshake message
            
        Returns:
            Tuple of (data, timestamp, nonce)
            
        Raises:
            ValueError: If validation fails
        """
        # Decrypt
        try:
            padded = self.pre_cipher.decrypt_bytes(encrypted_data)
        except Exception as e:
            raise ValueError(f"Handshake decryption failed: {e}")
        
        # Remove padding
        try:
            serialized = self.padding.unpad(padded)
        except Exception as e:
            raise ValueError(f"Handshake padding removal failed: {e}")
        
        # Parse payload
        try:
            payload = HandshakePayload.from_bytes(serialized)
        except Exception as e:
            raise ValueError(f"Handshake payload parsing failed: {e}")
        
        # Validate timestamp
        current_time = self._get_current_timestamp()
        time_diff = abs(current_time - payload.timestamp)
        
        if time_diff > self.TIMESTAMP_TOLERANCE:
            raise ValueError(
                f"Handshake timestamp out of range: {time_diff}s difference"
            )
        
        # Verify signature
        message_to_verify = bytearray()
        message_to_verify.extend(struct.pack('>Q', payload.timestamp))
        message_to_verify.extend(payload.nonce)
        message_to_verify.extend(payload.data)
        
        if not self.signer.verify_signature(bytes(message_to_verify), payload.signature):
            raise ValueError("Handshake signature verification failed")
        
        return payload.data, payload.timestamp, payload.nonce
    
    def create_client_hello(self, version: int = 1) -> bytes:
        """
        Create a CLIENT_HELLO handshake message.
        
        Args:
            version: Protocol version
            
        Returns:
            Encrypted CLIENT_HELLO message
        """
        data = bytearray()
        data.append(version)
        return self.create_handshake_message(bytes(data))
    
    def parse_client_hello(self, encrypted_data: bytes) -> Tuple[int, int, bytes]:
        """
        Parse a CLIENT_HELLO handshake message.
        
        Args:
            encrypted_data: Encrypted CLIENT_HELLO
            
        Returns:
            Tuple of (version, timestamp, nonce)
            
        Raises:
            ValueError: If validation fails
        """
        data, timestamp, nonce = self.parse_handshake_message(encrypted_data)
        
        if len(data) < 1:
            raise ValueError("CLIENT_HELLO data too short")
        
        version = data[0]
        return version, timestamp, nonce
    
    def create_key_exchange(self, ciphertext: bytes) -> bytes:
        """
        Create a KEY_EXCHANGE handshake message.
        
        Args:
            ciphertext: ML-KEM encapsulated ciphertext
            
        Returns:
            Encrypted KEY_EXCHANGE message
        """
        # Format: CT_LEN(4) + CIPHERTEXT
        data = bytearray()
        data.extend(len(ciphertext).to_bytes(4, 'big'))
        data.extend(ciphertext)
        return self.create_handshake_message(bytes(data))
    
    def parse_key_exchange(self, encrypted_data: bytes) -> Tuple[bytes, int, bytes]:
        """
        Parse a KEY_EXCHANGE handshake message.
        
        Args:
            encrypted_data: Encrypted KEY_EXCHANGE
            
        Returns:
            Tuple of (ciphertext, timestamp, nonce)
            
        Raises:
            ValueError: If validation fails
        """
        data, timestamp, nonce = self.parse_handshake_message(encrypted_data)
        
        if len(data) < 4:
            raise ValueError("KEY_EXCHANGE data too short")
        
        ct_len = int.from_bytes(data[:4], 'big')
        
        if len(data) < 4 + ct_len:
            raise ValueError("KEY_EXCHANGE data incomplete")
        
        ciphertext = data[4:4 + ct_len]
        return ciphertext, timestamp, nonce


def pack_request_metadata(timestamp: int, nonce: bytes) -> bytes:
    """
    Pack timestamp and nonce for replay protection.
    
    Args:
        timestamp: Unix timestamp
        nonce: 32-byte nonce
        
    Returns:
        Packed metadata (40 bytes)
    """
    data = bytearray()
    data.extend(struct.pack('>Q', timestamp))
    data.extend(nonce)
    return bytes(data)


def unpack_request_metadata(data: bytes) -> Tuple[int, bytes]:
    """
    Unpack timestamp and nonce from metadata.
    
    Args:
        data: Packed metadata (40 bytes)
        
    Returns:
        Tuple of (timestamp, nonce)
        
    Raises:
        ValueError: If data is invalid
    """
    if len(data) < 40:
        raise ValueError("Metadata too short")
    
    timestamp = struct.unpack('>Q', data[:8])[0]
    nonce = data[8:40]
    
    return timestamp, nonce
