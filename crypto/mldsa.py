"""
ML-DSA-87 (Module-Lattice-Based Digital Signature Algorithm) Module
Implements quantum-safe digital signatures using wolfssl Python bindings ML-DSA-87.
"""

import os
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass

try:
    from wolfssl.ciphers import MlDsa87
except ImportError:
    raise ImportError(
        "wolfssl library is required for ML-DSA support. "
        "Install it with: pip install wolfssl"
    )


@dataclass
class SignatureKeyPair:
    """Represents an ML-DSA-87 key pair."""
    private_key: bytes
    public_key: bytes


class MLDSAKeyManager:
    """
    Manages ML-DSA-87 key pairs for the server.
    Handles key generation, storage, loading, and signing operations.
    """
    
    def __init__(self, private_key_path: Path, public_key_path: Path):
        """
        Initialize the signature key manager.
        
        Args:
            private_key_path: Path to store/load private signing key
            public_key_path: Path to store/load public verification key
        """
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)
        self._key_pair: Optional[SignatureKeyPair] = None
        self._mldsa: Optional[MlDsa87] = None
    
    def generate_keypair(self) -> SignatureKeyPair:
        """
        Generate a new ML-DSA-87 key pair.
        
        Returns:
            SignatureKeyPair containing private and public keys
        """
        mldsa = MlDsa87()
        mldsa.make_key()
        
        private_key = mldsa.export_private()
        public_key = mldsa.export_public()
        
        self._key_pair = SignatureKeyPair(private_key=private_key, public_key=public_key)
        self._mldsa = mldsa
        
        return self._key_pair
    
    def save_keypair(self) -> None:
        """Save the current key pair to files."""
        if self._key_pair is None:
            raise ValueError("No key pair to save. Generate one first.")
        
        # Ensure directories exist
        self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
        self.public_key_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save private key with restricted permissions
        with open(self.private_key_path, 'wb') as f:
            f.write(self._key_pair.private_key)
        
        # Try to set restrictive permissions on private key (Unix-like systems)
        try:
            os.chmod(self.private_key_path, 0o600)
        except (OSError, AttributeError):
            pass  # Windows or permission error
        
        # Save public key
        with open(self.public_key_path, 'wb') as f:
            f.write(self._key_pair.public_key)
    
    def load_keypair(self) -> SignatureKeyPair:
        """
        Load key pair from files.
        
        Returns:
            SignatureKeyPair loaded from files
            
        Raises:
            FileNotFoundError: If key files don't exist
        """
        if not self.private_key_path.exists():
            raise FileNotFoundError(f"Private signing key not found: {self.private_key_path}")
        if not self.public_key_path.exists():
            raise FileNotFoundError(f"Public verification key not found: {self.public_key_path}")
        
        with open(self.private_key_path, 'rb') as f:
            private_key = f.read()
        
        with open(self.public_key_path, 'rb') as f:
            public_key = f.read()
        
        self._key_pair = SignatureKeyPair(private_key=private_key, public_key=public_key)
        
        # Initialize ML-DSA instance with loaded keys
        self._mldsa = MlDsa87()
        self._mldsa.import_private(private_key)
        
        return self._key_pair
    
    def load_or_generate(self) -> SignatureKeyPair:
        """
        Load existing key pair or generate new one if not found.
        
        Returns:
            SignatureKeyPair (loaded or newly generated)
        """
        try:
            return self.load_keypair()
        except FileNotFoundError:
            keypair = self.generate_keypair()
            self.save_keypair()
            return keypair
    
    def regenerate_keypair(self) -> SignatureKeyPair:
        """
        Generate a new key pair and save it, replacing any existing keys.
        
        Returns:
            Newly generated SignatureKeyPair
        """
        keypair = self.generate_keypair()
        self.save_keypair()
        return keypair
    
    def get_public_key(self) -> bytes:
        """
        Get the current public verification key.
        
        Returns:
            Public key bytes
        """
        if self._key_pair is None:
            raise ValueError("No key pair loaded. Load or generate one first.")
        return self._key_pair.public_key
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using ML-DSA-87.
        
        Args:
            message: Message to sign
            
        Returns:
            Signature bytes
        """
        if self._mldsa is None:
            raise ValueError("No ML-DSA instance available. Load or generate keys first.")
        
        signature = self._mldsa.sign(message)
        return signature
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature using ML-DSA-87.
        
        Args:
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        if self._mldsa is None:
            raise ValueError("No ML-DSA instance available. Load or generate keys first.")
        
        try:
            return self._mldsa.verify(message, signature)
        except Exception:
            return False


class MLDSASigner:
    """
    Handles ML-DSA-87 signing and verification operations.
    """
    
    def __init__(self, key_manager: MLDSAKeyManager):
        """
        Initialize signer.
        
        Args:
            key_manager: MLDSAKeyManager instance with loaded keys
        """
        self.key_manager = key_manager
    
    def sign_message(self, message: bytes) -> bytes:
        """
        Sign a message.
        
        Args:
            message: Message to sign
            
        Returns:
            Signature bytes
        """
        return self.key_manager.sign(message)
    
    def verify_signature(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a message signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if valid, False otherwise
        """
        return self.key_manager.verify(message, signature)
    
    @staticmethod
    def create_signed_payload(message: bytes, signature: bytes) -> bytes:
        """
        Create a signed payload with signature appended.
        
        Format: SIG_LEN(4) + SIGNATURE + MESSAGE
        
        Args:
            message: Original message
            signature: Message signature
            
        Returns:
            Signed payload bytes
        """
        payload = bytearray()
        payload.extend(len(signature).to_bytes(4, 'big'))
        payload.extend(signature)
        payload.extend(message)
        return bytes(payload)
    
    @staticmethod
    def parse_signed_payload(payload: bytes) -> Tuple[bytes, bytes]:
        """
        Parse a signed payload.
        
        Args:
            payload: Signed payload bytes
            
        Returns:
            Tuple of (message, signature)
            
        Raises:
            ValueError: If payload format is invalid
        """
        if len(payload) < 4:
            raise ValueError("Signed payload too short")
        
        sig_len = int.from_bytes(payload[:4], 'big')
        
        if len(payload) < 4 + sig_len:
            raise ValueError("Signed payload incomplete")
        
        signature = payload[4:4 + sig_len]
        message = payload[4 + sig_len:]
        
        return message, signature
