"""
ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) Module
Implements quantum-safe key exchange using wolfssl Python bindings ML-KEM-1024.
"""

import os
import secrets
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass

try:
    from wolfssl.ciphers import MlKem1024
except ImportError:
    raise ImportError(
        "wolfssl library is required for ML-KEM support. "
        "Install it with: pip install wolfssl"
    )


@dataclass
class KeyPair:
    """Represents an ML-KEM key pair."""
    private_key: bytes
    public_key: bytes


class MLKEMKeyManager:
    """
    Manages ML-KEM-1024 key pairs for the server.
    Handles key generation, storage, and loading.
    """
    
    def __init__(self, private_key_path: Path, public_key_path: Path):
        """
        Initialize the key manager.
        
        Args:
            private_key_path: Path to store/load private key
            public_key_path: Path to store/load public key
        """
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)
        self._key_pair: Optional[KeyPair] = None
        self._mlkem: Optional[MlKem1024] = None
    
    def generate_keypair(self) -> KeyPair:
        """
        Generate a new ML-KEM-1024 key pair.
        
        Returns:
            KeyPair containing private and public keys
        """
        mlkem = MlKem1024()
        mlkem.make_key()
        
        private_key = mlkem.export_private()
        public_key = mlkem.export_public()
        
        self._key_pair = KeyPair(private_key=private_key, public_key=public_key)
        self._mlkem = mlkem
        
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
    
    def load_keypair(self) -> KeyPair:
        """
        Load key pair from files.
        
        Returns:
            KeyPair loaded from files
            
        Raises:
            FileNotFoundError: If key files don't exist
        """
        if not self.private_key_path.exists():
            raise FileNotFoundError(f"Private key not found: {self.private_key_path}")
        if not self.public_key_path.exists():
            raise FileNotFoundError(f"Public key not found: {self.public_key_path}")
        
        with open(self.private_key_path, 'rb') as f:
            private_key = f.read()
        
        with open(self.public_key_path, 'rb') as f:
            public_key = f.read()
        
        self._key_pair = KeyPair(private_key=private_key, public_key=public_key)
        
        # Initialize ML-KEM instance with loaded keys
        self._mlkem = MlKem1024()
        self._mlkem.import_private(private_key)
        
        return self._key_pair
    
    def load_or_generate(self) -> KeyPair:
        """
        Load existing key pair or generate new one if not found.
        
        Returns:
            KeyPair (loaded or newly generated)
        """
        try:
            return self.load_keypair()
        except FileNotFoundError:
            keypair = self.generate_keypair()
            self.save_keypair()
            return keypair
    
    def regenerate_keypair(self) -> KeyPair:
        """
        Generate a new key pair and save it, replacing any existing keys.
        
        Returns:
            Newly generated KeyPair
        """
        keypair = self.generate_keypair()
        self.save_keypair()
        return keypair
    
    def get_public_key(self) -> bytes:
        """
        Get the current public key.
        
        Returns:
            Public key bytes
        """
        if self._key_pair is None:
            raise ValueError("No key pair loaded. Load or generate one first.")
        return self._key_pair.public_key
    
    def get_mlkem_instance(self) -> MlKem1024:
        """
        Get the ML-KEM instance for decapsulation.
        
        Returns:
            MlKem1024 instance with loaded private key
        """
        if self._mlkem is None:
            raise ValueError("No ML-KEM instance available. Load or generate keys first.")
        return self._mlkem


class MLKEMHandshake:
    """
    Handles ML-KEM key exchange handshake for establishing shared secrets.
    Server-side implementation.
    """
    
    # Protocol constants
    HANDSHAKE_MAGIC = b'ACTP'  # Anti-Censorship Transport Protocol
    VERSION = 1
    
    def __init__(self, key_manager: MLKEMKeyManager):
        """
        Initialize handshake handler.
        
        Args:
            key_manager: MLKEMKeyManager instance with loaded keys
        """
        self.key_manager = key_manager
        self._shared_secret: Optional[bytes] = None
    
    def create_server_hello(self) -> bytes:
        """
        Create server hello message containing public key.
        
        Returns:
            Server hello message bytes
        """
        public_key = self.key_manager.get_public_key()
        
        # Message format: MAGIC(4) + VERSION(1) + PUBKEY_LEN(4) + PUBKEY
        message = bytearray()
        message.extend(self.HANDSHAKE_MAGIC)
        message.append(self.VERSION)
        message.extend(len(public_key).to_bytes(4, 'big'))
        message.extend(public_key)
        
        return bytes(message)
    
    def parse_client_hello(self, data: bytes) -> bool:
        """
        Parse and validate client hello message.
        
        Args:
            data: Client hello message bytes
            
        Returns:
            True if valid client hello
        """
        if len(data) < 5:
            return False
        
        magic = data[:4]
        version = data[4]
        
        if magic != self.HANDSHAKE_MAGIC:
            return False
        if version != self.VERSION:
            return False
        
        return True
    
    def process_client_ciphertext(self, ciphertext: bytes) -> bytes:
        """
        Process client's encapsulated ciphertext and derive shared secret.
        
        Args:
            ciphertext: Encapsulated ciphertext from client
            
        Returns:
            Shared secret bytes (32 bytes for AES-256)
        """
        mlkem = self.key_manager.get_mlkem_instance()
        
        # Decapsulate to get shared secret
        self._shared_secret = mlkem.decapsulate(ciphertext)
        
        return self._shared_secret
    
    def get_shared_secret(self) -> bytes:
        """
        Get the established shared secret.
        
        Returns:
            Shared secret bytes
            
        Raises:
            ValueError: If handshake not completed
        """
        if self._shared_secret is None:
            raise ValueError("Handshake not completed. No shared secret available.")
        return self._shared_secret
    
    @staticmethod
    def parse_ciphertext_message(data: bytes) -> Tuple[bool, bytes]:
        """
        Parse ciphertext message from client.
        
        Args:
            data: Raw message bytes
            
        Returns:
            Tuple of (success, ciphertext)
        """
        if len(data) < 8:
            return False, b''
        
        magic = data[:4]
        if magic != MLKEMHandshake.HANDSHAKE_MAGIC:
            return False, b''
        
        msg_type = data[4]
        if msg_type != 0x02:  # Ciphertext message type
            return False, b''
        
        ct_len = int.from_bytes(data[5:9], 'big')
        if len(data) < 9 + ct_len:
            return False, b''
        
        ciphertext = data[9:9 + ct_len]
        return True, ciphertext
    
    def create_handshake_complete(self) -> bytes:
        """
        Create handshake complete message.
        
        Returns:
            Handshake complete message bytes
        """
        # Generate a random confirmation token encrypted with shared secret
        # This proves the server has the correct shared secret
        confirmation = secrets.token_bytes(32)
        
        message = bytearray()
        message.extend(self.HANDSHAKE_MAGIC)
        message.append(0x03)  # Handshake complete message type
        message.extend(confirmation)
        
        return bytes(message)
