"""
Protocol Handler Module
Defines the wire protocol for BunnyTunnel transport.
"""

import struct
from enum import IntEnum
from typing import Tuple, Optional
from dataclasses import dataclass


class MessageType(IntEnum):
    """Protocol message types."""
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    CLIENT_KEY_EXCHANGE = 0x03
    HANDSHAKE_COMPLETE = 0x04
    DATA = 0x10
    KEEPALIVE = 0x20
    ERROR = 0xFF


@dataclass
class ProtocolMessage:
    """Represents a protocol message."""
    msg_type: MessageType
    payload: bytes
    
    def to_bytes(self) -> bytes:
        """
        Serialize message to bytes.
        
        Format: MAGIC(4) + TYPE(1) + LENGTH(4) + PAYLOAD
        """
        data = bytearray()
        data.extend(ProtocolHandler.PROTOCOL_MAGIC)
        data.append(self.msg_type)
        data.extend(len(self.payload).to_bytes(4, 'big'))
        data.extend(self.payload)
        return bytes(data)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple[Optional['ProtocolMessage'], int]:
        """
        Deserialize message from bytes.
        
        Args:
            data: Raw bytes
            
        Returns:
            Tuple of (message or None, bytes consumed)
        """
        header_size = ProtocolHandler.HEADER_SIZE
        
        if len(data) < header_size:
            return None, 0
        
        magic = data[:4]
        if magic != ProtocolHandler.PROTOCOL_MAGIC:
            raise ValueError("Invalid protocol magic")
        
        msg_type = MessageType(data[4])
        payload_len = int.from_bytes(data[5:9], 'big')
        
        total_len = header_size + payload_len
        if len(data) < total_len:
            return None, 0
        
        payload = data[header_size:total_len]
        
        return cls(msg_type=msg_type, payload=payload), total_len


class ProtocolHandler:
    """
    Handles protocol message framing and parsing.
    """
    
    # Protocol constants
    PROTOCOL_MAGIC = b'BNYT'  # BunnyTunnel Protocol
    PROTOCOL_VERSION = 1
    HEADER_SIZE = 9  # MAGIC(4) + TYPE(1) + LENGTH(4)
    MAX_PAYLOAD_SIZE = 16 * 1024 * 1024  # 16 MB max payload
    
    def __init__(self):
        """Initialize protocol handler."""
        self._buffer = bytearray()
    
    def feed_data(self, data: bytes) -> list[ProtocolMessage]:
        """
        Feed data into the protocol handler and extract complete messages.
        
        Args:
            data: Raw bytes received
            
        Returns:
            List of complete messages
        """
        self._buffer.extend(data)
        messages = []
        
        while True:
            if len(self._buffer) < self.HEADER_SIZE:
                break
            
            # Check magic
            if self._buffer[:4] != self.PROTOCOL_MAGIC:
                raise ValueError("Invalid protocol magic in buffer")
            
            # Get payload length
            payload_len = int.from_bytes(self._buffer[5:9], 'big')
            
            if payload_len > self.MAX_PAYLOAD_SIZE:
                raise ValueError(f"Payload too large: {payload_len}")
            
            total_len = self.HEADER_SIZE + payload_len
            
            if len(self._buffer) < total_len:
                break
            
            # Extract message
            msg_type = MessageType(self._buffer[4])
            payload = bytes(self._buffer[self.HEADER_SIZE:total_len])
            
            messages.append(ProtocolMessage(msg_type=msg_type, payload=payload))
            
            # Remove processed data from buffer
            del self._buffer[:total_len]
        
        return messages
    
    def clear_buffer(self) -> None:
        """Clear the internal buffer."""
        self._buffer.clear()
    
    def get_buffer_size(self) -> int:
        """Get current buffer size."""
        return len(self._buffer)
    
    @staticmethod
    def create_client_hello() -> ProtocolMessage:
        """Create a client hello message."""
        payload = bytearray()
        payload.append(ProtocolHandler.PROTOCOL_VERSION)
        return ProtocolMessage(msg_type=MessageType.CLIENT_HELLO, payload=bytes(payload))
    
    @staticmethod
    def create_server_hello(public_key: bytes) -> ProtocolMessage:
        """
        Create a server hello message with public key.
        
        Args:
            public_key: Server's ML-KEM public key
        """
        payload = bytearray()
        payload.append(ProtocolHandler.PROTOCOL_VERSION)
        payload.extend(len(public_key).to_bytes(4, 'big'))
        payload.extend(public_key)
        return ProtocolMessage(msg_type=MessageType.SERVER_HELLO, payload=bytes(payload))
    
    @staticmethod
    def parse_server_hello(payload: bytes) -> Tuple[int, bytes]:
        """
        Parse server hello payload.
        
        Args:
            payload: Server hello payload
            
        Returns:
            Tuple of (version, public_key)
        """
        if len(payload) < 5:
            raise ValueError("Server hello payload too short")
        
        version = payload[0]
        key_len = int.from_bytes(payload[1:5], 'big')
        
        if len(payload) < 5 + key_len:
            raise ValueError("Server hello payload incomplete")
        
        public_key = payload[5:5 + key_len]
        return version, public_key
    
    @staticmethod
    def create_key_exchange(ciphertext: bytes) -> ProtocolMessage:
        """
        Create a key exchange message with encapsulated ciphertext.
        
        Args:
            ciphertext: ML-KEM encapsulated ciphertext
        """
        payload = bytearray()
        payload.extend(len(ciphertext).to_bytes(4, 'big'))
        payload.extend(ciphertext)
        return ProtocolMessage(msg_type=MessageType.CLIENT_KEY_EXCHANGE, payload=bytes(payload))
    
    @staticmethod
    def parse_key_exchange(payload: bytes) -> bytes:
        """
        Parse key exchange payload.
        
        Args:
            payload: Key exchange payload
            
        Returns:
            Ciphertext bytes
        """
        if len(payload) < 4:
            raise ValueError("Key exchange payload too short")
        
        ct_len = int.from_bytes(payload[:4], 'big')
        
        if len(payload) < 4 + ct_len:
            raise ValueError("Key exchange payload incomplete")
        
        return payload[4:4 + ct_len]
    
    @staticmethod
    def create_handshake_complete(confirmation: bytes) -> ProtocolMessage:
        """
        Create handshake complete message.
        
        Args:
            confirmation: Encrypted confirmation token
        """
        return ProtocolMessage(msg_type=MessageType.HANDSHAKE_COMPLETE, payload=confirmation)
    
    @staticmethod
    def create_data_message(encrypted_data: bytes) -> ProtocolMessage:
        """
        Create a data message.
        
        Args:
            encrypted_data: Encrypted and padded data
        """
        return ProtocolMessage(msg_type=MessageType.DATA, payload=encrypted_data)
    
    @staticmethod
    def create_keepalive(padding: bytes) -> ProtocolMessage:
        """
        Create a keepalive message.
        
        Args:
            padding: Random padding bytes
        """
        return ProtocolMessage(msg_type=MessageType.KEEPALIVE, payload=padding)
    
    @staticmethod
    def create_error(error_code: int = 0) -> ProtocolMessage:
        """
        Create an error message.
        
        Args:
            error_code: Error code
        """
        return ProtocolMessage(msg_type=MessageType.ERROR, payload=bytes([error_code]))
