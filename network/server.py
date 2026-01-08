"""
Async TCP Server Module
Implements the main TCP server with multiplexing using asyncio.
"""

import asyncio
import logging
import secrets
from typing import Optional, Dict, Set, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum, auto
import time

from ..config import ServerConfig
from ..crypto import (
    MLKEMKeyManager,
    MLDSAKeyManager,
    AESGCMCipher,
    PayloadPadding,
    HandshakeCrypto
)
from .protocol import ProtocolHandler, ProtocolMessage, MessageType
from .keepalive import KeepaliveManager, KeepaliveConfig
from .replay_protection import ReplayProtection, ReplayProtectionConfig


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('BunnyTunnel.Server')


class ConnectionState(Enum):
    """Connection state machine states."""
    AWAITING_CLIENT_HELLO = auto()
    SENT_SERVER_HELLO = auto()
    AWAITING_KEY_EXCHANGE = auto()
    ESTABLISHED = auto()
    CLOSING = auto()


@dataclass
class ClientConnection:
    """Represents a connected client."""
    client_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    state: ConnectionState = ConnectionState.AWAITING_CLIENT_HELLO
    protocol: ProtocolHandler = field(default_factory=ProtocolHandler)
    cipher: Optional[AESGCMCipher] = None
    padding: PayloadPadding = field(default_factory=PayloadPadding)
    keepalive: Optional[KeepaliveManager] = None
    connected_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()
    
    @property
    def address(self) -> str:
        """Get client address string."""
        try:
            peername = self.writer.get_extra_info('peername')
            if peername:
                return f"{peername[0]}:{peername[1]}"
        except Exception:
            pass
        return "unknown"


class AsyncTCPServer:
    """
    Asynchronous TCP server with multiplexing support.
    Handles multiple client connections concurrently using asyncio.
    """
    
    def __init__(
        self,
        config: ServerConfig,
        key_manager: MLKEMKeyManager,
        signature_manager: MLDSAKeyManager
    ):
        """
        Initialize the server.
        
        Args:
            config: Server configuration
            key_manager: ML-KEM key manager with loaded keys
            signature_manager: ML-DSA key manager for handshake signing
        """
        self.config = config
        self.key_manager = key_manager
        self.signature_manager = signature_manager
        
        self._server: Optional[asyncio.Server] = None
        self._connections: Dict[str, ClientConnection] = {}
        self._running = False
        self._connection_counter = 0
        
        # Data handler callback
        self._data_handler: Optional[Callable[[str, bytes], Awaitable[Optional[bytes]]]] = None
        
        # Replay protection
        self._replay_protection = ReplayProtection(ReplayProtectionConfig())
        
        # Handshake crypto handler
        self._handshake_crypto = HandshakeCrypto(
            mlkem_manager=key_manager,
            mldsa_manager=signature_manager
        )
    
    def set_data_handler(
        self,
        handler: Callable[[str, bytes], Awaitable[Optional[bytes]]]
    ) -> None:
        """
        Set the data handler callback.
        
        Args:
            handler: Async function(client_id, data) -> Optional[response_data]
        """
        self._data_handler = handler
    
    def _generate_client_id(self) -> str:
        """Generate a unique client ID."""
        self._connection_counter += 1
        random_part = secrets.token_hex(4)
        return f"client_{self._connection_counter}_{random_part}"
    
    async def start(self) -> None:
        """Start the server."""
        if self._running:
            logger.warning("Server already running")
            return
        
        # Start replay protection
        self._replay_protection.start()
        
        self._server = await asyncio.start_server(
            self._handle_client,
            self.config.host,
            self.config.port,
            limit=self.config.read_buffer_size
        )
        
        self._running = True
        
        addrs = ', '.join(str(sock.getsockname()) for sock in self._server.sockets)
        logger.info(f"Server started on {addrs}")
        
        async with self._server:
            await self._server.serve_forever()
    
    async def stop(self) -> None:
        """Stop the server and close all connections."""
        if not self._running:
            return
        
        self._running = False
        
        # Stop replay protection
        await self._replay_protection.stop()
        
        # Close all client connections
        for client_id in list(self._connections.keys()):
            await self._close_connection(client_id, "Server shutdown")
        
        # Stop the server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        
        logger.info("Server stopped")
    
    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """
        Handle a new client connection.
        
        Args:
            reader: Stream reader
            writer: Stream writer
        """
        # Check connection limit
        if len(self._connections) >= self.config.max_connections:
            logger.warning("Connection limit reached, rejecting new connection")
            writer.close()
            await writer.wait_closed()
            return
        
        # Create client connection
        client_id = self._generate_client_id()
        client = ClientConnection(
            client_id=client_id,
            reader=reader,
            writer=writer
        )
        
        self._connections[client_id] = client
        logger.info(f"New connection: {client_id} from {client.address}")
        
        try:
            await self._connection_loop(client)
        except Exception as e:
            logger.error(f"Connection error for {client_id}: {e}")
        finally:
            await self._close_connection(client_id, "Connection ended")
    
    async def _connection_loop(self, client: ClientConnection) -> None:
        """
        Main connection handling loop.
        
        Args:
            client: Client connection
        """
        while self._running and client.state != ConnectionState.CLOSING:
            try:
                # Read data with timeout
                data = await asyncio.wait_for(
                    client.reader.read(self.config.read_buffer_size),
                    timeout=self.config.connection_timeout
                )
                
                if not data:
                    # Connection closed by client
                    logger.info(f"Client {client.client_id} disconnected")
                    break
                
                client.update_activity()
                
                # Process received data
                await self._process_data(client, data)
                
            except asyncio.TimeoutError:
                logger.warning(f"Connection timeout for {client.client_id}")
                break
            except asyncio.CancelledError:
                break
            except ValueError as e:
                # Protocol error - close immediately
                logger.error(f"Protocol error for {client.client_id}: {e}")
                break
            except Exception as e:
                logger.error(f"Error processing data for {client.client_id}: {e}")
                break
    
    async def _process_data(self, client: ClientConnection, data: bytes) -> None:
        """
        Process received data from client.
        
        Args:
            client: Client connection
            data: Raw received data
        """
        try:
            messages = client.protocol.feed_data(data)
        except ValueError as e:
            # Protocol error - close immediately
            raise ValueError(f"Protocol parse error: {e}")
        
        for message in messages:
            await self._handle_message(client, message)
    
    async def _handle_message(
        self,
        client: ClientConnection,
        message: ProtocolMessage
    ) -> None:
        """
        Handle a protocol message.
        
        Args:
            client: Client connection
            message: Protocol message
        """
        if message.msg_type == MessageType.CLIENT_HELLO:
            await self._handle_client_hello(client, message)
        
        elif message.msg_type == MessageType.CLIENT_KEY_EXCHANGE:
            await self._handle_key_exchange(client, message)
        
        elif message.msg_type == MessageType.DATA:
            await self._handle_data(client, message)
        
        elif message.msg_type == MessageType.KEEPALIVE:
            await self._handle_keepalive(client, message)
        
        elif message.msg_type == MessageType.ERROR:
            logger.warning(f"Received error from {client.client_id}")
            client.state = ConnectionState.CLOSING
        
        else:
            logger.warning(f"Unknown message type from {client.client_id}: {message.msg_type}")
            client.state = ConnectionState.CLOSING
    
    async def _handle_client_hello(
        self,
        client: ClientConnection,
        message: ProtocolMessage
    ) -> None:
        """Handle client hello message with pre-encryption, signature verification, and replay protection."""
        if client.state != ConnectionState.AWAITING_CLIENT_HELLO:
            logger.error(f"Unexpected CLIENT_HELLO from {client.client_id}")
            client.state = ConnectionState.CLOSING
            return
        
        # Parse encrypted and signed CLIENT_HELLO
        try:
            version, timestamp, nonce = self._handshake_crypto.parse_client_hello(message.payload)
        except Exception as e:
            logger.error(f"Failed to parse CLIENT_HELLO from {client.client_id}: {e}")
            client.state = ConnectionState.CLOSING
            return
        
        # Validate protocol version
        if version != ProtocolHandler.PROTOCOL_VERSION:
            logger.error(f"Version mismatch from {client.client_id}: {version}")
            client.state = ConnectionState.CLOSING
            return
        
        # Validate against replay attacks
        try:
            if not await self._replay_protection.validate_request(timestamp, nonce):
                logger.warning(f"Replay attack detected from {client.client_id}")
                client.state = ConnectionState.CLOSING
                return
        except Exception as e:
            logger.error(f"Failed to validate replay protection: {e}")
            client.state = ConnectionState.CLOSING
            return
        
        # Send server hello with public key (not encrypted for client to use)
        public_key = self.key_manager.get_public_key()
        server_hello = ProtocolHandler.create_server_hello(public_key)
        
        await self._send_message(client, server_hello)
        
        client.state = ConnectionState.AWAITING_KEY_EXCHANGE
        logger.debug(f"Sent SERVER_HELLO to {client.client_id}")
    
    async def _handle_key_exchange(
        self,
        client: ClientConnection,
        message: ProtocolMessage
    ) -> None:
        """Handle client key exchange message with pre-encryption and signature verification."""
        if client.state != ConnectionState.AWAITING_KEY_EXCHANGE:
            logger.error(f"Unexpected KEY_EXCHANGE from {client.client_id}")
            client.state = ConnectionState.CLOSING
            return
        
        try:
            # Parse encrypted and signed KEY_EXCHANGE
            ciphertext, timestamp, nonce = self._handshake_crypto.parse_key_exchange(message.payload)
            
            # Validate against replay attacks
            if not await self._replay_protection.validate_request(timestamp, nonce):
                logger.warning(f"Replay attack detected in KEY_EXCHANGE from {client.client_id}")
                client.state = ConnectionState.CLOSING
                return
            
            # Decapsulate to get shared secret
            mlkem = self.key_manager.get_mlkem_instance()
            shared_secret = mlkem.decapsulate(ciphertext)
            
            # Derive AES key from shared secret
            aes_key = AESGCMCipher.derive_key_from_shared_secret(shared_secret)
            
            # Initialize cipher for data payload encryption
            client.cipher = AESGCMCipher(aes_key)
            
            # Create and send handshake complete
            # Encrypt a confirmation token to prove we have the key
            confirmation_token = secrets.token_bytes(32)
            encrypted_confirmation = client.cipher.encrypt_bytes(confirmation_token)
            
            complete_msg = ProtocolHandler.create_handshake_complete(encrypted_confirmation)
            await self._send_message(client, complete_msg)
            
            # Start keepalive
            keepalive_config = KeepaliveConfig(
                min_interval=self.config.keepalive_min_interval,
                max_interval=self.config.keepalive_max_interval,
                min_size=self.config.keepalive_min_size,
                max_size=self.config.keepalive_max_size
            )
            client.keepalive = KeepaliveManager(
                config=keepalive_config,
                send_callback=lambda data: self._send_keepalive(client, data)
            )
            client.keepalive.start()
            
            client.state = ConnectionState.ESTABLISHED
            logger.info(f"Handshake complete with {client.client_id}, switched to AES-256-GCM encryption")
            
        except Exception as e:
            logger.error(f"Key exchange failed for {client.client_id}: {e}")
            client.state = ConnectionState.CLOSING
    
    async def _handle_data(
        self,
        client: ClientConnection,
        message: ProtocolMessage
    ) -> None:
        """Handle data message."""
        if client.state != ConnectionState.ESTABLISHED:
            logger.error(f"Unexpected DATA from {client.client_id}")
            client.state = ConnectionState.CLOSING
            return
        
        if client.cipher is None:
            logger.error(f"No cipher for {client.client_id}")
            client.state = ConnectionState.CLOSING
            return
        
        try:
            # Decrypt data
            decrypted = client.cipher.decrypt_bytes(message.payload)
            
            # Remove padding
            unpadded = client.padding.unpad(decrypted)
            
            # Call data handler
            if self._data_handler is not None:
                response = await self._data_handler(client.client_id, unpadded)
                
                if response is not None:
                    await self._send_data(client, response)
            
        except Exception as e:
            logger.error(f"Data processing failed for {client.client_id}: {e}")
            client.state = ConnectionState.CLOSING
    
    async def _handle_keepalive(
        self,
        client: ClientConnection,
        message: ProtocolMessage
    ) -> None:
        """Handle keepalive message."""
        if client.state != ConnectionState.ESTABLISHED:
            return
        
        if client.keepalive is not None:
            client.keepalive.record_received()
        
        logger.debug(f"Received keepalive from {client.client_id}")
    
    async def _send_message(
        self,
        client: ClientConnection,
        message: ProtocolMessage
    ) -> None:
        """
        Send a protocol message to client.
        
        Args:
            client: Client connection
            message: Message to send
        """
        try:
            data = message.to_bytes()
            client.writer.write(data)
            await client.writer.drain()
        except Exception as e:
            logger.error(f"Failed to send message to {client.client_id}: {e}")
            client.state = ConnectionState.CLOSING
    
    async def _send_data(self, client: ClientConnection, data: bytes) -> None:
        """
        Send encrypted data to client.
        
        Args:
            client: Client connection
            data: Plaintext data to send
        """
        if client.cipher is None:
            return
        
        try:
            # Add padding
            padded = client.padding.pad(data)
            
            # Encrypt
            encrypted = client.cipher.encrypt_bytes(padded)
            
            # Create and send message
            message = ProtocolHandler.create_data_message(encrypted)
            await self._send_message(client, message)
            
        except Exception as e:
            logger.error(f"Failed to send data to {client.client_id}: {e}")
            client.state = ConnectionState.CLOSING
    
    async def _send_keepalive(self, client: ClientConnection, data: bytes) -> None:
        """
        Send keepalive message to client.
        
        Args:
            client: Client connection
            data: Keepalive data
        """
        if client.state != ConnectionState.ESTABLISHED:
            return
        
        try:
            message = ProtocolHandler.create_keepalive(data)
            await self._send_message(client, message)
            logger.debug(f"Sent keepalive to {client.client_id}")
        except Exception as e:
            logger.error(f"Failed to send keepalive to {client.client_id}: {e}")
    
    async def _close_connection(self, client_id: str, reason: str = "") -> None:
        """
        Close a client connection.
        
        Args:
            client_id: Client ID to close
            reason: Reason for closing
        """
        client = self._connections.pop(client_id, None)
        if client is None:
            return
        
        client.state = ConnectionState.CLOSING
        
        # Stop keepalive
        if client.keepalive is not None:
            await client.keepalive.stop()
        
        # Close writer
        try:
            client.writer.close()
            await client.writer.wait_closed()
        except Exception:
            pass
        
        logger.info(f"Closed connection {client_id}: {reason}")
    
    async def broadcast_data(self, data: bytes) -> None:
        """
        Broadcast data to all established connections.
        
        Args:
            data: Data to broadcast
        """
        for client in list(self._connections.values()):
            if client.state == ConnectionState.ESTABLISHED:
                await self._send_data(client, data)
    
    def get_connection_count(self) -> int:
        """Get number of active connections."""
        return len(self._connections)
    
    def get_established_count(self) -> int:
        """Get number of established (handshake complete) connections."""
        return sum(
            1 for c in self._connections.values()
            if c.state == ConnectionState.ESTABLISHED
        )
