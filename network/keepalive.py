"""
Keepalive Manager Module
Implements automatic keepalive mechanism with random intervals and sizes.
"""

import asyncio
import secrets
import string
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass


@dataclass
class KeepaliveConfig:
    """Keepalive configuration."""
    min_interval: float = 1.0  # Minimum interval in seconds
    max_interval: float = 10.0  # Maximum interval in seconds
    min_size: int = 44  # Minimum message size in bytes
    max_size: int = 283  # Maximum message size in bytes


class KeepaliveManager:
    """
    Manages keepalive messages for maintaining connection stability.
    Sends keepalive messages at random intervals with random sizes.
    """
    
    # Keepalive message type identifier
    KEEPALIVE_MAGIC = b'\x04KA'
    
    # ASCII printable characters for padding
    PRINTABLE_CHARS = string.ascii_letters + string.digits + string.punctuation
    
    def __init__(
        self,
        config: Optional[KeepaliveConfig] = None,
        send_callback: Optional[Callable[[bytes], Awaitable[None]]] = None
    ):
        """
        Initialize keepalive manager.
        
        Args:
            config: Keepalive configuration
            send_callback: Async callback to send keepalive messages
        """
        self.config = config or KeepaliveConfig()
        self._send_callback = send_callback
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_received: float = 0.0
    
    def set_send_callback(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """
        Set the callback for sending keepalive messages.
        
        Args:
            callback: Async function to send data
        """
        self._send_callback = callback
    
    def _get_random_interval(self) -> float:
        """
        Get a random keepalive interval.
        
        Returns:
            Random interval between min and max (in seconds)
        """
        range_ms = int((self.config.max_interval - self.config.min_interval) * 1000)
        random_ms = secrets.randbelow(range_ms + 1)
        return self.config.min_interval + (random_ms / 1000.0)
    
    def _get_random_size(self) -> int:
        """
        Get a random keepalive message size.
        
        Returns:
            Random size between min and max (in bytes)
        """
        return secrets.randbelow(
            self.config.max_size - self.config.min_size + 1
        ) + self.config.min_size
    
    def _generate_keepalive_padding(self, size: int) -> bytes:
        """
        Generate random ASCII padding for keepalive message.
        
        Args:
            size: Number of bytes to generate
            
        Returns:
            Random ASCII bytes
        """
        chars = self.PRINTABLE_CHARS
        padding = ''.join(secrets.choice(chars) for _ in range(size))
        return padding.encode('ascii')
    
    def create_keepalive_message(self) -> bytes:
        """
        Create a keepalive message with random size.
        
        Format: MAGIC(3) + SIZE(2) + RANDOM_PADDING
        
        Returns:
            Keepalive message bytes
        """
        target_size = self._get_random_size()
        
        # Account for header size (magic + size field)
        header_size = len(self.KEEPALIVE_MAGIC) + 2
        padding_size = max(0, target_size - header_size)
        
        padding = self._generate_keepalive_padding(padding_size)
        
        message = bytearray()
        message.extend(self.KEEPALIVE_MAGIC)
        message.extend(len(padding).to_bytes(2, 'big'))
        message.extend(padding)
        
        return bytes(message)
    
    def is_keepalive_message(self, data: bytes) -> bool:
        """
        Check if data is a keepalive message.
        
        Args:
            data: Message data to check
            
        Returns:
            True if this is a keepalive message
        """
        if len(data) < len(self.KEEPALIVE_MAGIC):
            return False
        return data[:len(self.KEEPALIVE_MAGIC)] == self.KEEPALIVE_MAGIC
    
    def parse_keepalive_message(self, data: bytes) -> bool:
        """
        Parse and validate a keepalive message.
        
        Args:
            data: Keepalive message data
            
        Returns:
            True if valid keepalive message
        """
        if not self.is_keepalive_message(data):
            return False
        
        if len(data) < len(self.KEEPALIVE_MAGIC) + 2:
            return False
        
        magic_len = len(self.KEEPALIVE_MAGIC)
        padding_len = int.from_bytes(data[magic_len:magic_len + 2], 'big')
        
        expected_len = magic_len + 2 + padding_len
        if len(data) != expected_len:
            return False
        
        # Validate total size is within range
        if not (self.config.min_size <= len(data) <= self.config.max_size):
            return False
        
        return True
    
    def record_received(self) -> None:
        """Record that a keepalive was received."""
        import time
        self._last_received = time.monotonic()
    
    async def _keepalive_loop(self) -> None:
        """Internal keepalive sending loop."""
        while self._running:
            try:
                # Wait for random interval
                interval = self._get_random_interval()
                await asyncio.sleep(interval)
                
                if not self._running:
                    break
                
                # Send keepalive
                if self._send_callback is not None:
                    message = self.create_keepalive_message()
                    await self._send_callback(message)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue
                print(f"Keepalive error: {e}")
                continue
    
    def start(self) -> None:
        """Start the keepalive manager."""
        if self._running:
            return
        
        self._running = True
        self._task = asyncio.create_task(self._keepalive_loop())
    
    async def stop(self) -> None:
        """Stop the keepalive manager."""
        self._running = False
        
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
    
    def is_running(self) -> bool:
        """Check if keepalive manager is running."""
        return self._running
