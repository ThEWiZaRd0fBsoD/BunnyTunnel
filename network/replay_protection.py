"""
Replay Attack Protection Module
Implements timestamp and nonce-based replay attack protection.
"""

import time
import secrets
import logging
from typing import Set, Optional
from dataclasses import dataclass
from collections import deque
import asyncio


logger = logging.getLogger('BunnyTunnel.ReplayProtection')


@dataclass
class ReplayProtectionConfig:
    """Configuration for replay protection."""
    max_clock_skew: float = 10.0  # Maximum allowed clock skew in seconds
    nonce_size: int = 32  # Nonce size in bytes
    nonce_window: float = 10.0  # Time window to keep nonces in seconds


class ReplayProtection:
    """
    Replay attack protection using timestamp and nonce validation.
    
    Features:
    - Validates UTC timestamps within max_clock_skew tolerance
    - Tracks nonces within a sliding time window
    - Immediately rejects duplicate nonces or expired timestamps
    """
    
    def __init__(self, config: Optional[ReplayProtectionConfig] = None):
        """
        Initialize replay protection.
        
        Args:
            config: Replay protection configuration
        """
        self.config = config or ReplayProtectionConfig()
        
        # Nonce storage: {nonce: timestamp}
        self._nonces: dict[bytes, float] = {}
        
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()
        
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
    
    def start(self) -> None:
        """Start the replay protection service."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Replay protection started")
    
    async def stop(self) -> None:
        """Stop the replay protection service."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
            logger.info("Replay protection stopped")
    
    async def _cleanup_loop(self) -> None:
        """Periodically clean up expired nonces."""
        while True:
            try:
                await asyncio.sleep(1.0)  # Cleanup every second
                await self._cleanup_expired_nonces()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def _cleanup_expired_nonces(self) -> None:
        """Remove nonces older than the time window."""
        async with self._lock:
            current_time = time.time()
            cutoff_time = current_time - self.config.nonce_window
            
            # Remove expired nonces
            expired_nonces = [
                nonce for nonce, timestamp in self._nonces.items()
                if timestamp < cutoff_time
            ]
            
            for nonce in expired_nonces:
                del self._nonces[nonce]
            
            if expired_nonces:
                logger.debug(f"Cleaned up {len(expired_nonces)} expired nonces")
    
    def _get_current_utc_timestamp(self) -> float:
        """
        Get current UTC timestamp.
        
        Returns:
            Current UTC timestamp in seconds
        """
        return time.time()
    
    def _validate_timestamp(self, timestamp: float) -> bool:
        """
        Validate timestamp is within acceptable clock skew.
        
        Args:
            timestamp: UTC timestamp to validate
            
        Returns:
            True if timestamp is valid, False otherwise
        """
        current_time = self._get_current_utc_timestamp()
        time_diff = abs(current_time - timestamp)
        
        if time_diff > self.config.max_clock_skew:
            logger.warning(
                f"Timestamp validation failed: "
                f"time_diff={time_diff:.2f}s, max_skew={self.config.max_clock_skew}s"
            )
            return False
        
        return True
    
    async def validate_request(
        self,
        timestamp: float,
        nonce: bytes
    ) -> bool:
        """
        Validate a request against replay attacks.
        
        Args:
            timestamp: UTC timestamp from the request
            nonce: Random nonce from the request
            
        Returns:
            True if request is valid, False if it's a replay attack
        """
        # Validate nonce size
        if len(nonce) != self.config.nonce_size:
            logger.warning(
                f"Invalid nonce size: expected {self.config.nonce_size}, "
                f"got {len(nonce)}"
            )
            return False
        
        # Validate timestamp
        if not self._validate_timestamp(timestamp):
            return False
        
        # Check for duplicate nonce
        async with self._lock:
            if nonce in self._nonces:
                logger.warning("Duplicate nonce detected - replay attack!")
                return False
            
            # Record nonce with current time
            self._nonces[nonce] = self._get_current_utc_timestamp()
        
        return True
    
    def generate_nonce(self) -> bytes:
        """
        Generate a cryptographically secure random nonce.
        
        Returns:
            Random nonce bytes
        """
        return secrets.token_bytes(self.config.nonce_size)
    
    def get_current_timestamp(self) -> float:
        """
        Get current UTC timestamp for creating requests.
        
        Returns:
            Current UTC timestamp
        """
        return self._get_current_utc_timestamp()
    
    async def get_stats(self) -> dict:
        """
        Get replay protection statistics.
        
        Returns:
            Dictionary with statistics
        """
        async with self._lock:
            return {
                'active_nonces': len(self._nonces),
                'max_clock_skew': self.config.max_clock_skew,
                'nonce_window': self.config.nonce_window,
                'nonce_size': self.config.nonce_size,
            }
    
    async def clear(self) -> None:
        """Clear all stored nonces (for testing)."""
        async with self._lock:
            self._nonces.clear()
            logger.info("Replay protection cleared")


def create_request_metadata() -> tuple[float, bytes]:
    """
    Create request metadata (timestamp and nonce).
    
    Returns:
        Tuple of (timestamp, nonce)
    """
    timestamp = time.time()
    nonce = secrets.token_bytes(ReplayProtectionConfig.nonce_size)
    return timestamp, nonce


def pack_request_metadata(timestamp: float, nonce: bytes) -> bytes:
    """
    Pack request metadata into bytes.
    
    Format: TIMESTAMP(8 bytes, double) + NONCE(32 bytes)
    
    Args:
        timestamp: UTC timestamp
        nonce: Random nonce
        
    Returns:
        Packed metadata bytes
    """
    import struct
    return struct.pack('!d', timestamp) + nonce


def unpack_request_metadata(data: bytes) -> tuple[float, bytes]:
    """
    Unpack request metadata from bytes.
    
    Args:
        data: Packed metadata bytes
        
    Returns:
        Tuple of (timestamp, nonce)
        
    Raises:
        ValueError: If data format is invalid
    """
    import struct
    
    if len(data) < 40:  # 8 + 32
        raise ValueError("Invalid metadata: too short")
    
    timestamp = struct.unpack('!d', data[:8])[0]
    nonce = data[8:40]
    
    return timestamp, nonce
