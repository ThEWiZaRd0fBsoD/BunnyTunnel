"""
Payload Padding Module
Implements ASCII printable character padding to reduce information entropy.
"""

import secrets
import string
from typing import Tuple


class PayloadPadding:
    """
    Handles padding of data payloads with ASCII printable characters.
    Padding is added to both head and tail of the payload to reduce entropy.
    """
    
    # ASCII printable characters (excluding space for better entropy reduction)
    PRINTABLE_CHARS = string.ascii_letters + string.digits + string.punctuation
    
    # Padding size range (as per requirements: 2-8 bytes)
    MIN_PADDING_SIZE = 2
    MAX_PADDING_SIZE = 8
    
    # Padding markers to identify padding boundaries
    PADDING_START_MARKER = b'\x01'
    PADDING_END_MARKER = b'\x02'
    
    def __init__(self, min_size: int = MIN_PADDING_SIZE, max_size: int = MAX_PADDING_SIZE):
        """
        Initialize padding handler.
        
        Args:
            min_size: Minimum padding size (default: 2)
            max_size: Maximum padding size (default: 8)
        """
        if min_size < 1:
            raise ValueError("Minimum padding size must be at least 1")
        if max_size < min_size:
            raise ValueError("Maximum padding size must be >= minimum")
        
        self.min_size = min_size
        self.max_size = max_size
    
    def _generate_random_padding(self, size: int) -> bytes:
        """
        Generate random ASCII printable padding.
        
        Args:
            size: Number of padding bytes to generate
            
        Returns:
            Random ASCII printable bytes
        """
        chars = self.PRINTABLE_CHARS
        padding = ''.join(secrets.choice(chars) for _ in range(size))
        return padding.encode('ascii')
    
    def _get_random_padding_size(self) -> int:
        """
        Get a random padding size within configured range.
        
        Returns:
            Random size between min_size and max_size
        """
        return secrets.randbelow(self.max_size - self.min_size + 1) + self.min_size
    
    def pad(self, data: bytes) -> bytes:
        """
        Add random ASCII padding to head and tail of data.
        
        Format: HEAD_PAD_LEN(1) + HEAD_PAD + DATA + TAIL_PAD + TAIL_PAD_LEN(1)
        
        Args:
            data: Original data to pad
            
        Returns:
            Padded data
        """
        head_size = self._get_random_padding_size()
        tail_size = self._get_random_padding_size()
        
        head_padding = self._generate_random_padding(head_size)
        tail_padding = self._generate_random_padding(tail_size)
        
        # Build padded message
        result = bytearray()
        result.append(head_size)  # Head padding length
        result.extend(head_padding)  # Head padding
        result.extend(data)  # Original data
        result.extend(tail_padding)  # Tail padding
        result.append(tail_size)  # Tail padding length
        
        return bytes(result)
    
    def unpad(self, padded_data: bytes) -> bytes:
        """
        Remove padding from data.
        
        Args:
            padded_data: Padded data
            
        Returns:
            Original data without padding
            
        Raises:
            ValueError: If padding is invalid
        """
        if len(padded_data) < 4:  # Minimum: 1 + min_pad + 0 + min_pad + 1
            raise ValueError("Padded data too short")
        
        head_size = padded_data[0]
        tail_size = padded_data[-1]
        
        # Validate padding sizes
        if not (self.min_size <= head_size <= self.max_size):
            raise ValueError(f"Invalid head padding size: {head_size}")
        if not (self.min_size <= tail_size <= self.max_size):
            raise ValueError(f"Invalid tail padding size: {tail_size}")
        
        # Calculate expected minimum length
        min_length = 1 + head_size + tail_size + 1
        if len(padded_data) < min_length:
            raise ValueError("Padded data length mismatch")
        
        # Extract original data
        data_start = 1 + head_size
        data_end = len(padded_data) - 1 - tail_size
        
        if data_end < data_start:
            raise ValueError("Invalid padding: negative data length")
        
        return padded_data[data_start:data_end]
    
    def validate_padding(self, padded_data: bytes) -> bool:
        """
        Validate that padding is correctly formatted.
        
        Args:
            padded_data: Data to validate
            
        Returns:
            True if padding is valid
        """
        try:
            self.unpad(padded_data)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def calculate_overhead(head_size: int, tail_size: int) -> int:
        """
        Calculate total padding overhead.
        
        Args:
            head_size: Head padding size
            tail_size: Tail padding size
            
        Returns:
            Total overhead in bytes
        """
        return 1 + head_size + tail_size + 1  # length bytes + padding
