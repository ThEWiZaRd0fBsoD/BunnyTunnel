"""
BunnyTunnel Bridge Configuration Generator
Generates bridge configuration in Tor obfs4 format.
"""

import base64
import secrets
from pathlib import Path
from typing import Optional


class BridgeConfigGenerator:
    """Generates bridge configuration strings in Tor obfs4 format."""
    
    @staticmethod
    def generate_cert(public_key: bytes) -> str:
        """
        Generate certificate string from public key.
        
        Args:
            public_key: ML-KEM public key bytes
            
        Returns:
            Base64-encoded certificate string
        """
        # Encode public key as base64 without padding
        cert = base64.b64encode(public_key).decode('ascii').rstrip('=')
        return cert
    
    @staticmethod
    def generate_bridge_line(
        host: str,
        port: int,
        public_key: bytes
    ) -> str:
        """
        Generate bridge configuration line in Tor obfs4 format.
        
        Format: bunnytunnel <IP:PORT> cert=<base64_cert>
        
        Args:
            host: Server IP address or hostname
            port: Server port
            public_key: ML-KEM public key
            
        Returns:
            Bridge configuration line
        """
        cert = BridgeConfigGenerator.generate_cert(public_key)
        return f"bunnytunnel {host}:{port} cert={cert}"
    
    @staticmethod
    def save_bridge_config(
        config_line: str,
        output_path: Path
    ) -> None:
        """
        Save bridge configuration to file.
        
        Args:
            config_line: Bridge configuration line
            output_path: Path to save configuration
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(config_line + '\n')
    
    @staticmethod
    def load_bridge_config(config_path: Path) -> str:
        """
        Load bridge configuration from file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Bridge configuration line
        """
        with open(config_path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    
    @staticmethod
    def parse_bridge_line(bridge_line: str) -> tuple[str, int, bytes]:
        """
        Parse bridge configuration line.
        
        Args:
            bridge_line: Bridge configuration line
            
        Returns:
            Tuple of (host, port, public_key)
            
        Raises:
            ValueError: If bridge line format is invalid
        """
        parts = bridge_line.strip().split()
        
        if len(parts) != 3 or parts[0] != 'bunnytunnel':
            raise ValueError("Invalid bridge line format")
        
        # Parse host:port
        try:
            host, port_str = parts[1].split(':')
            port = int(port_str)
        except ValueError:
            raise ValueError("Invalid host:port format")
        
        # Parse cert
        if not parts[2].startswith('cert='):
            raise ValueError("Missing cert parameter")
        
        cert_b64 = parts[2][5:]  # Remove 'cert=' prefix
        
        # Add padding if needed
        padding = (4 - len(cert_b64) % 4) % 4
        cert_b64 += '=' * padding
        
        try:
            public_key = base64.b64decode(cert_b64)
        except Exception:
            raise ValueError("Invalid certificate encoding")
        
        return host, port, public_key
