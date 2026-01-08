#!/usr/bin/env python3
"""
BunnyTunnel Server - Main Entry Point
A quantum-safe encrypted transport protocol server.

Usage:
    First run:  python -m anti_censorship_server
                (Automatically generates keys and selects random port)
    
    Subsequent: python -m anti_censorship_server
                (Uses saved configuration and keys)
    
    Change port: python -m anti_censorship_server --port 9443
    
    Regenerate keys: python -m anti_censorship_server --regenerate-keys
    
    Show bridge config: python -m anti_censorship_server --show-bridge
"""

import asyncio
import argparse
import signal
import sys
import logging
from pathlib import Path
from typing import Optional

from .config import ConfigManager, ServerConfig
from .config.bridge_config import BridgeConfigGenerator
from .crypto import MLKEMKeyManager, MLDSAKeyManager
from .network import AsyncTCPServer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('BunnyTunnel.Main')


class ServerApplication:
    """Main server application class."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the server application.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_manager = ConfigManager(config_path)
        self.config: Optional[ServerConfig] = None
        self.key_manager: Optional[MLKEMKeyManager] = None
        self.signature_manager: Optional[MLDSAKeyManager] = None
        self.server: Optional[AsyncTCPServer] = None
        self._shutdown_event = asyncio.Event()
        self._is_first_run = False
    
    def _get_base_path(self) -> Path:
        """Get base path for relative paths."""
        return self.config_manager.config_path.parent.parent
    
    def _setup_keys(self) -> None:
        """
        Setup ML-KEM and ML-DSA keys.
        Automatically generates and saves keys on first run.
        Automatically loads existing keys on subsequent runs.
        """
        base_path = self._get_base_path()
        
        # ML-KEM keys for key exchange
        mlkem_private_key_path = base_path / self.config.private_key_file
        mlkem_public_key_path = base_path / self.config.public_key_file
        
        # ML-DSA keys for signing (stored alongside ML-KEM keys)
        mldsa_private_key_path = base_path / "keys" / "mldsa_private.key"
        mldsa_public_key_path = base_path / "keys" / "mldsa_public.key"
        
        # Setup ML-KEM keys
        self.key_manager = MLKEMKeyManager(mlkem_private_key_path, mlkem_public_key_path)
        
        # Setup ML-DSA keys
        self.signature_manager = MLDSAKeyManager(mldsa_private_key_path, mldsa_public_key_path)
        
        try:
            # load_or_generate handles both first run and subsequent runs
            mlkem_keypair = self.key_manager.load_or_generate()
            mldsa_keypair = self.signature_manager.load_or_generate()
            
            if self._is_first_run:
                logger.info(f"Generated new ML-KEM-1024 key pair")
                logger.info(f"  Private key: {mlkem_private_key_path}")
                logger.info(f"  Public key: {mlkem_public_key_path}")
                logger.info(f"Generated new ML-DSA-87 signature key pair")
                logger.info(f"  Private key: {mldsa_private_key_path}")
                logger.info(f"  Public key: {mldsa_public_key_path}")
            else:
                logger.info(f"Loaded ML-KEM-1024 keys from {mlkem_private_key_path}")
                logger.info(f"Loaded ML-DSA-87 keys from {mldsa_private_key_path}")
        except Exception as e:
            logger.error(f"Failed to setup keys: {e}")
            raise
    
    async def _handle_data(self, client_id: str, data: bytes) -> Optional[bytes]:
        """
        Handle received data from clients.
        This is a simple echo handler for demonstration.
        
        Args:
            client_id: Client identifier
            data: Received data
            
        Returns:
            Response data or None
        """
        logger.debug(f"Received {len(data)} bytes from {client_id}")
        # Echo back the data (for demonstration)
        return data
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()
        
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda: asyncio.create_task(self._shutdown())
                )
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                signal.signal(sig, lambda s, f: asyncio.create_task(self._shutdown()))
    
    async def _shutdown(self) -> None:
        """Graceful shutdown handler."""
        logger.info("Shutdown signal received")
        self._shutdown_event.set()
        
        if self.server:
            await self.server.stop()
    
    async def run(self) -> None:
        """Run the server."""
        # Check if first run
        self._is_first_run = self.config_manager.is_first_run()
        
        if self._is_first_run:
            logger.info("First run detected - initializing server...")
        
        # Load configuration (auto-generates random port on first run)
        self.config = self.config_manager.load()
        logger.info(f"Configuration loaded from {self.config_manager.config_path}")
        
        if self._is_first_run:
            logger.info(f"Auto-selected random port: {self.config.port}")
        
        # Setup keys (auto-generates on first run, loads on subsequent runs)
        self._setup_keys()
        
        # Create server with both ML-KEM and ML-DSA key managers
        self.server = AsyncTCPServer(self.config, self.key_manager, self.signature_manager)
        self.server.set_data_handler(self._handle_data)
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        logger.info(f"Starting server on {self.config.host}:{self.config.port}")
        
        try:
            await self.server.start()
        except asyncio.CancelledError:
            pass
        finally:
            await self.server.stop()
            logger.info("Server shutdown complete")


def regenerate_keys(config_path: Optional[str] = None) -> None:
    """
    Regenerate server ML-KEM and ML-DSA keys.
    
    Args:
        config_path: Path to configuration file
    """
    config_manager = ConfigManager(config_path)
    config = config_manager.load()
    
    base_path = config_manager.config_path.parent.parent
    
    # ML-KEM keys
    mlkem_private_key_path = base_path / config.private_key_file
    mlkem_public_key_path = base_path / config.public_key_file
    
    # ML-DSA keys
    mldsa_private_key_path = base_path / "keys" / "mldsa_private.key"
    mldsa_public_key_path = base_path / "keys" / "mldsa_public.key"
    
    # Regenerate ML-KEM keys
    mlkem_manager = MLKEMKeyManager(mlkem_private_key_path, mlkem_public_key_path)
    logger.info("Generating new ML-KEM-1024 key pair...")
    mlkem_manager.regenerate_keypair()
    
    # Regenerate ML-DSA keys
    mldsa_manager = MLDSAKeyManager(mldsa_private_key_path, mldsa_public_key_path)
    logger.info("Generating new ML-DSA-87 signature key pair...")
    mldsa_manager.regenerate_keypair()
    
    logger.info(f"New keys saved to:")
    logger.info(f"  ML-KEM Private key: {mlkem_private_key_path}")
    logger.info(f"  ML-KEM Public key: {mlkem_public_key_path}")
    logger.info(f"  ML-DSA Private key: {mldsa_private_key_path}")
    logger.info(f"  ML-DSA Public key: {mldsa_public_key_path}")
    logger.info("Key regeneration complete")


def update_port(port: int, config_path: Optional[str] = None) -> None:
    """
    Update server port in configuration.
    
    Args:
        port: New port number (1025-65535)
        config_path: Path to configuration file
    """
    config_manager = ConfigManager(config_path)
    config_manager.load()
    config_manager.update_port(port)
    
    logger.info(f"Server port updated to {port}")
    logger.info(f"Configuration saved to {config_manager.config_path}")


def show_config(config_path: Optional[str] = None) -> None:
    """
    Display current server configuration.
    
    Args:
        config_path: Path to configuration file
    """
    config_manager = ConfigManager(config_path)
    
    if config_manager.is_first_run():
        print("Server has not been initialized yet.")
        print("Run the server once to auto-generate configuration and keys.")
        return
    
    config = config_manager.load()
    
    print("\n=== Server Configuration ===")
    print(f"Host: {config.host}")
    print(f"Port: {config.port}")
    print(f"Max Connections: {config.max_connections}")
    print(f"Connection Timeout: {config.connection_timeout}s")
    print(f"Read Buffer Size: {config.read_buffer_size}")
    print(f"Write Buffer Size: {config.write_buffer_size}")
    print(f"Config File: {config_manager.config_path}")
    
    private_key_path, public_key_path = config_manager.get_key_paths()
    print(f"\n=== Key Files ===")
    print(f"Private Key: {private_key_path}")
    print(f"Public Key: {public_key_path}")
    print(f"Keys Exist: {private_key_path.exists() and public_key_path.exists()}")


def show_bridge_config(config_path: Optional[str] = None, host: Optional[str] = None) -> None:
    """
    Display bridge configuration in Tor obfs4 format.
    
    Args:
        config_path: Path to configuration file
        host: Server hostname or IP (if None, uses 0.0.0.0)
    """
    config_manager = ConfigManager(config_path)
    
    if config_manager.is_first_run():
        print("Server has not been initialized yet.")
        print("Run the server once to auto-generate configuration and keys.")
        return
    
    config = config_manager.load()
    private_key_path, public_key_path = config_manager.get_key_paths()
    
    if not public_key_path.exists():
        print("Public key not found. Run the server once to generate keys.")
        return
    
    # Load public key
    with open(public_key_path, 'rb') as f:
        public_key = f.read()
    
    # Use provided host or default
    server_host = host or "YOUR_SERVER_IP"
    
    # Generate bridge line
    bridge_line = BridgeConfigGenerator.generate_bridge_line(
        server_host,
        config.port,
        public_key
    )
    
    print("\n=== BunnyTunnel Bridge Configuration ===")
    print(f"\n{bridge_line}\n")
    print("Note: Replace YOUR_SERVER_IP with your actual server IP address if needed.")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='BunnyTunnel Server - Quantum-safe encrypted transport',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Start server (first run auto-generates keys and random port):
    python -m anti_censorship_server
    
  Start with custom config:
    python -m anti_censorship_server --config /path/to/config.json
    
  Regenerate keys:
    python -m anti_censorship_server --regenerate-keys
    
  Update port:
    python -m anti_censorship_server --port 9443
    
  Show current configuration:
    python -m anti_censorship_server --show-config
    
  Show bridge configuration:
    python -m anti_censorship_server --show-bridge
    python -m anti_censorship_server --show-bridge --host 1.2.3.4
'''
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default=None,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--regenerate-keys',
        action='store_true',
        help='Regenerate ML-KEM key pair'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=None,
        help='Update server port (1025-65535)'
    )
    
    parser.add_argument(
        '--show-config',
        action='store_true',
        help='Show current server configuration'
    )
    
    parser.add_argument(
        '--show-bridge',
        action='store_true',
        help='Show bridge configuration in Tor obfs4 format'
    )
    
    parser.add_argument(
        '--host',
        type=str,
        default=None,
        help='Server hostname or IP for bridge configuration'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Handle show config
    if args.show_config:
        show_config(args.config)
        return
    
    # Handle show bridge
    if args.show_bridge:
        show_bridge_config(args.config, args.host)
        return
    
    # Handle key regeneration
    if args.regenerate_keys:
        regenerate_keys(args.config)
        return
    
    # Handle port update
    if args.port is not None:
        update_port(args.port, args.config)
        return
    
    # Run server
    app = ServerApplication(args.config)
    
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        logger.info("Server interrupted")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
