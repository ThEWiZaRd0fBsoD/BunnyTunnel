"""
Configuration Manager for BunnyTunnel Server
Handles loading, saving, and managing server configuration.
"""

import json
import random
from dataclasses import dataclass
from typing import Optional
from pathlib import Path


@dataclass
class ServerConfig:
    """Server configuration data class."""
    # Network settings
    host: str = "0.0.0.0"
    port: int = 0  # 0 means auto-select random port on first run
    
    # Connection settings
    max_connections: int = 1000
    connection_timeout: float = 30.0
    
    # Buffer settings
    read_buffer_size: int = 65536
    write_buffer_size: int = 65536
    
    # Keepalive settings (fixed ranges as per requirements)
    keepalive_min_interval: float = 1.0
    keepalive_max_interval: float = 10.0
    keepalive_min_size: int = 44
    keepalive_max_size: int = 283
    
    # Padding settings (fixed ranges as per requirements)
    padding_min_size: int = 2
    padding_max_size: int = 8
    
    # Key file paths (internal, not user-configurable)
    private_key_file: str = "keys/server_private.key"
    public_key_file: str = "keys/server_public.key"
    
    # First run flag (internal)
    initialized: bool = False
    
    def validate(self) -> bool:
        """Validate configuration values."""
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid port number: {self.port}")
        if self.max_connections < 1:
            raise ValueError(f"Invalid max_connections: {self.max_connections}")
        if self.connection_timeout <= 0:
            raise ValueError(f"Invalid connection_timeout: {self.connection_timeout}")
        if self.read_buffer_size < 1024:
            raise ValueError(f"Invalid read_buffer_size: {self.read_buffer_size}")
        if self.write_buffer_size < 1024:
            raise ValueError(f"Invalid write_buffer_size: {self.write_buffer_size}")
        return True


class ConfigManager:
    """Manages server configuration loading and saving."""
    
    DEFAULT_CONFIG_PATH = "config/server_config.json"
    
    # Port range for auto-selection
    MIN_PORT = 1025
    MAX_PORT = 65535
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize ConfigManager.
        
        Args:
            config_path: Path to configuration file. Uses default if not specified.
        """
        self.config_path = Path(config_path or self.DEFAULT_CONFIG_PATH)
        self._config: Optional[ServerConfig] = None
    
    def _generate_random_port(self) -> int:
        """
        Generate a random port number in the valid range.
        
        Returns:
            Random port number between MIN_PORT and MAX_PORT
        """
        return random.randint(self.MIN_PORT, self.MAX_PORT)
    
    def is_first_run(self) -> bool:
        """
        Check if this is the first run (no config file exists or not initialized).
        
        Returns:
            True if first run, False otherwise
        """
        if not self.config_path.exists():
            return True
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return not data.get('initialized', False)
        except (json.JSONDecodeError, KeyError):
            return True
    
    def load(self) -> ServerConfig:
        """
        Load configuration from file.
        On first run, creates default configuration with random port.
        
        Returns:
            ServerConfig instance
        """
        first_run = self.is_first_run()
        
        if self.config_path.exists() and not first_run:
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                # Only load user-configurable options (port only after first run)
                self._config = ServerConfig(
                    host=data.get('host', ServerConfig.host),
                    port=data.get('port', ServerConfig.port),
                    max_connections=data.get('max_connections', ServerConfig.max_connections),
                    connection_timeout=data.get('connection_timeout', ServerConfig.connection_timeout),
                    read_buffer_size=data.get('read_buffer_size', ServerConfig.read_buffer_size),
                    write_buffer_size=data.get('write_buffer_size', ServerConfig.write_buffer_size),
                    initialized=True,
                )
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Failed to load config, using defaults: {e}")
                self._config = ServerConfig()
                self._config.port = self._generate_random_port()
                self._config.initialized = True
        else:
            # First run: generate random port
            self._config = ServerConfig()
            self._config.port = self._generate_random_port()
            self._config.initialized = True
            self.save()
        
        self._config.validate()
        return self._config
    
    def save(self) -> None:
        """Save current configuration to file."""
        if self._config is None:
            self._config = ServerConfig()
        
        # Ensure directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Only save user-configurable options
        save_data = {
            'host': self._config.host,
            'port': self._config.port,
            'max_connections': self._config.max_connections,
            'connection_timeout': self._config.connection_timeout,
            'read_buffer_size': self._config.read_buffer_size,
            'write_buffer_size': self._config.write_buffer_size,
            'initialized': self._config.initialized,
        }
        
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, indent=4, ensure_ascii=False)
    
    def get_config(self) -> ServerConfig:
        """
        Get current configuration.
        Loads from file if not already loaded.
        
        Returns:
            ServerConfig instance
        """
        if self._config is None:
            return self.load()
        return self._config
    
    def update_port(self, port: int) -> None:
        """
        Update server port.
        
        Args:
            port: New port number (1025-65535)
        """
        if not (self.MIN_PORT <= port <= self.MAX_PORT):
            raise ValueError(f"Invalid port number: {port}. Must be between {self.MIN_PORT} and {self.MAX_PORT}")
        
        config = self.get_config()
        config.port = port
        self.save()
    
    def get_key_paths(self) -> tuple[Path, Path]:
        """
        Get paths to key files.
        
        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        config = self.get_config()
        base_path = self.config_path.parent.parent
        return (
            base_path / config.private_key_file,
            base_path / config.public_key_file
        )
