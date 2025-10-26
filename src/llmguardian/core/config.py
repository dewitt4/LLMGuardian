"""
core/config.py - Configuration management for LLMGuardian
"""

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .exceptions import (
    ConfigLoadError,
    ConfigurationNotFoundError,
    ConfigValidationError,
)
from .logger import SecurityLogger


class ConfigFormat(Enum):
    """Configuration file formats"""

    YAML = "yaml"
    JSON = "json"


@dataclass
class SecurityConfig:
    """Security-specific configuration"""

    risk_threshold: int = 7
    confidence_threshold: float = 0.7
    max_token_length: int = 2048
    rate_limit: int = 100
    enable_logging: bool = True
    audit_mode: bool = False
    allowed_models: List[str] = field(
        default_factory=lambda: ["gpt-3.5-turbo", "gpt-4"]
    )
    banned_patterns: List[str] = field(default_factory=list)
    max_request_size: int = 1024 * 1024  # 1MB
    token_expiry: int = 3600  # 1 hour


@dataclass
class APIConfig:
    """API-related configuration"""

    timeout: int = 30
    max_retries: int = 3
    backoff_factor: float = 0.5
    verify_ssl: bool = True
    base_url: Optional[str] = None
    api_version: str = "v1"
    max_batch_size: int = 50


@dataclass
class LoggingConfig:
    """Logging configuration"""

    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_file: Optional[str] = None
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5
    enable_console: bool = True
    enable_file: bool = True


@dataclass
class MonitoringConfig:
    """Monitoring configuration"""

    enable_metrics: bool = True
    metrics_interval: int = 60
    alert_threshold: int = 5
    enable_alerting: bool = True
    alert_channels: List[str] = field(default_factory=lambda: ["console"])


class Config:
    """Main configuration management class"""

    DEFAULT_CONFIG_PATH = Path.home() / ".llmguardian" / "config.yml"

    def __init__(
        self,
        config_path: Optional[str] = None,
        security_logger: Optional[SecurityLogger] = None,
    ):
        """Initialize configuration manager"""
        self.config_path = (
            Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        )
        self.security_logger = security_logger
        self._lock = threading.Lock()
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from file"""
        try:
            if not self.config_path.exists():
                self._create_default_config()

            with open(self.config_path, "r") as f:
                if self.config_path.suffix in [".yml", ".yaml"]:
                    config_data = yaml.safe_load(f)
                else:
                    config_data = json.load(f)

            # Initialize configuration sections
            self.security = SecurityConfig(**config_data.get("security", {}))
            self.api = APIConfig(**config_data.get("api", {}))
            self.logging = LoggingConfig(**config_data.get("logging", {}))
            self.monitoring = MonitoringConfig(**config_data.get("monitoring", {}))

            # Store raw config data
            self.config_data = config_data

            # Validate configuration
            self._validate_config()

        except Exception as e:
            raise ConfigLoadError(f"Failed to load configuration: {str(e)}")

    def _create_default_config(self) -> None:
        """Create default configuration file"""
        default_config = {
            "security": asdict(SecurityConfig()),
            "api": asdict(APIConfig()),
            "logging": asdict(LoggingConfig()),
            "monitoring": asdict(MonitoringConfig()),
        }

        os.makedirs(self.config_path.parent, exist_ok=True)

        with open(self.config_path, "w") as f:
            if self.config_path.suffix in [".yml", ".yaml"]:
                yaml.safe_dump(default_config, f)
            else:
                json.dump(default_config, f, indent=2)

    def _validate_config(self) -> None:
        """Validate configuration values"""
        errors = []

        # Validate security config
        if self.security.risk_threshold < 1 or self.security.risk_threshold > 10:
            errors.append("risk_threshold must be between 1 and 10")

        if (
            self.security.confidence_threshold < 0
            or self.security.confidence_threshold > 1
        ):
            errors.append("confidence_threshold must be between 0 and 1")

        # Validate API config
        if self.api.timeout < 0:
            errors.append("timeout must be positive")

        if self.api.max_retries < 0:
            errors.append("max_retries must be positive")

        # Validate logging config
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.logging.log_level not in valid_log_levels:
            errors.append(f"log_level must be one of {valid_log_levels}")

        if errors:
            raise ConfigValidationError("\n".join(errors))

    def save_config(self) -> None:
        """Save current configuration to file"""
        with self._lock:
            config_data = {
                "security": asdict(self.security),
                "api": asdict(self.api),
                "logging": asdict(self.logging),
                "monitoring": asdict(self.monitoring),
            }

            try:
                with open(self.config_path, "w") as f:
                    if self.config_path.suffix in [".yml", ".yaml"]:
                        yaml.safe_dump(config_data, f)
                    else:
                        json.dump(config_data, f, indent=2)

                if self.security_logger:
                    self.security_logger.log_security_event(
                        "configuration_updated", config_path=str(self.config_path)
                    )

            except Exception as e:
                raise ConfigLoadError(f"Failed to save configuration: {str(e)}")

    def update_section(self, section: str, updates: Dict[str, Any]) -> None:
        """Update a configuration section"""
        with self._lock:
            try:
                current_section = getattr(self, section)
                for key, value in updates.items():
                    if hasattr(current_section, key):
                        setattr(current_section, key, value)
                    else:
                        raise ConfigValidationError(f"Invalid configuration key: {key}")

                self._validate_config()
                self.save_config()

                if self.security_logger:
                    self.security_logger.log_security_event(
                        "configuration_section_updated",
                        section=section,
                        updates=updates,
                    )

            except Exception as e:
                raise ConfigLoadError(
                    f"Failed to update configuration section: {str(e)}"
                )

    def get_value(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        try:
            return getattr(getattr(self, section), key)
        except AttributeError:
            return default

    def set_value(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value"""
        self.update_section(section, {key: value})

    def reset_to_default(self) -> None:
        """Reset configuration to default values"""
        with self._lock:
            self._create_default_config()
            self._load_config()


def create_config(
    config_path: Optional[str] = None, security_logger: Optional[SecurityLogger] = None
) -> Config:
    """Create and initialize configuration"""
    return Config(config_path, security_logger)


if __name__ == "__main__":
    # Example usage
    from .logger import setup_logging

    security_logger, _ = setup_logging()
    config = create_config(security_logger=security_logger)

    # Print current configuration
    print("\nCurrent Configuration:")
    print("\nSecurity Configuration:")
    print(asdict(config.security))

    print("\nAPI Configuration:")
    print(asdict(config.api))

    # Update configuration
    config.update_section("security", {"risk_threshold": 8, "max_token_length": 4096})

    # Verify updates
    print("\nUpdated Security Configuration:")
    print(asdict(config.security))
