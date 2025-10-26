"""
core/__init__.py - Core module initialization for LLMGuardian
"""

from typing import Dict, Any, Optional
import logging
from pathlib import Path

# Version information
__version__ = "1.0.0"
__author__ = "dewitt4"
__license__ = "Apache-2.0"

# Core components
from .config import Config, SecurityConfig, APIConfig, LoggingConfig, MonitoringConfig
from .exceptions import (
    LLMGuardianError,
    SecurityError,
    ValidationError,
    ConfigurationError,
    PromptInjectionError,
    RateLimitError,
)
from .logger import SecurityLogger, AuditLogger
from .rate_limiter import (
    RateLimiter,
    RateLimit,
    RateLimitType,
    TokenBucket,
    create_rate_limiter,
)
from .security import (
    SecurityService,
    SecurityContext,
    SecurityPolicy,
    SecurityMetrics,
    SecurityMonitor,
)

# Initialize logging
logging.getLogger(__name__).addHandler(logging.NullHandler())


class CoreService:
    """Main entry point for LLMGuardian core functionality"""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize core services"""
        # Load configuration
        self.config = Config(config_path)

        # Initialize loggers
        self.security_logger = SecurityLogger()
        self.audit_logger = AuditLogger()

        # Initialize core services
        self.security_service = SecurityService(
            self.config, self.security_logger, self.audit_logger
        )

        # Initialize rate limiter
        self.rate_limiter = create_rate_limiter(
            self.security_logger, self.security_service.event_manager
        )

        # Initialize security monitor
        self.security_monitor = SecurityMonitor(self.security_logger)

    @property
    def version(self) -> str:
        """Get the current version"""
        return __version__

    def get_status(self) -> Dict[str, Any]:
        """Get current status of core services"""
        return {
            "version": self.version,
            "config_loaded": bool(self.config),
            "security_enabled": True,
            "rate_limiting_enabled": True,
            "monitoring_enabled": True,
            "security_metrics": self.security_service.get_metrics(),
        }


def create_core_service(config_path: Optional[str] = None) -> CoreService:
    """Create and configure a core service instance"""
    return CoreService(config_path)


# Default exports
__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    # Core classes
    "CoreService",
    "Config",
    "SecurityConfig",
    "APIConfig",
    "LoggingConfig",
    "MonitoringConfig",
    # Security components
    "SecurityService",
    "SecurityContext",
    "SecurityPolicy",
    "SecurityMetrics",
    "SecurityMonitor",
    # Rate limiting
    "RateLimiter",
    "RateLimit",
    "RateLimitType",
    "TokenBucket",
    # Logging
    "SecurityLogger",
    "AuditLogger",
    # Exceptions
    "LLMGuardianError",
    "SecurityError",
    "ValidationError",
    "ConfigurationError",
    "PromptInjectionError",
    "RateLimitError",
    # Factory functions
    "create_core_service",
    "create_rate_limiter",
]


def get_version() -> str:
    """Return the version string"""
    return __version__


def get_core_info() -> Dict[str, Any]:
    """Get information about the core module"""
    return {
        "version": __version__,
        "author": __author__,
        "license": __license__,
        "python_path": str(Path(__file__).parent),
        "components": [
            "Configuration Management",
            "Security Service",
            "Rate Limiting",
            "Security Logging",
            "Monitoring",
            "Exception Handling",
        ],
    }


if __name__ == "__main__":
    # Example usage
    core = create_core_service()
    print(f"LLMGuardian Core v{core.version}")
    print("\nStatus:")
    for key, value in core.get_status().items():
        print(f"{key}: {value}")

    print("\nCore Info:")
    for key, value in get_core_info().items():
        print(f"{key}: {value}")
