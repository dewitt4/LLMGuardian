"""
core/exceptions.py - Custom exceptions for LLMGuardian
"""

import logging
import traceback
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class ErrorContext:
    """Context information for errors"""

    timestamp: datetime
    trace: str
    additional_info: Dict[str, Any]


class LLMGuardianError(Exception):
    """Base exception class for LLMGuardian"""

    def __init__(
        self, message: str, error_code: str = None, context: Dict[str, Any] = None
    ):
        self.message = message
        self.error_code = error_code
        self.context = ErrorContext(
            timestamp=datetime.utcnow(),
            trace=traceback.format_exc(),
            additional_info=context or {},
        )
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary format"""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "timestamp": self.context.timestamp.isoformat(),
            "additional_info": self.context.additional_info,
        }


# Security Exceptions
class SecurityError(LLMGuardianError):
    """Base class for security-related errors"""

    def __init__(
        self, message: str, error_code: str = None, context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code=error_code, context=context)


class PromptInjectionError(SecurityError):
    """Raised when prompt injection is detected"""

    def __init__(
        self, message: str = "Prompt injection detected", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="SEC001", context=context)


class AuthenticationError(SecurityError):
    """Raised when authentication fails"""

    def __init__(
        self, message: str = "Authentication failed", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="SEC002", context=context)


class AuthorizationError(SecurityError):
    """Raised when authorization fails"""

    def __init__(
        self, message: str = "Authorization failed", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="SEC003", context=context)


class RateLimitError(SecurityError):
    """Raised when rate limit is exceeded"""

    def __init__(
        self, message: str = "Rate limit exceeded", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="SEC004", context=context)


class TokenValidationError(SecurityError):
    """Raised when token validation fails"""

    def __init__(
        self, message: str = "Token validation failed", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="SEC005", context=context)


class DataLeakageError(SecurityError):
    """Raised when potential data leakage is detected"""

    def __init__(
        self,
        message: str = "Potential data leakage detected",
        context: Dict[str, Any] = None,
    ):
        super().__init__(message, error_code="SEC006", context=context)


# Validation Exceptions
class ValidationError(LLMGuardianError):
    """Base class for validation-related errors"""

    def __init__(
        self, message: str, error_code: str = None, context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code=error_code, context=context)


class InputValidationError(ValidationError):
    """Raised when input validation fails"""

    def __init__(
        self, message: str = "Input validation failed", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="VAL001", context=context)


class OutputValidationError(ValidationError):
    """Raised when output validation fails"""

    def __init__(
        self, message: str = "Output validation failed", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="VAL002", context=context)


class SchemaValidationError(ValidationError):
    """Raised when schema validation fails"""

    def __init__(
        self, message: str = "Schema validation failed", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="VAL003", context=context)


class ContentTypeError(ValidationError):
    """Raised when content type is invalid"""

    def __init__(
        self, message: str = "Invalid content type", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="VAL004", context=context)


# Configuration Exceptions
class ConfigurationError(LLMGuardianError):
    """Base class for configuration-related errors"""

    def __init__(
        self, message: str, error_code: str = None, context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code=error_code, context=context)


class ConfigLoadError(ConfigurationError):
    """Raised when configuration loading fails"""

    def __init__(
        self,
        message: str = "Failed to load configuration",
        context: Dict[str, Any] = None,
    ):
        super().__init__(message, error_code="CFG001", context=context)


class ConfigValidationError(ConfigurationError):
    """Raised when configuration validation fails"""

    def __init__(
        self,
        message: str = "Configuration validation failed",
        context: Dict[str, Any] = None,
    ):
        super().__init__(message, error_code="CFG002", context=context)


class ConfigurationNotFoundError(ConfigurationError):
    """Raised when configuration is not found"""

    def __init__(
        self, message: str = "Configuration not found", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="CFG003", context=context)


# Monitoring Exceptions
class MonitoringError(LLMGuardianError):
    """Base class for monitoring-related errors"""

    def __init__(
        self, message: str, error_code: str = None, context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code=error_code, context=context)


class MetricCollectionError(MonitoringError):
    """Raised when metric collection fails"""

    def __init__(
        self, message: str = "Failed to collect metrics", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="MON001", context=context)


class AlertError(MonitoringError):
    """Raised when alert processing fails"""

    def __init__(
        self, message: str = "Failed to process alert", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="MON002", context=context)


# Resource Exceptions
class ResourceError(LLMGuardianError):
    """Base class for resource-related errors"""

    def __init__(
        self, message: str, error_code: str = None, context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code=error_code, context=context)


class ResourceExhaustedError(ResourceError):
    """Raised when resource limits are exceeded"""

    def __init__(
        self, message: str = "Resource limits exceeded", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="RES001", context=context)


class ResourceNotFoundError(ResourceError):
    """Raised when a required resource is not found"""

    def __init__(
        self, message: str = "Resource not found", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="RES002", context=context)


# API Exceptions
class APIError(LLMGuardianError):
    """Base class for API-related errors"""

    def __init__(
        self, message: str, error_code: str = None, context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code=error_code, context=context)


class APIConnectionError(APIError):
    """Raised when API connection fails"""

    def __init__(
        self, message: str = "API connection failed", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="API001", context=context)


class APIResponseError(APIError):
    """Raised when API response is invalid"""

    def __init__(
        self, message: str = "Invalid API response", context: Dict[str, Any] = None
    ):
        super().__init__(message, error_code="API002", context=context)


class ExceptionHandler:
    """Handle and process exceptions"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)

    def handle_exception(
        self, e: Exception, log_level: int = logging.ERROR
    ) -> Dict[str, Any]:
        """Handle and format exception information"""
        if isinstance(e, LLMGuardianError):
            error_info = e.to_dict()
            self.logger.log(
                log_level, f"{e.__class__.__name__}: {e.message}", extra=error_info
            )
            return error_info

        # Handle unknown exceptions
        error_info = {
            "error": "UnhandledException",
            "message": str(e),
            "error_code": "ERR999",
            "timestamp": datetime.utcnow().isoformat(),
            "traceback": traceback.format_exc(),
        }
        self.logger.error(f"Unhandled exception: {str(e)}", extra=error_info)
        return error_info


def create_exception_handler(
    logger: Optional[logging.Logger] = None,
) -> ExceptionHandler:
    """Create and configure an exception handler"""
    return ExceptionHandler(logger)


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    handler = create_exception_handler(logger)

    # Example usage
    try:
        # Simulate a prompt injection attack
        context = {
            "user_id": "test_user",
            "ip_address": "127.0.0.1",
            "timestamp": datetime.utcnow().isoformat(),
        }
        raise PromptInjectionError(
            "Malicious prompt pattern detected in user input", context=context
        )
    except LLMGuardianError as e:
        error_info = handler.handle_exception(e)
        print("\nCaught LLMGuardianError:")
        print(f"Error Type: {error_info['error']}")
        print(f"Message: {error_info['message']}")
        print(f"Error Code: {error_info['error_code']}")
        print(f"Timestamp: {error_info['timestamp']}")
        print("Additional Info:", error_info["additional_info"])

    try:
        # Simulate a resource exhaustion
        raise ResourceExhaustedError(
            "Memory limit exceeded for prompt processing",
            context={"memory_usage": "95%", "process_id": "12345"},
        )
    except LLMGuardianError as e:
        error_info = handler.handle_exception(e)
        print("\nCaught ResourceError:")
        print(f"Error Type: {error_info['error']}")
        print(f"Message: {error_info['message']}")
        print(f"Error Code: {error_info['error_code']}")

    try:
        # Simulate an unknown error
        raise ValueError("Unexpected value in configuration")
    except Exception as e:
        error_info = handler.handle_exception(e)
        print("\nCaught Unknown Error:")
        print(f"Error Type: {error_info['error']}")
        print(f"Message: {error_info['message']}")
        print(f"Error Code: {error_info['error_code']}")
