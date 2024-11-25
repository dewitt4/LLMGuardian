# LLMGuardian Core Package

The core package provides the fundamental building blocks and essential services for the LLMGuardian security framework. It implements critical security features, configuration management, logging, rate limiting, and exception handling.

## Components

### 1. Configuration Management (`config.py`)
Manages all configuration aspects of LLMGuardian.

```python
from llmguardian.core import Config

# Initialize configuration
config = Config()

# Access configuration sections
security_config = config.security
api_config = config.api

# Update configuration
config.update_section('security', {
    'risk_threshold': 8,
    'confidence_threshold': 0.8
})

# Get specific values
max_tokens = config.get_value('security', 'max_token_length')
```

Key Features:
- YAML/JSON configuration support
- Environment-specific settings
- Secure storage of sensitive configs
- Configuration validation
- Dynamic updates

### 2. Security Service (`security.py`)
Provides core security functionality and coordination.

```python
from llmguardian.core import SecurityService, SecurityContext

# Initialize service
security = SecurityService(config)

# Create security context
context = security.create_security_context(
    user_id="user123",
    roles=["user"],
    permissions=["read", "generate"]
)

# Validate request
if security.validate_request(context, "model/generate", "execute"):
    # Process request
    pass

# Create and verify tokens
token = security.create_token(context)
verified_context = security.verify_token(token)
```

Key Features:
- Authentication management
- Authorization control
- Security context handling
- Token management
- Request validation

### 3. Rate Limiter (`rate_limiter.py`)
Implements rate limiting and resource control.

```python
from llmguardian.core import RateLimiter, RateLimit, RateLimitType

# Initialize rate limiter
limiter = RateLimiter(security_logger, event_manager)

# Add rate limit
limiter.add_limit(
    "api_requests",
    RateLimit(
        limit=100,
        window=60,  # 60 seconds
        type=RateLimitType.REQUESTS
    )
)

# Check rate limit
if limiter.check_limit("api_requests", "user123"):
    # Process request
    pass
else:
    # Handle rate limit exceeded
    pass

# Get limit info
info = limiter.get_limit_info("api_requests", "user123")
print(f"Remaining requests: {info['remaining']}")
```

Key Features:
- Multiple rate limiting strategies
- Token bucket algorithm
- Window-based limiting
- Concurrent request control
- Adaptive rate limiting

### 4. Security Logger (`logger.py`)
Provides comprehensive security event logging.

```python
from llmguardian.core import SecurityLogger, AuditLogger

# Initialize loggers
security_logger = SecurityLogger()
audit_logger = AuditLogger()

# Log security event
security_logger.log_security_event(
    "prompt_injection_detected",
    severity="high",
    user_id="user123",
    details={"pattern": "system_prompt_override"}
)

# Log audit event
audit_logger.log_access(
    user="user123",
    resource="model/generate",
    action="execute"
)
```

Key Features:
- Structured logging
- Security event tracking
- Audit trail
- Log rotation
- Multiple outputs

### 5. Exception Handling (`exceptions.py`)
Manages custom exceptions and error handling.

```python
from llmguardian.core.exceptions import (
    SecurityError,
    ValidationError,
    RateLimitError
)

try:
    # Attempt operation
    if suspicious_activity_detected:
        raise SecurityError(
            "Suspicious activity detected",
            error_code="SEC001",
            context={"user_id": "user123"}
        )
except SecurityError as e:
    # Handle security error
    logger.error(f"Security violation: {e.message}")
    logger.error(f"Error code: {e.error_code}")
    logger.error(f"Context: {e.context}")
```

Key Features:
- Hierarchical exception structure
- Error context preservation
- Security-focused error handling
- Detailed error information
- Error code system

## Integration Example

Here's how to integrate core components in an application:

```python
from llmguardian.core import (
    Config,
    SecurityService,
    RateLimiter,
    SecurityLogger,
    AuditLogger
)

class SecureLLMApplication:
    def __init__(self):
        # Initialize components
        self.config = Config()
        self.security_logger = SecurityLogger()
        self.audit_logger = AuditLogger()
        
        self.security = SecurityService(
            self.config,
            self.security_logger,
            self.audit_logger
        )
        
        self.rate_limiter = RateLimiter(
            self.security_logger,
            self.security.event_manager
        )

    async def process_request(self, request, user_id: str):
        try:
            # Create security context
            context = self.security.create_security_context(
                user_id=user_id,
                roles=["user"],
                permissions=["generate"]
            )

            # Check rate limit
            if not self.rate_limiter.check_limit("api", user_id):
                raise RateLimitError("Rate limit exceeded")

            # Validate request
            if not self.security.validate_request(
                context, 
                "model/generate", 
                "execute"
            ):
                raise SecurityError("Unauthorized request")

            # Process request
            response = await self.generate_response(request)

            # Log success
            self.audit_logger.log_access(
                user=user_id,
                resource="model/generate",
                action="execute"
            )

            return response

        except Exception as e:
            # Log error
            self.security_logger.log_security_event(
                "request_failed",
                error=str(e),
                user_id=user_id
            )
            raise
```

## Configuration Files

### Default Configuration (config.yml)
```yaml
security:
  risk_threshold: 7
  confidence_threshold: 0.7
  max_token_length: 2048
  rate_limit: 100
  enable_logging: true
  audit_mode: false

api:
  timeout: 30
  max_retries: 3
  backoff_factor: 0.5
  verify_ssl: true

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: logs/security.log
```

## Best Practices

### 1. Configuration Management
- Use environment-specific configurations
- Regularly validate configurations
- Secure sensitive settings
- Monitor configuration changes

### 2. Security
- Implement proper authentication
- Use role-based access control
- Validate all requests
- Monitor security events

### 3. Rate Limiting
- Set appropriate limits
- Monitor usage patterns
- Implement graceful degradation
- Use adaptive limits when possible

### 4. Logging
- Enable comprehensive logging
- Implement log rotation
- Secure log storage
- Regular log analysis

### 5. Error Handling
- Use appropriate exception types
- Include detailed error contexts
- Implement proper error recovery
- Monitor error patterns

## Development

### Testing
```bash
# Run core tests
pytest tests/core/

# Run specific test file
pytest tests/core/test_security.py
```