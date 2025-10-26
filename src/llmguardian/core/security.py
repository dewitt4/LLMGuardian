"""
core/security.py - Core security services for LLMGuardian
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import jwt

from .config import Config
from .logger import AuditLogger, SecurityLogger


@dataclass
class SecurityContext:
    """Security context for requests"""

    user_id: str
    roles: List[str]
    permissions: List[str]
    session_id: str
    timestamp: datetime


class RateLimiter:
    """Rate limiting implementation"""

    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}

    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed under rate limit"""
        now = datetime.utcnow()
        request_history = self.requests.get(key, [])

        # Clean old requests
        request_history = [
            time
            for time in request_history
            if now - time < timedelta(seconds=self.time_window)
        ]

        # Check rate limit
        if len(request_history) >= self.max_requests:
            return False

        # Update history
        request_history.append(now)
        self.requests[key] = request_history
        return True


class SecurityService:
    """Core security service"""

    def __init__(
        self, config: Config, security_logger: SecurityLogger, audit_logger: AuditLogger
    ):
        """Initialize security service"""
        self.config = config
        self.security_logger = security_logger
        self.audit_logger = audit_logger
        self.rate_limiter = RateLimiter(
            config.security.rate_limit, 60  # 1 minute window
        )
        self.secret_key = self._load_or_generate_key()

    def _load_or_generate_key(self) -> bytes:
        """Load or generate secret key"""
        try:
            with open(".secret_key", "rb") as f:
                return f.read()
        except FileNotFoundError:
            key = secrets.token_bytes(32)
            with open(".secret_key", "wb") as f:
                f.write(key)
            return key

    def create_security_context(
        self, user_id: str, roles: List[str], permissions: List[str]
    ) -> SecurityContext:
        """Create a new security context"""
        return SecurityContext(
            user_id=user_id,
            roles=roles,
            permissions=permissions,
            session_id=secrets.token_urlsafe(16),
            timestamp=datetime.utcnow(),
        )

    def validate_request(
        self, context: SecurityContext, resource: str, action: str
    ) -> bool:
        """Validate request against security context"""
        # Check rate limiting
        if not self.rate_limiter.is_allowed(context.user_id):
            self.security_logger.log_security_event(
                "rate_limit_exceeded", user_id=context.user_id
            )
            return False

        # Log access attempt
        self.audit_logger.log_access(
            user=context.user_id, resource=resource, action=action
        )

        return True

    def create_token(self, context: SecurityContext) -> str:
        """Create JWT token from security context"""
        payload = {
            "user_id": context.user_id,
            "roles": context.roles,
            "permissions": context.permissions,
            "session_id": context.session_id,
            "timestamp": context.timestamp.isoformat(),
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def verify_token(self, token: str) -> Optional[SecurityContext]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return SecurityContext(
                user_id=payload["user_id"],
                roles=payload["roles"],
                permissions=payload["permissions"],
                session_id=payload["session_id"],
                timestamp=datetime.fromisoformat(payload["timestamp"]),
            )
        except jwt.InvalidTokenError:
            self.security_logger.log_security_event(
                "invalid_token",
                token=token[:10] + "...",  # Log partial token for tracking
            )
            return None

    def hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data using SHA-256"""
        return hashlib.sha256(data.encode()).hexdigest()

    def generate_hmac(self, data: str) -> str:
        """Generate HMAC for data integrity"""
        return hmac.new(self.secret_key, data.encode(), hashlib.sha256).hexdigest()

    def verify_hmac(self, data: str, signature: str) -> bool:
        """Verify HMAC signature"""
        expected = self.generate_hmac(data)
        return hmac.compare_digest(expected, signature)

    def audit_configuration_change(
        self, user: str, old_config: Dict[str, Any], new_config: Dict[str, Any]
    ) -> None:
        """Audit configuration changes"""
        changes = {
            k: {"old": old_config.get(k), "new": v}
            for k, v in new_config.items()
            if v != old_config.get(k)
        }

        self.audit_logger.log_configuration_change(user, changes)

        if any(k.startswith("security.") for k in changes):
            self.security_logger.log_security_event(
                "security_config_change",
                user=user,
                changes={k: v for k, v in changes.items() if k.startswith("security.")},
            )

    def validate_prompt_security(
        self, prompt: str, context: SecurityContext
    ) -> Dict[str, Any]:
        """Validate prompt against security rules"""
        results = {"allowed": True, "warnings": [], "blocked_reasons": []}

        # Check prompt length
        if len(prompt) > self.config.security.max_token_length:
            results["blocked_reasons"].append("Prompt exceeds maximum length")
            results["allowed"] = False

        # Rate limiting check
        if not self.rate_limiter.is_allowed(context.user_id):
            results["blocked_reasons"].append("Rate limit exceeded")
            results["allowed"] = False

        # Log validation result
        self.security_logger.log_validation(
            "prompt_security",
            {
                "user_id": context.user_id,
                "prompt_length": len(prompt),
                "results": results,
            },
        )

        return results

    def check_permission(
        self, context: SecurityContext, required_permission: str
    ) -> bool:
        """Check if context has required permission"""
        return required_permission in context.permissions

    def sanitize_output(self, output: str) -> str:
        """Sanitize LLM output for security"""
        # Implementation would depend on specific security requirements
        # This is a basic example
        sanitized = output

        # Remove potential command injections
        sanitized = sanitized.replace("sudo ", "")
        sanitized = sanitized.replace("rm -rf", "")

        # Remove potential SQL injections
        sanitized = sanitized.replace("DROP TABLE", "")
        sanitized = sanitized.replace("DELETE FROM", "")

        return sanitized


class SecurityPolicy:
    """Security policy management"""

    def __init__(self):
        self.policies = {}

    def add_policy(self, name: str, policy: Dict[str, Any]) -> None:
        """Add a security policy"""
        self.policies[name] = policy

    def check_policy(self, name: str, context: Dict[str, Any]) -> bool:
        """Check if context meets policy requirements"""
        if name not in self.policies:
            return False

        policy = self.policies[name]
        return all(context.get(k) == v for k, v in policy.items())


class SecurityMetrics:
    """Security metrics tracking"""

    def __init__(self):
        self.metrics = {
            "requests": 0,
            "blocked_requests": 0,
            "warnings": 0,
            "rate_limits": 0,
        }

    def increment(self, metric: str) -> None:
        """Increment a metric counter"""
        if metric in self.metrics:
            self.metrics[metric] += 1

    def get_metrics(self) -> Dict[str, int]:
        """Get current metrics"""
        return self.metrics.copy()

    def reset_metrics(self) -> None:
        """Reset all metrics to zero"""
        for key in self.metrics:
            self.metrics[key] = 0


class SecurityEvent:
    """Security event representation"""

    def __init__(self, event_type: str, severity: int, details: Dict[str, Any]):
        self.event_type = event_type
        self.severity = severity
        self.details = details
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


class SecurityMonitor:
    """Security monitoring service"""

    def __init__(self, security_logger: SecurityLogger):
        self.security_logger = security_logger
        self.metrics = SecurityMetrics()
        self.events = []
        self.alert_threshold = 5  # Number of high-severity events before alerting

    def monitor_event(self, event: SecurityEvent) -> None:
        """Monitor a security event"""
        self.events.append(event)

        if event.severity >= 8:  # High severity
            self.metrics.increment("high_severity_events")

            # Check if we need to trigger an alert
            high_severity_count = sum(
                1
                for e in self.events[-10:]  # Look at last 10 events
                if e.severity >= 8
            )

            if high_severity_count >= self.alert_threshold:
                self.trigger_alert("High severity event threshold exceeded")

    def trigger_alert(self, reason: str) -> None:
        """Trigger a security alert"""
        self.security_logger.log_security_event(
            "security_alert",
            reason=reason,
            recent_events=[e.to_dict() for e in self.events[-10:]],
        )


if __name__ == "__main__":
    # Example usage
    config = Config()
    security_logger, audit_logger = setup_logging()
    security_service = SecurityService(config, security_logger, audit_logger)

    # Create security context
    context = security_service.create_security_context(
        user_id="test_user", roles=["user"], permissions=["read", "write"]
    )

    # Create and verify token
    token = security_service.create_token(context)
    verified_context = security_service.verify_token(token)

    # Validate request
    is_valid = security_service.validate_request(
        context, resource="api/data", action="read"
    )

    print(f"Request validation result: {is_valid}")
