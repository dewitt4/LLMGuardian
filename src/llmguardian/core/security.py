"""
core/security.py - Core security services for LLMGuardian
"""

import hashlib
import hmac
import secrets
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import jwt
from .config import Config
from .logger import SecurityLogger, AuditLogger

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
        request_history = [time for time in request_history 
                         if now - time < timedelta(seconds=self.time_window)]
        
        # Check rate limit
        if len(request_history) >= self.max_requests:
            return False
        
        # Update history
        request_history.append(now)
        self.requests[key] = request_history
        return True

class SecurityService:
    """Core security service"""
    
    def __init__(self, config: Config, 
                 security_logger: SecurityLogger, 
                 audit_logger: AuditLogger):
        """Initialize security service"""
        self.config = config
        self.security_logger = security_logger
        self.audit_logger = audit_logger
        self.rate_limiter = RateLimiter(
            config.security.rate_limit,
            60  # 1 minute window
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

    def create_security_context(self, user_id: str, 
                              roles: List[str], 
                              permissions: List[str]) -> SecurityContext:
        """Create a new security context"""
        return SecurityContext(
            user_id=user_id,
            roles=roles,
            permissions=permissions,
            session_id=secrets.token_urlsafe(16),
            timestamp=datetime.utcnow()
        )

    def validate_request(self, context: SecurityContext, 
                        resource: str, action: str) -> bool:
        """Validate request against security context"""
        # Check rate limiting
        if not self.rate_limiter.is_allowed(context.user_id):
            self.security_logger.log_security_event(
                "rate_limit_exceeded",
                user_id=context.user_id
            )
            return False

        # Log access attempt
        self.audit_logger.log_access(
            user=context.user_id,
            resource=resource,
            action=action
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
            "exp": datetime.utcnow() + timedelta(hours=1)
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
                timestamp=datetime.fromisoformat(payload["timestamp"])
            )
        except jwt.InvalidTokenError:
            self.security_logger.log_security_event(
                "invalid_token",
                token=token[:10] + "..."  # Log partial token for tracking
            )
            return None

    def hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data using SHA-256"""
        return hashlib.sha256(data.encode()).hexdigest()

    def generate_hmac(self, data: str) -> str:
        """Generate HMAC for data integrity"""
        return hmac.new(
            self.secret_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()

    def verify_hmac(self, data: str, signature: str) -> bool:
        """Verify HMAC signature"""
        expected = self.generate_hmac(data)
        return hmac.compare_digest(expected, signature)

    def audit_configuration_change(self, user: str, 
                                 old_config: Dict[str, Any],
                                 new_config: Dict[str, Any]) -> None:
        """Audit configuration changes"""
        self.audit_logger.log_configuration_change(
            user