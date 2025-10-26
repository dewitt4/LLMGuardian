"""
defenders/token_validator.py - Token and credential validation
"""

from typing import Dict, Optional, Any, List
from dataclasses import dataclass
import re
import jwt
from datetime import datetime, timedelta
from ..core.logger import SecurityLogger
from ..core.exceptions import TokenValidationError


@dataclass
class TokenRule:
    pattern: str
    description: str
    min_length: int
    max_length: int
    required_chars: str
    expiry_time: int  # in seconds


@dataclass
class TokenValidationResult:
    is_valid: bool
    errors: List[str]
    metadata: Dict[str, Any]
    expiry: Optional[datetime]


class TokenValidator:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.rules = self._initialize_rules()
        self.secret_key = self._load_secret_key()

    def _initialize_rules(self) -> Dict[str, TokenRule]:
        return {
            "jwt": TokenRule(
                pattern=r"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+$",
                description="JWT token",
                min_length=32,
                max_length=4096,
                required_chars=".-_",
                expiry_time=3600,
            ),
            "api_key": TokenRule(
                pattern=r"^[A-Za-z0-9]{32,64}$",
                description="API key",
                min_length=32,
                max_length=64,
                required_chars="",
                expiry_time=86400,
            ),
            "session_token": TokenRule(
                pattern=r"^[A-Fa-f0-9]{64}$",
                description="Session token",
                min_length=64,
                max_length=64,
                required_chars="",
                expiry_time=7200,
            ),
        }

    def _load_secret_key(self) -> bytes:
        # Implementation would load from secure storage
        return b"your-256-bit-secret"

    def validate_token(self, token: str, token_type: str) -> TokenValidationResult:
        try:
            if token_type not in self.rules:
                raise TokenValidationError(f"Unknown token type: {token_type}")

            rule = self.rules[token_type]
            errors = []
            metadata = {}

            # Length validation
            if len(token) < rule.min_length or len(token) > rule.max_length:
                errors.append(
                    f"Token length must be between {rule.min_length} and {rule.max_length}"
                )

            # Pattern validation
            if not re.match(rule.pattern, token):
                errors.append("Token format is invalid")

            # Required characters
            if rule.required_chars:
                missing_chars = set(rule.required_chars) - set(token)
                if missing_chars:
                    errors.append(f"Token missing required characters: {missing_chars}")

            # JWT-specific validation
            if token_type == "jwt":
                try:
                    payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
                    metadata = payload
                    exp = datetime.fromtimestamp(payload.get("exp", 0))
                    if exp < datetime.utcnow():
                        errors.append("Token has expired")
                except jwt.InvalidTokenError as e:
                    errors.append(f"Invalid JWT: {str(e)}")

            is_valid = len(errors) == 0
            expiry = datetime.utcnow() + timedelta(seconds=rule.expiry_time)

            if not is_valid and self.security_logger:
                self.security_logger.log_security_event(
                    "token_validation_failure", token_type=token_type, errors=errors
                )

            return TokenValidationResult(
                is_valid=is_valid,
                errors=errors,
                metadata=metadata,
                expiry=expiry if is_valid else None,
            )

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "token_validation_error", error=str(e)
                )
            raise TokenValidationError(f"Validation failed: {str(e)}")

    def create_token(self, token_type: str, payload: Dict[str, Any]) -> str:
        if token_type not in self.rules:
            raise TokenValidationError(f"Unknown token type: {token_type}")

        try:
            if token_type == "jwt":
                expiry = datetime.utcnow() + timedelta(
                    seconds=self.rules[token_type].expiry_time
                )
                payload["exp"] = expiry.timestamp()
                return jwt.encode(payload, self.secret_key, algorithm="HS256")

            # Add other token type creation logic here
            raise TokenValidationError(
                f"Token creation not implemented for {token_type}"
            )

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "token_creation_error", error=str(e)
                )
            raise TokenValidationError(f"Token creation failed: {str(e)}")
