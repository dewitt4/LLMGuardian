"""
defenders/output_validator.py - Output validation and sanitization
"""

import re
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from ..core.logger import SecurityLogger
from ..core.exceptions import ValidationError


@dataclass
class ValidationRule:
    pattern: str
    description: str
    severity: int  # 1-10
    block: bool = True
    sanitize: bool = True
    replacement: str = ""


@dataclass
class ValidationResult:
    is_valid: bool
    violations: List[str]
    sanitized_output: Optional[str]
    risk_score: int
    details: Dict[str, Any]


class OutputValidator:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.rules = self._initialize_rules()
        self.compiled_rules = {
            name: re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            for name, rule in self.rules.items()
        }
        self.sensitive_patterns = self._initialize_sensitive_patterns()

    def _initialize_rules(self) -> Dict[str, ValidationRule]:
        return {
            "sql_injection": ValidationRule(
                pattern=r"(?:SELECT|INSERT|UPDATE|DELETE)\s+(?:FROM|INTO)\s+\w+",
                description="SQL query in output",
                severity=9,
                block=True,
            ),
            "code_injection": ValidationRule(
                pattern=r"<script.*?>.*?</script>",
                description="JavaScript code in output",
                severity=8,
                block=True,
            ),
            "system_info": ValidationRule(
                pattern=r"(?:system|config|env|secret)(?:_|\s+)?(?:key|token|password)",
                description="System information leak",
                severity=9,
                block=True,
            ),
            "personal_data": ValidationRule(
                pattern=r"\b\d{3}-\d{2}-\d{4}\b|\b\d{16}\b",
                description="Personal data (SSN/CC)",
                severity=10,
                block=True,
            ),
            "file_paths": ValidationRule(
                pattern=r"(?:/[\w./]+)|(?:C:\\[\w\\]+)",
                description="File system paths",
                severity=7,
                block=True,
            ),
            "html_content": ValidationRule(
                pattern=r"<(?!br|p|b|i|em|strong)[^>]+>",
                description="HTML content",
                severity=6,
                sanitize=True,
                replacement="",
            ),
        }

    def _initialize_sensitive_patterns(self) -> Set[str]:
        return {
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP address
            r"(?i)api[_-]?key",  # API keys
            r"(?i)password|passwd|pwd",  # Passwords
            r"(?i)token|secret|credential",  # Credentials
            r"\b[A-Z0-9]{20,}\b",  # Long alphanumeric strings
        }

    def validate(
        self, output: str, context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        try:
            violations = []
            risk_score = 0
            sanitized = output
            is_valid = True

            # Check against validation rules
            for name, rule in self.rules.items():
                pattern = self.compiled_rules[name]
                matches = pattern.findall(sanitized)

                if matches:
                    violations.append(f"{name}: {rule.description}")
                    risk_score = max(risk_score, rule.severity)

                    if rule.block:
                        is_valid = False

                    if rule.sanitize:
                        sanitized = pattern.sub(rule.replacement, sanitized)

            # Check for sensitive data patterns
            for pattern in self.sensitive_patterns:
                matches = re.findall(pattern, sanitized)
                if matches:
                    violations.append(f"Sensitive data detected: {pattern}")
                    risk_score = max(risk_score, 8)
                    is_valid = False
                    sanitized = re.sub(pattern, "[REDACTED]", sanitized)

            result = ValidationResult(
                is_valid=is_valid,
                violations=violations,
                sanitized_output=sanitized if violations else output,
                risk_score=risk_score,
                details={
                    "original_length": len(output),
                    "sanitized_length": len(sanitized),
                    "violation_count": len(violations),
                    "context": context or {},
                },
            )

            if violations and self.security_logger:
                self.security_logger.log_security_event(
                    "output_validation",
                    violations=violations,
                    risk_score=risk_score,
                    is_valid=is_valid,
                )

            return result

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "validation_error", error=str(e), output_length=len(output)
                )
            raise ValidationError(f"Output validation failed: {str(e)}")

    def add_rule(self, name: str, rule: ValidationRule) -> None:
        self.rules[name] = rule
        self.compiled_rules[name] = re.compile(
            rule.pattern, re.IGNORECASE | re.MULTILINE
        )

    def remove_rule(self, name: str) -> None:
        self.rules.pop(name, None)
        self.compiled_rules.pop(name, None)

    def add_sensitive_pattern(self, pattern: str) -> None:
        self.sensitive_patterns.add(pattern)

    def get_rules(self) -> Dict[str, Dict[str, Any]]:
        return {
            name: {
                "pattern": rule.pattern,
                "description": rule.description,
                "severity": rule.severity,
                "block": rule.block,
                "sanitize": rule.sanitize,
            }
            for name, rule in self.rules.items()
        }
