"""
defenders/input_sanitizer.py - Input sanitization for LLM inputs
"""

import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from ..core.logger import SecurityLogger
from ..core.exceptions import ValidationError


@dataclass
class SanitizationRule:
    pattern: str
    replacement: str
    description: str
    enabled: bool = True


@dataclass
class SanitizationResult:
    original: str
    sanitized: str
    applied_rules: List[str]
    is_modified: bool
    risk_level: str


class InputSanitizer:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.rules = self._initialize_rules()
        self.compiled_rules = {
            name: re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            for name, rule in self.rules.items()
            if rule.enabled
        }

    def _initialize_rules(self) -> Dict[str, SanitizationRule]:
        return {
            "system_instructions": SanitizationRule(
                pattern=r"system:\s*|instruction:\s*",
                replacement=" ",
                description="Remove system instruction markers",
            ),
            "code_injection": SanitizationRule(
                pattern=r"<script.*?>.*?</script>",
                replacement="",
                description="Remove script tags",
            ),
            "delimiter_injection": SanitizationRule(
                pattern=r"[<\[{](?:system|prompt|instruction)[>\]}]",
                replacement="",
                description="Remove delimiter-based injections",
            ),
            "command_injection": SanitizationRule(
                pattern=r"(?:exec|eval|system)\s*\(",
                replacement="",
                description="Remove command execution attempts",
            ),
            "encoding_patterns": SanitizationRule(
                pattern=r"(?:base64|hex|rot13)\s*\(",
                replacement="",
                description="Remove encoding attempts",
            ),
        }

    def sanitize(
        self, input_text: str, context: Optional[Dict[str, Any]] = None
    ) -> SanitizationResult:
        original = input_text
        applied_rules = []
        is_modified = False

        try:
            sanitized = input_text
            for name, rule in self.rules.items():
                if not rule.enabled:
                    continue

                pattern = self.compiled_rules.get(name)
                if not pattern:
                    continue

                new_text = pattern.sub(rule.replacement, sanitized)
                if new_text != sanitized:
                    applied_rules.append(name)
                    is_modified = True
                    sanitized = new_text

            risk_level = self._assess_risk(applied_rules)

            if is_modified and self.security_logger:
                self.security_logger.log_security_event(
                    "input_sanitization",
                    original_length=len(original),
                    sanitized_length=len(sanitized),
                    applied_rules=applied_rules,
                    risk_level=risk_level,
                )

            return SanitizationResult(
                original=original,
                sanitized=sanitized,
                applied_rules=applied_rules,
                is_modified=is_modified,
                risk_level=risk_level,
            )

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "sanitization_error", error=str(e), input_length=len(input_text)
                )
            raise ValidationError(f"Sanitization failed: {str(e)}")

    def _assess_risk(self, applied_rules: List[str]) -> str:
        if not applied_rules:
            return "low"
        if len(applied_rules) >= 3:
            return "high"
        if "command_injection" in applied_rules or "code_injection" in applied_rules:
            return "high"
        return "medium"

    def add_rule(self, name: str, rule: SanitizationRule) -> None:
        self.rules[name] = rule
        if rule.enabled:
            self.compiled_rules[name] = re.compile(
                rule.pattern, re.IGNORECASE | re.MULTILINE
            )

    def remove_rule(self, name: str) -> None:
        self.rules.pop(name, None)
        self.compiled_rules.pop(name, None)

    def get_rules(self) -> Dict[str, Dict[str, Any]]:
        return {
            name: {
                "pattern": rule.pattern,
                "replacement": rule.replacement,
                "description": rule.description,
                "enabled": rule.enabled,
            }
            for name, rule in self.rules.items()
        }
