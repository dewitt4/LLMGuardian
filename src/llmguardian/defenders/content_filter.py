"""
defenders/content_filter.py - Content filtering and moderation
"""

import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
from ..core.logger import SecurityLogger
from ..core.exceptions import ValidationError


class ContentCategory(Enum):
    MALICIOUS = "malicious"
    SENSITIVE = "sensitive"
    HARMFUL = "harmful"
    INAPPROPRIATE = "inappropriate"
    POTENTIAL_EXPLOIT = "potential_exploit"


@dataclass
class FilterRule:
    pattern: str
    category: ContentCategory
    severity: int  # 1-10
    description: str
    action: str  # "block" or "sanitize"
    replacement: str = "[FILTERED]"


@dataclass
class FilterResult:
    is_allowed: bool
    filtered_content: str
    matched_rules: List[str]
    risk_score: int
    categories: Set[ContentCategory]
    details: Dict[str, Any]


class ContentFilter:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.rules = self._initialize_rules()
        self.compiled_rules = {
            name: re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            for name, rule in self.rules.items()
        }

    def _initialize_rules(self) -> Dict[str, FilterRule]:
        return {
            "code_execution": FilterRule(
                pattern=r"(?:exec|eval|system|subprocess|os\.)",
                category=ContentCategory.MALICIOUS,
                severity=9,
                description="Code execution attempt",
                action="block",
            ),
            "sql_commands": FilterRule(
                pattern=r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+(?:FROM|INTO|TABLE)",
                category=ContentCategory.MALICIOUS,
                severity=8,
                description="SQL command",
                action="block",
            ),
            "file_operations": FilterRule(
                pattern=r"(?:read|write|open|delete|remove)\s*\(['\"].*?['\"]",
                category=ContentCategory.POTENTIAL_EXPLOIT,
                severity=7,
                description="File operation",
                action="block",
            ),
            "pii_data": FilterRule(
                pattern=r"\b\d{3}-\d{2}-\d{4}\b|\b\d{16}\b",
                category=ContentCategory.SENSITIVE,
                severity=8,
                description="PII data",
                action="sanitize",
                replacement="[REDACTED]",
            ),
            "harmful_content": FilterRule(
                pattern=r"(?:hack|exploit|bypass|vulnerability)\s+(?:system|security|protection)",
                category=ContentCategory.HARMFUL,
                severity=7,
                description="Potentially harmful content",
                action="block",
            ),
            "inappropriate_content": FilterRule(
                pattern=r"(?:explicit|offensive|inappropriate).*content",
                category=ContentCategory.INAPPROPRIATE,
                severity=6,
                description="Inappropriate content",
                action="sanitize",
            ),
        }

    def filter_content(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> FilterResult:
        try:
            matched_rules = []
            categories = set()
            risk_score = 0
            filtered = content
            is_allowed = True

            for name, rule in self.rules.items():
                pattern = self.compiled_rules[name]
                matches = pattern.findall(filtered)

                if matches:
                    matched_rules.append(name)
                    categories.add(rule.category)
                    risk_score = max(risk_score, rule.severity)

                    if rule.action == "block":
                        is_allowed = False
                    elif rule.action == "sanitize":
                        filtered = pattern.sub(rule.replacement, filtered)

            result = FilterResult(
                is_allowed=is_allowed,
                filtered_content=filtered if is_allowed else "[CONTENT BLOCKED]",
                matched_rules=matched_rules,
                risk_score=risk_score,
                categories=categories,
                details={
                    "original_length": len(content),
                    "filtered_length": len(filtered),
                    "rule_matches": len(matched_rules),
                    "context": context or {},
                },
            )

            if matched_rules and self.security_logger:
                self.security_logger.log_security_event(
                    "content_filtered",
                    matched_rules=matched_rules,
                    categories=[c.value for c in categories],
                    risk_score=risk_score,
                    is_allowed=is_allowed,
                )

            return result

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "filter_error", error=str(e), content_length=len(content)
                )
            raise ValidationError(f"Content filtering failed: {str(e)}")

    def add_rule(self, name: str, rule: FilterRule) -> None:
        self.rules[name] = rule
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
                "category": rule.category.value,
                "severity": rule.severity,
                "description": rule.description,
                "action": rule.action,
            }
            for name, rule in self.rules.items()
        }
