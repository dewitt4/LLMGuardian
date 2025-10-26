"""
data/privacy_guard.py - Privacy protection and enforcement
"""

import hashlib
import json
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Add these imports at the top
from typing import Any, Dict, List, Optional, Set, Union

from ..core.exceptions import SecurityError
from ..core.logger import SecurityLogger


class PrivacyLevel(Enum):
    """Privacy sensitivity levels"""  # Fix docstring format

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


class DataCategory(Enum):
    """Categories of sensitive data"""  # Fix docstring format

    PII = "personally_identifiable_information"
    PHI = "protected_health_information"
    FINANCIAL = "financial_data"
    CREDENTIALS = "credentials"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    BUSINESS = "business_sensitive"
    LOCATION = "location_data"
    BIOMETRIC = "biometric_data"


@dataclass  # Add decorator
class PrivacyRule:
    """Definition of a privacy rule"""

    name: str
    category: DataCategory  # Fix type hint
    level: PrivacyLevel
    patterns: List[str]
    actions: List[str]
    exceptions: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class PrivacyCheck:
    # Result of a privacy check
    compliant: bool
    violations: List[str]
    risk_level: str
    required_actions: List[str]
    metadata: Dict[str, Any]


class PrivacyGuard:
    # Privacy protection and enforcement system

    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.rules = self._initialize_rules()
        self.compiled_patterns = self._compile_patterns()
        self.check_history: List[PrivacyCheck] = []


def _initialize_rules(self) -> Dict[str, PrivacyRule]:
    """Initialize privacy rules"""
    return {
        "pii_basic": PrivacyRule(
            name="Basic PII Protection",
            category=DataCategory.PII,
            level=PrivacyLevel.CONFIDENTIAL,
            patterns=[
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                r"\b\d{10,11}\b",  # Phone numbers
                r"\b[A-Z]{2}\d{6,8}\b",  # License numbers
            ],
            actions=["mask", "log", "alert"],
        ),
        "phi_protection": PrivacyRule(
            name="PHI Protection",
            category=DataCategory.PHI,
            level=PrivacyLevel.RESTRICTED,
            patterns=[
                r"(?i)\b(medical|health|diagnosis|treatment)\b.*\b(record|number|id)\b",
                r"\b\d{3}-\d{2}-\d{4}\b.*\b(health|medical)\b",
                r"(?i)\b(prescription|medication)\b.*\b(number|id)\b",
            ],
            actions=["block", "log", "alert", "report"],
        ),
        "financial_data": PrivacyRule(
            name="Financial Data Protection",
            category=DataCategory.FINANCIAL,
            level=PrivacyLevel.CONFIDENTIAL,
            patterns=[
                r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # Credit card
                r"\b\d{9,18}\b(?=.*bank)",  # Bank account numbers
                r"(?i)\b(swift|iban|routing)\b.*\b(code|number)\b",
            ],
            actions=["mask", "log", "alert"],
        ),
        "credentials": PrivacyRule(
            name="Credential Protection",
            category=DataCategory.CREDENTIALS,
            level=PrivacyLevel.SECRET,
            patterns=[
                r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+",
                r"(?i)(api[_-]?key|secret[_-]?key)\s*[=:]\s*\S+",
                r"(?i)(auth|bearer)\s+token\s*[=:]\s*\S+",
            ],
            actions=["block", "log", "alert", "report"],
        ),
        "location_data": PrivacyRule(
            name="Location Data Protection",
            category=DataCategory.LOCATION,
            level=PrivacyLevel.CONFIDENTIAL,
            patterns=[
                r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP addresses
                r"(?i)\b(latitude|longitude)\b\s*[=:]\s*-?\d+\.\d+",
                r"(?i)\b(gps|coordinates)\b.*\b\d+\.\d+,\s*-?\d+\.\d+\b",
            ],
            actions=["mask", "log"],
        ),
        "intellectual_property": PrivacyRule(
            name="IP Protection",
            category=DataCategory.INTELLECTUAL_PROPERTY,
            level=PrivacyLevel.RESTRICTED,
            patterns=[
                r"(?i)\b(confidential|proprietary|trade\s+secret)\b",
                r"(?i)\b(patent\s+pending|copyright|trademark)\b",
                r"(?i)\b(internal\s+use\s+only|classified)\b",
            ],
            actions=["block", "log", "alert", "report"],
        ),
    }


def _compile_patterns(self) -> Dict[str, Dict[str, re.Pattern]]:
    """Compile regex patterns for rules"""
    compiled = {}
    for name, rule in self.rules.items():
        if rule.enabled:
            compiled[name] = {
                str(i): re.compile(pattern, re.IGNORECASE)
                for i, pattern in enumerate(rule.patterns)
            }
    return compiled


def check_privacy(
    self, content: Union[str, Dict[str, Any]], context: Optional[Dict[str, Any]] = None
) -> PrivacyCheck:
    """Check content for privacy violations"""
    try:
        violations = []
        required_actions = set()
        detected_categories = set()
        max_level = PrivacyLevel.PUBLIC

        # Convert content to string if it's a dictionary
        if isinstance(content, dict):
            content = json.dumps(content)

        # Check each enabled rule
        for rule_name, rule in self.rules.items():
            if not rule.enabled:
                continue

            # Check patterns
            patterns = self.compiled_patterns.get(rule_name, {})
            for pattern in patterns.values():
                matches = list(pattern.finditer(content))
                if matches:
                    violations.append(
                        {
                            "rule": rule_name,
                            "category": rule.category.value,
                            "level": rule.level.value,
                            "matches": [self._safe_capture(m.group()) for m in matches],
                        }
                    )
                    required_actions.update(rule.actions)
                    detected_categories.add(rule.category)
                    if rule.level.value > max_level.value:
                        max_level = rule.level

        # Determine overall risk level
        risk_level = self._determine_risk_level(violations, max_level)

        result = PrivacyCheck(
            compliant=len(violations) == 0,
            violations=violations,
            risk_level=risk_level,
            required_actions=list(required_actions),
            metadata={
                "timestamp": datetime.utcnow().isoformat(),
                "categories": [cat.value for cat in detected_categories],
                "max_privacy_level": max_level.value,
                "context": context or {},
            },
        )

        if not result.compliant and self.security_logger:
            self.security_logger.log_security_event(
                "privacy_violation_detected",
                violations=len(violations),
                risk_level=risk_level,
                categories=[cat.value for cat in detected_categories],
            )

        self.check_history.append(result)
        return result

    except Exception as e:
        if self.security_logger:
            self.security_logger.log_security_event("privacy_check_error", error=str(e))
        raise SecurityError(f"Privacy check failed: {str(e)}")


def enforce_privacy(
    self,
    content: Union[str, Dict[str, Any]],
    level: PrivacyLevel,
    context: Optional[Dict[str, Any]] = None,
) -> str:
    """Enforce privacy rules on content"""
    try:
        # First check privacy
        check_result = self.check_privacy(content, context)

        if isinstance(content, dict):
            content = json.dumps(content)

        # Apply required actions based on privacy level
        for violation in check_result.violations:
            rule = self.rules.get(violation["rule"])
            if rule and rule.level.value >= level.value:
                content = self._apply_privacy_actions(
                    content, violation["matches"], rule.actions
                )

        return content

    except Exception as e:
        if self.security_logger:
            self.security_logger.log_security_event(
                "privacy_enforcement_error", error=str(e)
            )
        raise SecurityError(f"Privacy enforcement failed: {str(e)}")


def _safe_capture(self, data: str) -> str:
    """Safely capture matched data without exposing it"""
    if len(data) <= 8:
        return "*" * len(data)
    return f"{data[:4]}{'*' * (len(data) - 8)}{data[-4:]}"


def _determine_risk_level(
    self, violations: List[Dict[str, Any]], max_level: PrivacyLevel
) -> str:
    """Determine overall risk level"""
    if not violations:
        return "low"

    violation_count = len(violations)
    level_value = max_level.value

    if level_value == PrivacyLevel.SECRET.value or violation_count > 10:
        return "critical"
    elif level_value == PrivacyLevel.RESTRICTED.value or violation_count > 5:
        return "high"
    elif level_value == PrivacyLevel.CONFIDENTIAL.value or violation_count > 2:
        return "medium"
    return "low"


def _apply_privacy_actions(
    self, content: str, matches: List[str], actions: List[str]
) -> str:
    """Apply privacy actions to content"""
    processed_content = content

    for action in actions:
        if action == "mask":
            for match in matches:
                processed_content = processed_content.replace(
                    match, self._mask_data(match)
                )
        elif action == "block":
            for match in matches:
                processed_content = processed_content.replace(match, "[REDACTED]")

    return processed_content


def _mask_data(self, data: str) -> str:
    """Mask sensitive data"""
    if len(data) <= 4:
        return "*" * len(data)
    return f"{data[:2]}{'*' * (len(data) - 4)}{data[-2:]}"


def add_rule(self, rule: PrivacyRule):
    """Add a new privacy rule"""
    self.rules[rule.name] = rule
    if rule.enabled:
        self.compiled_patterns[rule.name] = {
            str(i): re.compile(pattern, re.IGNORECASE)
            for i, pattern in enumerate(rule.patterns)
        }


def remove_rule(self, rule_name: str):
    """Remove a privacy rule"""
    self.rules.pop(rule_name, None)
    self.compiled_patterns.pop(rule_name, None)


def update_rule(self, rule_name: str, updates: Dict[str, Any]):
    """Update an existing rule"""
    if rule_name in self.rules:
        rule = self.rules[rule_name]
        for key, value in updates.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        # Recompile patterns if needed
        if rule.enabled and ("patterns" in updates or "enabled" in updates):
            self.compiled_patterns[rule_name] = {
                str(i): re.compile(pattern, re.IGNORECASE)
                for i, pattern in enumerate(rule.patterns)
            }


def get_privacy_stats(self) -> Dict[str, Any]:
    """Get privacy check statistics"""
    if not self.check_history:
        return {}

    stats = {
        "total_checks": len(self.check_history),
        "violation_count": sum(
            1 for check in self.check_history if not check.compliant
        ),
        "risk_levels": defaultdict(int),
        "categories": defaultdict(int),
        "rules_triggered": defaultdict(int),
    }

    for check in self.check_history:
        stats["risk_levels"][check.risk_level] += 1
        for violation in check.violations:
            stats["categories"][violation["category"]] += 1
            stats["rules_triggered"][violation["rule"]] += 1

    return stats


def analyze_trends(self) -> Dict[str, Any]:
    """Analyze privacy violation trends"""
    if len(self.check_history) < 2:
        return {}

    trends = {
        "violation_frequency": [],
        "risk_distribution": defaultdict(list),
        "category_trends": defaultdict(list),
    }

    # Group by day for trend analysis
    daily_stats = defaultdict(
        lambda: {
            "violations": 0,
            "risks": defaultdict(int),
            "categories": defaultdict(int),
        }
    )

    for check in self.check_history:
        date = datetime.fromisoformat(check.metadata["timestamp"]).date().isoformat()

        if not check.compliant:
            daily_stats[date]["violations"] += 1
            daily_stats[date]["risks"][check.risk_level] += 1

            for violation in check.violations:
                daily_stats[date]["categories"][violation["category"]] += 1

    # Calculate trends
    dates = sorted(daily_stats.keys())
    for date in dates:
        stats = daily_stats[date]
        trends["violation_frequency"].append(
            {"date": date, "count": stats["violations"]}
        )

        for risk, count in stats["risks"].items():
            trends["risk_distribution"][risk].append({"date": date, "count": count})

        for category, count in stats["categories"].items():
            trends["category_trends"][category].append({"date": date, "count": count})

    def generate_privacy_report(self) -> Dict[str, Any]:
        """Generate comprehensive privacy report"""
        stats = self.get_privacy_stats()
        trends = self.analyze_trends()

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_checks": stats.get("total_checks", 0),
            "violation_count": stats.get("violation_count", 0),
            "compliance_rate": (
                (stats["total_checks"] - stats["violation_count"])
                / stats["total_checks"]
                if stats.get("total_checks", 0) > 0
                else 1.0
            ),
        },
        "risk_analysis": {
            "risk_levels": dict(stats.get("risk_levels", {})),
            "high_risk_percentage": (
                (
                    stats.get("risk_levels", {}).get("high", 0)
                    + stats.get("risk_levels", {}).get("critical", 0)
                )
                / stats["total_checks"]
                if stats.get("total_checks", 0) > 0
                else 0.0
            ),
        },
        "category_analysis": {
            "categories": dict(stats.get("categories", {})),
            "most_common": self._get_most_common_categories(
                stats.get("categories", {})
            ),
        },
        "rule_effectiveness": {
            "triggered_rules": dict(stats.get("rules_triggered", {})),
            "recommendations": self._generate_rule_recommendations(
                stats.get("rules_triggered", {})
            ),
        },
        "trends": trends,
        "recommendations": self._generate_privacy_recommendations(),
    }


def _get_most_common_categories(
    self, categories: Dict[str, int], limit: int = 3
) -> List[Dict[str, Any]]:
    """Get most commonly violated categories"""
    sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:limit]

    return [
        {
            "category": cat,
            "violations": count,
            "recommendations": self._get_category_recommendations(cat),
        }
        for cat, count in sorted_cats
    ]


def _get_category_recommendations(self, category: str) -> List[str]:
    """Get recommendations for specific category"""
    recommendations = {
        DataCategory.PII.value: [
            "Implement data masking for PII",
            "Add PII detection to preprocessing",
            "Review PII handling procedures",
        ],
        DataCategory.PHI.value: [
            "Enhance PHI protection measures",
            "Implement HIPAA compliance checks",
            "Review healthcare data handling",
        ],
        DataCategory.FINANCIAL.value: [
            "Strengthen financial data encryption",
            "Implement PCI DSS controls",
            "Review financial data access",
        ],
        DataCategory.CREDENTIALS.value: [
            "Enhance credential protection",
            "Implement secret detection",
            "Review access control systems",
        ],
        DataCategory.INTELLECTUAL_PROPERTY.value: [
            "Strengthen IP protection",
            "Implement content filtering",
            "Review data classification",
        ],
        DataCategory.BUSINESS.value: [
            "Enhance business data protection",
            "Implement confidentiality checks",
            "Review data sharing policies",
        ],
        DataCategory.LOCATION.value: [
            "Implement location data masking",
            "Review geolocation handling",
            "Enhance location privacy",
        ],
        DataCategory.BIOMETRIC.value: [
            "Strengthen biometric data protection",
            "Review biometric handling",
            "Implement specific safeguards",
        ],
    }
    return recommendations.get(category, ["Review privacy controls"])


def _generate_rule_recommendations(
    self, triggered_rules: Dict[str, int]
) -> List[Dict[str, Any]]:
    """Generate recommendations for rule improvements"""
    recommendations = []

    for rule_name, trigger_count in triggered_rules.items():
        if rule_name in self.rules:
            rule = self.rules[rule_name]

            # High trigger count might indicate need for enhancement
            if trigger_count > 100:
                recommendations.append(
                    {
                        "rule": rule_name,
                        "type": "high_triggers",
                        "message": "Consider strengthening rule patterns",
                        "priority": "high",
                    }
                )

            # Check pattern effectiveness
            if len(rule.patterns) == 1 and trigger_count > 50:
                recommendations.append(
                    {
                        "rule": rule_name,
                        "type": "pattern_enhancement",
                        "message": "Consider adding additional patterns",
                        "priority": "medium",
                    }
                )

            # Check action effectiveness
            if "mask" in rule.actions and trigger_count > 75:
                recommendations.append(
                    {
                        "rule": rule_name,
                        "type": "action_enhancement",
                        "message": "Consider stronger privacy actions",
                        "priority": "medium",
                    }
                )

    return recommendations


def _generate_privacy_recommendations(self) -> List[Dict[str, Any]]:
    """Generate overall privacy recommendations"""
    stats = self.get_privacy_stats()
    recommendations = []

    # Check overall violation rate
    if stats.get("violation_count", 0) > stats.get("total_checks", 0) * 0.1:
        recommendations.append(
            {
                "type": "high_violation_rate",
                "message": "High privacy violation rate detected",
                "actions": [
                    "Review privacy controls",
                    "Enhance detection patterns",
                    "Implement additional safeguards",
                ],
                "priority": "high",
            }
        )

    # Check risk distribution
    risk_levels = stats.get("risk_levels", {})
    if risk_levels.get("critical", 0) > 0:
        recommendations.append(
            {
                "type": "critical_risks",
                "message": "Critical privacy risks detected",
                "actions": [
                    "Immediate review required",
                    "Enhance protection measures",
                    "Implement stricter controls",
                ],
                "priority": "critical",
            }
        )

    # Check category distribution
    categories = stats.get("categories", {})
    for category, count in categories.items():
        if count > stats.get("total_checks", 0) * 0.2:
            recommendations.append(
                {
                    "type": "category_concentration",
                    "category": category,
                    "message": f"High concentration of {category} violations",
                    "actions": self._get_category_recommendations(category),
                    "priority": "high",
                }
            )

    return recommendations


def export_privacy_configuration(self) -> Dict[str, Any]:
    """Export privacy configuration"""
    return {
        "rules": {
            name: {
                "category": rule.category.value,
                "level": rule.level.value,
                "patterns": rule.patterns,
                "actions": rule.actions,
                "exceptions": rule.exceptions,
                "enabled": rule.enabled,
            }
            for name, rule in self.rules.items()
        },
        "metadata": {
            "exported_at": datetime.utcnow().isoformat(),
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled),
        },
    }


def import_privacy_configuration(self, config: Dict[str, Any]):
    """Import privacy configuration"""
    try:
        new_rules = {}
        for name, rule_config in config.get("rules", {}).items():
            new_rules[name] = PrivacyRule(
                name=name,
                category=DataCategory(rule_config["category"]),
                level=PrivacyLevel(rule_config["level"]),
                patterns=rule_config["patterns"],
                actions=rule_config["actions"],
                exceptions=rule_config.get("exceptions", []),
                enabled=rule_config.get("enabled", True),
            )

        self.rules = new_rules
        self.compiled_patterns = self._compile_patterns()

        if self.security_logger:
            self.security_logger.log_security_event(
                "privacy_config_imported", rule_count=len(new_rules)
            )

    except Exception as e:
        if self.security_logger:
            self.security_logger.log_security_event(
                "privacy_config_import_error", error=str(e)
            )
        raise SecurityError(f"Privacy configuration import failed: {str(e)}")


def validate_configuration(self) -> Dict[str, Any]:
    """Validate current privacy configuration"""
    validation = {
        "valid": True,
        "issues": [],
        "warnings": [],
        "statistics": {
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled),
            "pattern_count": sum(len(r.patterns) for r in self.rules.values()),
            "action_count": sum(len(r.actions) for r in self.rules.values()),
        },
    }

    # Check each rule
    for name, rule in self.rules.items():
        # Check for empty patterns
        if not rule.patterns:
            validation["issues"].append(
                {
                    "rule": name,
                    "type": "empty_patterns",
                    "message": "Rule has no detection patterns",
                }
            )
            validation["valid"] = False

        # Check for empty actions
        if not rule.actions:
            validation["issues"].append(
                {
                    "rule": name,
                    "type": "empty_actions",
                    "message": "Rule has no privacy actions",
                }
            )
            validation["valid"] = False

        # Check for invalid patterns
        for pattern in rule.patterns:
            try:
                re.compile(pattern)
            except re.error:
                validation["issues"].append(
                    {
                        "rule": name,
                        "type": "invalid_pattern",
                        "message": f"Invalid regex pattern: {pattern}",
                    }
                )
                validation["valid"] = False

        # Check for potentially weak patterns
        if any(len(p) < 4 for p in rule.patterns):
            validation["warnings"].append(
                {
                    "rule": name,
                    "type": "weak_pattern",
                    "message": "Rule contains potentially weak patterns",
                }
            )

        # Check for missing required actions
        if rule.level in [PrivacyLevel.RESTRICTED, PrivacyLevel.SECRET]:
            required_actions = {"block", "log", "alert"}
            missing_actions = required_actions - set(rule.actions)
            if missing_actions:
                validation["warnings"].append(
                    {
                        "rule": name,
                        "type": "missing_actions",
                        "message": f"Missing recommended actions: {missing_actions}",
                    }
                )

    return validation


def clear_history(self):
    """Clear check history"""
    self.check_history.clear()


def monitor_privacy_compliance(
    self, interval: int = 3600, callback: Optional[callable] = None
) -> None:
    """Start privacy compliance monitoring"""
    if not hasattr(self, "_monitoring"):
        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop, args=(interval, callback), daemon=True
        )
        self._monitor_thread.start()


def stop_monitoring(self) -> None:
    """Stop privacy compliance monitoring"""
    self._monitoring = False
    if hasattr(self, "_monitor_thread"):
        self._monitor_thread.join()


def _monitoring_loop(self, interval: int, callback: Optional[callable]) -> None:
    """Main monitoring loop"""
    while self._monitoring:
        try:
            # Generate compliance report
            report = self.generate_privacy_report()

            # Check for critical issues
            critical_issues = self._check_critical_issues(report)

            if critical_issues and self.security_logger:
                self.security_logger.log_security_event(
                    "privacy_critical_issues", issues=critical_issues
                )

            # Execute callback if provided
            if callback and critical_issues:
                callback(critical_issues)

            time.sleep(interval)

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "privacy_monitoring_error", error=str(e)
                )


def _check_critical_issues(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for critical privacy issues"""
    critical_issues = []

    # Check high-risk violations
    risk_analysis = report.get("risk_analysis", {})
    if risk_analysis.get("high_risk_percentage", 0) > 0.1:  # More than 10%
        critical_issues.append(
            {
                "type": "high_risk_rate",
                "message": "High rate of high-risk privacy violations",
                "details": risk_analysis,
            }
        )

    # Check specific categories
    category_analysis = report.get("category_analysis", {})
    sensitive_categories = {
        DataCategory.PHI.value,
        DataCategory.CREDENTIALS.value,
        DataCategory.FINANCIAL.value,
    }

    for category, count in category_analysis.get("categories", {}).items():
        if category in sensitive_categories and count > 10:
            critical_issues.append(
                {
                    "type": "sensitive_category_violation",
                    "category": category,
                    "message": f"High number of {category} violations",
                    "count": count,
                }
            )

    return critical_issues


def batch_check_privacy(
    self,
    items: List[Union[str, Dict[str, Any]]],
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Perform privacy check on multiple items"""
    results = {
        "compliant_items": 0,
        "non_compliant_items": 0,
        "violations_by_item": {},
        "overall_risk_level": "low",
        "critical_items": [],
    }

    max_risk_level = "low"

    for i, item in enumerate(items):
        result = self.check_privacy(item, context)

        if result.is_compliant:
            results["compliant_items"] += 1
        else:
            results["non_compliant_items"] += 1
            results["violations_by_item"][i] = {
                "violations": result.violations,
                "risk_level": result.risk_level,
            }

            # Track critical items
            if result.risk_level in ["high", "critical"]:
                results["critical_items"].append(i)

            # Update max risk level
            if self._compare_risk_levels(result.risk_level, max_risk_level) > 0:
                max_risk_level = result.risk_level

    results["overall_risk_level"] = max_risk_level
    return results


def _compare_risk_levels(self, level1: str, level2: str) -> int:
    """Compare two risk levels. Returns 1 if level1 > level2, -1 if level1 < level2, 0 if equal"""
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return risk_order.get(level1, 0) - risk_order.get(level2, 0)


def validate_data_handling(self, handler_config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate data handling configuration"""
    validation = {"valid": True, "issues": [], "warnings": []}

    required_handlers = {
        PrivacyLevel.RESTRICTED.value: {"encryption", "logging", "audit"},
        PrivacyLevel.SECRET.value: {"encryption", "logging", "audit", "monitoring"},
    }

    recommended_handlers = {PrivacyLevel.CONFIDENTIAL.value: {"encryption", "logging"}}

    # Check handlers for each privacy level
    for level, config in handler_config.items():
        handlers = set(config.get("handlers", []))

        # Check required handlers
        if level in required_handlers:
            missing_handlers = required_handlers[level] - handlers
            if missing_handlers:
                validation["issues"].append(
                    {
                        "level": level,
                        "type": "missing_required_handlers",
                        "handlers": list(missing_handlers),
                    }
                )
                validation["valid"] = False

        # Check recommended handlers
        if level in recommended_handlers:
            missing_handlers = recommended_handlers[level] - handlers
            if missing_handlers:
                validation["warnings"].append(
                    {
                        "level": level,
                        "type": "missing_recommended_handlers",
                        "handlers": list(missing_handlers),
                    }
                )

    return validation


def simulate_privacy_impact(
    self, content: Union[str, Dict[str, Any]], simulation_config: Dict[str, Any]
) -> Dict[str, Any]:
    """Simulate privacy impact of content changes"""
    baseline_result = self.check_privacy(content)
    simulations = []

    # Apply each simulation scenario
    for scenario in simulation_config.get("scenarios", []):
        modified_content = self._apply_simulation_scenario(content, scenario)

        result = self.check_privacy(modified_content)

        simulations.append(
            {
                "scenario": scenario["name"],
                "risk_change": self._compare_risk_levels(
                    result.risk_level, baseline_result.risk_level
                ),
                "new_violations": len(result.violations)
                - len(baseline_result.violations),
                "details": {
                    "original_risk": baseline_result.risk_level,
                    "new_risk": result.risk_level,
                    "new_violations": result.violations,
                },
            }
        )

    return {
        "baseline": {
            "risk_level": baseline_result.risk_level,
            "violations": len(baseline_result.violations),
        },
        "simulations": simulations,
    }


def _apply_simulation_scenario(
    self, content: Union[str, Dict[str, Any]], scenario: Dict[str, Any]
) -> Union[str, Dict[str, Any]]:
    """Apply a simulation scenario to content"""
    if isinstance(content, dict):
        content = json.dumps(content)

    modified = content

    # Apply modifications based on scenario type
    if scenario.get("type") == "add_data":
        modified = f"{content} {scenario['data']}"
    elif scenario.get("type") == "remove_pattern":
        modified = re.sub(scenario["pattern"], "", modified)
    elif scenario.get("type") == "replace_pattern":
        modified = re.sub(scenario["pattern"], scenario["replacement"], modified)

    return modified


def export_privacy_metrics(self) -> Dict[str, Any]:
    """Export privacy metrics for monitoring"""
    stats = self.get_privacy_stats()
    trends = self.analyze_trends()

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": {
            "violation_rate": (
                stats.get("violation_count", 0) / stats.get("total_checks", 1)
            ),
            "high_risk_rate": (
                (
                    stats.get("risk_levels", {}).get("high", 0)
                    + stats.get("risk_levels", {}).get("critical", 0)
                )
                / stats.get("total_checks", 1)
            ),
            "category_distribution": stats.get("categories", {}),
            "trend_indicators": self._calculate_trend_indicators(trends),
        },
        "thresholds": {
            "violation_rate": 0.1,  # 10%
            "high_risk_rate": 0.05,  # 5%
            "trend_change": 0.2,  # 20%
        },
    }


def _calculate_trend_indicators(self, trends: Dict[str, Any]) -> Dict[str, float]:
    """Calculate trend indicators from trend data"""
    indicators = {}

    # Calculate violation trend
    if trends.get("violation_frequency"):
        frequencies = [item["count"] for item in trends["violation_frequency"]]
        if len(frequencies) >= 2:
            change = (frequencies[-1] - frequencies[0]) / frequencies[0]
            indicators["violation_trend"] = change

    # Calculate risk distribution trend
    if trends.get("risk_distribution"):
        for risk_level, data in trends["risk_distribution"].items():
            if len(data) >= 2:
                change = (data[-1]["count"] - data[0]["count"]) / data[0]["count"]
                indicators[f"{risk_level}_trend"] = change

    return indicators


def add_privacy_callback(self, event_type: str, callback: callable) -> None:
    """Add callback for privacy events"""
    if not hasattr(self, "_callbacks"):
        self._callbacks = defaultdict(list)

    self._callbacks[event_type].append(callback)


def _trigger_callbacks(self, event_type: str, event_data: Dict[str, Any]) -> None:
    """Trigger registered callbacks for an event"""
    if hasattr(self, "_callbacks"):
        for callback in self._callbacks.get(event_type, []):
            try:
                callback(event_data)
            except Exception as e:
                if self.security_logger:
                    self.security_logger.log_security_event(
                        "callback_error", error=str(e), event_type=event_type
                    )
