"""
data/leak_detector.py - Data leakage detection and prevention
"""

import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
from collections import defaultdict
from ..core.logger import SecurityLogger
from ..core.exceptions import SecurityError


class LeakageType(Enum):
    """Types of data leakage"""

    PII = "personally_identifiable_information"
    CREDENTIALS = "credentials"
    API_KEYS = "api_keys"
    INTERNAL_DATA = "internal_data"
    BUSINESS_DATA = "business_data"
    SYSTEM_INFO = "system_information"
    SOURCE_CODE = "source_code"
    MODEL_INFO = "model_information"


@dataclass
class LeakagePattern:
    """Pattern for detecting data leakage"""

    pattern: str
    type: LeakageType
    severity: int  # 1-10
    description: str
    remediation: str
    enabled: bool = True


@dataclass
class ScanResult:
    """Result of leak detection scan"""

    has_leaks: bool
    leaks: List[Dict[str, Any]]
    severity: int
    affected_data: Set[str]
    remediation_steps: List[str]
    metadata: Dict[str, Any]


class LeakDetector:
    """Detector for sensitive data leakage"""

    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.patterns = self._initialize_patterns()
        self.compiled_patterns = self._compile_patterns()
        self.detection_history: List[ScanResult] = []

    def _initialize_patterns(self) -> Dict[str, LeakagePattern]:
        """Initialize leakage detection patterns"""
        return {
            "email": LeakagePattern(
                pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                type=LeakageType.PII,
                severity=7,
                description="Email address detection",
                remediation="Mask or remove email addresses",
            ),
            "ssn": LeakagePattern(
                pattern=r"\b\d{3}-?\d{2}-?\d{4}\b",
                type=LeakageType.PII,
                severity=9,
                description="Social Security Number detection",
                remediation="Remove or encrypt SSN",
            ),
            "credit_card": LeakagePattern(
                pattern=r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                type=LeakageType.PII,
                severity=9,
                description="Credit card number detection",
                remediation="Remove or encrypt credit card numbers",
            ),
            "api_key": LeakagePattern(
                pattern=r"\b([A-Za-z0-9_-]{32,})\b",
                type=LeakageType.API_KEYS,
                severity=8,
                description="API key detection",
                remediation="Remove API keys and rotate compromised keys",
            ),
            "password": LeakagePattern(
                pattern=r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+",
                type=LeakageType.CREDENTIALS,
                severity=9,
                description="Password detection",
                remediation="Remove passwords and reset compromised credentials",
            ),
            "internal_url": LeakagePattern(
                pattern=r"https?://[a-zA-Z0-9.-]+\.internal\b",
                type=LeakageType.INTERNAL_DATA,
                severity=6,
                description="Internal URL detection",
                remediation="Remove internal URLs",
            ),
            "ip_address": LeakagePattern(
                pattern=r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                type=LeakageType.SYSTEM_INFO,
                severity=5,
                description="IP address detection",
                remediation="Remove or mask IP addresses",
            ),
            "aws_key": LeakagePattern(
                pattern=r"AKIA[0-9A-Z]{16}",
                type=LeakageType.CREDENTIALS,
                severity=9,
                description="AWS key detection",
                remediation="Remove AWS keys and rotate credentials",
            ),
            "private_key": LeakagePattern(
                pattern=r"-----BEGIN\s+PRIVATE\s+KEY-----",
                type=LeakageType.CREDENTIALS,
                severity=10,
                description="Private key detection",
                remediation="Remove private keys and rotate affected keys",
            ),
            "model_info": LeakagePattern(
                pattern=r"model\.(safetensors|bin|pt|pth|ckpt)",
                type=LeakageType.MODEL_INFO,
                severity=7,
                description="Model file reference detection",
                remediation="Remove model file references",
            ),
            "database_connection": LeakagePattern(
                pattern=r"(?i)(jdbc|mongodb|postgresql):.*",
                type=LeakageType.SYSTEM_INFO,
                severity=8,
                description="Database connection string detection",
                remediation="Remove database connection strings",
            ),
        }

    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns"""
        return {
            name: re.compile(pattern.pattern)
            for name, pattern in self.patterns.items()
            if pattern.enabled
        }

    def scan_text(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Scan text for potential data leaks"""
        try:
            leaks = []
            affected_data = set()
            max_severity = 0
            remediation_steps = set()

            for name, pattern in self.compiled_patterns.items():
                matches = list(pattern.finditer(text))
                if matches:
                    leak_pattern = self.patterns[name]
                    max_severity = max(max_severity, leak_pattern.severity)
                    remediation_steps.add(leak_pattern.remediation)
                    affected_data.add(leak_pattern.type.value)

                    for match in matches:
                        leak = {
                            "type": leak_pattern.type.value,
                            "pattern_name": name,
                            "severity": leak_pattern.severity,
                            "match": self._mask_sensitive_data(match.group()),
                            "position": match.span(),
                            "description": leak_pattern.description,
                            "remediation": leak_pattern.remediation,
                        }
                        leaks.append(leak)

            result = ScanResult(
                has_leaks=bool(leaks),
                leaks=leaks,
                severity=max_severity,
                affected_data=affected_data,
                remediation_steps=list(remediation_steps),
                metadata={
                    "timestamp": datetime.utcnow().isoformat(),
                    "context": context or {},
                    "total_leaks": len(leaks),
                    "scan_coverage": len(self.compiled_patterns),
                },
            )

            if result.has_leaks and self.security_logger:
                self.security_logger.log_security_event(
                    "data_leak_detected",
                    leak_count=len(leaks),
                    severity=max_severity,
                    affected_data=list(affected_data),
                )

            self.detection_history.append(result)
            return result

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "leak_detection_error", error=str(e)
                )
            raise SecurityError(f"Leak detection failed: {str(e)}")

    def _mask_sensitive_data(self, data: str) -> str:
        """Mask sensitive data for safe logging"""
        if len(data) <= 8:
            return "*" * len(data)
        return f"{data[:4]}{'*' * (len(data) - 8)}{data[-4:]}"

    def add_pattern(self, name: str, pattern: LeakagePattern):
        """Add a new leakage pattern"""
        self.patterns[name] = pattern
        if pattern.enabled:
            self.compiled_patterns[name] = re.compile(pattern.pattern)

    def remove_pattern(self, name: str):
        """Remove a leakage pattern"""
        self.patterns.pop(name, None)
        self.compiled_patterns.pop(name, None)

    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        if not self.detection_history:
            return {}

        stats = {
            "total_scans": len(self.detection_history),
            "total_leaks": sum(len(r.leaks) for r in self.detection_history),
            "leak_types": defaultdict(int),
            "severity_distribution": defaultdict(int),
            "pattern_matches": defaultdict(int),
        }

        for result in self.detection_history:
            for leak in result.leaks:
                stats["leak_types"][leak["type"]] += 1
                stats["severity_distribution"][leak["severity"]] += 1
                stats["pattern_matches"][leak["pattern_name"]] += 1

        return stats

    def analyze_trends(self) -> Dict[str, Any]:
        """Analyze leak detection trends"""
        if len(self.detection_history) < 2:
            return {}

        trends = {
            "leak_frequency": [],
            "severity_trends": [],
            "type_distribution": defaultdict(list),
        }

        # Group by day for trend analysis
        daily_stats = defaultdict(
            lambda: {"leaks": 0, "severity": [], "types": defaultdict(int)}
        )

        for result in self.detection_history:
            date = (
                datetime.fromisoformat(result.metadata["timestamp"]).date().isoformat()
            )

            daily_stats[date]["leaks"] += len(result.leaks)
            daily_stats[date]["severity"].append(result.severity)

            for leak in result.leaks:
                daily_stats[date]["types"][leak["type"]] += 1

        # Calculate trends
        dates = sorted(daily_stats.keys())
        for date in dates:
            stats = daily_stats[date]
            trends["leak_frequency"].append({"date": date, "count": stats["leaks"]})

            trends["severity_trends"].append(
                {
                    "date": date,
                    "average_severity": (
                        sum(stats["severity"]) / len(stats["severity"])
                        if stats["severity"]
                        else 0
                    ),
                }
            )

            for leak_type, count in stats["types"].items():
                trends["type_distribution"][leak_type].append(
                    {"date": date, "count": count}
                )

        return trends

    def get_remediation_report(self) -> List[Dict[str, Any]]:
        """Generate remediation recommendations"""
        if not self.detection_history:
            return []

        # Aggregate issues by type
        issues = defaultdict(
            lambda: {
                "count": 0,
                "severity": 0,
                "remediation_steps": set(),
                "examples": [],
            }
        )

        for result in self.detection_history:
            for leak in result.leaks:
                leak_type = leak["type"]
                issues[leak_type]["count"] += 1
                issues[leak_type]["severity"] = max(
                    issues[leak_type]["severity"], leak["severity"]
                )
                issues[leak_type]["remediation_steps"].add(leak["remediation"])
                if len(issues[leak_type]["examples"]) < 3:
                    issues[leak_type]["examples"].append(leak["match"])

        # Generate report
        return [
            {
                "type": leak_type,
                "frequency": data["count"],
                "severity": data["severity"],
                "remediation_steps": list(data["remediation_steps"]),
                "examples": data["examples"],
                "priority": (
                    "high"
                    if data["severity"] >= 8
                    else "medium" if data["severity"] >= 5 else "low"
                ),
            }
            for leak_type, data in issues.items()
        ]

    def clear_history(self):
        """Clear detection history"""
        self.detection_history.clear()
