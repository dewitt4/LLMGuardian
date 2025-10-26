"""
vectors/retrieval_guard.py - Security for Retrieval-Augmented Generation (RAG) operations
"""

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

from ..core.exceptions import SecurityError
from ..core.logger import SecurityLogger


class RetrievalRisk(Enum):
    """Types of retrieval-related risks"""

    RELEVANCE_MANIPULATION = "relevance_manipulation"
    CONTEXT_INJECTION = "context_injection"
    DATA_POISONING = "data_poisoning"
    RETRIEVAL_BYPASS = "retrieval_bypass"
    PRIVACY_LEAK = "privacy_leak"
    EMBEDDING_ATTACK = "embedding_attack"
    CHUNKING_MANIPULATION = "chunking_manipulation"


@dataclass
class RetrievalContext:
    """Context for retrieval operations"""

    query_embedding: np.ndarray
    retrieved_embeddings: List[np.ndarray]
    retrieved_content: List[str]
    metadata: Optional[Dict[str, Any]] = None
    source: Optional[str] = None


@dataclass
class SecurityCheck:
    """Security check definition"""

    name: str
    description: str
    threshold: float
    severity: int  # 1-10


@dataclass
class CheckResult:
    """Result of a security check"""

    check_name: str
    passed: bool
    risk_level: float
    details: Dict[str, Any]
    recommendations: List[str]


@dataclass
class GuardResult:
    """Complete result of retrieval guard checks"""

    is_safe: bool
    checks_passed: List[str]
    checks_failed: List[str]
    risks: List[RetrievalRisk]
    filtered_content: List[str]
    metadata: Dict[str, Any]


class RetrievalGuard:
    """Security guard for RAG operations"""

    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.security_checks = self._initialize_security_checks()
        self.risk_patterns = self._initialize_risk_patterns()
        self.check_history: List[GuardResult] = []

    def _initialize_security_checks(self) -> Dict[str, SecurityCheck]:
        """Initialize security checks"""
        return {
            "relevance": SecurityCheck(
                name="relevance_check",
                description="Check relevance between query and retrieved content",
                threshold=0.7,
                severity=7,
            ),
            "consistency": SecurityCheck(
                name="consistency_check",
                description="Check consistency among retrieved chunks",
                threshold=0.6,
                severity=6,
            ),
            "privacy": SecurityCheck(
                name="privacy_check",
                description="Check for potential privacy leaks",
                threshold=0.8,
                severity=9,
            ),
            "injection": SecurityCheck(
                name="injection_check",
                description="Check for context injection attempts",
                threshold=0.75,
                severity=8,
            ),
            "chunking": SecurityCheck(
                name="chunking_check",
                description="Check for chunking manipulation",
                threshold=0.65,
                severity=6,
            ),
        }

    def _initialize_risk_patterns(self) -> Dict[str, Any]:
        """Initialize risk detection patterns"""
        return {
            "privacy_patterns": {
                "pii": r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                "api_key": r"\b([A-Za-z0-9]{32,})\b",
            },
            "injection_patterns": {
                "system_prompt": r"system:\s*|instruction:\s*",
                "delimiter": r"[<\[{](?:system|prompt|instruction)[>\]}]",
                "escape": r"\\n|\\r|\\t|\\b|\\f",
            },
            "manipulation_patterns": {
                "repetition": r"(.{50,}?)\1{2,}",
                "formatting": r"\[format\]|\[style\]|\[template\]",
                "control": r"\[control\]|\[override\]|\[skip\]",
            },
        }

    def check_retrieval(self, context: RetrievalContext) -> GuardResult:
        """Perform security checks on retrieval operation"""
        try:
            checks_passed = []
            checks_failed = []
            risks = []
            filtered_content = []

            # Check relevance
            relevance_result = self._check_relevance(context)
            self._process_check_result(
                relevance_result, checks_passed, checks_failed, risks
            )

            # Check consistency
            consistency_result = self._check_consistency(context)
            self._process_check_result(
                consistency_result, checks_passed, checks_failed, risks
            )

            # Check privacy
            privacy_result = self._check_privacy(context)
            self._process_check_result(
                privacy_result, checks_passed, checks_failed, risks
            )

            # Check for injection attempts
            injection_result = self._check_injection(context)
            self._process_check_result(
                injection_result, checks_passed, checks_failed, risks
            )

            # Check chunking
            chunking_result = self._check_chunking(context)
            self._process_check_result(
                chunking_result, checks_passed, checks_failed, risks
            )

            # Filter content based on check results
            filtered_content = self._filter_content(context, risks)

            # Create result
            result = GuardResult(
                is_safe=len(checks_failed) == 0,
                checks_passed=checks_passed,
                checks_failed=checks_failed,
                risks=list(set(risks)),
                filtered_content=filtered_content,
                metadata={
                    "timestamp": datetime.utcnow().isoformat(),
                    "original_count": len(context.retrieved_content),
                    "filtered_count": len(filtered_content),
                    "risk_count": len(risks),
                },
            )

            # Log result
            if not result.is_safe and self.security_logger:
                self.security_logger.log_security_event(
                    "retrieval_guard_alert",
                    checks_failed=checks_failed,
                    risks=[r.value for r in risks],
                    filtered_ratio=len(filtered_content)
                    / len(context.retrieved_content),
                )

            self.check_history.append(result)
            return result

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "retrieval_guard_error", error=str(e)
                )
            raise SecurityError(f"Retrieval guard check failed: {str(e)}")

    def _check_relevance(self, context: RetrievalContext) -> CheckResult:
        """Check relevance between query and retrieved content"""
        relevance_scores = []

        # Calculate cosine similarity between query and each retrieved embedding
        for emb in context.retrieved_embeddings:
            score = float(
                np.dot(context.query_embedding, emb)
                / (np.linalg.norm(context.query_embedding) * np.linalg.norm(emb))
            )
            relevance_scores.append(score)

        avg_relevance = np.mean(relevance_scores)
        check = self.security_checks["relevance"]

        return CheckResult(
            check_name=check.name,
            passed=avg_relevance >= check.threshold,
            risk_level=1.0 - avg_relevance,
            details={
                "average_relevance": float(avg_relevance),
                "min_relevance": float(min(relevance_scores)),
                "max_relevance": float(max(relevance_scores)),
            },
            recommendations=(
                [
                    "Adjust retrieval threshold",
                    "Implement semantic filtering",
                    "Review chunking strategy",
                ]
                if avg_relevance < check.threshold
                else []
            ),
        )

    def _check_consistency(self, context: RetrievalContext) -> CheckResult:
        """Check consistency among retrieved chunks"""
        consistency_scores = []

        # Calculate pairwise similarities between retrieved embeddings
        for i in range(len(context.retrieved_embeddings)):
            for j in range(i + 1, len(context.retrieved_embeddings)):
                score = float(
                    np.dot(
                        context.retrieved_embeddings[i], context.retrieved_embeddings[j]
                    )
                    / (
                        np.linalg.norm(context.retrieved_embeddings[i])
                        * np.linalg.norm(context.retrieved_embeddings[j])
                    )
                )
                consistency_scores.append(score)

        avg_consistency = np.mean(consistency_scores) if consistency_scores else 0
        check = self.security_checks["consistency"]

        return CheckResult(
            check_name=check.name,
            passed=avg_consistency >= check.threshold,
            risk_level=1.0 - avg_consistency,
            details={
                "average_consistency": float(avg_consistency),
                "min_consistency": (
                    float(min(consistency_scores)) if consistency_scores else 0
                ),
                "max_consistency": (
                    float(max(consistency_scores)) if consistency_scores else 0
                ),
            },
            recommendations=(
                [
                    "Review chunk coherence",
                    "Adjust chunk size",
                    "Implement overlap detection",
                ]
                if avg_consistency < check.threshold
                else []
            ),
        )

    def _check_privacy(self, context: RetrievalContext) -> CheckResult:
        """Check for potential privacy leaks"""
        privacy_violations = defaultdict(list)

        for idx, content in enumerate(context.retrieved_content):
            for pattern_name, pattern in self.risk_patterns["privacy_patterns"].items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    privacy_violations[pattern_name].append((idx, match.group()))

        check = self.security_checks["privacy"]
        violation_count = sum(len(v) for v in privacy_violations.values())
        risk_level = min(1.0, violation_count / len(context.retrieved_content))

        return CheckResult(
            check_name=check.name,
            passed=risk_level < (1 - check.threshold),
            risk_level=risk_level,
            details={
                "violation_count": violation_count,
                "violation_types": list(privacy_violations.keys()),
                "affected_chunks": list(
                    set(
                        idx
                        for violations in privacy_violations.values()
                        for idx, _ in violations
                    )
                ),
            },
            recommendations=(
                [
                    "Implement data masking",
                    "Add privacy filters",
                    "Review content preprocessing",
                ]
                if violation_count > 0
                else []
            ),
        )

    def _check_injection(self, context: RetrievalContext) -> CheckResult:
        """Check for context injection attempts"""
        injection_attempts = defaultdict(list)

        for idx, content in enumerate(context.retrieved_content):
            for pattern_name, pattern in self.risk_patterns[
                "injection_patterns"
            ].items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    injection_attempts[pattern_name].append((idx, match.group()))

        check = self.security_checks["injection"]
        attempt_count = sum(len(v) for v in injection_attempts.values())
        risk_level = min(1.0, attempt_count / len(context.retrieved_content))

        return CheckResult(
            check_name=check.name,
            passed=risk_level < (1 - check.threshold),
            risk_level=risk_level,
            details={
                "attempt_count": attempt_count,
                "attempt_types": list(injection_attempts.keys()),
                "affected_chunks": list(
                    set(
                        idx
                        for attempts in injection_attempts.values()
                        for idx, _ in attempts
                    )
                ),
            },
            recommendations=(
                [
                    "Enhance input sanitization",
                    "Implement content filtering",
                    "Add injection detection",
                ]
                if attempt_count > 0
                else []
            ),
        )

    def _check_chunking(self, context: RetrievalContext) -> CheckResult:
        """Check for chunking manipulation"""
        manipulation_attempts = defaultdict(list)
        chunk_sizes = [len(content) for content in context.retrieved_content]

        # Check for suspicious patterns
        for idx, content in enumerate(context.retrieved_content):
            for pattern_name, pattern in self.risk_patterns[
                "manipulation_patterns"
            ].items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    manipulation_attempts[pattern_name].append((idx, match.group()))

        # Analyze chunk size distribution
        mean_size = np.mean(chunk_sizes)
        std_size = np.std(chunk_sizes)
        suspicious_chunks = [
            idx
            for idx, size in enumerate(chunk_sizes)
            if abs(size - mean_size) > 2 * std_size
        ]

        check = self.security_checks["chunking"]
        violation_count = len(suspicious_chunks) + sum(
            len(v) for v in manipulation_attempts.values()
        )
        risk_level = min(1.0, violation_count / len(context.retrieved_content))

        return CheckResult(
            check_name=check.name,
            passed=risk_level < (1 - check.threshold),
            risk_level=risk_level,
            details={
                "violation_count": violation_count,
                "suspicious_chunks": suspicious_chunks,
                "manipulation_types": list(manipulation_attempts.keys()),
                "chunk_stats": {
                    "mean_size": float(mean_size),
                    "std_size": float(std_size),
                    "min_size": min(chunk_sizes),
                    "max_size": max(chunk_sizes),
                },
            },
            recommendations=(
                [
                    "Review chunking strategy",
                    "Implement size normalization",
                    "Add pattern detection",
                ]
                if violation_count > 0
                else []
            ),
        )

    def _process_check_result(
        self,
        result: CheckResult,
        checks_passed: List[str],
        checks_failed: List[str],
        risks: List[RetrievalRisk],
    ):
        """Process check result and update tracking lists"""
        if result.passed:
            checks_passed.append(result.check_name)
        else:
            checks_failed.append(result.check_name)
            # Map check names to risks
            risk_mapping = {
                "relevance_check": RetrievalRisk.RELEVANCE_MANIPULATION,
                "consistency_check": RetrievalRisk.CONTEXT_INJECTION,
                "privacy_check": RetrievalRisk.PRIVACY_LEAK,
                "injection_check": RetrievalRisk.CONTEXT_INJECTION,
                "chunking_check": RetrievalRisk.CHUNKING_MANIPULATION,
            }
            if result.check_name in risk_mapping:
                risks.append(risk_mapping[result.check_name])

            # Log failed check if logger is available
            if self.security_logger:
                self.security_logger.log_security_event(
                    "retrieval_check_failed",
                    check_name=result.check_name,
                    risk_level=result.risk_level,
                    details=result.details,
                )

    def _check_chunking(self, context: RetrievalContext) -> CheckResult:
        """Check for chunking manipulation and anomalies"""
        check = self.security_checks["chunking"]
        manipulation_attempts = defaultdict(list)
        anomalies = []

        # Get chunk statistics
        chunk_sizes = [len(content) for content in context.retrieved_content]
        chunk_mean = np.mean(chunk_sizes)
        chunk_std = np.std(chunk_sizes)

        # Check each chunk for issues
        for idx, content in enumerate(context.retrieved_content):
            # Check size anomalies
            if abs(len(content) - chunk_mean) > 2 * chunk_std:
                anomalies.append(("size_anomaly", idx))

            # Check for manipulation patterns
            for pattern_name, pattern in self.risk_patterns[
                "manipulation_patterns"
            ].items():
                if matches := list(re.finditer(pattern, content)):
                    manipulation_attempts[pattern_name].extend(
                        (idx, match.group()) for match in matches
                    )

            # Check for content repetition
            if self._detect_repetition(content):
                anomalies.append(("repetition", idx))

            # Check for suspicious formatting
            if self._detect_suspicious_formatting(content):
                anomalies.append(("suspicious_formatting", idx))

        # Calculate risk metrics
        total_issues = len(anomalies) + sum(
            len(attempts) for attempts in manipulation_attempts.values()
        )
        risk_level = min(1.0, total_issues / (len(context.retrieved_content) * 2))

        # Generate recommendations based on findings
        recommendations = []
        if anomalies:
            recommendations.append("Review chunk size distribution and normalization")
        if manipulation_attempts:
            recommendations.append("Implement stricter content validation")
            recommendations.append("Add pattern-based filtering")
        if risk_level > 0.5:
            recommendations.append("Consider reducing chunk size variance")

        return CheckResult(
            check_name=check.name,
            passed=risk_level < (1 - check.threshold),
            risk_level=risk_level,
            details={
                "anomalies": [
                    {"type": a_type, "chunk_index": idx} for a_type, idx in anomalies
                ],
                "manipulation_attempts": {
                    pattern: [
                        {"chunk_index": idx, "content": content}
                        for idx, content in attempts
                    ]
                    for pattern, attempts in manipulation_attempts.items()
                },
                "chunk_stats": {
                    "mean_size": float(chunk_mean),
                    "std_size": float(chunk_std),
                    "size_range": (int(min(chunk_sizes)), int(max(chunk_sizes))),
                    "total_chunks": len(context.retrieved_content),
                },
            },
            recommendations=recommendations,
        )

    def _detect_repetition(self, content: str) -> bool:
        """Detect suspicious content repetition"""
        # Check for repeated phrases (50+ characters)
        repetition_pattern = r"(.{50,}?)\1+"
        if re.search(repetition_pattern, content):
            return True

        # Check for unusual character repetition
        char_counts = defaultdict(int)
        for char in content:
            char_counts[char] += 1

        total_chars = len(content)
        for count in char_counts.values():
            if count > total_chars * 0.3:  # More than 30% of same character
                return True

        return False

    def _detect_suspicious_formatting(self, content: str) -> bool:
        """Detect suspicious content formatting"""
        suspicious_patterns = [
            r"\[(?:format|style|template)\]",  # Format tags
            r"\{(?:format|style|template)\}",  # Format braces
            r"<(?:format|style|template)>",  # Format HTML-style tags
            r"\\[nr]{10,}",  # Excessive newlines/returns
            r"\s{10,}",  # Excessive whitespace
            r"[^\w\s]{10,}",  # Excessive special characters
        ]

        return any(re.search(pattern, content) for pattern in suspicious_patterns)

    def _filter_content(
        self, context: RetrievalContext, risks: List[RetrievalRisk]
    ) -> List[str]:
        """Filter retrieved content based on detected risks"""
        filtered_content = []
        skip_indices = set()

        # Collect indices to skip based on risks
        for risk in risks:
            if risk == RetrievalRisk.PRIVACY_LEAK:
                # Skip chunks with privacy violations
                skip_indices.update(self._find_privacy_violations(context))
            elif risk == RetrievalRisk.CONTEXT_INJECTION:
                # Skip chunks with injection attempts
                skip_indices.update(self._find_injection_attempts(context))
            elif risk == RetrievalRisk.RELEVANCE_MANIPULATION:
                # Skip irrelevant chunks
                skip_indices.update(self._find_irrelevant_chunks(context))

        # Filter content
        for idx, content in enumerate(context.retrieved_content):
            if idx not in skip_indices:
                # Apply any necessary sanitization
                sanitized = self._sanitize_content(content)
                if sanitized:
                    filtered_content.append(sanitized)

        return filtered_content

    def _find_privacy_violations(self, context: RetrievalContext) -> Set[int]:
        """Find chunks containing privacy violations"""
        violation_indices = set()

        for idx, content in enumerate(context.retrieved_content):
            for pattern in self.risk_patterns["privacy_patterns"].values():
                if re.search(pattern, content):
                    violation_indices.add(idx)
                    break

        return violation_indices

    def _find_injection_attempts(self, context: RetrievalContext) -> Set[int]:
        """Find chunks containing injection attempts"""
        injection_indices = set()

        for idx, content in enumerate(context.retrieved_content):
            for pattern in self.risk_patterns["injection_patterns"].values():
                if re.search(pattern, content):
                    injection_indices.add(idx)
                    break

        return injection_indices

    def _find_irrelevant_chunks(self, context: RetrievalContext) -> Set[int]:
        """Find irrelevant chunks based on similarity"""
        irrelevant_indices = set()
        threshold = self.security_checks["relevance"].threshold

        for idx, emb in enumerate(context.retrieved_embeddings):
            similarity = float(
                np.dot(context.query_embedding, emb)
                / (np.linalg.norm(context.query_embedding) * np.linalg.norm(emb))
            )
            if similarity < threshold:
                irrelevant_indices.add(idx)

        return irrelevant_indices

    def _sanitize_content(self, content: str) -> Optional[str]:
        """Sanitize content by removing or masking sensitive information"""
        sanitized = content

        # Mask privacy-sensitive information
        for pattern in self.risk_patterns["privacy_patterns"].values():
            sanitized = re.sub(pattern, "[REDACTED]", sanitized)

        # Remove injection attempts
        for pattern in self.risk_patterns["injection_patterns"].values():
            sanitized = re.sub(pattern, "", sanitized)

        # Remove manipulation attempts
        for pattern in self.risk_patterns["manipulation_patterns"].values():
            sanitized = re.sub(pattern, "", sanitized)

        # Clean up whitespace
        sanitized = " ".join(sanitized.split())

        return sanitized if sanitized.strip() else None

    def update_security_checks(self, updates: Dict[str, SecurityCheck]):
        """Update security check configurations"""
        self.security_checks.update(updates)

    def update_risk_patterns(self, updates: Dict[str, Dict[str, str]]):
        """Update risk detection patterns"""
        for category, patterns in updates.items():
            if category in self.risk_patterns:
                self.risk_patterns[category].update(patterns)
            else:
                self.risk_patterns[category] = patterns

    def get_check_history(self) -> List[Dict[str, Any]]:
        """Get history of guard check results"""
        return [
            {
                "timestamp": result.metadata["timestamp"],
                "is_safe": result.is_safe,
                "checks_passed": result.checks_passed,
                "checks_failed": result.checks_failed,
                "risks": [risk.value for risk in result.risks],
                "filtered_ratio": result.metadata["filtered_count"]
                / result.metadata["original_count"],
            }
            for result in self.check_history
        ]

    def clear_history(self):
        """Clear check history"""
        self.check_history.clear()

    def add_security_check(self, name: str, check: SecurityCheck):
        """Add a new security check"""
        self.security_checks[name] = check

    def remove_security_check(self, name: str):
        """Remove a security check"""
        self.security_checks.pop(name, None)

    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze detection patterns effectiveness"""
        pattern_stats = {
            "privacy": defaultdict(int),
            "injection": defaultdict(int),
            "manipulation": defaultdict(int),
        }

        for result in self.check_history:
            if not result.is_safe:
                for risk in result.risks:
                    if risk == RetrievalRisk.PRIVACY_LEAK:
                        for pattern in self.risk_patterns["privacy_patterns"]:
                            pattern_stats["privacy"][pattern] += 1
                    elif risk == RetrievalRisk.CONTEXT_INJECTION:
                        for pattern in self.risk_patterns["injection_patterns"]:
                            pattern_stats["injection"][pattern] += 1
                    elif risk == RetrievalRisk.CHUNKING_MANIPULATION:
                        for pattern in self.risk_patterns["manipulation_patterns"]:
                            pattern_stats["manipulation"][pattern] += 1

        return {
            "total_checks": len(self.check_history),
            "pattern_matches": dict(pattern_stats),
            "pattern_effectiveness": {
                category: {
                    pattern: count / len(self.check_history)
                    for pattern, count in patterns.items()
                }
                for category, patterns in pattern_stats.items()
            },
        }

    def get_recommendations(self) -> List[Dict[str, Any]]:
        """Get security recommendations based on check history"""
        if not self.check_history:
            return []

        recommendations = []
        risk_counts = defaultdict(int)
        total_checks = len(self.check_history)

        # Count risk occurrences
        for result in self.check_history:
            for risk in result.risks:
                risk_counts[risk] += 1

        # Generate recommendations
        for risk, count in risk_counts.items():
            frequency = count / total_checks
            if frequency > 0.1:  # More than 10% occurrence
                recommendations.append(
                    {
                        "risk": risk.value,
                        "frequency": frequency,
                        "severity": "high" if frequency > 0.5 else "medium",
                        "recommendations": self._get_risk_recommendations(risk),
                    }
                )

        return recommendations

    def _get_risk_recommendations(self, risk: RetrievalRisk) -> List[str]:
        """Get recommendations for specific risk"""
        recommendations = {
            RetrievalRisk.PRIVACY_LEAK: [
                "Implement stronger data masking",
                "Add privacy-focused preprocessing",
                "Review data handling policies",
            ],
            RetrievalRisk.CONTEXT_INJECTION: [
                "Enhance input validation",
                "Implement context boundaries",
                "Add injection detection",
            ],
            RetrievalRisk.RELEVANCE_MANIPULATION: [
                "Adjust similarity thresholds",
                "Implement semantic filtering",
                "Review retrieval strategy",
            ],
            RetrievalRisk.CHUNKING_MANIPULATION: [
                "Standardize chunk sizes",
                "Add chunk validation",
                "Implement overlap detection",
            ],
        }
        return recommendations.get(risk, [])
