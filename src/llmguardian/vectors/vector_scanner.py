"""
vectors/vector_scanner.py - Security scanner for vector databases and operations
"""

import numpy as np
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
from collections import defaultdict
from ..core.logger import SecurityLogger
from ..core.exceptions import SecurityError


class VectorVulnerability(Enum):
    """Types of vector-related vulnerabilities"""

    POISONED_VECTORS = "poisoned_vectors"
    MALICIOUS_PAYLOAD = "malicious_payload"
    DATA_LEAKAGE = "data_leakage"
    DIMENSION_MISMATCH = "dimension_mismatch"
    METADATA_TAMPERING = "metadata_tampering"
    CLUSTERING_ATTACK = "clustering_attack"
    SIMILARITY_MANIPULATION = "similarity_manipulation"
    INDEX_POISONING = "index_poisoning"


@dataclass
class ScanTarget:
    """Definition of a scan target"""

    vectors: np.ndarray
    metadata: Optional[Dict[str, Any]] = None
    index_data: Optional[Dict[str, Any]] = None
    source: Optional[str] = None


@dataclass
class VulnerabilityReport:
    """Detailed vulnerability report"""

    vulnerability_type: VectorVulnerability
    severity: int  # 1-10
    affected_indices: List[int]
    description: str
    recommendations: List[str]
    metadata: Dict[str, Any]


@dataclass
class ScanResult:
    """Result of a vector database scan"""

    vulnerabilities: List[VulnerabilityReport]
    statistics: Dict[str, Any]
    timestamp: datetime
    scan_duration: float


class VectorScanner:
    """Scanner for vector-related security issues"""

    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.vulnerability_patterns = self._initialize_patterns()
        self.scan_history: List[ScanResult] = []

    def _initialize_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize vulnerability detection patterns"""
        return {
            "clustering": {
                "min_cluster_size": 10,
                "isolation_threshold": 0.3,
                "similarity_threshold": 0.85,
            },
            "metadata": {
                "required_fields": {"timestamp", "source", "dimension"},
                "sensitive_patterns": {
                    r"password",
                    r"secret",
                    r"key",
                    r"token",
                    r"credential",
                    r"auth",
                    r"\bpii\b",
                },
            },
            "poisoning": {
                "variance_threshold": 0.1,
                "outlier_threshold": 2.0,
                "minimum_samples": 5,
            },
        }

    def scan_vectors(self, target: ScanTarget) -> ScanResult:
        """Scan vectors for security vulnerabilities"""
        try:
            start_time = datetime.utcnow()
            vulnerabilities = []
            statistics = defaultdict(int)

            # Check for poisoned vectors
            poisoning_report = self._check_vector_poisoning(target)
            if poisoning_report:
                vulnerabilities.append(poisoning_report)
                statistics["poisoned_vectors"] = len(poisoning_report.affected_indices)

            # Check for malicious payloads
            payload_report = self._check_malicious_payloads(target)
            if payload_report:
                vulnerabilities.append(payload_report)
                statistics["malicious_payloads"] = len(payload_report.affected_indices)

            # Check for data leakage
            leakage_report = self._check_data_leakage(target)
            if leakage_report:
                vulnerabilities.append(leakage_report)
                statistics["data_leakage"] = len(leakage_report.affected_indices)

            # Check for clustering attacks
            clustering_report = self._check_clustering_attacks(target)
            if clustering_report:
                vulnerabilities.append(clustering_report)
                statistics["clustering_attacks"] = len(
                    clustering_report.affected_indices
                )

            # Check metadata
            metadata_report = self._check_metadata_tampering(target)
            if metadata_report:
                vulnerabilities.append(metadata_report)
                statistics["metadata_issues"] = len(metadata_report.affected_indices)

            # Create scan result
            scan_duration = (datetime.utcnow() - start_time).total_seconds()
            result = ScanResult(
                vulnerabilities=vulnerabilities,
                statistics=dict(statistics),
                timestamp=datetime.utcnow(),
                scan_duration=scan_duration,
            )

            # Log scan results
            if vulnerabilities and self.security_logger:
                self.security_logger.log_security_event(
                    "vector_scan_completed",
                    vulnerability_count=len(vulnerabilities),
                    statistics=statistics,
                )

            self.scan_history.append(result)
            return result

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "vector_scan_error", error=str(e)
                )
            raise SecurityError(f"Vector scan failed: {str(e)}")

    def _check_vector_poisoning(
        self, target: ScanTarget
    ) -> Optional[VulnerabilityReport]:
        """Check for poisoned vectors"""
        affected_indices = []
        vectors = target.vectors

        # Calculate statistical properties
        mean_vector = np.mean(vectors, axis=0)
        distances = np.linalg.norm(vectors - mean_vector, axis=1)
        mean_distance = np.mean(distances)
        std_distance = np.std(distances)

        # Check for outliers
        threshold = self.vulnerability_patterns["poisoning"]["outlier_threshold"]
        for i, distance in enumerate(distances):
            if abs(distance - mean_distance) > threshold * std_distance:
                affected_indices.append(i)

        if affected_indices:
            return VulnerabilityReport(
                vulnerability_type=VectorVulnerability.POISONED_VECTORS,
                severity=8,
                affected_indices=affected_indices,
                description="Detected potential poisoned vectors based on statistical analysis",
                recommendations=[
                    "Remove or quarantine affected vectors",
                    "Implement stronger validation for new vectors",
                    "Monitor vector statistics regularly",
                ],
                metadata={
                    "mean_distance": float(mean_distance),
                    "std_distance": float(std_distance),
                    "threshold_used": float(threshold),
                },
            )
        return None

    def _check_malicious_payloads(
        self, target: ScanTarget
    ) -> Optional[VulnerabilityReport]:
        """Check for malicious payloads in metadata"""
        if not target.metadata:
            return None

        affected_indices = []
        suspicious_patterns = {
            r"eval\(",
            r"exec\(",
            r"system\(",  # Code execution
            r"<script",
            r"javascript:",  # XSS
            r"DROP TABLE",
            r"DELETE FROM",  # SQL injection
            r"\\x[0-9a-fA-F]+",  # Encoded content
        }

        for idx, metadata in enumerate(target.metadata):
            for key, value in metadata.items():
                if isinstance(value, str):
                    for pattern in suspicious_patterns:
                        if re.search(pattern, value, re.IGNORECASE):
                            affected_indices.append(idx)
                            break

        if affected_indices:
            return VulnerabilityReport(
                vulnerability_type=VectorVulnerability.MALICIOUS_PAYLOAD,
                severity=9,
                affected_indices=affected_indices,
                description="Detected potential malicious payloads in metadata",
                recommendations=[
                    "Sanitize metadata before storage",
                    "Implement strict metadata validation",
                    "Use allowlist for metadata fields",
                ],
                metadata={"patterns_checked": list(suspicious_patterns)},
            )
        return None

    def _check_data_leakage(self, target: ScanTarget) -> Optional[VulnerabilityReport]:
        """Check for potential data leakage"""
        if not target.metadata:
            return None

        affected_indices = []
        sensitive_patterns = self.vulnerability_patterns["metadata"][
            "sensitive_patterns"
        ]

        for idx, metadata in enumerate(target.metadata):
            for key, value in metadata.items():
                if isinstance(value, str):
                    for pattern in sensitive_patterns:
                        if re.search(pattern, value, re.IGNORECASE):
                            affected_indices.append(idx)
                            break

        if affected_indices:
            return VulnerabilityReport(
                vulnerability_type=VectorVulnerability.DATA_LEAKAGE,
                severity=7,
                affected_indices=affected_indices,
                description="Detected potential sensitive information in metadata",
                recommendations=[
                    "Remove or encrypt sensitive information",
                    "Implement data masking",
                    "Review metadata handling policies",
                ],
                metadata={"sensitive_patterns": list(sensitive_patterns)},
            )
        return None

    def _check_clustering_attacks(
        self, target: ScanTarget
    ) -> Optional[VulnerabilityReport]:
        """Check for potential clustering-based attacks"""
        vectors = target.vectors
        affected_indices = []

        # Calculate pairwise similarities
        similarities = np.dot(vectors, vectors.T)
        np.fill_diagonal(similarities, 0)  # Ignore self-similarity

        # Check for suspicious clusters
        threshold = self.vulnerability_patterns["clustering"]["similarity_threshold"]
        min_cluster_size = self.vulnerability_patterns["clustering"]["min_cluster_size"]

        for i in range(len(vectors)):
            similar_vectors = np.where(similarities[i] > threshold)[0]
            if len(similar_vectors) >= min_cluster_size:
                affected_indices.extend(similar_vectors)

        affected_indices = list(set(affected_indices))  # Remove duplicates

        if affected_indices:
            return VulnerabilityReport(
                vulnerability_type=VectorVulnerability.CLUSTERING_ATTACK,
                severity=6,
                affected_indices=affected_indices,
                description="Detected suspicious vector clustering patterns",
                recommendations=[
                    "Review clustered vectors for legitimacy",
                    "Implement diversity requirements",
                    "Monitor clustering patterns",
                ],
                metadata={
                    "similarity_threshold": threshold,
                    "min_cluster_size": min_cluster_size,
                    "cluster_count": len(affected_indices),
                },
            )
        return None

    def _check_metadata_tampering(
        self, target: ScanTarget
    ) -> Optional[VulnerabilityReport]:
        """Check for metadata tampering"""
        if not target.metadata:
            return None

        affected_indices = []
        required_fields = self.vulnerability_patterns["metadata"]["required_fields"]

        for idx, metadata in enumerate(target.metadata):
            # Check for missing required fields
            if not all(field in metadata for field in required_fields):
                affected_indices.append(idx)
                continue

            # Check for timestamp consistency
            if "timestamp" in metadata:
                try:
                    ts = datetime.fromisoformat(str(metadata["timestamp"]))
                    if ts > datetime.utcnow():
                        affected_indices.append(idx)
                except (ValueError, TypeError):
                    affected_indices.append(idx)

        if affected_indices:
            return VulnerabilityReport(
                vulnerability_type=VectorVulnerability.METADATA_TAMPERING,
                severity=5,
                affected_indices=affected_indices,
                description="Detected potential metadata tampering",
                recommendations=[
                    "Validate metadata integrity",
                    "Implement metadata signing",
                    "Monitor metadata changes",
                ],
                metadata={
                    "required_fields": list(required_fields),
                    "affected_count": len(affected_indices),
                },
            )
        return None

    def get_scan_history(self) -> List[Dict[str, Any]]:
        """Get history of scan results"""
        return [
            {
                "timestamp": result.timestamp.isoformat(),
                "vulnerability_count": len(result.vulnerabilities),
                "statistics": result.statistics,
                "scan_duration": result.scan_duration,
            }
            for result in self.scan_history
        ]

    def clear_scan_history(self):
        """Clear scan history"""
        self.scan_history.clear()

    def update_patterns(self, patterns: Dict[str, Dict[str, Any]]):
        """Update vulnerability detection patterns"""
        self.vulnerability_patterns.update(patterns)
