"""
data/poison_detector.py - Detection and prevention of data poisoning attacks
"""

import numpy as np
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from collections import defaultdict
import json
import hashlib
from ..core.logger import SecurityLogger
from ..core.exceptions import SecurityError


class PoisonType(Enum):
    """Types of data poisoning attacks"""

    LABEL_FLIPPING = "label_flipping"
    BACKDOOR = "backdoor"
    CLEAN_LABEL = "clean_label"
    DATA_MANIPULATION = "data_manipulation"
    TRIGGER_INJECTION = "trigger_injection"
    ADVERSARIAL = "adversarial"
    SEMANTIC = "semantic"


@dataclass
class PoisonPattern:
    """Pattern for detecting poisoning attempts"""

    name: str
    description: str
    indicators: List[str]
    severity: int  # 1-10
    detection_method: str
    threshold: float
    enabled: bool = True


@dataclass
class DataPoint:
    """Individual data point for analysis"""

    content: Any
    metadata: Dict[str, Any]
    embedding: Optional[np.ndarray] = None
    label: Optional[str] = None


@dataclass
class DetectionResult:
    """Result of poison detection"""

    is_poisoned: bool
    poison_types: List[PoisonType]
    confidence: float
    affected_indices: List[int]
    analysis: Dict[str, Any]
    remediation: List[str]
    metadata: Dict[str, Any]


class PoisonDetector:
    """Detector for data poisoning attempts"""

    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.patterns = self._initialize_patterns()
        self.detection_history: List[DetectionResult] = []
        self.statistics = defaultdict(int)

    def _initialize_patterns(self) -> Dict[str, PoisonPattern]:
        """Initialize poisoning detection patterns"""
        return {
            "label_flip": PoisonPattern(
                name="Label Flipping Attack",
                description="Detection of maliciously flipped labels",
                indicators=[
                    "label_distribution_shift",
                    "confidence_mismatch",
                    "semantic_inconsistency",
                ],
                severity=8,
                detection_method="statistical_analysis",
                threshold=0.8,
            ),
            "backdoor": PoisonPattern(
                name="Backdoor Attack",
                description="Detection of embedded backdoor triggers",
                indicators=[
                    "trigger_pattern",
                    "activation_anomaly",
                    "consistent_misclassification",
                ],
                severity=9,
                detection_method="pattern_matching",
                threshold=0.85,
            ),
            "clean_label": PoisonPattern(
                name="Clean Label Attack",
                description="Detection of clean label poisoning",
                indicators=[
                    "feature_manipulation",
                    "embedding_shift",
                    "boundary_distortion",
                ],
                severity=7,
                detection_method="embedding_analysis",
                threshold=0.75,
            ),
            "manipulation": PoisonPattern(
                name="Data Manipulation",
                description="Detection of manipulated training data",
                indicators=[
                    "statistical_anomaly",
                    "distribution_shift",
                    "outlier_pattern",
                ],
                severity=8,
                detection_method="distribution_analysis",
                threshold=0.8,
            ),
            "trigger": PoisonPattern(
                name="Trigger Injection",
                description="Detection of injected trigger patterns",
                indicators=["visual_pattern", "text_pattern", "feature_pattern"],
                severity=9,
                detection_method="pattern_recognition",
                threshold=0.9,
            ),
        }

    def detect_poison(
        self, data_points: List[DataPoint], context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """Detect poisoning in a dataset"""
        try:
            poison_types = []
            confidence_scores = []
            affected_indices = set()
            analysis_results = {}

            # Check each pattern
            for pattern_name, pattern in self.patterns.items():
                if not pattern.enabled:
                    continue

                # Apply appropriate detection method
                if pattern.detection_method == "statistical_analysis":
                    result = self._statistical_analysis(data_points, pattern)
                elif pattern.detection_method == "pattern_matching":
                    result = self._pattern_matching(data_points, pattern)
                elif pattern.detection_method == "embedding_analysis":
                    result = self._embedding_analysis(data_points, pattern)
                elif pattern.detection_method == "distribution_analysis":
                    result = self._distribution_analysis(data_points, pattern)
                elif pattern.detection_method == "pattern_recognition":
                    result = self._pattern_recognition(data_points, pattern)
                else:
                    continue

                if result.confidence >= pattern.threshold:
                    poison_types.append(self._map_pattern_to_type(pattern_name))
                    confidence_scores.append(result.confidence)
                    affected_indices.update(result.affected_indices)
                    analysis_results[pattern_name] = result.analysis

            # Calculate overall confidence
            overall_confidence = (
                sum(confidence_scores) / len(confidence_scores)
                if confidence_scores
                else 0.0
            )

            result = DetectionResult(
                is_poisoned=bool(poison_types),
                poison_types=poison_types,
                confidence=overall_confidence,
                affected_indices=sorted(affected_indices),
                analysis=analysis_results,
                remediation=self._get_remediation_steps(poison_types),
                metadata={
                    "timestamp": datetime.utcnow().isoformat(),
                    "data_points": len(data_points),
                    "affected_percentage": len(affected_indices) / len(data_points),
                    "context": context or {},
                },
            )

            if result.is_poisoned and self.security_logger:
                self.security_logger.log_security_event(
                    "poison_detected",
                    poison_types=[pt.value for pt in poison_types],
                    confidence=overall_confidence,
                    affected_count=len(affected_indices),
                )

            self.detection_history.append(result)
            return result

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "poison_detection_error", error=str(e)
                )
            raise SecurityError(f"Poison detection failed: {str(e)}")

    def _statistical_analysis(
        self, data_points: List[DataPoint], pattern: PoisonPattern
    ) -> DetectionResult:
        """Perform statistical analysis for poisoning detection"""
        analysis = {}
        affected_indices = []

        if any(dp.label is not None for dp in data_points):
            # Analyze label distribution
            label_dist = defaultdict(int)
            for dp in data_points:
                if dp.label:
                    label_dist[dp.label] += 1

            # Check for anomalous distributions
            total = len(data_points)
            expected_freq = total / len(label_dist)
            anomalous_labels = []

            for label, count in label_dist.items():
                if abs(count - expected_freq) > expected_freq * 0.5:  # 50% threshold
                    anomalous_labels.append(label)

            # Find affected indices
            for i, dp in enumerate(data_points):
                if dp.label in anomalous_labels:
                    affected_indices.append(i)

            analysis["label_distribution"] = dict(label_dist)
            analysis["anomalous_labels"] = anomalous_labels

        confidence = len(affected_indices) / len(data_points) if affected_indices else 0

        return DetectionResult(
            is_poisoned=confidence >= pattern.threshold,
            poison_types=[PoisonType.LABEL_FLIPPING],
            confidence=confidence,
            affected_indices=affected_indices,
            analysis=analysis,
            remediation=["Review and correct anomalous labels"],
            metadata={"method": "statistical_analysis"},
        )

    def _pattern_matching(
        self, data_points: List[DataPoint], pattern: PoisonPattern
    ) -> DetectionResult:
        """Perform pattern matching for backdoor detection"""
        analysis = {}
        affected_indices = []
        trigger_patterns = set()

        # Look for consistent patterns in content
        for i, dp in enumerate(data_points):
            content_str = str(dp.content)
            # Check for suspicious patterns
            if self._contains_trigger_pattern(content_str):
                affected_indices.append(i)
                trigger_patterns.update(self._extract_trigger_patterns(content_str))

        confidence = len(affected_indices) / len(data_points) if affected_indices else 0

        analysis["trigger_patterns"] = list(trigger_patterns)
        analysis["pattern_frequency"] = len(affected_indices)

        return DetectionResult(
            is_poisoned=confidence >= pattern.threshold,
            poison_types=[PoisonType.BACKDOOR],
            confidence=confidence,
            affected_indices=affected_indices,
            analysis=analysis,
            remediation=["Remove detected trigger patterns"],
            metadata={"method": "pattern_matching"},
        )

    def _embedding_analysis(
        self, data_points: List[DataPoint], pattern: PoisonPattern
    ) -> DetectionResult:
        """Analyze embeddings for poisoning detection"""
        analysis = {}
        affected_indices = []

        # Collect embeddings
        embeddings = [dp.embedding for dp in data_points if dp.embedding is not None]

        if embeddings:
            embeddings = np.array(embeddings)
            # Calculate centroid
            centroid = np.mean(embeddings, axis=0)
            # Calculate distances
            distances = np.linalg.norm(embeddings - centroid, axis=1)
            # Find outliers
            threshold = np.mean(distances) + 2 * np.std(distances)

            for i, dist in enumerate(distances):
                if dist > threshold:
                    affected_indices.append(i)

            analysis["distance_stats"] = {
                "mean": float(np.mean(distances)),
                "std": float(np.std(distances)),
                "threshold": float(threshold),
            }

        confidence = len(affected_indices) / len(data_points) if affected_indices else 0

        return DetectionResult(
            is_poisoned=confidence >= pattern.threshold,
            poison_types=[PoisonType.CLEAN_LABEL],
            confidence=confidence,
            affected_indices=affected_indices,
            analysis=analysis,
            remediation=["Review outlier embeddings"],
            metadata={"method": "embedding_analysis"},
        )

    def _distribution_analysis(
        self, data_points: List[DataPoint], pattern: PoisonPattern
    ) -> DetectionResult:
        """Analyze data distribution for manipulation detection"""
        analysis = {}
        affected_indices = []

        if any(dp.embedding is not None for dp in data_points):
            # Analyze feature distribution
            embeddings = np.array(
                [dp.embedding for dp in data_points if dp.embedding is not None]
            )

            # Calculate distribution statistics
            mean_vec = np.mean(embeddings, axis=0)
            std_vec = np.std(embeddings, axis=0)

            # Check for anomalies in feature distribution
            z_scores = np.abs((embeddings - mean_vec) / std_vec)
            anomaly_threshold = 3  # 3 standard deviations

            for i, z_score in enumerate(z_scores):
                if np.any(z_score > anomaly_threshold):
                    affected_indices.append(i)

            analysis["distribution_stats"] = {
                "feature_means": mean_vec.tolist(),
                "feature_stds": std_vec.tolist(),
            }

        confidence = len(affected_indices) / len(data_points) if affected_indices else 0

        return DetectionResult(
            is_poisoned=confidence >= pattern.threshold,
            poison_types=[PoisonType.DATA_MANIPULATION],
            confidence=confidence,
            affected_indices=affected_indices,
            analysis=analysis,
            remediation=["Review anomalous feature distributions"],
            metadata={"method": "distribution_analysis"},
        )

    def _pattern_recognition(
        self, data_points: List[DataPoint], pattern: PoisonPattern
    ) -> DetectionResult:
        """Recognize trigger patterns in data"""
        analysis = {}
        affected_indices = []
        detected_patterns = defaultdict(int)

        for i, dp in enumerate(data_points):
            patterns = self._detect_trigger_patterns(dp)
            if patterns:
                affected_indices.append(i)
                for p in patterns:
                    detected_patterns[p] += 1

        confidence = len(affected_indices) / len(data_points) if affected_indices else 0

        analysis["detected_patterns"] = dict(detected_patterns)

        return DetectionResult(
            is_poisoned=confidence >= pattern.threshold,
            poison_types=[PoisonType.TRIGGER_INJECTION],
            confidence=confidence,
            affected_indices=affected_indices,
            analysis=analysis,
            remediation=["Remove detected trigger patterns"],
            metadata={"method": "pattern_recognition"},
        )

    def _contains_trigger_pattern(self, content: str) -> bool:
        """Check if content contains trigger patterns"""
        trigger_patterns = [
            r"hidden_trigger_",
            r"backdoor_pattern_",
            r"malicious_tag_",
            r"poison_marker_",
        ]
        return any(re.search(pattern, content) for pattern in trigger_patterns)

    def _extract_trigger_patterns(self, content: str) -> Set[str]:
        """Extract trigger patterns from content"""
        # Implementation would extract actual patterns
        return set()

    def _detect_trigger_patterns(self, data_point: DataPoint) -> List[str]:
        """Detect trigger patterns in a data point"""
        # Implementation would detect specific patterns
        return []

    def _map_pattern_to_type(self, pattern_name: str) -> PoisonType:
        """Map pattern name to poison type"""
        mapping = {
            "label_flip": PoisonType.LABEL_FLIPPING,
            "backdoor": PoisonType.BACKDOOR,
            "clean_label": PoisonType.CLEAN_LABEL,
            "manipulation": PoisonType.DATA_MANIPULATION,
            "trigger": PoisonType.TRIGGER_INJECTION,
        }
        return mapping.get(pattern_name, PoisonType.ADVERSARIAL)

    def _get_remediation_steps(self, poison_types: List[PoisonType]) -> List[str]:
        """Get remediation steps for detected poison types"""
        remediation_steps = set()

        for poison_type in poison_types:
            if poison_type == PoisonType.LABEL_FLIPPING:
                remediation_steps.update(
                    [
                        "Review and correct suspicious labels",
                        "Implement label validation",
                        "Add consistency checks",
                    ]
                )
            elif poison_type == PoisonType.BACKDOOR:
                remediation_steps.update(
                    [
                        "Remove detected backdoor triggers",
                        "Implement trigger detection",
                        "Enhance input validation",
                    ]
                )
            elif poison_type == PoisonType.CLEAN_LABEL:
                remediation_steps.update(
                    [
                        "Review outlier samples",
                        "Validate data sources",
                        "Implement feature verification",
                    ]
                )
            elif poison_type == PoisonType.DATA_MANIPULATION:
                remediation_steps.update(
                    [
                        "Verify data integrity",
                        "Check data sources",
                        "Implement data validation",
                    ]
                )
            elif poison_type == PoisonType.TRIGGER_INJECTION:
                remediation_steps.update(
                    [
                        "Remove injected triggers",
                        "Enhance pattern detection",
                        "Implement input sanitization",
                    ]
                )
            elif poison_type == PoisonType.ADVERSARIAL:
                remediation_steps.update(
                    [
                        "Review adversarial samples",
                        "Implement robust validation",
                        "Enhance security measures",
                    ]
                )
            elif poison_type == PoisonType.SEMANTIC:
                remediation_steps.update(
                    [
                        "Validate semantic consistency",
                        "Review content relationships",
                        "Implement semantic checks",
                    ]
                )

        return list(remediation_steps)

    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        if not self.detection_history:
            return {}

        stats = {
            "total_scans": len(self.detection_history),
            "poisoned_datasets": sum(
                1 for r in self.detection_history if r.is_poisoned
            ),
            "poison_types": defaultdict(int),
            "confidence_distribution": defaultdict(list),
            "affected_samples": {"total": 0, "average": 0, "max": 0},
        }

        for result in self.detection_history:
            if result.is_poisoned:
                for poison_type in result.poison_types:
                    stats["poison_types"][poison_type.value] += 1

                stats["confidence_distribution"][
                    self._categorize_confidence(result.confidence)
                ].append(result.confidence)

                affected_count = len(result.affected_indices)
                stats["affected_samples"]["total"] += affected_count
                stats["affected_samples"]["max"] = max(
                    stats["affected_samples"]["max"], affected_count
                )

        if stats["poisoned_datasets"]:
            stats["affected_samples"]["average"] = (
                stats["affected_samples"]["total"] / stats["poisoned_datasets"]
            )

        return stats

    def _categorize_confidence(self, confidence: float) -> str:
        """Categorize confidence scores"""
        if confidence >= 0.9:
            return "very_high"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"

    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze detection patterns and their effectiveness"""
        if not self.detection_history:
            return {}

        pattern_stats = {
            name: {
                "triggers": 0,
                "false_positives": 0,
                "confidence_avg": 0.0,
                "affected_samples": 0,
            }
            for name in self.patterns.keys()
        }

        # Analyze each detection result
        for result in self.detection_history:
            for pattern_name, analysis in result.analysis.items():
                if pattern_name in pattern_stats:
                    stats = pattern_stats[pattern_name]
                    stats["triggers"] += 1
                    stats["affected_samples"] += len(result.affected_indices)
                    stats["confidence_avg"] += result.confidence

        # Calculate averages
        for stats in pattern_stats.values():
            if stats["triggers"] > 0:
                stats["confidence_avg"] /= stats["triggers"]

        return {
            "pattern_statistics": pattern_stats,
            "recommendations": self._generate_pattern_recommendations(pattern_stats),
        }

    def _generate_pattern_recommendations(
        self, pattern_stats: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations for pattern improvements"""
        recommendations = []

        for name, stats in pattern_stats.items():
            if stats["triggers"] == 0:
                recommendations.append(
                    {
                        "pattern": name,
                        "type": "unused",
                        "recommendation": "Consider removing or updating unused pattern",
                        "priority": "low",
                    }
                )
            elif stats["confidence_avg"] < 0.5:
                recommendations.append(
                    {
                        "pattern": name,
                        "type": "low_confidence",
                        "recommendation": "Review and adjust pattern threshold",
                        "priority": "high",
                    }
                )
            elif (
                stats["false_positives"] > stats["triggers"] * 0.2
            ):  # 20% false positive rate
                recommendations.append(
                    {
                        "pattern": name,
                        "type": "false_positives",
                        "recommendation": "Refine pattern to reduce false positives",
                        "priority": "medium",
                    }
                )

        return recommendations

    def export_detection_report(self) -> Dict[str, Any]:
        """Generate comprehensive detection report"""
        stats = self.get_detection_stats()
        pattern_analysis = self.analyze_patterns()

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_scans": stats.get("total_scans", 0),
                "poisoned_datasets": stats.get("poisoned_datasets", 0),
                "total_affected_samples": stats.get("affected_samples", {}).get(
                    "total", 0
                ),
            },
            "poison_types": dict(stats.get("poison_types", {})),
            "pattern_effectiveness": pattern_analysis.get("pattern_statistics", {}),
            "recommendations": pattern_analysis.get("recommendations", []),
            "confidence_metrics": {
                level: {
                    "count": len(scores),
                    "average": sum(scores) / len(scores) if scores else 0,
                }
                for level, scores in stats.get("confidence_distribution", {}).items()
            },
        }

    def add_pattern(self, pattern: PoisonPattern):
        """Add a new detection pattern"""
        self.patterns[pattern.name] = pattern

    def remove_pattern(self, pattern_name: str):
        """Remove a detection pattern"""
        self.patterns.pop(pattern_name, None)

    def update_pattern(self, pattern_name: str, updates: Dict[str, Any]):
        """Update an existing pattern"""
        if pattern_name in self.patterns:
            pattern = self.patterns[pattern_name]
            for key, value in updates.items():
                if hasattr(pattern, key):
                    setattr(pattern, key, value)

    def clear_history(self):
        """Clear detection history"""
        self.detection_history.clear()

    def validate_dataset(
        self, data_points: List[DataPoint], context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Validate entire dataset for poisoning"""
        result = self.detect_poison(data_points, context)
        return not result.is_poisoned
