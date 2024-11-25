"""
monitors/threat_detector.py - Real-time threat detection for LLM applications
"""

from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import threading
from collections import defaultdict
from ..core.logger import SecurityLogger
from ..core.exceptions import MonitoringError

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatCategory(Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    SUPPLY_CHAIN = "supply_chain"
    POISONING = "poisoning"
    DOS = "denial_of_service"
    UNAUTHORIZED_ACCESS = "unauthorized_access"

@dataclass
class Threat:
    category: ThreatCategory
    level: ThreatLevel
    description: str
    source: str
    timestamp: datetime
    indicators: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None

@dataclass
class ThreatRule:
    category: ThreatCategory
    indicators: List[str]
    threshold: float
    cooldown: int  # seconds
    level: ThreatLevel

class ThreatDetector:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.rules = self._initialize_rules()
        self.threats: List[Threat] = []
        self.alert_thresholds = {
            ThreatLevel.LOW: 0.3,
            ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.CRITICAL: 0.9
        }
        self.detection_history = defaultdict(list)
        self._lock = threading.Lock()

    def _initialize_rules(self) -> Dict[str, ThreatRule]:
        return {
            "injection_attempt": ThreatRule(
                category=ThreatCategory.PROMPT_INJECTION,
                indicators=[
                    "system prompt manipulation",
                    "instruction override",
                    "delimiter injection"
                ],
                threshold=0.7,
                cooldown=300,
                level=ThreatLevel.HIGH
            ),
            "data_leak": ThreatRule(
                category=ThreatCategory.DATA_LEAKAGE,
                indicators=[
                    "sensitive data exposure",
                    "credential leak",
                    "system information disclosure"
                ],
                threshold=0.8,
                cooldown=600,
                level=ThreatLevel.CRITICAL
            ),
            "dos_attack": ThreatRule(
                category=ThreatCategory.DOS,
                indicators=[
                    "rapid requests",
                    "resource exhaustion",
                    "token depletion"
                ],
                threshold=0.6,
                cooldown=120,
                level=ThreatLevel.MEDIUM
            ),
            "poisoning_attempt": ThreatRule(
                category=ThreatCategory.POISONING,
                indicators=[
                    "malicious training data",
                    "model manipulation",
                    "adversarial input"
                ],
                threshold=0.75,
                cooldown=900,
                level=ThreatLevel.HIGH
            )
        }

    def detect_threats(self, 
                      data: Dict[str, Any], 
                      context: Optional[Dict[str, Any]] = None) -> List[Threat]:
        try:
            detected_threats = []
            
            with self._lock:
                for rule_name, rule in self.rules.items():
                    if self._is_in_cooldown(rule_name):
                        continue

                    confidence = self._calculate_confidence(rule, data)
                    if confidence >= rule.threshold:
                        threat = Threat(
                            category=rule.category,
                            level=rule.level,
                            description=f"Detected {rule_name} with confidence {confidence:.2f}",
                            source=data.get("source", "unknown"),
                            timestamp=datetime.utcnow(),
                            indicators={"confidence": confidence},
                            context=context
                        )
                        detected_threats.append(threat)
                        self.threats.append(threat)
                        self._update_detection_history(rule_name)

                        if self.security_logger:
                            self.security_logger.log_security_event(
                                "threat_detected",
                                rule=rule_name,
                                confidence=confidence,
                                level=rule.level.value,
                                category=rule.category.value
                            )

            return detected_threats

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "threat_detection_error",
                    error=str(e)
                )
            raise MonitoringError(f"Threat detection failed: {str(e)}")

    def _calculate_confidence(self, rule: ThreatRule, data: Dict[str, Any]) -> float:
        matches = 0
        for indicator in rule.indicators:
            # Check in values of the data dictionary
            for value in data.values():
                if isinstance(value, str) and indicator.lower() in value.lower():
                    matches += 1
                    break
        return matches / len(rule.indicators)

    def _is_in_cooldown(self, rule_name: str) -> bool:
        if rule_name not in self.detection_history:
            return False
        
        last_detection = self.detection_history[rule_name][-1]
        cooldown = self.rules[rule_name].cooldown
        return (datetime.utcnow() - last_detection).seconds < cooldown

    def _update_detection_history(self, rule_name: str):
        self.detection_history[rule_name].append(datetime.utcnow())
        # Keep only last 24 hours
        cutoff = datetime.utcnow() - timedelta(hours=24)
        self.detection_history[rule_name] = [
            dt for dt in self.detection_history[rule_name]
            if dt > cutoff
        ]

    def get_active_threats(self, 
                         min_level: ThreatLevel = ThreatLevel.LOW,
                         category: Optional[ThreatCategory] = None) -> List[Dict[str, Any]]:
        return [
            {
                "category": threat.category.value,
                "level": threat.level.value,
                "description": threat.description,
                "source": threat.source,
                "timestamp": threat.timestamp.isoformat(),
                "indicators": threat.indicators
            }
            for threat in self.threats
            if threat.level.value >= min_level.value and
            (category is None or threat.category == category)
        ]

    def add_rule(self, name: str, rule: ThreatRule):
        with self._lock:
            self.rules[name] = rule

    def remove_rule(self, name: str):
        with self._lock:
            self.rules.pop(name, None)

    def clear_threats(self):
        with self._lock:
            self.threats.clear()
            self.detection_history.clear()

    def get_threat_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_threats": len(self.threats),
            "threats_by_level": defaultdict(int),
            "threats_by_category": defaultdict(int),
            "detection_history": {
                name: len(detections)
                for name, detections in self.detection_history.items()
            }
        }

        for threat in self.threats:
            stats["threats_by_level"][threat.level.value] += 1
            stats["threats_by_category"][threat.category.value] += 1

        return stats