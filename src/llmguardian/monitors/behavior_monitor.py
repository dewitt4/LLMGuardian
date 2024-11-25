"""
monitors/behavior_monitor.py - LLM behavior monitoring
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from ..core.logger import SecurityLogger
from ..core.exceptions import MonitoringError

@dataclass
class BehaviorPattern:
    name: str
    description: str
    indicators: List[str]
    severity: int
    threshold: float

@dataclass
class BehaviorEvent:
    pattern: str
    confidence: float
    context: Dict[str, Any]
    timestamp: datetime

class BehaviorMonitor:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.patterns = self._initialize_patterns()
        self.events: List[BehaviorEvent] = []

    def _initialize_patterns(self) -> Dict[str, BehaviorPattern]:
        return {
            "prompt_manipulation": BehaviorPattern(
                name="Prompt Manipulation",
                description="Attempts to manipulate system prompts",
                indicators=["system prompt override", "instruction manipulation"],
                severity=8,
                threshold=0.7
            ),
            "data_exfiltration": BehaviorPattern(
                name="Data Exfiltration",
                description="Attempts to extract sensitive data",
                indicators=["sensitive data request", "system info probe"],
                severity=9,
                threshold=0.8
            ),
            "resource_abuse": BehaviorPattern(
                name="Resource Abuse",
                description="Excessive resource consumption",
                indicators=["repeated requests", "large outputs"],
                severity=7,
                threshold=0.6
            )
        }

    def monitor_behavior(self, 
                        input_text: str, 
                        output_text: str, 
                        context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            matches = {}
            for name, pattern in self.patterns.items():
                confidence = self._analyze_pattern(
                    pattern, input_text, output_text
                )
                if confidence >= pattern.threshold:
                    matches[name] = confidence
                    self._record_event(name, confidence, context)

            if matches and self.security_logger:
                self.security_logger.log_security_event(
                    "suspicious_behavior_detected",
                    patterns=list(matches.keys()),
                    confidences=matches
                )

            return {
                "matches": matches,
                "timestamp": datetime.utcnow().isoformat(),
                "input_length": len(input_text),
                "output_length": len(output_text)
            }

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "behavior_monitoring_error",
                    error=str(e)
                )
            raise MonitoringError(f"Behavior monitoring failed: {str(e)}")

    def _analyze_pattern(self, 
                        pattern: BehaviorPattern, 
                        input_text: str, 
                        output_text: str) -> float:
        matches = 0
        for indicator in pattern.indicators:
            if (indicator.lower() in input_text.lower() or 
                indicator.lower() in output_text.lower()):
                matches += 1
        return matches / len(pattern.indicators)

    def _record_event(self, 
                     pattern_name: str, 
                     confidence: float, 
                     context: Dict[str, Any]):
        event = BehaviorEvent(
            pattern=pattern_name,
            confidence=confidence,
            context=context,
            timestamp=datetime.utcnow()
        )
        self.events.append(event)

    def get_events(self, 
                  pattern: Optional[str] = None, 
                  min_confidence: float = 0.0) -> List[Dict[str, Any]]:
        filtered = [
            e for e in self.events
            if (not pattern or e.pattern == pattern) and 
            e.confidence >= min_confidence
        ]
        return [
            {
                "pattern": e.pattern,
                "confidence": e.confidence,
                "context": e.context,
                "timestamp": e.timestamp.isoformat()
            }
            for e in filtered
        ]

    def add_pattern(self, name: str, pattern: BehaviorPattern):
        self.patterns[name] = pattern

    def remove_pattern(self, name: str):
        self.patterns.pop(name, None)

    def clear_events(self):
        self.events.clear()