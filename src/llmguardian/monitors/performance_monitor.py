"""
monitors/performance_monitor.py - LLM performance monitoring
"""

import time
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import mean, median, stdev
from collections import deque
from ..core.logger import SecurityLogger
from ..core.exceptions import MonitoringError


@dataclass
class PerformanceMetric:
    name: str
    value: float
    timestamp: datetime
    context: Optional[Dict[str, Any]] = None


@dataclass
class MetricThreshold:
    warning: float
    critical: float
    window_size: int  # number of samples
    calculation: str  # "average", "median", "percentile"


class PerformanceMonitor:
    def __init__(
        self, security_logger: Optional[SecurityLogger] = None, max_history: int = 1000
    ):
        self.security_logger = security_logger
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))
        self.thresholds = self._initialize_thresholds()
        self._lock = threading.Lock()

    def _initialize_thresholds(self) -> Dict[str, MetricThreshold]:
        return {
            "response_time": MetricThreshold(
                warning=1.0,  # seconds
                critical=5.0,
                window_size=100,
                calculation="average",
            ),
            "token_usage": MetricThreshold(
                warning=1000, critical=2000, window_size=50, calculation="median"
            ),
            "error_rate": MetricThreshold(
                warning=0.05,  # 5%
                critical=0.10,
                window_size=200,
                calculation="average",
            ),
            "memory_usage": MetricThreshold(
                warning=80.0,  # percentage
                critical=90.0,
                window_size=20,
                calculation="average",
            ),
        }

    def record_metric(
        self, name: str, value: float, context: Optional[Dict[str, Any]] = None
    ):
        try:
            metric = PerformanceMetric(
                name=name, value=value, timestamp=datetime.utcnow(), context=context
            )

            with self._lock:
                self.metrics[name].append(metric)
                self._check_threshold(name)

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "performance_monitoring_error",
                    error=str(e),
                    metric_name=name,
                    metric_value=value,
                )
            raise MonitoringError(f"Failed to record metric: {str(e)}")

    def _check_threshold(self, metric_name: str):
        if metric_name not in self.thresholds:
            return

        threshold = self.thresholds[metric_name]
        recent_metrics = list(self.metrics[metric_name])[-threshold.window_size :]

        if not recent_metrics:
            return

        values = [m.value for m in recent_metrics]

        if threshold.calculation == "average":
            current_value = mean(values)
        elif threshold.calculation == "median":
            current_value = median(values)
        else:
            current_value = mean(values)  # default to average

        if current_value >= threshold.critical:
            level = "critical"
        elif current_value >= threshold.warning:
            level = "warning"
        else:
            return

        if self.security_logger:
            self.security_logger.log_security_event(
                "performance_threshold_exceeded",
                metric_name=metric_name,
                current_value=current_value,
                threshold_level=level,
                threshold_value=(
                    threshold.critical if level == "critical" else threshold.warning
                ),
            )

    def get_metrics(
        self, metric_name: str, window: Optional[timedelta] = None
    ) -> List[Dict[str, Any]]:
        with self._lock:
            metrics = list(self.metrics[metric_name])

            if window:
                cutoff = datetime.utcnow() - window
                metrics = [m for m in metrics if m.timestamp >= cutoff]

            return [
                {
                    "value": m.value,
                    "timestamp": m.timestamp.isoformat(),
                    "context": m.context,
                }
                for m in metrics
            ]

    def get_statistics(
        self, metric_name: str, window: Optional[timedelta] = None
    ) -> Dict[str, float]:
        with self._lock:
            metrics = self.get_metrics(metric_name, window)
            if not metrics:
                return {}

            values = [m["value"] for m in metrics]

            stats = {
                "min": min(values),
                "max": max(values),
                "average": mean(values),
                "median": median(values),
            }

            if len(values) > 1:
                stats["std_dev"] = stdev(values)

            return stats

    def update_threshold(self, metric_name: str, threshold: MetricThreshold):
        with self._lock:
            self.thresholds[metric_name] = threshold

    def clear_metrics(self, metric_name: Optional[str] = None):
        with self._lock:
            if metric_name:
                self.metrics[metric_name].clear()
            else:
                self.metrics.clear()

    def get_alerts(self, window: Optional[timedelta] = None) -> List[Dict[str, Any]]:
        alerts = []
        for name, threshold in self.thresholds.items():
            stats = self.get_statistics(name, window)
            if not stats:
                continue

            if stats["average"] >= threshold.critical:
                alerts.append(
                    {
                        "metric_name": name,
                        "level": "critical",
                        "value": stats["average"],
                        "threshold": threshold.critical,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
            elif stats["average"] >= threshold.warning:
                alerts.append(
                    {
                        "metric_name": name,
                        "level": "warning",
                        "value": stats["average"],
                        "threshold": threshold.warning,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

        return alerts
