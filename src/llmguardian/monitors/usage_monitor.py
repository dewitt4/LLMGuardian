"""
monitors/usage_monitor.py - Resource usage monitoring
"""

import time
import psutil
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from ..core.logger import SecurityLogger
from ..core.exceptions import MonitoringError


@dataclass
class ResourceMetrics:
    cpu_percent: float
    memory_percent: float
    disk_usage: float
    network_io: Dict[str, int]
    timestamp: datetime


class UsageMonitor:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.metrics_history: List[ResourceMetrics] = []
        self.thresholds = {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "disk_usage": 90.0,
        }
        self._monitoring = False
        self._monitor_thread = None

    def start_monitoring(self, interval: int = 60):
        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, args=(interval,), daemon=True
        )
        self._monitor_thread.start()

    def stop_monitoring(self):
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join()

    def _monitor_loop(self, interval: int):
        while self._monitoring:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                self._check_thresholds(metrics)
                time.sleep(interval)
            except Exception as e:
                if self.security_logger:
                    self.security_logger.log_security_event(
                        "monitoring_error", error=str(e)
                    )

    def _collect_metrics(self) -> ResourceMetrics:
        return ResourceMetrics(
            cpu_percent=psutil.cpu_percent(),
            memory_percent=psutil.virtual_memory().percent,
            disk_usage=psutil.disk_usage("/").percent,
            network_io={
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv,
            },
            timestamp=datetime.utcnow(),
        )

    def _check_thresholds(self, metrics: ResourceMetrics):
        for metric, threshold in self.thresholds.items():
            value = getattr(metrics, metric)
            if value > threshold:
                if self.security_logger:
                    self.security_logger.log_security_event(
                        "resource_threshold_exceeded",
                        metric=metric,
                        value=value,
                        threshold=threshold,
                    )

    def get_current_usage(self) -> Dict:
        metrics = self._collect_metrics()
        return {
            "cpu_percent": metrics.cpu_percent,
            "memory_percent": metrics.memory_percent,
            "disk_usage": metrics.disk_usage,
            "network_io": metrics.network_io,
            "timestamp": metrics.timestamp.isoformat(),
        }

    def get_metrics_history(self) -> List[Dict]:
        return [
            {
                "cpu_percent": m.cpu_percent,
                "memory_percent": m.memory_percent,
                "disk_usage": m.disk_usage,
                "network_io": m.network_io,
                "timestamp": m.timestamp.isoformat(),
            }
            for m in self.metrics_history
        ]

    def update_thresholds(self, new_thresholds: Dict[str, float]):
        self.thresholds.update(new_thresholds)
