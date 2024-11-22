"""
core/monitoring.py - Monitoring system for LLMGuardian
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import threading
import time
import json
from collections import deque
import statistics
from .logger import SecurityLogger

@dataclass
class MonitoringMetric:
    """Representation of a monitoring metric"""
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str]

@dataclass
class Alert:
    """Alert representation"""
    severity: str
    message: str
    metric: str
    threshold: float
    current_value: float
    timestamp: datetime

class MetricsCollector:
    """Collect and store monitoring metrics"""
    
    def __init__(self, max_history: int = 1000):
        self.metrics: Dict[str, deque] = {}
        self.max_history = max_history
        self._lock = threading.Lock()

    def record_metric(self, name: str, value: float, 
                     labels: Optional[Dict[str, str]] = None) -> None:
        """Record a new metric value"""
        with self._lock:
            if name not in self.metrics:
                self.metrics[name] = deque(maxlen=self.max_history)
            
            metric = MonitoringMetric(
                name=name,
                value=value,
                timestamp=datetime.utcnow(),
                labels=labels or {}
            )
            self.metrics[name].append(metric)

    def get_metrics(self, name: str, 
                   time_window: Optional[timedelta] = None) -> List[MonitoringMetric]:
        """Get metrics for a specific name within time window"""
        with self._lock:
            if name not in self.metrics:
                return []
            
            if not time_window:
                return list(self.metrics[name])
            
            cutoff = datetime.utcnow() - time_window
            return [m for m in self.metrics[name] if m.timestamp >= cutoff]

    def calculate_statistics(self, name: str, 
                           time_window: Optional[timedelta] = None) -> Dict[str, float]:
        """Calculate statistics for a metric"""
        metrics = self.get_metrics(name, time_window)
        if not metrics:
            return {}
        
        values = [m.value for m in metrics]
        return {
            "min": min(values),
            "max": max(values),
            "avg": statistics.mean(values),
            "median": statistics.median(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0
        }

class AlertManager:
    """Manage monitoring alerts"""
    
    def __init__(self, security_logger: SecurityLogger):
        self.security_logger = security_logger
        self.alerts: List[Alert] = []
        self.alert_handlers: Dict[str, List[callable]] = {}
        self._lock = threading.Lock()

    def add_alert_handler(self, severity: str, handler: callable) -> None:
        """Add an alert handler for a specific severity"""
        with self._lock:
            if severity not in self.alert_handlers:
                self.alert_handlers[severity] = []
            self.alert_handlers[severity].append(handler)

    def trigger_alert(self, alert: Alert) -> None:
        """Trigger an alert"""
        with self._lock:
            self.alerts.append(alert)
            
            # Log alert
            self.security_logger.log_security_event(
                "monitoring_alert",
                severity=alert.severity,
                message=alert.message,
                metric=alert.metric,
                threshold=alert.threshold,
                current_value=alert.current_value
            )
            
            # Call handlers
            handlers = self.alert_handlers.get(alert.severity, [])
            for handler in handlers:
                try:
                    handler(alert)
                except Exception as e:
                    self.security_logger.log_security_event(
                        "alert_handler_error",
                        error=str(e),
                        handler=handler.__name__
                    )

    def get_recent_alerts(self, time_window: timedelta) -> List[Alert]:
        """Get recent alerts within time window"""
        cutoff = datetime.utcnow() - time_window
        return [a for a in self.alerts if a.timestamp >= cutoff]

class MonitoringRule:
    """Rule for monitoring metrics"""
    
    def __init__(self, metric_name: str, threshold: float, 
                 comparison: str, severity: str, message: str):
        self.metric_name = metric_name
        self.threshold = threshold
        self.comparison = comparison
        self.severity = severity
        self.message = message

    def evaluate(self, value: float) -> Optional[Alert]:
        """Evaluate the rule against a value"""
        triggered = False
        
        if self.comparison == "gt" and value > self.threshold:
            triggered = True
        elif self.comparison == "lt" and value < self.threshold:
            triggered = True
        elif self.comparison == "eq" and value == self.threshold:
            triggered = True
        
        if triggered:
            return Alert(
                severity=self.severity,
                message=self.message,
                metric=self.metric_name,
                threshold=self.threshold,
                current_value=value,
                timestamp=datetime.utcnow()
            )
        return None

class MonitoringService:
    """Main monitoring service"""
    
    def __init__(self, security_logger: SecurityLogger):
        self.collector = MetricsCollector()
        self.alert_manager = AlertManager(security_logger)
        self.rules: List[MonitoringRule] = []
        self.security_logger = security_logger
        self._running = False
        self._monitor_thread = None

    def add_rule(self, rule: MonitoringRule) -> None:
        """Add a monitoring rule"""
        self.rules.append(rule)

    def start_monitoring(self, interval: int = 60) -> None:
        """Start the monitoring service"""
        if self._running:
            return
        
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,)
        )
        self._monitor_thread.daemon = True
        self._monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop the monitoring service"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join()

    def _monitoring_loop(self, interval: int) -> None:
        """Main monitoring loop"""
        while self._running:
            try:
                self._check_rules()
                time.sleep(interval)
            except Exception as e:
                self.security_logger.log_security_event(
                    "monitoring_error",
                    error=str(e)
                )

    def _check_rules(self) -> None:
        """Check all monitoring rules"""
        for rule in self.rules:
            metrics = self.collector.get_metrics(
                rule.metric_name,
                timedelta(minutes=5)  # Look at last 5 minutes
            )
            
            if not metrics:
                continue
            
            # Use the most recent metric
            latest_metric = metrics[-1]
            alert = rule.evaluate(latest_metric.value)
            
            if alert:
                self.alert_manager.trigger_alert(alert)

    def record_metric(self, name: str, value: float, 
                     labels: Optional[Dict[str, str]] = None) -> None:
        """Record a new metric"""
        self.collector.record_metric(name, value, labels)

def create_monitoring_service(security_logger: SecurityLogger) -> MonitoringService:
    """Create and configure a monitoring service"""
    service = MonitoringService(security_logger)
    
    # Add default rules
    rules = [
        MonitoringRule(
            metric_name="request_rate",
            threshold=100,
            comparison="gt",
            severity="warning",
            message="High request rate detected"
        ),
        MonitoringRule(
            metric_name="error_rate",
            threshold=0.1,
            comparison="gt",
            severity="error",
            message="High error rate detected"
        ),
        MonitoringRule(
            metric_name="response_time",
            threshold=1.0,
            comparison="gt",
            severity="warning",
            message="Slow response time detected"
        )
    ]
    
    for rule in rules:
        service.add_rule(rule)
    
    return service

if __name__ == "__main__":
    # Example usage
    from .logger import setup_logging
    
    security_logger, _ = setup_logging()
    monitoring = create_monitoring_service(security_logger)
    
    # Add custom alert handler
    def alert_handler(alert: Alert):
        print(f"Alert: {alert.message} (Severity: {alert.severity})")
    
    monitoring.alert_manager.add_alert_handler("warning", alert_handler)
    monitoring.alert_manager.add_alert_handler("error", alert_handler)
    
    # Start monitoring
    monitoring.start_monitoring(interval=10)
    
    # Simulate some metrics
    try:
        while True:
            monitoring.record_metric("request_rate", 150)  # Should trigger alert
            time.sleep(5)
    except KeyboardInterrupt:
        monitoring.stop_monitoring()