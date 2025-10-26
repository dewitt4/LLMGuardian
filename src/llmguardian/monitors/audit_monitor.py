"""
monitors/audit_monitor.py - Audit trail and compliance monitoring
"""

import json
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..core.exceptions import MonitoringError
from ..core.logger import SecurityLogger


class AuditEventType(Enum):
    # Authentication events
    LOGIN = "login"
    LOGOUT = "logout"
    AUTH_FAILURE = "auth_failure"

    # Access events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PERMISSION_CHANGE = "permission_change"

    # Data events
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"

    # System events
    CONFIG_CHANGE = "config_change"
    SYSTEM_ERROR = "system_error"
    SECURITY_ALERT = "security_alert"

    # Model events
    MODEL_ACCESS = "model_access"
    MODEL_UPDATE = "model_update"
    PROMPT_INJECTION = "prompt_injection"

    # Compliance events
    COMPLIANCE_CHECK = "compliance_check"
    POLICY_VIOLATION = "policy_violation"
    DATA_BREACH = "data_breach"


@dataclass
class AuditEvent:
    """Representation of an audit event"""

    event_type: AuditEventType
    timestamp: datetime
    user_id: str
    action: str
    resource: str
    status: str
    details: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None


@dataclass
class CompliancePolicy:
    """Definition of a compliance policy"""

    name: str
    description: str
    required_events: Set[AuditEventType]
    retention_period: timedelta
    alert_threshold: int


class AuditMonitor:
    def __init__(
        self,
        security_logger: Optional[SecurityLogger] = None,
        audit_dir: Optional[str] = None,
    ):
        self.security_logger = security_logger
        self.audit_dir = (
            Path(audit_dir) if audit_dir else Path.home() / ".llmguardian" / "audit"
        )
        self.events: List[AuditEvent] = []
        self.policies = self._initialize_policies()
        self.compliance_status = defaultdict(list)
        self._lock = threading.Lock()
        self._setup_audit_directory()

    def _setup_audit_directory(self):
        """Set up audit directory and ensure it exists"""
        try:
            self.audit_dir.mkdir(parents=True, exist_ok=True)
            (self.audit_dir / "events").mkdir(exist_ok=True)
            (self.audit_dir / "reports").mkdir(exist_ok=True)
        except Exception as e:
            raise MonitoringError(f"Failed to setup audit directory: {str(e)}")

    def _initialize_policies(self) -> Dict[str, CompliancePolicy]:
        """Initialize default compliance policies"""
        return {
            "data_access_tracking": CompliancePolicy(
                name="Data Access Tracking",
                description="Track all data access events",
                required_events={
                    AuditEventType.DATA_ACCESS,
                    AuditEventType.DATA_MODIFICATION,
                    AuditEventType.DATA_DELETION,
                },
                retention_period=timedelta(days=90),
                alert_threshold=5,
            ),
            "authentication_monitoring": CompliancePolicy(
                name="Authentication Monitoring",
                description="Monitor authentication events",
                required_events={
                    AuditEventType.LOGIN,
                    AuditEventType.LOGOUT,
                    AuditEventType.AUTH_FAILURE,
                },
                retention_period=timedelta(days=30),
                alert_threshold=3,
            ),
            "security_compliance": CompliancePolicy(
                name="Security Compliance",
                description="Monitor security-related events",
                required_events={
                    AuditEventType.SECURITY_ALERT,
                    AuditEventType.PROMPT_INJECTION,
                    AuditEventType.DATA_BREACH,
                },
                retention_period=timedelta(days=365),
                alert_threshold=1,
            ),
        }

    def log_event(self, event: AuditEvent):
        """Log an audit event"""
        try:
            with self._lock:
                self.events.append(event)
                self._write_event_to_file(event)
                self._check_compliance(event)

                if self.security_logger:
                    self.security_logger.log_security_event(
                        "audit_event_logged",
                        event_type=event.event_type.value,
                        user_id=event.user_id,
                        action=event.action,
                    )

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "audit_logging_error", error=str(e)
                )
            raise MonitoringError(f"Failed to log audit event: {str(e)}")

    def _write_event_to_file(self, event: AuditEvent):
        """Write event to audit file"""
        try:
            timestamp = event.timestamp.strftime("%Y%m%d")
            file_path = self.audit_dir / "events" / f"audit_{timestamp}.jsonl"

            event_data = {
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "user_id": event.user_id,
                "action": event.action,
                "resource": event.resource,
                "status": event.status,
                "details": event.details,
                "metadata": event.metadata,
                "session_id": event.session_id,
                "ip_address": event.ip_address,
            }

            with open(file_path, "a") as f:
                f.write(json.dumps(event_data) + "\n")

        except Exception as e:
            raise MonitoringError(f"Failed to write audit event: {str(e)}")

    def _check_compliance(self, event: AuditEvent):
        """Check event against compliance policies"""
        for policy_name, policy in self.policies.items():
            if event.event_type in policy.required_events:
                self.compliance_status[policy_name].append(event)

                # Check for violations
                recent_events = [
                    e
                    for e in self.compliance_status[policy_name]
                    if datetime.utcnow() - e.timestamp < timedelta(hours=24)
                ]

                if len(recent_events) >= policy.alert_threshold:
                    if self.security_logger:
                        self.security_logger.log_security_event(
                            "compliance_threshold_exceeded",
                            policy=policy_name,
                            events_count=len(recent_events),
                        )

    def get_events(
        self,
        event_type: Optional[AuditEventType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get filtered audit events"""
        with self._lock:
            events = self.events

            if event_type:
                events = [e for e in events if e.event_type == event_type]
            if start_time:
                events = [e for e in events if e.timestamp >= start_time]
            if end_time:
                events = [e for e in events if e.timestamp <= end_time]
            if user_id:
                events = [e for e in events if e.user_id == user_id]

            return [
                {
                    "event_type": e.event_type.value,
                    "timestamp": e.timestamp.isoformat(),
                    "user_id": e.user_id,
                    "action": e.action,
                    "resource": e.resource,
                    "status": e.status,
                    "details": e.details,
                }
                for e in events
            ]

    def generate_compliance_report(self, policy_name: str) -> Dict[str, Any]:
        """Generate compliance report for a specific policy"""
        if policy_name not in self.policies:
            raise MonitoringError(f"Unknown policy: {policy_name}")

        policy = self.policies[policy_name]
        events = self.compliance_status[policy_name]

        report = {
            "policy_name": policy.name,
            "description": policy.description,
            "generated_at": datetime.utcnow().isoformat(),
            "total_events": len(events),
            "events_by_type": defaultdict(int),
            "violations": [],
        }

        for event in events:
            report["events_by_type"][event.event_type.value] += 1

        # Check for missing required events
        for required_event in policy.required_events:
            if report["events_by_type"][required_event.value] == 0:
                report["violations"].append(
                    f"Missing required event type: {required_event.value}"
                )

        report_path = (
            self.audit_dir
            / "reports"
            / f"compliance_{policy_name}_{datetime.utcnow().strftime('%Y%m%d')}.json"
        )
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        return report

    def add_policy(self, name: str, policy: CompliancePolicy):
        """Add a new compliance policy"""
        with self._lock:
            self.policies[name] = policy

    def remove_policy(self, name: str):
        """Remove a compliance policy"""
        with self._lock:
            self.policies.pop(name, None)
            self.compliance_status.pop(name, None)

    def clear_old_events(self):
        """Clear events older than retention period"""
        with self._lock:
            for policy in self.policies.values():
                cutoff = datetime.utcnow() - policy.retention_period
                self.events = [e for e in self.events if e.timestamp >= cutoff]

                if policy.name in self.compliance_status:
                    self.compliance_status[policy.name] = [
                        e
                        for e in self.compliance_status[policy.name]
                        if e.timestamp >= cutoff
                    ]

    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get audit statistics"""
        stats = {
            "total_events": len(self.events),
            "events_by_type": defaultdict(int),
            "events_by_user": defaultdict(int),
            "policy_status": {},
            "recent_violations": [],
        }

        for event in self.events:
            stats["events_by_type"][event.event_type.value] += 1
            stats["events_by_user"][event.user_id] += 1

        for policy_name, policy in self.policies.items():
            events = self.compliance_status[policy_name]
            recent_events = [
                e
                for e in events
                if datetime.utcnow() - e.timestamp < timedelta(hours=24)
            ]

            stats["policy_status"][policy_name] = {
                "total_events": len(events),
                "recent_events": len(recent_events),
                "violation_threshold": policy.alert_threshold,
                "status": (
                    "violation"
                    if len(recent_events) >= policy.alert_threshold
                    else "compliant"
                ),
            }

        return stats
