"""
core/logger.py - Logging configuration for LLMGuardian
"""

import logging
import logging.handlers
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

class SecurityLogger:
    """Custom logger for security events"""

    def __init__(self, log_path: Optional[str] = None):
        """Initialize the security logger"""
        self.log_path = log_path or str(Path.home() / ".llmguardian" / "logs")
        self.logger = self._setup_logger()
        self._setup_file_handler()
        self._setup_security_handler()

    def _setup_logger(self) -> logging.Logger:
        """Configure the main logger"""
        logger = logging.getLogger("llmguardian.security")
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger

    def _setup_file_handler(self) -> None:
        """Set up rotating file handler"""
        Path(self.log_path).mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            Path(self.log_path) / "security.log",
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(file_handler)

    def _setup_security_handler(self) -> None:
        """Set up security-specific logging handler"""
        security_handler = logging.handlers.RotatingFileHandler(
            Path(self.log_path) / "audit.log",
            maxBytes=10485760,
            backupCount=10
        )
        security_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(security_handler)

    def _format_log_entry(self, event_type: str, data: Dict[str, Any]) -> str:
        """Format log entry as JSON"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "data": data
        }
        return json.dumps(entry)

    def log_security_event(self, event_type: str, **kwargs) -> None:
        """Log a security event"""
        log_entry = self._format_log_entry(event_type, kwargs)
        self.logger.warning(log_entry)

    def log_attack(self, attack_type: str, details: Dict[str, Any]) -> None:
        """Log detected attack"""
        self.log_security_event("attack_detected", 
                              attack_type=attack_type, 
                              details=details)

    def log_validation(self, validation_type: str, result: Dict[str, Any]) -> None:
        """Log validation result"""
        self.log_security_event("validation_result", 
                              validation_type=validation_type, 
                              result=result)

class AuditLogger:
    """Logger for audit events"""

    def __init__(self, log_path: Optional[str] = None):
        """Initialize the audit logger"""
        self.log_path = log_path or str(Path.home() / ".llmguardian" / "logs" / "audit")
        Path(self.log_path).mkdir(parents=True, exist_ok=True)
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Set up audit logger"""
        logger = logging.getLogger("llmguardian.audit")
        logger.setLevel(logging.INFO)
        
        handler = logging.handlers.RotatingFileHandler(
            Path(self.log_path) / "audit.log",
            maxBytes=10485760,
            backupCount=10
        )
        formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger

    def log_access(self, user: str, resource: str, action: str) -> None:
        """Log access event"""
        self.logger.info(json.dumps({
            "event_type": "access",
            "user": user,
            "resource": resource,
            "action": action,
            "timestamp": datetime.utcnow().isoformat()
        }))

    def log_configuration_change(self, user: str, changes: Dict[str, Any]) -> None:
        """Log configuration changes"""
        self.logger.info(json.dumps({
            "event_type": "config_change",
            "user": user,
            "changes": changes,
            "timestamp": datetime.utcnow().isoformat()
        }))

def setup_logging(log_path: Optional[str] = None) -> tuple[SecurityLogger, AuditLogger]:
    """Setup both security and audit logging"""
    security_logger = SecurityLogger(log_path)
    audit_logger = AuditLogger(log_path)
    return security_logger, audit_logger