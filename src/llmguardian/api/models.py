# src/llmguardian/api/models.py
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class SecurityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityRequest(BaseModel):
    content: str
    context: Optional[Dict[str, Any]]
    security_level: SecurityLevel = SecurityLevel.MEDIUM


class SecurityResponse(BaseModel):
    is_safe: bool
    risk_level: SecurityLevel
    violations: List[Dict[str, Any]]
    recommendations: List[str]
    metadata: Dict[str, Any]
    timestamp: datetime


class PrivacyRequest(BaseModel):
    content: str
    privacy_level: str
    context: Optional[Dict[str, Any]]


class VectorRequest(BaseModel):
    vectors: List[List[float]]
    metadata: Optional[Dict[str, Any]]
