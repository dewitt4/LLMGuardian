# src/llmguardian/api/models.py
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


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
