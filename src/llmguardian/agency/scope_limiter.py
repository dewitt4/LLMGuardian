# src/llmguardian/agency/scope_limiter.py
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
from ..core.logger import SecurityLogger

class ScopeType(Enum):
    DATA = "data"
    FUNCTION = "function"
    SYSTEM = "system"
    NETWORK = "network"

@dataclass
class Scope:
    type: ScopeType
    resources: Set[str]
    limits: Optional[Dict] = None

class ScopeLimiter:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.scopes: Dict[str, Scope] = {}

    def check_scope(self, user_id: str, scope_type: ScopeType, resource: str) -> bool:
        if user_id not in self.scopes:
            return False
            
        scope = self.scopes[user_id]
        return (scope.type == scope_type and 
                resource in scope.resources)

    def add_scope(self, user_id: str, scope: Scope):
        self.scopes[user_id] = scope