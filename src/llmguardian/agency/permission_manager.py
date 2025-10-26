# src/llmguardian/agency/permission_manager.py
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
from ..core.logger import SecurityLogger


class PermissionLevel(Enum):
    NO_ACCESS = 0
    READ = 1
    WRITE = 2
    EXECUTE = 3
    ADMIN = 4


@dataclass
class Permission:
    resource: str
    level: PermissionLevel
    conditions: Optional[Dict[str, str]] = None


class PermissionManager:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.permissions: Dict[str, Set[Permission]] = {}

    def check_permission(
        self, user_id: str, resource: str, level: PermissionLevel
    ) -> bool:
        if user_id not in self.permissions:
            return False

        for perm in self.permissions[user_id]:
            if perm.resource == resource and perm.level.value >= level.value:
                return True
        return False

    def grant_permission(self, user_id: str, permission: Permission):
        if user_id not in self.permissions:
            self.permissions[user_id] = set()
        self.permissions[user_id].add(permission)

        if self.security_logger:
            self.security_logger.log_security_event(
                "permission_granted", user_id=user_id, permission=permission.__dict__
            )

    def revoke_permission(self, user_id: str, resource: str):
        if user_id in self.permissions:
            self.permissions[user_id] = {
                p for p in self.permissions[user_id] if p.resource != resource
            }
