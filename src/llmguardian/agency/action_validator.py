# src/llmguardian/agency/action_validator.py
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from ..core.logger import SecurityLogger


class ActionType(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    MODIFY = "modify"


@dataclass
class Action:
    type: ActionType
    resource: str
    parameters: Optional[Dict] = None


class ActionValidator:
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.allowed_actions: Dict[str, List[ActionType]] = {}

    def validate_action(self, action: Action, context: Dict) -> bool:
        if action.resource not in self.allowed_actions:
            return False

        if action.type not in self.allowed_actions[action.resource]:
            return False

        # Validate parameters and context
        return self._validate_parameters(action, context)

    def _validate_parameters(self, action: Action, context: Dict) -> bool:
        # Implementation of parameter validation
        return True
