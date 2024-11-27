# LLMGuardian Agency Package

Controls and limits LLM model agency through permissions, actions, scopes and secure execution.

## Components

### PermissionManager
Manages access permissions for LLM operations.

```python
from llmguardian.agency import PermissionManager

manager = PermissionManager()
manager.grant_permission(
    "user_123",
    Permission(resource="model_x", level=PermissionLevel.READ)
)
```

### ActionValidator 
Validates LLM actions against security policies.

```python
from llmguardian.agency import ActionValidator, Action

validator = ActionValidator()
action = Action(
    type=ActionType.READ,
    resource="customer_data",
    parameters={"id": "123"}
)
is_valid = validator.validate_action(action, context={})
```

### ScopeLimiter
Enforces operational boundaries for LLMs.

```python
from llmguardian.agency import ScopeLimiter, Scope, ScopeType

limiter = ScopeLimiter()
limiter.add_scope(
    "user_123",
    Scope(type=ScopeType.DATA, resources={"public_data"})
)
```

### SafeExecutor
Provides secure execution of validated LLM actions.

```python
from llmguardian.agency import SafeExecutor

executor = SafeExecutor()
result = await executor.execute(
    action=action,
    user_id="user_123", 
    context={}
)
```

## Security Features

- Fine-grained permission control
- Action validation and filtering
- Resource scope limitations  
- Secure execution environment
- Comprehensive audit logging

## Configuration

```python
config = {
    "permissions": {
        "default_level": "READ",
        "require_explicit": True
    },
    "actions": {
        "allowed_types": ["READ", "WRITE"],
        "require_validation": True
    },
    "scopes": {
        "default_type": "DATA",
        "max_resources": 10
    }
}
```

## Installation

```bash
pip install llmguardian[agency]
```