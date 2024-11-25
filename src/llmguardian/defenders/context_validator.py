"""
defenders/context_validator.py - Context validation for LLM interactions
"""

from typing import Dict, Optional, List, Any
from dataclasses import dataclass
from datetime import datetime
import hashlib
from ..core.logger import SecurityLogger
from ..core.exceptions import ValidationError

@dataclass
class ContextRule:
   max_age: int  # seconds
   required_fields: List[str] 
   forbidden_fields: List[str]
   max_depth: int
   checksum_fields: List[str]

@dataclass
class ValidationResult:
   is_valid: bool
   errors: List[str]
   modified_context: Dict[str, Any]
   metadata: Dict[str, Any]

class ContextValidator:
   def __init__(self, security_logger: Optional[SecurityLogger] = None):
       self.security_logger = security_logger
       self.rule = ContextRule(
           max_age=3600,
           required_fields=["user_id", "session_id", "timestamp"],
           forbidden_fields=["password", "secret", "token"],
           max_depth=5,
           checksum_fields=["user_id", "session_id"]
       )

   def validate_context(self, context: Dict[str, Any], previous_context: Optional[Dict[str, Any]] = None) -> ValidationResult:
       try:
           errors = []
           modified = context.copy()

           # Check required fields
           missing = [f for f in self.rule.required_fields if f not in context]
           if missing:
               errors.append(f"Missing required fields: {missing}")

           # Check forbidden fields
           forbidden = [f for f in self.rule.forbidden_fields if f in context]
           if forbidden:
               errors.append(f"Forbidden fields present: {forbidden}")
               for field in forbidden:
                   modified.pop(field, None)

           # Validate timestamp
           if "timestamp" in context:
               age = (datetime.utcnow() - datetime.fromisoformat(str(context["timestamp"]))).seconds
               if age > self.rule.max_age:
                   errors.append(f"Context too old: {age} seconds")

           # Check context depth
           if not self._check_depth(context, 0):
               errors.append(f"Context exceeds max depth of {self.rule.max_depth}")

           # Verify checksums if previous context exists
           if previous_context:
               if not self._verify_checksums(context, previous_context):
                   errors.append("Context checksum mismatch")

           # Build metadata
           metadata = {
               "validation_time": datetime.utcnow().isoformat(),
               "original_size": len(str(context)),
               "modified_size": len(str(modified)),
               "changes": len(errors)
           }

           result = ValidationResult(
               is_valid=len(errors) == 0,
               errors=errors,
               modified_context=modified,
               metadata=metadata
           )

           if errors and self.security_logger:
               self.security_logger.log_security_event(
                   "context_validation_failure",
                   errors=errors,
                   context_id=context.get("context_id")
               )

           return result

       except Exception as e:
           if self.security_logger:
               self.security_logger.log_security_event(
                   "context_validation_error",
                   error=str(e)
               )
           raise ValidationError(f"Context validation failed: {str(e)}")

   def _check_depth(self, obj: Any, depth: int) -> bool:
       if depth > self.rule.max_depth:
           return False
       if isinstance(obj, dict):
           return all(self._check_depth(v, depth + 1) for v in obj.values())
       if isinstance(obj, list):
           return all(self._check_depth(v, depth + 1) for v in obj)
       return True

   def _verify_checksums(self, current: Dict[str, Any], previous: Dict[str, Any]) -> bool:
       for field in self.rule.checksum_fields:
           if field in current and field in previous:
               current_hash = hashlib.sha256(str(current[field]).encode()).hexdigest()
               previous_hash = hashlib.sha256(str(previous[field]).encode()).hexdigest()
               if current_hash != previous_hash:
                   return False
       return True

   def update_rule(self, updates: Dict[str, Any]) -> None:
       for key, value in updates.items():
           if hasattr(self.rule, key):
               setattr(self.rule, key, value)