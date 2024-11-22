"""
core/validation.py - Input/Output validation for LLMGuardian
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import json
from .logger import SecurityLogger

@dataclass
class ValidationResult:
    """Validation result container"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    sanitized_content: Optional[str] = None

class ContentValidator:
    """Content validation and sanitization"""
    
    def __init__(self, security_logger: SecurityLogger):
        self.security_logger = security_logger
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for validation"""
        return {
            'sql_injection': re.compile(
                r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|JOIN)\b',
                re.IGNORECASE
            ),
            'command_injection': re.compile(
                r'\b(system|exec|eval|os\.|subprocess\.|shell)\b',
                re.IGNORECASE
            ),
            'path_traversal': re.compile(r'\.\./', re.IGNORECASE),
            'xss': re.compile(r'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL),
            'sensitive_data': re.compile(
                r'\b(\d{16}|\d{3}-\d{2}-\d{4}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b'
            )
        }

    def validate_input(self, content: str) -> ValidationResult:
        """Validate input content"""
        errors = []
        warnings = []
        
        # Check for common injection patterns
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(content):
                errors.append(f"Detected potential {pattern_name}")
        
        # Check content length
        if len(content) > 10000:  # Configurable limit
            warnings.append("Content exceeds recommended length")
        
        # Log validation result if there are issues
        if errors or warnings:
            self.security_logger.log_validation(
                "input_validation",
                {
                    "errors": errors,
                    "warnings": warnings,
                    "content_length": len(content)
                }
            )
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_content=self.sanitize_content(content) if errors else content
        )

    def validate_output(self, content: str) -> ValidationResult:
        """Validate output content"""
        errors = []
        warnings = []
        
        # Check for sensitive data leakage
        if self.patterns['sensitive_data'].search(content):
            errors.append("Detected potential sensitive data in output")
        
        # Check for malicious content
        if self.patterns['xss'].search(content):
            errors.append("Detected potential XSS in output")
        
        # Log validation issues
        if errors or warnings:
            self.security_logger.log_validation(
                "output_validation",
                {
                    "errors": errors,
                    "warnings": warnings
                }
            )
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_content=self.sanitize_content(content) if errors else content
        )

    def sanitize_content(self, content: str) -> str:
        """Sanitize content by removing potentially dangerous elements"""
        sanitized = content
        
        # Remove potential script tags
        sanitized = self.patterns['xss'].sub('', sanitized)
        
        # Remove sensitive data patterns
        sanitized = self.patterns['sensitive_data'].sub('[REDACTED]', sanitized)
        
        # Replace SQL keywords
        sanitized = self.patterns['sql_injection'].sub('[FILTERED]', sanitized)
        
        # Replace command injection patterns
        sanitized = self.patterns['command_injection'].sub('[FILTERED]', sanitized)
        
        return sanitized

class JSONValidator:
    """JSON validation and sanitization"""
    
    def validate_json(self, content: str) -> Tuple[bool, Optional[Dict], List[str]]:
        """Validate JSON content"""
        errors = []
        parsed_json = None
        
        try:
            parsed_json = json.loads(content)
            
            # Validate structure if needed
            if not isinstance(parsed_json, dict):
                errors.append("JSON root must be an object")
            
            # Add additional JSON validation rules here
            
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON format: {str(e)}")
        
        return len(errors) == 0, parsed_json, errors

class SchemaValidator:
    """Schema validation for structured data"""
    
    def validate_schema(self, data: Dict[str, Any], 
                       schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate data against a schema"""
        errors = []
        
        for field, requirements in schema.items():
            # Check required fields
            if requirements.get('required', False) and field not in data:
                errors.append(f"Missing required field: {field}")
                continue
            
            if field in data:
                value = data[field]
                
                # Type checking
                expected_type = requirements.get('type')
                if expected_type and not isinstance(value, expected_type):
                    errors.append(
                        f"Invalid type for {field}: expected {expected_type.__name__}, "
                        f"got {type(value).__name__}"
                    )
                
                # Range validation
                if 'min' in requirements and value < requirements['min']:
                    errors.append(
                        f"Value for {field} below minimum: {requirements['min']}"
                    )
                if 'max' in requirements and value > requirements['max']:
                    errors.append(
                        f"Value for {field} exceeds maximum: {requirements['max']}"
                    )
                
                # Pattern validation
                if 'pattern' in requirements:
                    if not re.match(requirements['pattern'], str(value)):
                        errors.append(
                            f"Value for {field} does not match required pattern"
                        )
        
        return len(errors) == 0, errors

def create_validators(security_logger: SecurityLogger) -> Tuple[
    ContentValidator, JSONValidator, SchemaValidator
]:
    """Create instances of all validators"""
    return (
        ContentValidator(security_logger),
        JSONValidator(),
        SchemaValidator()
    )

if __name__ == "__main__":
    # Example usage
    from .logger import setup_logging
    
    security_logger, _ = setup_logging()
    content_validator, json_validator, schema_validator = create_validators(
        security_logger
    )
    
    # Test content validation
    test_content = "SELECT * FROM users; <script>alert('xss')</script>"
    result = content_validator.validate_input(test_content)
    print(f"Validation result: {result}")
    
    # Test JSON validation
    test_json = '{"name": "test", "value": 123}'
    is_valid, parsed, errors = json_validator.validate_json(test_json)
    print(f"JSON validation: {is_valid}, Errors: {errors}")
    
    # Test schema validation
    schema = {
        "name": {"type": str, "required": True},
        "age": {"type": int, "min": 0, "max": 150}
    }
    data = {"name": "John", "age": 30}
    is_valid, errors = schema_validator.validate_schema(data, schema)
    print(f"Schema validation: {is_valid}, Errors: {errors}")