# LLMGuardian Prompt Injection Scanner

## Overview
The Prompt Injection Scanner is a core security component of LLMGuardian, designed to detect and prevent various types of prompt injection attacks against LLM applications. Based on OWASP's LLM01:2025 guidelines, it provides comprehensive protection against both direct and indirect prompt injection attempts.

## Key Features

### 1. Multi-Layer Detection
- **Direct Injection Detection**: Identifies attempts to override system prompts or security controls
- **Indirect Injection Detection**: Catches subtle attempts to manipulate model behavior
- **Delimiter Attack Detection**: Identifies attempts to exploit system prompt structures
- **Encoded Payload Detection**: Recognizes base64, hex, and other encoding techniques
- **Context-Aware Scanning**: Considers previous prompts and context for better accuracy

### 2. Risk Assessment System
- **Dynamic Risk Scoring**: 1-10 scale based on pattern severity and match confidence
- **Confidence Calculation**: Considers multiple factors including:
  - Number of matched patterns
  - Pattern severity
  - Text length and complexity
  - Historical context
- **Detailed Reporting**: Comprehensive scan results with explanations

### 3. Pattern Management
- **Extensible Pattern System**: Easy to add or modify detection patterns
- **Pattern Categories**: Organized by injection type and severity
- **Regular Expression Support**: Powerful pattern matching capabilities
- **Pattern Versioning**: Track and update pattern effectiveness

### 4. Security Controls

#### Input Validation
- Type checking for all inputs
- Size limits for prompts
- Character encoding validation
- Input sanitization

#### Pattern Security
- Severity-based pattern prioritization
- Regular pattern updates capability
- Context-based pattern matching
- Multi-stage validation process

#### Runtime Protection
- Exception handling for all operations
- Resource usage monitoring
- Timeout controls
- Logging and monitoring integration

## Implementation Details

### Core Components

1. **InjectionType Enum**
   ```python
   class InjectionType(Enum):
       DIRECT = "direct"
       INDIRECT = "indirect"
       LEAKAGE = "leakage"
       INSTRUCTION = "instruction"
       DELIMITER = "delimiter"
       ADVERSARIAL = "adversarial"
   ```
   Categorizes different types of injection attempts for targeted response

2. **InjectionPattern Class**
   ```python
   @dataclass
   class InjectionPattern:
       pattern: str
       type: InjectionType
       severity: int  # 1-10
       description: str
   ```
   Defines the structure for detection patterns

3. **ScanResult Class**
   ```python
   @dataclass
   class ScanResult:
       is_suspicious: bool
       injection_type: Optional[InjectionType]
       confidence_score: float  # 0-1
       matched_patterns: List[InjectionPattern]
       risk_score: int  # 1-10
       details: str
   ```
   Provides comprehensive scan results

### Key Methods

1. **Scan Operation**
   ```python
   def scan(self, prompt: str, context: Optional[str] = None) -> ScanResult:
   ```
   - Primary scanning method
   - Processes input prompt and optional context
   - Returns detailed scan results
   - Implements multiple detection strategies

2. **Pattern Management**
   ```python
   def add_pattern(self, pattern: InjectionPattern)
   def remove_pattern(self, pattern_str: str)
   ```
   - Dynamic pattern management
   - Runtime pattern updates
   - Pattern validation

3. **Risk Assessment**
   ```python
   def _calculate_risk_score(self, matched_patterns: List[InjectionPattern]) -> int:
   def _calculate_confidence(self, matched_patterns: List[InjectionPattern], text_length: int) -> float:
   ```
   - Sophisticated scoring algorithms
   - Multiple factor consideration
   - Weighted pattern matching

## Usage Examples

### Basic Usage
```python
scanner = PromptInjectionScanner()
result = scanner.scan("Tell me about the weather")
print(f"Suspicious: {result.is_suspicious}")
print(f"Risk Score: {result.risk_score}")
```

### With Context
```python
context = "Previous conversation about weather"
result = scanner.scan("Show me the forecast", context)
```

### Adding Custom Patterns
```python
new_pattern = InjectionPattern(
    pattern=r"custom_attack_pattern",
    type=InjectionType.DIRECT,
    severity=8,
    description="Custom attack detection"
)
scanner.add_pattern(new_pattern)
```

## Security Considerations

### Protected Against
- Direct prompt injection attempts
- System prompt leakage
- Delimiter-based attacks
- Encoded malicious content
- Context manipulation attempts
- Resource exhaustion attacks

### Best Practices
1. Regular pattern updates
2. Monitoring and logging of all scan results
3. Integration with broader security systems
4. Regular testing with new attack patterns
5. Performance optimization for large-scale use

## Integration Guidelines

### With LLM Applications
1. Implement as early as possible in the request pipeline
2. Configure appropriate risk thresholds
3. Set up proper error handling
4. Enable logging and monitoring
5. Regular pattern updates

### With Security Systems
1. Integration with SIEM systems
2. Alert configuration
3. Incident response planning
4. Audit trail maintenance
5. Compliance reporting

## Testing and Validation

The scanner includes a comprehensive test suite covering:
1. Basic functionality testing
2. Edge case handling
3. Performance testing
4. Security verification
5. Pattern effectiveness validation

## Future Enhancements

Planned improvements include:
1. Machine learning-based pattern detection
2. Advanced context analysis
3. Enhanced performance optimization
4. Additional pattern categories
5. Improved reporting capabilities

## Maintenance and Updates

Regular maintenance includes:
1. Pattern database updates
2. Performance optimization
3. Security enhancement
4. Bug fixes and improvements
5. Documentation updates

This component serves as a critical first line of defense against prompt injection attacks in LLM applications, providing robust, extensible, and maintainable protection.
