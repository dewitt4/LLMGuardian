# LLMGuardian Monitors Package

The monitors package provides comprehensive monitoring, detection, and auditing capabilities for LLM applications. It addresses several key security concerns outlined in the OWASP Top 10 for LLM applications, particularly focusing on unbounded consumption, behavior monitoring, and audit trails.

## Components

### 1. Usage Monitor (`usage_monitor.py`)
Monitors system resource usage and enforces limits to prevent unbounded consumption.

```python
from llmguardian.monitors import UsageMonitor

# Initialize monitor
usage_monitor = UsageMonitor()

# Start monitoring
usage_monitor.start_monitoring(interval=60)  # 60-second intervals

# Get current usage
usage = usage_monitor.get_current_usage()
print(f"CPU Usage: {usage['cpu_percent']}%")
print(f"Memory Usage: {usage['memory_percent']}%")
```

Key Features:
- Real-time resource monitoring
- Configurable thresholds
- Automatic alerts
- Usage history tracking

### 2. Behavior Monitor (`behavior_monitor.py`)
Tracks and analyzes LLM behavior patterns to detect anomalies and potential security issues.

```python
from llmguardian.monitors import BehaviorMonitor

# Initialize monitor
behavior_monitor = BehaviorMonitor()

# Monitor behavior
result = behavior_monitor.monitor_behavior(
    input_text="user prompt",
    output_text="model response",
    context={"user_id": "123", "session_id": "abc"}
)

# Get suspicious events
events = behavior_monitor.get_events(min_confidence=0.8)
```

Key Features:
- Pattern-based detection
- Confidence scoring
- Historical analysis
- Context awareness

### 3. Threat Detector (`threat_detector.py`)
Provides real-time threat detection and response capabilities.

```python
from llmguardian.monitors import ThreatDetector
from llmguardian.monitors.threat_detector import ThreatLevel, ThreatCategory

# Initialize detector
detector = ThreatDetector()

# Check for threats
threats = detector.detect_threats({
    "input": "user input",
    "source": "api_endpoint",
    "context": {"session_id": "xyz"}
})

# Get active threats
active_threats = detector.get_active_threats(
    min_level=ThreatLevel.HIGH,
    category=ThreatCategory.PROMPT_INJECTION
)
```

Key Features:
- Multiple threat categories
- Severity levels
- Real-time detection
- Threat analytics

### 4. Performance Monitor (`performance_monitor.py`)
Tracks performance metrics and ensures system reliability.

```python
from llmguardian.monitors import PerformanceMonitor

# Initialize monitor
perf_monitor = PerformanceMonitor()

# Record metrics
perf_monitor.record_metric(
    name="response_time",
    value=0.45,
    context={"endpoint": "/api/generate"}
)

# Get statistics
stats = perf_monitor.get_statistics("response_time")
print(f"Average response time: {stats['average']:.2f}s")
```

Key Features:
- Response time tracking
- Resource utilization monitoring
- Performance alerts
- Statistical analysis

### 5. Audit Monitor (`audit_monitor.py`)
Provides comprehensive audit logging and compliance tracking.

```python
from llmguardian.monitors import AuditMonitor
from llmguardian.monitors.audit_monitor import AuditEvent, AuditEventType

# Initialize monitor
audit_monitor = AuditMonitor()

# Log audit event
event = AuditEvent(
    event_type=AuditEventType.MODEL_ACCESS,
    timestamp=datetime.utcnow(),
    user_id="user123",
    action="generate_text",
    resource="gpt-4",
    status="success",
    details={"prompt_length": 128}
)
audit_monitor.log_event(event)

# Generate compliance report
report = audit_monitor.generate_compliance_report("data_access_tracking")
```

Key Features:
- Comprehensive event logging
- Compliance monitoring
- Audit trail maintenance
- Report generation

## Installation

```bash
pip install llmguardian
```

For development:
```bash
pip install -r requirements/dev.txt
```

## Configuration

Each monitor can be configured through its constructor or by updating settings after initialization:

```python
# Configure through constructor
monitor = UsageMonitor(
    security_logger=custom_logger,
    thresholds={"cpu_percent": 80.0}
)

# Update configuration
monitor.update_thresholds({"memory_percent": 85.0})
```

## Best Practices

1. **Resource Monitoring**
   - Set appropriate thresholds for resource usage
   - Implement graceful degradation
   - Monitor trends over time

2. **Threat Detection**
   - Configure alert thresholds based on your risk tolerance
   - Regularly update threat patterns
   - Implement response procedures

3. **Audit Logging**
   - Define retention periods
   - Implement secure storage
   - Regular compliance checks

4. **Performance Tracking**
   - Set baseline metrics
   - Monitor degradation patterns
   - Configure appropriate alerts

## Integration

### With LLM Applications

```python
from llmguardian.monitors import (
    UsageMonitor,
    BehaviorMonitor,
    ThreatDetector,
    PerformanceMonitor,
    AuditMonitor
)

class LLMApplication:
    def __init__(self):
        self.usage_monitor = UsageMonitor()
        self.behavior_monitor = BehaviorMonitor()
        self.threat_detector = ThreatDetector()
        self.performance_monitor = PerformanceMonitor()
        self.audit_monitor = AuditMonitor()
        
        # Start monitoring
        self.usage_monitor.start_monitoring()

    async def generate_response(self, prompt: str):
        # Record performance
        start_time = time.time()
        
        try:
            # Monitor behavior
            self.behavior_monitor.monitor_behavior(
                input_text=prompt,
                output_text=None,
                context={"request_id": "123"}
            )
            
            # Check for threats
            threats = self.threat_detector.detect_threats({
                "input": prompt,
                "source": "api"
            })
            
            if threats:
                raise SecurityError("Potential security threat detected")
            
            # Generate response
            response = await self.llm.generate(prompt)
            
            # Record metrics
            self.performance_monitor.record_metric(
                "response_time",
                time.time() - start_time
            )
            
            return response
            
        finally:
            # Log audit event
            self.audit_monitor.log_event(
                AuditEvent(
                    event_type=AuditEventType.MODEL_ACCESS,
                    timestamp=datetime.utcnow(),
                    user_id="user123",
                    action="generate_text",
                    resource="model",
                    status="success",
                    details={"prompt_length": len(prompt)}
                )
            )
```

