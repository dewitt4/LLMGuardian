"""
core/events.py - Event handling system for LLMGuardian
"""

from typing import Dict, List, Callable, Any, Optional
from datetime import datetime
import threading
from dataclasses import dataclass
from enum import Enum
from .logger import SecurityLogger
from .exceptions import LLMGuardianError

class EventType(Enum):
    """Types of events that can be emitted"""
    SECURITY_ALERT = "security_alert"
    PROMPT_INJECTION = "prompt_injection"
    VALIDATION_FAILURE = "validation_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    AUTHENTICATION_FAILURE = "authentication_failure"
    CONFIGURATION_CHANGE = "configuration_change"
    MODEL_ERROR = "model_error"
    SYSTEM_ERROR = "system_error"
    MONITORING_ALERT = "monitoring_alert"
    API_ERROR = "api_error"

@dataclass
class Event:
    """Event data structure"""
    type: EventType
    timestamp: datetime
    data: Dict[str, Any]
    source: str
    severity: str
    correlation_id: Optional[str] = None

class EventEmitter:
    """Event emitter implementation"""
    
    def __init__(self, security_logger: SecurityLogger):
        self.listeners: Dict[EventType, List[Callable]] = {}
        self.security_logger = security_logger
        self._lock = threading.Lock()

    def on(self, event_type: EventType, callback: Callable) -> None:
        """Register an event listener"""
        with self._lock:
            if event_type not in self.listeners:
                self.listeners[event_type] = []
            self.listeners[event_type].append(callback)

    def off(self, event_type: EventType, callback: Callable) -> None:
        """Remove an event listener"""
        with self._lock:
            if event_type in self.listeners:
                self.listeners[event_type].remove(callback)

    def emit(self, event: Event) -> None:
        """Emit an event to all registered listeners"""
        with self._lock:
            if event.type in self.listeners:
                for callback in self.listeners[event.type]:
                    try:
                        callback(event)
                    except Exception as e:
                        self.security_logger.log_security_event(
                            "event_handler_error",
                            error=str(e),
                            event_type=event.type.value,
                            handler=callback.__name__
                        )

class EventProcessor:
    """Process and handle events"""
    
    def __init__(self, security_logger: SecurityLogger):
        self.security_logger = security_logger
        self.handlers: Dict[EventType, List[Callable]] = {}
        self._lock = threading.Lock()

    def register_handler(self, event_type: EventType, handler: Callable) -> None:
        """Register a handler for an event type"""
        with self._lock:
            if event_type not in self.handlers:
                self.handlers[event_type] = []
            self.handlers[event_type].append(handler)

    def process_event(self, event: Event) -> None:
        """Process an event with registered handlers"""
        with self._lock:
            if event.type in self.handlers:
                for handler in self.handlers[event.type]:
                    try:
                        handler(event)
                    except Exception as e:
                        self.security_logger.log_security_event(
                            "event_processing_error",
                            error=str(e),
                            event_type=event.type.value,
                            handler=handler.__name__
                        )

class EventStore:
    """Store and query events"""
    
    def __init__(self, max_events: int = 1000):
        self.events: List[Event] = []
        self.max_events = max_events
        self._lock = threading.Lock()

    def add_event(self, event: Event) -> None:
        """Add an event to the store"""
        with self._lock:
            self.events.append(event)
            if len(self.events) > self.max_events:
                self.events.pop(0)

    def get_events(self, event_type: Optional[EventType] = None, 
                  since: Optional[datetime] = None) -> List[Event]:
        """Get events with optional filtering"""
        with self._lock:
            filtered_events = self.events
            
            if event_type:
                filtered_events = [e for e in filtered_events 
                                 if e.type == event_type]
            
            if since:
                filtered_events = [e for e in filtered_events 
                                 if e.timestamp >= since]
            
            return filtered_events

    def clear_events(self) -> None:
        """Clear all stored events"""
        with self._lock:
            self.events.clear()

class EventManager:
    """Main event management system"""
    
    def __init__(self, security_logger: SecurityLogger):
        self.emitter = EventEmitter(security_logger)
        self.processor = EventProcessor(security_logger)
        self.store = EventStore()
        self.security_logger = security_logger

    def handle_event(self, event_type: EventType, data: Dict[str, Any], 
                    source: str, severity: str) -> None:
        """Handle a new event"""
        event = Event(
            type=event_type,
            timestamp=datetime.utcnow(),
            data=data,
            source=source,
            severity=severity
        )
        
        # Log security events
        self.security_logger.log_security_event(
            event_type.value,
            **data
        )
        
        # Store the event
        self.store.add_event(event)
        
        # Process the event
        self.processor.process_event(event)
        
        # Emit the event
        self.emitter.emit(event)

    def add_handler(self, event_type: EventType, handler: Callable) -> None:
        """Add an event handler"""
        self.processor.register_handler(event_type, handler)

    def subscribe(self, event_type: EventType, callback: Callable) -> None:
        """Subscribe to an event type"""
        self.emitter.on(event_type, callback)

    def get_recent_events(self, event_type: Optional[EventType] = None, 
                         since: Optional[datetime] = None) -> List[Event]:
        """Get recent events"""
        return self.store.get_events(event_type, since)

def create_event_manager(security_logger: SecurityLogger) -> EventManager:
    """Create and configure an event manager"""
    manager = EventManager(security_logger)
    
    # Add default handlers for security events
    def security_alert_handler(event: Event):
        print(f"Security Alert: {event.data.get('message')}")
    
    def prompt_injection_handler(event: Event):
        print(f"Prompt Injection Detected: {event.data.get('details')}")
    
    manager.add_handler(EventType.SECURITY_ALERT, security_alert_handler)
    manager.add_handler(EventType.PROMPT_INJECTION, prompt_injection_handler)
    
    return manager

if __name__ == "__main__":
    # Example usage
    from .logger import setup_logging
    
    security_logger, _ = setup_logging()
    event_manager = create_event_manager(security_logger)
    
    # Subscribe to events
    def on_security_alert(event: Event):
        print(f"Received security alert: {event.data}")
    
    event_manager.subscribe(EventType.SECURITY_ALERT, on_security_alert)
    
    # Trigger an event
    event_manager.handle_event(
        event_type=EventType.SECURITY_ALERT,
        data={"message": "Suspicious activity detected"},
        source="test",
        severity="high"
    )