"""
core/rate_limiter.py - Rate limiting implementation for LLMGuardian
"""

import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import psutil

from .events import EventManager, EventType
from .exceptions import RateLimitError
from .logger import SecurityLogger


class RateLimitType(Enum):
    """Types of rate limits"""

    REQUESTS = "requests"
    TOKENS = "tokens"
    BANDWIDTH = "bandwidth"
    CONCURRENT = "concurrent"


@dataclass
class RateLimit:
    """Rate limit configuration"""

    limit: int
    window: int  # in seconds
    type: RateLimitType
    burst_multiplier: float = 2.0
    adaptive: bool = False


@dataclass
class RateLimitState:
    """Current state of a rate limit"""

    count: int
    window_start: float
    last_reset: datetime
    concurrent: int = 0


class SystemMetrics:
    """System metrics collector for adaptive rate limiting"""

    @staticmethod
    def get_cpu_usage() -> float:
        """Get current CPU usage percentage"""
        return psutil.cpu_percent(interval=1)

    @staticmethod
    def get_memory_usage() -> float:
        """Get current memory usage percentage"""
        return psutil.virtual_memory().percent

    @staticmethod
    def get_load_average() -> Tuple[float, float, float]:
        """Get system load averages"""
        return os.getloadavg()

    @staticmethod
    def calculate_load_factor() -> float:
        """Calculate overall system load factor"""
        cpu_usage = SystemMetrics.get_cpu_usage()
        memory_usage = SystemMetrics.get_memory_usage()
        load_avg = SystemMetrics.get_load_average()[0]  # 1-minute average

        # Normalize load average to percentage (assuming max load of 4)
        load_percent = min(100, (load_avg / 4) * 100)

        # Weighted average of metrics
        return (0.4 * cpu_usage + 0.4 * memory_usage + 0.2 * load_percent) / 100


class TokenBucket:
    """Token bucket rate limiter implementation"""

    def __init__(self, capacity: int, fill_rate: float):
        """Initialize token bucket"""
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = capacity
        self.last_update = time.time()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Consume tokens from the bucket"""
        with self._lock:
            now = time.time()
            # Add new tokens based on time passed
            time_passed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + time_passed * self.fill_rate)
            self.last_update = now

            if tokens <= self.tokens:
                self.tokens -= tokens
                return True
            return False

    def get_tokens(self) -> float:
        """Get current token count"""
        with self._lock:
            now = time.time()
            time_passed = now - self.last_update
            return min(self.capacity, self.tokens + time_passed * self.fill_rate)


class RateLimiter:
    """Main rate limiter implementation"""

    def __init__(self, security_logger: SecurityLogger, event_manager: EventManager):
        self.limits: Dict[str, RateLimit] = {}
        self.states: Dict[str, Dict[str, RateLimitState]] = {}
        self.token_buckets: Dict[str, TokenBucket] = {}
        self.security_logger = security_logger
        self.event_manager = event_manager
        self._lock = threading.Lock()
        self.metrics = SystemMetrics()

    def add_limit(self, name: str, limit: RateLimit) -> None:
        """Add a new rate limit"""
        with self._lock:
            self.limits[name] = limit
            self.states[name] = {}

            if limit.type == RateLimitType.TOKENS:
                self.token_buckets[name] = TokenBucket(
                    capacity=limit.limit, fill_rate=limit.limit / limit.window
                )

    def check_limit(self, name: str, key: str, amount: int = 1) -> bool:
        """Check if an operation is within rate limits"""
        with self._lock:
            if name not in self.limits:
                return True

            limit = self.limits[name]

            # Handle token bucket limiting
            if limit.type == RateLimitType.TOKENS:
                if not self.token_buckets[name].consume(amount):
                    self._handle_limit_exceeded(name, key, limit)
                    return False
                return True

            # Initialize state for new keys
            if key not in self.states[name]:
                self.states[name][key] = RateLimitState(
                    count=0, window_start=time.time(), last_reset=datetime.utcnow()
                )

            state = self.states[name][key]
            now = time.time()

            # Check if window has expired
            if now - state.window_start >= limit.window:
                state.count = 0
                state.window_start = now
                state.last_reset = datetime.utcnow()

            # Get effective limit based on adaptive settings
            effective_limit = self._get_effective_limit(limit)

            # Handle concurrent limits
            if limit.type == RateLimitType.CONCURRENT:
                if state.concurrent >= effective_limit:
                    self._handle_limit_exceeded(name, key, limit)
                    return False
                state.concurrent += 1
                return True

            # Check if limit is exceeded
            if state.count + amount > effective_limit:
                self._handle_limit_exceeded(name, key, limit)
                return False

            # Update count
            state.count += amount
            return True

    def release_concurrent(self, name: str, key: str) -> None:
        """Release a concurrent limit hold"""
        with self._lock:
            if (
                name in self.limits
                and self.limits[name].type == RateLimitType.CONCURRENT
                and key in self.states[name]
            ):
                self.states[name][key].concurrent = max(
                    0, self.states[name][key].concurrent - 1
                )

    def _get_effective_limit(self, limit: RateLimit) -> int:
        """Get effective limit considering adaptive settings"""
        if not limit.adaptive:
            return limit.limit

        load_factor = self.metrics.calculate_load_factor()

        # Adjust limit based on system load
        if load_factor > 0.8:  # High load
            return int(limit.limit * 0.5)  # Reduce by 50%
        elif load_factor > 0.6:  # Medium load
            return int(limit.limit * 0.75)  # Reduce by 25%
        else:  # Normal load
            return limit.limit

    def _handle_limit_exceeded(self, name: str, key: str, limit: RateLimit) -> None:
        """Handle rate limit exceeded event"""
        self.security_logger.log_security_event(
            "rate_limit_exceeded",
            limit_name=name,
            key=key,
            limit=limit.limit,
            window=limit.window,
            type=limit.type.value,
        )

        self.event_manager.handle_event(
            event_type=EventType.RATE_LIMIT_EXCEEDED,
            data={
                "limit_name": name,
                "key": key,
                "limit": limit.limit,
                "window": limit.window,
                "type": limit.type.value,
            },
            source="rate_limiter",
            severity="warning",
        )

    def get_limit_info(self, name: str, key: str) -> Dict[str, Any]:
        """Get current rate limit information"""
        with self._lock:
            if name not in self.limits:
                return {}

            limit = self.limits[name]

            if limit.type == RateLimitType.TOKENS:
                bucket = self.token_buckets[name]
                return {
                    "type": "token_bucket",
                    "limit": limit.limit,
                    "remaining": bucket.get_tokens(),
                    "reset": time.time()
                    + ((limit.limit - bucket.get_tokens()) / bucket.fill_rate),
                }

            if key not in self.states[name]:
                return {
                    "type": limit.type.value,
                    "limit": self._get_effective_limit(limit),
                    "remaining": self._get_effective_limit(limit),
                    "reset": time.time() + limit.window,
                    "window": limit.window,
                }

            state = self.states[name][key]
            effective_limit = self._get_effective_limit(limit)

            if limit.type == RateLimitType.CONCURRENT:
                remaining = effective_limit - state.concurrent
            else:
                remaining = max(0, effective_limit - state.count)

            reset_time = state.window_start + limit.window

            return {
                "type": limit.type.value,
                "limit": effective_limit,
                "remaining": remaining,
                "reset": reset_time,
                "window": limit.window,
                "current_usage": state.count,
                "window_start": state.window_start,
                "last_reset": state.last_reset.isoformat(),
            }

    def clear_limits(self, name: str = None) -> None:
        """Clear rate limit states"""
        with self._lock:
            if name:
                if name in self.states:
                    self.states[name].clear()
                if name in self.token_buckets:
                    self.token_buckets[name] = TokenBucket(
                        self.limits[name].limit,
                        self.limits[name].limit / self.limits[name].window,
                    )
            else:
                self.states.clear()
                self.token_buckets.clear()
                for name, limit in self.limits.items():
                    if limit.type == RateLimitType.TOKENS:
                        self.token_buckets[name] = TokenBucket(
                            limit.limit, limit.limit / limit.window
                        )


def create_rate_limiter(
    security_logger: SecurityLogger, event_manager: EventManager
) -> RateLimiter:
    """Create and configure a rate limiter"""
    limiter = RateLimiter(security_logger, event_manager)

    # Add default limits
    default_limits = [
        RateLimit(limit=100, window=60, type=RateLimitType.REQUESTS, adaptive=True),
        RateLimit(
            limit=1000, window=3600, type=RateLimitType.TOKENS, burst_multiplier=1.5
        ),
        RateLimit(limit=10, window=1, type=RateLimitType.CONCURRENT, adaptive=True),
    ]

    for i, limit in enumerate(default_limits):
        limiter.add_limit(f"default_limit_{i}", limit)

    return limiter


if __name__ == "__main__":
    # Example usage
    from .events import create_event_manager
    from .logger import setup_logging

    security_logger, _ = setup_logging()
    event_manager = create_event_manager(security_logger)
    limiter = create_rate_limiter(security_logger, event_manager)

    # Test rate limiting
    test_key = "test_user"

    print("\nTesting request rate limit:")
    for i in range(12):
        allowed = limiter.check_limit("default_limit_0", test_key)
        print(f"Request {i+1}: {'Allowed' if allowed else 'Blocked'}")

    print("\nRate limit info:")
    print(json.dumps(limiter.get_limit_info("default_limit_0", test_key), indent=2))

    print("\nTesting concurrent limit:")
    concurrent_key = "concurrent_test"
    for i in range(5):
        allowed = limiter.check_limit("default_limit_2", concurrent_key)
        print(f"Concurrent request {i+1}: {'Allowed' if allowed else 'Blocked'}")
        if allowed:
            # Simulate some work
            time.sleep(0.1)
            # Release the concurrent limit
            limiter.release_concurrent("default_limit_2", concurrent_key)
