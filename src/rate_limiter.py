"""
Rate Limiting and Retry Logic Module.

Implements token bucket rate limiting and exponential backoff retry
for API resilience — exactly how enterprise SOAR platforms work.
"""

import time
import logging
import random
from typing import Callable, Optional, Any, Dict
from functools import wraps
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    requests_per_minute: int = 4
    burst_size: int = 1
    retry_attempts: int = 3
    retry_base_delay: float = 2.0
    retry_max_delay: float = 60.0
    retry_exponential_base: float = 2.0


class TokenBucket:
    """
    Token bucket rate limiter.

    Allows burst traffic while maintaining average rate.
    """

    def __init__(self, rate: float, capacity: int):
        """
        Args:
            rate: Tokens added per second
            capacity: Maximum bucket size (burst capacity)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()

    def _add_tokens(self):
        """Add tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now

    def acquire(self, tokens: int = 1, blocking: bool = True) -> bool:
        """
        Acquire tokens from bucket.

        Args:
            tokens: Number of tokens to acquire
            blocking: If True, wait until tokens available

        Returns:
            True if tokens acquired
        """
        self._add_tokens()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        if not blocking:
            return False

        # Calculate wait time
        needed = tokens - self.tokens
        wait_time = needed / self.rate
        logger.debug(f"Rate limit: waiting {wait_time:.2f}s")
        time.sleep(wait_time)

        return self.acquire(tokens, blocking)

    def get_wait_time(self, tokens: int = 1) -> float:
        """Get estimated wait time for tokens."""
        self._add_tokens()
        if self.tokens >= tokens:
            return 0.0
        return (tokens - self.tokens) / self.rate


class RetryWithBackoff:
    """
    Retry decorator with exponential backoff and jitter.

    Handles transient failures (timeouts, 429, 503, 502).
    """

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 2.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        retryable_status_codes: tuple = (429, 502, 503, 504),
        retryable_exceptions: tuple = (Exception,)
    ):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.retryable_status_codes = retryable_status_codes
        self.retryable_exceptions = retryable_exceptions

    def __call__(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(1, self.max_attempts + 1):
                try:
                    result = func(*args, **kwargs)

                    # Check if result is a response object with status code
                    if hasattr(result, 'status_code'):
                        if result.status_code in self.retryable_status_codes:
                            if attempt < self.max_attempts:
                                delay = self._calculate_delay(attempt, result)
                                logger.warning(
                                    f"Attempt {attempt}/{self.max_attempts} failed "
                                    f"with status {result.status_code}. "
                                    f"Retrying in {delay:.1f}s..."
                                )
                                time.sleep(delay)
                                continue

                    return result

                except self.retryable_exceptions as e:
                    last_exception = e
                    if attempt < self.max_attempts:
                        delay = self._calculate_delay(attempt)
                        logger.warning(
                            f"Attempt {attempt}/{self.max_attempts} failed: {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"All {self.max_attempts} attempts failed. Last error: {e}"
                        )

            raise last_exception

        return wrapper

    def _calculate_delay(self, attempt: int, response=None) -> float:
        """Calculate delay with exponential backoff and jitter."""
        # Check for Retry-After header
        if response and hasattr(response, 'headers'):
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    return float(retry_after)
                except (ValueError, TypeError):
                    pass

        # Exponential backoff with full jitter
        delay = min(
            self.base_delay * (self.exponential_base ** (attempt - 1)),
            self.max_delay
        )
        # Add jitter (0% to 100% of delay)
        jitter = random.uniform(0, delay)
        return delay + jitter


def rate_limited(
    requests_per_minute: int = 4,
    retry_attempts: int = 3,
    retry_base_delay: float = 2.0
):
    """
    Decorator factory combining rate limiting and retry logic.

    Usage:
        @rate_limited(requests_per_minute=4, retry_attempts=3)
        def query_api(...):
            ...
    """
    bucket = TokenBucket(
        rate=requests_per_minute / 60.0,
        capacity=1
    )

    retry = RetryWithBackoff(
        max_attempts=retry_attempts,
        base_delay=retry_base_delay
    )

    def decorator(func: Callable) -> Callable:
        @retry
        @wraps(func)
        def wrapper(*args, **kwargs):
            bucket.acquire()
            return func(*args, **kwargs)
        return wrapper

    return decorator


class APIClientBase:
    """Base class for API clients with rate limiting and retry."""

    def __init__(
        self,
        rate_limit_config: Optional[RateLimitConfig] = None
    ):
        self.config = rate_limit_config or RateLimitConfig()
        self.bucket = TokenBucket(
            rate=self.config.requests_per_minute / 60.0,
            capacity=self.config.burst_size
        )
        self.retry = RetryWithBackoff(
            max_attempts=self.config.retry_attempts,
            base_delay=self.config.retry_base_delay,
            max_delay=self.config.retry_max_delay,
            exponential_base=self.config.retry_exponential_base
        )

    def execute_with_limit(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with rate limiting and retry."""
        self.bucket.acquire()
        wrapped = self.retry(func)
        return wrapped(*args, **kwargs)
