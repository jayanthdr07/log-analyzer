"""Bounded retry with exponential backoff + full jitter and a hard overall deadline."""
import asyncio
import logging
import random
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")
logger = logging.getLogger("retry")


class RetryableError(Exception):
    """Transient failure (timeout, 429, 5xx, network). Safe to retry."""

    def __init__(self, message: str, *, retry_after: Optional[float] = None, status: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.status = status


class NonRetryableError(Exception):
    """Permanent failure (bad auth, bad request). Retrying cannot help."""

    def __init__(self, message: str, *, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class RetriesExhausted(Exception):
    def __init__(self, attempts: int, last: Optional[Exception]):
        super().__init__(f"gave up after {attempts} attempts")
        self.attempts, self.last = attempts, last


class DeadlineExceeded(Exception):
    def __init__(self, attempts: int, last: Optional[Exception]):
        super().__init__("overall deadline exceeded")
        self.attempts, self.last = attempts, last


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int
    base_delay: float
    max_delay: float
    total_timeout: float


def backoff_delay(attempt: int, base: float, cap: float) -> float:
    """Full jitter: uniform(0, min(cap, base * 2^(attempt-1))). Always bounded by cap."""
    return random.uniform(0, min(cap, base * (2 ** (attempt - 1))))


async def retry_async(operation: Callable[[int], Awaitable[T]], policy: RetryPolicy) -> T:
    """Run `operation(attempt)` until success, a non-retryable error, max attempts,
    or the overall deadline. Never loops unboundedly."""
    deadline = time.monotonic() + policy.total_timeout
    last: Optional[Exception] = None

    for attempt in range(1, policy.max_attempts + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExceeded(attempt - 1, last)
        try:
            # Hard cap on this attempt, regardless of what the HTTP layer does.
            return await asyncio.wait_for(operation(attempt), timeout=remaining)
        except NonRetryableError:
            raise  # stop immediately
        except RetryableError as exc:
            last = exc
        except asyncio.TimeoutError:
            raise DeadlineExceeded(attempt, last)

        if attempt == policy.max_attempts:
            break

        delay = backoff_delay(attempt, policy.base_delay, policy.max_delay)
        retry_after = getattr(last, "retry_after", None)
        if retry_after:  # honor server hint, but still capped
            delay = max(delay, min(retry_after, policy.max_delay))
        if delay >= deadline - time.monotonic():
            raise DeadlineExceeded(attempt, last)

        logger.warning(
            "retrying after transient failure",
            extra={"event": "retry_scheduled", "attempt": attempt,
                   "max_attempts": policy.max_attempts, "delay_s": round(delay, 3),
                   "status": getattr(last, "status", None),
                   "error_type": type(last).__name__},
        )
        await asyncio.sleep(delay)

    raise RetriesExhausted(policy.max_attempts, last)
