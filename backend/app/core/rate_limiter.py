"""
core/rate_limiter.py
--------------------
Lightweight, thread-safe, in-memory sliding window rate limiter for Cipherix endpoints.

Protects against brute-force authentication attacks and resource exhaustion
(expensive document processing, vector search, RAG generation, computer access execution).
"""

import threading
import time
from typing import Dict, List

from fastapi import HTTPException, Request, status

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    """
    In-memory sliding window rate limiter.
    """

    def __init__(self) -> None:
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def clear(self) -> None:
        """Reset all tracked rate limits (useful for testing)."""
        with self._lock:
            self._requests.clear()

    def check(self, key: str, limit: int, window_seconds: int = 60) -> None:
        """
        Record a request timestamp and enforce rate limit threshold.

        Raises
        ------
        HTTPException(429)
            If request count within window_seconds exceeds limit.
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._requests.get(key, [])
            # Prune expired timestamps
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]

            if len(valid_timestamps) >= limit:
                logger.warning("Rate limit exceeded | key=%s | limit=%d", key, limit)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Maximum {limit} requests allowed per {window_seconds} seconds.",
                    headers={"Retry-After": str(window_seconds)},
                )

            valid_timestamps.append(now)
            self._requests[key] = valid_timestamps


# Global singleton instance
_limiter = RateLimiter()


def get_client_ip(request: Request) -> str:
    """Extract client IP address from Request object."""
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def limit_auth_requests(request: Request) -> None:
    """FastAPI dependency enforcing rate limits on authentication routes."""
    ip = get_client_ip(request)
    _limiter.check(f"auth:{ip}", limit=settings.rate_limit_auth_per_minute)


def limit_expensive_requests(request: Request) -> None:
    """FastAPI dependency enforcing rate limits on resource-intensive endpoints."""
    ip = get_client_ip(request)
    _limiter.check(f"expensive:{ip}", limit=settings.rate_limit_expensive_per_minute)
