import threading
import time
from typing import Dict, List

from fastapi import HTTPException, Request, status

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    def __init__(self) -> None:
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()

    def check(self, key: str, limit: int, window_seconds: int = 60) -> None:
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._requests.get(key, [])
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


_limiter = RateLimiter()


def get_client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def limit_auth_requests(request: Request) -> None:
    ip = get_client_ip(request)
    _limiter.check(f"auth:{ip}", limit=settings.rate_limit_auth_per_minute)


def limit_expensive_requests(request: Request) -> None:
    ip = get_client_ip(request)
    _limiter.check(f"expensive:{ip}", limit=settings.rate_limit_expensive_per_minute)
