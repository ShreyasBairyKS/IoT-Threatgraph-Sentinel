"""
security.py - Auth and abuse-protection dependencies for the ingest routes.

POST /ingest/* is the trust boundary for the whole alert pipeline: anything
accepted there ends up as a device status or a broadcast alert. Two FastAPI
dependencies guard it:

  - require_ingest_api_key: optional shared-secret check (off unless
    settings.INGEST_API_KEY is set, so local dev and the existing test
    suite keep working unauthenticated).
  - enforce_ingest_rate_limit: a simple per-client sliding-window limiter,
    always on, independent of the API key.

The internal demo generators (backend/live_stream.py, backend/ws/synthetic_stream.py)
call process_anomaly_result() directly in-process rather than over HTTP, so
neither dependency affects them.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque

from fastapi import Header, HTTPException, Request, status

from backend.config import settings


def require_ingest_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not settings.INGEST_API_KEY:
        return
    if x_api_key != settings.INGEST_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-API-Key header.",
        )


class _SlidingWindowRateLimiter:
    """Per-key request cap over a rolling time window, keyed by client IP."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> None:
        now = time.monotonic()
        async with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > self.window_seconds:
                hits.popleft()
            if len(hits) >= self.max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded for /ingest/*.",
                )
            hits.append(now)


_ingest_rate_limiter = _SlidingWindowRateLimiter(
    max_requests=settings.INGEST_RATE_LIMIT_MAX_REQUESTS,
    window_seconds=settings.INGEST_RATE_LIMIT_WINDOW_SECONDS,
)


async def enforce_ingest_rate_limit(request: Request) -> None:
    client_key = request.client.host if request.client else "unknown"
    await _ingest_rate_limiter.check(client_key)
