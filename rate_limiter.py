from __future__ import annotations

from collections import defaultdict
from time import time


class RateLimiter:
    """In-memory fixed-window rate limiter for local HTTP requests."""

    def __init__(self, max_requests: int = 10, window: int = 60) -> None:
        """Create a limiter allowing max_requests per client within window seconds."""

        self.requests: dict[str, list[float]] = defaultdict(list)
        self.max_requests = max_requests
        self.window = window

    def is_allowed(self, client_ip: str) -> bool:
        """Return whether a client may make another request right now."""

        now = time()
        self.requests[client_ip] = [timestamp for timestamp in self.requests[client_ip] if now - timestamp < self.window]
        if len(self.requests[client_ip]) >= self.max_requests:
            return False
        self.requests[client_ip].append(now)
        return True
