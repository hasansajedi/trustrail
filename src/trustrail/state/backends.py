"""State backend implementations."""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Any


class MemoryStateBackend:
    """In-memory state backend with bounded capacity and TTL support.

    Thread-safe via asyncio Lock. Not suitable for multi-process deployments.
    """

    def __init__(self, max_keys: int = 10_000) -> None:
        self._max_keys = max_keys
        # value: (data, expires_at or None)
        self._store: OrderedDict[str, tuple[Any, float | None]] = OrderedDict()
        self._lock = asyncio.Lock()

    def _is_expired(self, expires_at: float | None) -> bool:
        if expires_at is None:
            return False
        return time.monotonic() > expires_at

    def _evict_if_needed(self) -> None:
        """Evict LRU entries if at capacity."""
        while len(self._store) >= self._max_keys:
            self._store.popitem(last=False)

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if self._is_expired(expires_at):
                del self._store[key]
                return None
            # Move to end (LRU update)
            self._store.move_to_end(key)
            return value

    async def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None:
        async with self._lock:
            expires_at = time.monotonic() + ttl_seconds if ttl_seconds is not None else None
            if key in self._store:
                self._store.move_to_end(key)
            else:
                self._evict_if_needed()
            self._store[key] = (value, expires_at)

    async def increment(self, key: str, delta: int = 1) -> int:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                new_val = delta
                expires_at = None
            else:
                current, expires_at = entry
                if self._is_expired(expires_at):
                    new_val = delta
                    expires_at = None
                else:
                    new_val = int(current) + delta
            self._store[key] = (new_val, expires_at)
            self._store.move_to_end(key)
            return new_val

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


class RateLimiter:
    """Sliding window rate limiter backed by a StateBackend."""

    def __init__(
        self,
        backend: MemoryStateBackend,
        max_requests: int = 100,
        window_seconds: float = 60.0,
    ) -> None:
        self._backend = backend
        self._max_requests = max_requests
        self._window = window_seconds

    async def check(self, key: str) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        count = await self._backend.increment(
            f"rl:{key}",
            delta=1,
        )
        if count == 1:
            # First request, set TTL
            await self._backend.set(f"rl:{key}", 1, ttl_seconds=self._window)
            return True
        return count <= self._max_requests

    async def reset(self, key: str) -> None:
        await self._backend.delete(f"rl:{key}")
