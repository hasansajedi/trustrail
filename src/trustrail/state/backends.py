"""State backend implementations."""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, Self

from trustrail.protocols import StateBackend

_ATOMIC_INCREMENT_WITH_TTL_SCRIPT = """
local existed = redis.call("EXISTS", KEYS[1])
local value = redis.call("INCRBY", KEYS[1], ARGV[1])
if existed == 0 then
    redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return value
"""


def _validate_positive_ttl(ttl_seconds: float) -> None:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
        raise TypeError("ttl_seconds must be a number")
    if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive, finite number")


class MemoryStateBackend:
    """In-memory state backend with bounded capacity and TTL support.

    Thread-safe via asyncio Lock. Not suitable for multi-process deployments.
    """

    def __init__(
        self,
        max_keys: int = 10_000,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_keys <= 0:
            raise ValueError("max_keys must be positive")
        self._max_keys = max_keys
        self._clock = clock
        # value: (data, expires_at or None)
        self._store: OrderedDict[str, tuple[Any, float | None]] = OrderedDict()
        self._lock = asyncio.Lock()

    def _is_expired(self, expires_at: float | None) -> bool:
        if expires_at is None:
            return False
        # The counter belongs to the next window at the exact expiry boundary.
        return self._clock() >= expires_at

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
            if ttl_seconds is not None:
                _validate_positive_ttl(ttl_seconds)
            expires_at = self._clock() + ttl_seconds if ttl_seconds is not None else None
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

    async def increment_with_ttl(
        self,
        key: str,
        delta: int = 1,
        ttl_seconds: float = 60.0,
    ) -> int:
        """Increment and initialize TTL atomically under the backend lock."""
        _validate_positive_ttl(ttl_seconds)
        async with self._lock:
            entry = self._store.get(key)
            expires_at: float | None
            if entry is None or self._is_expired(entry[1]):
                if entry is None:
                    self._evict_if_needed()
                new_value = delta
                expires_at = self._clock() + ttl_seconds
            else:
                current, expires_at = entry
                new_value = int(current) + delta
            self._store[key] = (new_value, expires_at)
            self._store.move_to_end(key)
            return new_value

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


class RedisStateBackend:
    """Redis-backed state shared safely across processes and application instances.

    Install the ``redis`` extra and construct this backend with ``from_url()``, or
    pass an existing ``redis.asyncio.Redis``-compatible client to the constructor.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> Self:
        """Create a backend from a Redis URL without requiring Redis at import time."""
        try:
            from redis.asyncio import Redis
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise ImportError(
                "RedisStateBackend requires the 'redis' extra: pip install 'trustrail[redis]'"
            ) from exc
        return cls(Redis.from_url(url, **kwargs))

    @staticmethod
    def _decode(value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
        return value

    async def get(self, key: str) -> Any | None:
        return self._decode(await self._client.get(key))

    async def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None:
        encoded = json.dumps(value, separators=(",", ":"))
        if ttl_seconds is None:
            await self._client.set(key, encoded)
            return
        _validate_positive_ttl(ttl_seconds)
        await self._client.set(key, encoded, px=max(1, math.ceil(ttl_seconds * 1000)))

    async def increment(self, key: str, delta: int = 1) -> int:
        return int(await self._client.incrby(key, delta))

    async def increment_with_ttl(
        self,
        key: str,
        delta: int = 1,
        ttl_seconds: float = 60.0,
    ) -> int:
        """Atomically increment and initialize TTL with one Redis Lua transaction."""
        _validate_positive_ttl(ttl_seconds)
        ttl_ms = max(1, math.ceil(ttl_seconds * 1000))
        result = await self._client.eval(
            _ATOMIC_INCREMENT_WITH_TTL_SCRIPT,
            1,
            key,
            delta,
            ttl_ms,
        )
        return int(result)

    async def delete(self, key: str) -> None:
        await self._client.delete(key)


class FixedWindowRateLimiter:
    """Fixed-window rate limiter backed by a public ``StateBackend``.

    The first request for a key starts its window. Every request increments the
    counter, including blocked requests, but only creation initializes the TTL.
    Therefore blocked requests never reset or extend the active window.
    """

    def __init__(
        self,
        backend: StateBackend,
        max_requests: int = 100,
        window_seconds: float = 60.0,
    ) -> None:
        if isinstance(max_requests, bool) or not isinstance(max_requests, int):
            raise TypeError("max_requests must be an integer")
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        _validate_positive_ttl(window_seconds)
        self._backend = backend
        self._max_requests = max_requests
        self._window = window_seconds

    async def check(self, key: str) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        count = await self._backend.increment_with_ttl(
            f"rl:{key}",
            delta=1,
            ttl_seconds=self._window,
        )
        return count <= self._max_requests

    async def reset(self, key: str) -> None:
        await self._backend.delete(f"rl:{key}")


# Backwards-compatible name retained for users of the original public class.
RateLimiter = FixedWindowRateLimiter
