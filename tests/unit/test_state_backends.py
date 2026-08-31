"""Tests for atomic state backends and fixed-window rate limiting."""

from __future__ import annotations

import asyncio
import math
from typing import Any

import pytest

from trustrail.protocols import StateBackend
from trustrail.state import (
    FixedWindowRateLimiter,
    MemoryStateBackend,
    RateLimiter,
    RedisStateBackend,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FakeRedis:
    """Small Redis emulator that exercises the adapter's atomic script contract."""

    def __init__(self, clock: _Clock) -> None:
        self.clock = clock
        self.values: dict[str, str] = {}
        self.expires_at: dict[str, float] = {}
        self.scripts: list[str] = []
        self._lock = asyncio.Lock()

    def _expire(self, key: str) -> None:
        expires_at = self.expires_at.get(key)
        if expires_at is not None and self.clock() >= expires_at:
            self.values.pop(key, None)
            self.expires_at.pop(key, None)

    async def get(self, key: str) -> bytes | None:
        self._expire(key)
        value = self.values.get(key)
        return value.encode() if value is not None else None

    async def set(self, key: str, value: str, *, px: int | None = None) -> bool:
        self.values[key] = value
        if px is None:
            self.expires_at.pop(key, None)
        else:
            self.expires_at[key] = self.clock() + px / 1_000
        return True

    async def incrby(self, key: str, delta: int) -> int:
        self._expire(key)
        value = int(self.values.get(key, "0")) + delta
        self.values[key] = str(value)
        return value

    async def delete(self, key: str) -> int:
        existed = key in self.values
        self.values.pop(key, None)
        self.expires_at.pop(key, None)
        return int(existed)

    async def eval(
        self,
        script: str,
        number_of_keys: int,
        key: str,
        delta: int,
        ttl_ms: int,
    ) -> int:
        assert number_of_keys == 1
        self.scripts.append(script)
        async with self._lock:
            self._expire(key)
            existed = key in self.values
            value = int(self.values.get(key, "0")) + delta
            self.values[key] = str(value)
            if not existed:
                self.expires_at[key] = self.clock() + ttl_ms / 1_000
            return value


@pytest.mark.asyncio
@pytest.mark.parametrize("backend_kind", ["memory", "redis"])
async def test_concurrent_checks_admit_exactly_the_configured_maximum(backend_kind: str):
    clock = _Clock()
    if backend_kind == "memory":
        backend: StateBackend = MemoryStateBackend(clock=clock)
    else:
        backend = RedisStateBackend(_FakeRedis(clock))
    limiter = FixedWindowRateLimiter(backend, max_requests=10, window_seconds=30)

    results = await asyncio.gather(*(limiter.check("tenant-user") for _ in range(100)))

    assert sum(results) == 10
    assert await backend.get("rl:tenant-user") == 100


@pytest.mark.asyncio
@pytest.mark.parametrize("backend_kind", ["memory", "redis"])
async def test_blocked_requests_do_not_extend_window_and_boundary_starts_new_window(
    backend_kind: str,
):
    clock = _Clock()
    if backend_kind == "memory":
        backend: StateBackend = MemoryStateBackend(clock=clock)
    else:
        backend = RedisStateBackend(_FakeRedis(clock))
    limiter = FixedWindowRateLimiter(backend, max_requests=1, window_seconds=5)

    assert await limiter.check("principal")
    clock.advance(4.9)
    assert not await limiter.check("principal")
    clock.advance(0.1)

    assert await limiter.check("principal")
    assert await backend.get("rl:principal") == 1


@pytest.mark.asyncio
async def test_reset_deletes_counter_and_next_request_starts_a_new_window():
    backend = MemoryStateBackend()
    limiter = RateLimiter(backend, max_requests=1, window_seconds=10)

    assert await limiter.check("principal")
    assert not await limiter.check("principal")
    await limiter.reset("principal")

    assert await limiter.check("principal")
    assert RateLimiter is FixedWindowRateLimiter


@pytest.mark.parametrize("max_requests", [0, -1])
def test_rate_limiter_requires_positive_request_limit(max_requests: int):
    with pytest.raises(ValueError, match="max_requests must be positive"):
        FixedWindowRateLimiter(MemoryStateBackend(), max_requests=max_requests)


@pytest.mark.parametrize("max_requests", [True, 1.5])
def test_rate_limiter_requires_integer_request_limit(max_requests: Any):
    with pytest.raises(TypeError, match="max_requests must be an integer"):
        FixedWindowRateLimiter(MemoryStateBackend(), max_requests=max_requests)


@pytest.mark.parametrize("window", [0.0, -1.0, math.inf, -math.inf, math.nan])
def test_rate_limiter_requires_positive_finite_window(window: float):
    with pytest.raises(ValueError, match="positive, finite"):
        FixedWindowRateLimiter(MemoryStateBackend(), window_seconds=window)


@pytest.mark.parametrize("window", [True, "60"])
def test_rate_limiter_requires_numeric_window(window: Any):
    with pytest.raises(TypeError, match="ttl_seconds must be a number"):
        FixedWindowRateLimiter(MemoryStateBackend(), window_seconds=window)


@pytest.mark.asyncio
async def test_redis_atomic_operation_sets_ttl_once_and_uses_one_transaction():
    clock = _Clock()
    client = _FakeRedis(clock)
    backend = RedisStateBackend(client)

    assert await backend.increment_with_ttl("counter", ttl_seconds=5) == 1
    first_expiry = client.expires_at["counter"]
    clock.advance(2)
    assert await backend.increment_with_ttl("counter", ttl_seconds=5) == 2

    assert client.expires_at["counter"] == first_expiry
    assert len(client.scripts) == 2
    assert all("INCRBY" in script and "PEXPIRE" in script for script in client.scripts)


@pytest.mark.asyncio
async def test_redis_state_round_trip_increment_and_delete():
    client = _FakeRedis(_Clock())
    backend = RedisStateBackend(client)

    await backend.set("document", {"trusted": True}, ttl_seconds=1.25)
    assert await backend.get("document") == {"trusted": True}
    assert await backend.increment("counter", 2) == 2
    await backend.delete("document")

    assert await backend.get("document") is None


class _FailingBackend:
    async def increment_with_ttl(
        self,
        key: str,
        delta: int = 1,
        ttl_seconds: float = 60.0,
    ) -> int:
        raise RuntimeError("state unavailable")

    async def delete(self, key: str) -> None:
        raise RuntimeError("state unavailable")


class _CancelledBackend(_FailingBackend):
    async def increment_with_ttl(
        self,
        key: str,
        delta: int = 1,
        ttl_seconds: float = 60.0,
    ) -> int:
        raise asyncio.CancelledError


@pytest.mark.asyncio
async def test_rate_limiter_propagates_backend_failure():
    limiter = FixedWindowRateLimiter(_FailingBackend(), max_requests=1)

    with pytest.raises(RuntimeError, match="state unavailable"):
        await limiter.check("principal")


@pytest.mark.asyncio
async def test_rate_limiter_does_not_swallow_cancellation():
    limiter = FixedWindowRateLimiter(_CancelledBackend(), max_requests=1)

    with pytest.raises(asyncio.CancelledError):
        await limiter.check("principal")


def test_memory_and_redis_backends_implement_public_protocol():
    assert isinstance(MemoryStateBackend(), StateBackend)
    assert isinstance(RedisStateBackend(_FakeRedis(_Clock())), StateBackend)
