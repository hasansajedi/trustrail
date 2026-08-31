"""Tests for atomic state backends and fixed-window rate limiting."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import sys
import types
from typing import Any

import pytest

from trustrail.models.enums import FailMode
from trustrail.protocols import StateBackend
from trustrail.state import (
    FixedWindowRateLimiter,
    MemoryStateBackend,
    RateLimiter,
    RedisStateBackend,
    StateBackendError,
    build_state_key,
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
        self.closed = False

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
            current = 0
            if existed:
                try:
                    envelope = json.loads(self.values[key])
                    current = envelope["value"]
                    valid = (
                        envelope.get("__trustrail_state__") == 1
                        and isinstance(current, int)
                        and not isinstance(current, bool)
                    )
                except (KeyError, TypeError, json.JSONDecodeError):
                    valid = False
                if not valid:
                    raise ValueError("TRUSTRAIL_STATE_MALFORMED")
            value = current + delta
            self.values[key] = json.dumps(
                {"__trustrail_state__": 1, "value": value},
                separators=(",", ":"),
            )
            if not existed and ttl_ms > 0:
                self.expires_at[key] = self.clock() + ttl_ms / 1_000
            return value

    async def aclose(self) -> None:
        self.closed = True


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
    redis_key = backend.key_for("counter")
    first_expiry = client.expires_at[redis_key]
    clock.advance(2)
    assert await backend.increment_with_ttl("counter", ttl_seconds=5) == 2

    assert client.expires_at[redis_key] == first_expiry
    assert len(client.scripts) == 2
    assert all(
        'redis.call("GET"' in script
        and 'redis.call("SET"' in script
        and 'redis.call("PEXPIRE"' in script
        for script in client.scripts
    )


@pytest.mark.asyncio
async def test_redis_state_round_trip_increment_and_delete():
    client = _FakeRedis(_Clock())
    backend = RedisStateBackend(client)

    await backend.set("document", {"trusted": True}, ttl_seconds=1.25)
    assert await backend.get("document") == {"trusted": True}
    assert await backend.increment("counter", 2) == 2
    await backend.delete("document")

    assert await backend.get("document") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("backend_kind", ["memory", "redis"])
async def test_state_backend_contract_set_get_increment_expire_and_delete(backend_kind: str):
    clock = _Clock()
    if backend_kind == "memory":
        backend: StateBackend = MemoryStateBackend(clock=clock)
    else:
        backend = RedisStateBackend(_FakeRedis(clock))

    await backend.set("record", {"allowed": True}, ttl_seconds=2)
    assert await backend.get("record") == {"allowed": True}
    await backend.set("counter", 4, ttl_seconds=2)
    assert await backend.increment("counter", 3) == 7
    clock.advance(2)
    assert await backend.get("record") is None
    assert await backend.get("counter") is None
    await backend.delete("record")


def test_build_state_key_is_collision_safe_and_hides_identity_components():
    first = build_state_key("rate-limit", "tenant:a", "user", "session")
    second = build_state_key("rate-limit", "tenant", "a:user", "session")

    assert first != second
    assert first.startswith("rate-limit:")
    assert "tenant" not in first
    assert "session" not in first


def test_redis_physical_keys_are_namespaced_versioned_and_content_free():
    backend = RedisStateBackend(_FakeRedis(_Clock()), namespace="product:security")

    redis_key = backend.key_for("tenant-secret:session-secret")

    assert redis_key.startswith("product:security:v1:")
    assert "tenant-secret" not in redis_key
    assert "session-secret" not in redis_key


@pytest.mark.asyncio
async def test_redis_serialization_is_versioned_and_rejects_malformed_data():
    client = _FakeRedis(_Clock())
    backend = RedisStateBackend(client)
    await backend.set("document", {"trusted": True})
    redis_key = backend.key_for("document")

    assert json.loads(client.values[redis_key]) == {
        "__trustrail_state__": 1,
        "value": {"trusted": True},
    }

    client.values[redis_key] = '{"__trustrail_state__":2,"value":"old"}'
    with pytest.raises(StateBackendError, match="operation failed"):
        await backend.get("document")


@pytest.mark.asyncio
async def test_redis_fail_open_returns_documented_fallbacks_without_sensitive_logs(caplog):
    secret = "redis://user:password@example.invalid/private-value"

    class _UnavailableRedis:
        async def get(self, _key: str) -> None:
            raise RuntimeError(secret)

        async def set(self, _key: str, _value: str, **_kwargs: Any) -> None:
            raise RuntimeError(secret)

        async def eval(self, *_args: Any) -> None:
            raise RuntimeError(secret)

        async def delete(self, _key: str) -> None:
            raise RuntimeError(secret)

    backend = RedisStateBackend(_UnavailableRedis(), fail_mode=FailMode.OPEN)
    with caplog.at_level(logging.WARNING, logger="trustrail.state"):
        assert await backend.get("private-key") is None
        await backend.set("private-key", "private-value")
        assert await backend.increment("private-key", 2) == 2
        assert await backend.increment_with_ttl("private-key", 3, 5) == 3
        await backend.delete("private-key")

    assert "password" not in caplog.text
    assert "private-key" not in caplog.text
    assert "private-value" not in caplog.text
    assert caplog.text.count("continuing in fail-open mode") == 5


@pytest.mark.asyncio
async def test_redis_fail_closed_raises_safe_backend_error():
    class _UnavailableRedis:
        async def get(self, _key: str) -> None:
            raise RuntimeError("credential-bearing provider failure")

    backend = RedisStateBackend(_UnavailableRedis())

    with pytest.raises(StateBackendError) as error:
        await backend.get("sensitive-key")

    assert error.value.operation == "get"
    assert "sensitive-key" not in str(error.value)
    assert "credential" not in str(error.value)


@pytest.mark.asyncio
async def test_redis_recovers_on_a_later_operation_after_transient_failure():
    class _FlakyRedis(_FakeRedis):
        def __init__(self) -> None:
            super().__init__(_Clock())
            self.fail_next_get = True

        async def get(self, key: str) -> bytes | None:
            if self.fail_next_get:
                self.fail_next_get = False
                raise ConnectionError("temporarily unavailable")
            return await super().get(key)

    client = _FlakyRedis()
    backend = RedisStateBackend(client)

    with pytest.raises(StateBackendError):
        await backend.get("record")
    await backend.set("record", "available")
    assert await backend.get("record") == "available"


@pytest.mark.asyncio
async def test_redis_owned_client_closes_once_and_context_manager_rejects_reuse():
    client = _FakeRedis(_Clock())
    backend = RedisStateBackend(client, close_client=True)

    async with backend:
        await backend.set("record", "value")

    assert client.closed
    await backend.aclose()
    with pytest.raises(StateBackendError, match="closed"):
        await backend.get("record")


def test_redis_from_url_configures_tls_auth_pool_and_timeouts(monkeypatch):
    captured: dict[str, Any] = {}
    client = _FakeRedis(_Clock())

    class _RedisFactory:
        @staticmethod
        def from_url(url: str, **kwargs: Any) -> _FakeRedis:
            captured.update(url=url, **kwargs)
            return client

    redis_package = types.ModuleType("redis")
    redis_asyncio = types.ModuleType("redis.asyncio")
    redis_asyncio.Redis = _RedisFactory  # type: ignore[attr-defined]
    redis_package.asyncio = redis_asyncio  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "redis", redis_package)
    monkeypatch.setitem(sys.modules, "redis.asyncio", redis_asyncio)

    backend = RedisStateBackend.from_url(
        "rediss://user:secret@redis.example:6380/2",
        socket_connect_timeout=1.5,
        socket_timeout=2.5,
        max_connections=32,
        health_check_interval=15,
        ssl_ca_certs="/run/secrets/redis-ca.pem",
    )

    assert captured == {
        "url": "rediss://user:secret@redis.example:6380/2",
        "socket_connect_timeout": 1.5,
        "socket_timeout": 2.5,
        "max_connections": 32,
        "health_check_interval": 15,
        "ssl_ca_certs": "/run/secrets/redis-ca.pem",
    }
    assert backend.namespace == "trustrail:state"


def test_redis_optional_dependency_error_is_actionable(monkeypatch):
    monkeypatch.setitem(sys.modules, "redis.asyncio", None)

    with pytest.raises(ImportError, match=r"pip install 'trustrail\[redis\]'"):
        RedisStateBackend.from_url("redis://localhost:6379/0")


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
