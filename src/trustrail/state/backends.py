"""State backend implementations."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, Self
from urllib.parse import urlsplit

from trustrail.exceptions import StateBackendError
from trustrail.models.enums import FailMode
from trustrail.protocols import StateBackend

logger = logging.getLogger("trustrail.state")

_DEFAULT_REDIS_NAMESPACE = "trustrail:state"
_SERIALIZATION_VERSION = 1
_SERIALIZATION_MARKER = "__trustrail_state__"
_NAMESPACE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$")
_ATOMIC_INCREMENT_WITH_TTL_SCRIPT = """
local raw = redis.call("GET", KEYS[1])
local existed = raw ~= false
local current = 0
local previous_ttl = -2

if existed then
    previous_ttl = redis.call("PTTL", KEYS[1])
    local decoded_ok, envelope = pcall(cjson.decode, raw)
    if not decoded_ok
        or type(envelope) ~= "table"
        or envelope["__trustrail_state__"] ~= 1
        or type(envelope["value"]) ~= "number"
        or envelope["value"] ~= math.floor(envelope["value"])
    then
        return redis.error_reply("TRUSTRAIL_STATE_MALFORMED")
    end
    current = envelope["value"]
end

local delta = tonumber(ARGV[1])
local value = current + delta
local encoded = cjson.encode({["__trustrail_state__"] = 1, ["value"] = value})
redis.call("SET", KEYS[1], encoded)

if existed then
    if previous_ttl >= 0 then
        redis.call("PEXPIRE", KEYS[1], previous_ttl)
    elseif previous_ttl == -1 then
        redis.call("PERSIST", KEYS[1])
    end
elseif tonumber(ARGV[2]) > 0 then
    redis.call("PEXPIRE", KEYS[1], ARGV[2])
end

return value
"""


def _validate_positive_ttl(ttl_seconds: float) -> None:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
        raise TypeError("ttl_seconds must be a number")
    if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive, finite number")


def _validate_delta(delta: int) -> None:
    if isinstance(delta, bool) or not isinstance(delta, int):
        raise TypeError("delta must be an integer")


def _validate_namespace(namespace: str) -> None:
    if not isinstance(namespace, str):
        raise TypeError("namespace must be a string")
    if not _NAMESPACE_PATTERN.fullmatch(namespace):
        raise ValueError(
            "namespace must be 1-128 characters containing only letters, numbers, ':', '_', "
            "'.', or '-'"
        )


def _validate_logical_key(key: str) -> None:
    if not isinstance(key, str):
        raise TypeError("state key must be a string")
    if not key:
        raise ValueError("state key must not be empty")


def build_state_key(scope: str, *components: str) -> str:
    """Build a collision-safe, content-free key from trusted identity components.

    The scope remains visible for operational grouping. Tenant, user, session, and
    other identity components are encoded as a canonical JSON tuple and hashed so
    delimiters cannot create collisions and raw identifiers do not enter Redis keys.
    """
    _validate_namespace(scope)
    if not components:
        raise ValueError("at least one state key component is required")
    if any(not isinstance(component, str) for component in components):
        raise TypeError("state key components must be strings")
    encoded = json.dumps(
        list(components),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{scope}:{hashlib.sha256(encoded).hexdigest()}"


def _encode_value(value: Any) -> str:
    try:
        return json.dumps(
            {_SERIALIZATION_MARKER: _SERIALIZATION_VERSION, "value": value},
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise TypeError("RedisStateBackend values must be JSON-serializable") from exc


def _decode_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Redis state contains malformed data") from exc
    if not isinstance(value, str):
        raise ValueError("Redis state contains malformed data")
    try:
        envelope = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Redis state contains malformed data") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get(_SERIALIZATION_MARKER) != _SERIALIZATION_VERSION
        or "value" not in envelope
    ):
        raise ValueError("Redis state contains an unsupported serialization format")
    return envelope["value"]


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
        _validate_delta(delta)
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
        _validate_delta(delta)
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

    def __init__(
        self,
        client: Any,
        *,
        namespace: str = _DEFAULT_REDIS_NAMESPACE,
        fail_mode: FailMode = FailMode.CLOSED,
        close_client: bool = False,
    ) -> None:
        _validate_namespace(namespace)
        self._client = client
        self._namespace = namespace
        self._fail_mode = FailMode(fail_mode)
        self._close_client = close_client
        self._closed = False

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        namespace: str = _DEFAULT_REDIS_NAMESPACE,
        fail_mode: FailMode = FailMode.CLOSED,
        socket_connect_timeout: float = 5.0,
        socket_timeout: float = 5.0,
        max_connections: int = 20,
        health_check_interval: float = 30.0,
        **kwargs: Any,
    ) -> Self:
        """Create a pooled backend from a Redis URL without importing Redis eagerly.

        ``redis://`` supports username/password authentication and ``rediss://``
        enables TLS. Additional redis-py connection options may be supplied as
        keyword arguments.
        """
        if not isinstance(url, str):
            raise TypeError("Redis URL must be a string")
        if urlsplit(url).scheme not in {"redis", "rediss", "unix"}:
            raise ValueError("Redis URL must use redis://, rediss://, or unix://")
        _validate_positive_ttl(socket_connect_timeout)
        _validate_positive_ttl(socket_timeout)
        _validate_positive_ttl(health_check_interval)
        if isinstance(max_connections, bool) or not isinstance(max_connections, int):
            raise TypeError("max_connections must be an integer")
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        try:
            from redis.asyncio import Redis
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise ImportError(
                "RedisStateBackend requires the 'redis' extra: pip install 'trustrail[redis]'"
            ) from exc
        options = dict(kwargs)
        options.setdefault("socket_connect_timeout", socket_connect_timeout)
        options.setdefault("socket_timeout", socket_timeout)
        options.setdefault("max_connections", max_connections)
        options.setdefault("health_check_interval", health_check_interval)
        client = Redis.from_url(url, **options)
        return cls(
            client,
            namespace=namespace,
            fail_mode=fail_mode,
            close_client=True,
        )

    @property
    def namespace(self) -> str:
        """Return the non-secret namespace used for physical Redis keys."""
        return self._namespace

    @property
    def fail_mode(self) -> FailMode:
        """Return the behavior used when Redis state cannot be accessed."""
        return self._fail_mode

    def key_for(self, key: str) -> str:
        """Return the versioned, content-free physical Redis key for a logical key."""
        _validate_logical_key(key)
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"{self._namespace}:v{_SERIALIZATION_VERSION}:{digest}"

    def _handle_failure(self, operation: str, error: Exception, fallback: Any) -> Any:
        if self._fail_mode == FailMode.CLOSED:
            raise StateBackendError(
                "Redis state backend operation failed",
                operation=operation,
            ) from error
        logger.warning(
            "Redis state backend %s failed; continuing in fail-open mode",
            operation,
        )
        return fallback

    def _ensure_open(self, operation: str) -> None:
        if self._closed:
            raise StateBackendError(
                "Redis state backend is closed",
                operation=operation,
            )

    async def __aenter__(self) -> Self:
        self._ensure_open("connect")
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close an owned Redis client and its pool; safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        if not self._close_client:
            return
        close = getattr(self._client, "aclose", None)
        if close is None:
            close = getattr(self._client, "close", None)
        if close is None:
            return
        try:
            result = close()
            if result is not None:
                await result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise StateBackendError(
                "Redis state backend shutdown failed",
                operation="close",
            ) from exc

    async def get(self, key: str) -> Any | None:
        self._ensure_open("get")
        redis_key = self.key_for(key)
        try:
            return _decode_value(await self._client.get(redis_key))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return self._handle_failure("get", exc, None)

    async def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None:
        self._ensure_open("set")
        redis_key = self.key_for(key)
        encoded = _encode_value(value)
        if ttl_seconds is not None:
            _validate_positive_ttl(ttl_seconds)
        try:
            if ttl_seconds is None:
                await self._client.set(redis_key, encoded)
            else:
                await self._client.set(
                    redis_key,
                    encoded,
                    px=max(1, math.ceil(ttl_seconds * 1000)),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._handle_failure("set", exc, None)

    async def increment(self, key: str, delta: int = 1) -> int:
        self._ensure_open("increment")
        _validate_delta(delta)
        redis_key = self.key_for(key)
        try:
            result = await self._client.eval(
                _ATOMIC_INCREMENT_WITH_TTL_SCRIPT,
                1,
                redis_key,
                delta,
                0,
            )
            return int(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return int(self._handle_failure("increment", exc, delta))

    async def increment_with_ttl(
        self,
        key: str,
        delta: int = 1,
        ttl_seconds: float = 60.0,
    ) -> int:
        """Atomically increment and initialize TTL with one Redis Lua transaction."""
        self._ensure_open("increment_with_ttl")
        _validate_delta(delta)
        _validate_positive_ttl(ttl_seconds)
        redis_key = self.key_for(key)
        ttl_ms = max(1, math.ceil(ttl_seconds * 1000))
        try:
            result = await self._client.eval(
                _ATOMIC_INCREMENT_WITH_TTL_SCRIPT,
                1,
                redis_key,
                delta,
                ttl_ms,
            )
            return int(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return int(self._handle_failure("increment_with_ttl", exc, delta))

    async def delete(self, key: str) -> None:
        self._ensure_open("delete")
        redis_key = self.key_for(key)
        try:
            await self._client.delete(redis_key)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._handle_failure("delete", exc, None)


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
