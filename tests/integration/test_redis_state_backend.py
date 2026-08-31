"""Contract tests against a real Redis service when one is configured."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest

from trustrail.state import RedisStateBackend, StateBackendError

REDIS_URL = os.environ.get("TRUSTRAIL_TEST_REDIS_URL")

pytestmark = pytest.mark.skipif(
    REDIS_URL is None,
    reason="set TRUSTRAIL_TEST_REDIS_URL to run Redis integration tests",
)


@pytest.mark.asyncio
async def test_real_redis_contract_concurrency_expiration_and_malformed_data():
    assert REDIS_URL is not None
    backend = RedisStateBackend.from_url(
        REDIS_URL,
        namespace=f"trustrail:test:{uuid.uuid4().hex}",
        socket_connect_timeout=2,
        socket_timeout=2,
        max_connections=64,
    )
    keys = ["record", "counter", "expiring-counter", "malformed"]
    try:
        await backend.set("record", {"trusted": True}, ttl_seconds=0.1)
        assert await backend.get("record") == {"trusted": True}

        values = await asyncio.gather(
            *(backend.increment_with_ttl("counter", ttl_seconds=2) for _ in range(50))
        )
        assert sorted(values) == list(range(1, 51))
        assert await backend.get("counter") == 50
        assert await backend.increment_with_ttl("expiring-counter", ttl_seconds=0.1) == 1

        await asyncio.sleep(0.15)
        assert await backend.get("record") is None
        assert await backend.get("expiring-counter") is None
        assert await backend.get("counter") == 50

        await backend._client.set(backend.key_for("malformed"), "not-versioned-json")
        with pytest.raises(StateBackendError):
            await backend.get("malformed")
    finally:
        for key in keys:
            await backend.delete(key)
        await backend.aclose()
