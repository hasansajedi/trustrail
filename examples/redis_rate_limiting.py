"""Share an atomic fixed-window limit across workers with Redis."""

import asyncio
import os

from trustrail import FailMode
from trustrail.state import FixedWindowRateLimiter, RedisStateBackend, build_state_key


async def main() -> None:
    redis_url = os.environ.get("TRUSTRAIL_REDIS_URL")
    if redis_url is None:
        print("Set TRUSTRAIL_REDIS_URL to run the multi-worker Redis example.")
        return
    backend = RedisStateBackend.from_url(
        redis_url,
        namespace="example:guard",
        fail_mode=FailMode.CLOSED,
        socket_connect_timeout=2,
        socket_timeout=2,
        max_connections=20,
    )
    limiter = FixedWindowRateLimiter(backend, max_requests=3, window_seconds=60)
    key = build_state_key("model-call", "tenant-a", "authenticated-user", "session-7")

    try:
        admissions = await asyncio.gather(*(limiter.check(key) for _ in range(5)))
        print(f"Admission decisions: {admissions}")
        print(f"Allowed: {sum(admissions)} of {len(admissions)}")
        assert sum(admissions) == 3
    finally:
        await limiter.reset(key)
        await backend.aclose()


if __name__ == "__main__":
    asyncio.run(main())
