"""Apply an atomic fixed-window limit using authenticated identity keys."""

import asyncio

from trustrail.state import FixedWindowRateLimiter, MemoryStateBackend, build_state_key


async def main() -> None:
    # MemoryStateBackend is single-process. In a multi-worker deployment use:
    # RedisStateBackend.from_url("redis://localhost:6379/0")
    backend = MemoryStateBackend()
    limiter = FixedWindowRateLimiter(
        backend,
        max_requests=3,
        window_seconds=60,
    )
    key = build_state_key("model-call", "tenant-a", "authenticated-user", "session-7")

    admissions = await asyncio.gather(*(limiter.check(key) for _ in range(5)))
    print(f"Admission decisions: {admissions}")
    print(f"Allowed: {sum(admissions)} of {len(admissions)}")
    assert sum(admissions) == 3


if __name__ == "__main__":
    asyncio.run(main())
