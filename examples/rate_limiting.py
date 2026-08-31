"""Apply an atomic fixed-window limit using authenticated identity keys."""

import asyncio
import hashlib
import json

from trustrail.state import FixedWindowRateLimiter, MemoryStateBackend


def bucket_key(tenant_id: str, user_id: str, session_id: str, scope: str) -> str:
    """Hash a canonical identity tuple to avoid collisions and exposed PII."""
    encoded = json.dumps(
        [tenant_id, user_id, session_id, scope],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


async def main() -> None:
    # MemoryStateBackend is single-process. In a multi-worker deployment use:
    # RedisStateBackend.from_url("redis://localhost:6379/0")
    backend = MemoryStateBackend()
    limiter = FixedWindowRateLimiter(
        backend,
        max_requests=3,
        window_seconds=60,
    )
    key = bucket_key("tenant-a", "authenticated-user", "session-7", "model-call")

    admissions = await asyncio.gather(*(limiter.check(key) for _ in range(5)))
    print(f"Admission decisions: {admissions}")
    print(f"Allowed: {sum(admissions)} of {len(admissions)}")
    assert sum(admissions) == 3


if __name__ == "__main__":
    asyncio.run(main())
