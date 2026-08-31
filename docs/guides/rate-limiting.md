# Rate limiting

`FixedWindowRateLimiter` provides atomic, application-level request limits. The
first request starts a fixed window; subsequent requests increment the same
counter without changing its expiry. A request at the exact expiration boundary
starts a new window. Blocked requests are counted but never extend the window.

Use the in-memory backend only for a single application process:

```python
from trustrail.state import FixedWindowRateLimiter, MemoryStateBackend

limiter = FixedWindowRateLimiter(
    MemoryStateBackend(),
    max_requests=20,
    window_seconds=60,
)

if not await limiter.check(bucket_key):
    raise RuntimeError("Rate limit exceeded")
```

For multiple workers or application instances, install `trustrail[redis]` and
share a Redis backend. Incrementing the counter and assigning its initial TTL
happen in one Redis transaction:

```python
from trustrail.state import FixedWindowRateLimiter, RedisStateBackend

backend = RedisStateBackend.from_url("redis://localhost:6379/0")
limiter = FixedWindowRateLimiter(backend, max_requests=20, window_seconds=60)
```

Backend errors and task cancellation propagate to the caller. Treat backend
failure as denial (fail closed) at the application boundary unless your threat
model explicitly permits degraded operation. `RateLimiter` remains available as
a compatibility alias, but its behavior is fixed-window, not sliding-window.

## Construct safe bucket keys

Build keys from authenticated server-side identity, never from a model-provided
identifier. Include every isolation boundary required by the policy—normally
tenant, user, session, and operation scope. Canonically encode or hash the tuple
so delimiters in one field cannot collide with another field:

```python
import hashlib
import json


def rate_limit_bucket(tenant_id: str, user_id: str, session_id: str, scope: str) -> str:
    identity = json.dumps(
        [tenant_id, user_id, session_id, scope],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(identity).hexdigest()
```

Do not omit the tenant identifier in multi-tenant deployments: identical user or
session identifiers must not share a bucket across tenants. Avoid putting raw
personal data or secrets in keys because Redis keys and operational telemetry may
be visible to administrators. Use separate limiter instances or include a stable
scope component when policies differ between model calls, retrieval, and tools.
