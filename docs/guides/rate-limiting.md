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
import os

from trustrail import FailMode
from trustrail.state import FixedWindowRateLimiter, RedisStateBackend, build_state_key

backend = RedisStateBackend.from_url(
    os.environ["TRUSTRAIL_REDIS_URL"],
    namespace="myapp:guard",
    fail_mode=FailMode.CLOSED,
    socket_connect_timeout=2,
    socket_timeout=2,
    max_connections=20,
)
limiter = FixedWindowRateLimiter(backend, max_requests=20, window_seconds=60)
bucket_key = build_state_key("model-call", tenant_id, user_id, session_id)

try:
    allowed = await limiter.check(bucket_key)
finally:
    await backend.aclose()
```

Create one backend at process startup, share it across requests, and call
`aclose()` during process shutdown. The Redis client owns a connection pool;
`max_connections` bounds each process's pool. Use authenticated `redis://` URLs or
`rediss://` with CA/certificate options for TLS. redis-py reconnects on later
operations after a broken pooled connection.

The backend defaults to `FailMode.CLOSED`: unavailable or malformed Redis state
raises `StateBackendError`, so the application can deny the protected operation.
`FailMode.OPEN` emits a content-free warning and uses operation-specific fallbacks:
reads return `None`, writes/deletes become no-ops, and increments return `delta`.
That permits availability but can admit every request while Redis is down, so use
it only when your threat model explicitly accepts that weakening. Task
cancellation always propagates. `RateLimiter` remains a compatibility alias, but
its behavior is fixed-window, not sliding-window.

The backend maps logical keys to
`<namespace>:v1:<sha256(logical-key)>` and serializes values in a versioned JSON
envelope. Deploy a new namespace when intentionally starting with empty state;
never mix arbitrary application values into TrustRail's namespace.

## Construct safe bucket keys

Build keys from authenticated server-side identity, never from a model-provided
identifier. Include every isolation boundary required by the policy—normally
tenant, user, session, and operation scope. Canonically encode or hash the tuple
so delimiters in one field cannot collide with another field:

```python
from trustrail.state import build_state_key

bucket_key = build_state_key(
    "model-call",
    authenticated_tenant_id,
    authenticated_user_id,
    authenticated_session_id,
)
```

Do not omit the tenant identifier in multi-tenant deployments: identical user or
session identifiers must not share a bucket across tenants. Avoid putting raw
personal data or secrets in keys because Redis keys and operational telemetry may
be visible to administrators. Use separate limiter instances or include a stable
scope component when policies differ between model calls, retrieval, and tools.

## Multi-worker FastAPI lifecycle

Every worker creates one pool, while all workers use the same Redis namespace and
therefore enforce one shared limit:

```python
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request

from trustrail.state import FixedWindowRateLimiter, RedisStateBackend, build_state_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    backend = RedisStateBackend.from_url(
        os.environ["TRUSTRAIL_REDIS_URL"],
        namespace="chat-api:guard",
        max_connections=20,
    )
    app.state.redis_backend = backend
    app.state.model_limiter = FixedWindowRateLimiter(backend, 100, 60)
    try:
        yield
    finally:
        await backend.aclose()


app = FastAPI(lifespan=lifespan)


@app.post("/chat")
async def chat(request: Request):
    identity = request.state.authenticated_identity
    key = build_state_key("model-call", identity.tenant_id, identity.user_id)
    if not await request.app.state.model_limiter.check(key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return {"accepted": True}
```

Run multiple workers with the same `TRUSTRAIL_REDIS_URL`:

```bash
uvicorn app:app --workers 4
```
