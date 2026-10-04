# FastAPI integration

```bash
python -m pip install "trustrail[fastapi]"
```

## Middleware

The ASGI middleware checks plain text and every field in JSON request bodies
before the endpoint runs. Scanning the complete JSON value prevents one safe
field from shadowing unsafe content in another field.

```python
from fastapi import FastAPI

from trustrail import Guard
from trustrail.integrations.fastapi import AegisRailMiddleware

app = FastAPI()
app.add_middleware(
    AegisRailMiddleware,
    guard=Guard.balanced(),
    check_request_body=True,
    check_response_body=True,
    block_status_code=400,
)
```

Blocked requests receive `{"error": "Request blocked by trustrail guardrail"}`.
When `check_response_body=True`, the middleware buffers the complete response and
checks it atomically before sending any content to the client. Leave response
checking disabled for streaming endpoints and guard their chunks with
`Guard.stream(...)` instead.

## Dependency injection

```python
from fastapi import Depends
from trustrail import Guard, GuardStage
from trustrail.integrations.fastapi import get_guard
from trustrail.integrations.fastapi.depends import configure_guard

configure_guard(Guard.strict())

@app.post("/chat")
async def chat(message: str, guard: Guard = Depends(get_guard)) -> dict[str, str]:
    safe = await guard.aprotect(message, GuardStage.USER_INPUT)
    return {"message": safe}
```

Set request-size limits at the proxy or ASGI server as well; middleware must read
the request body before evaluating it.
