"""FastAPI middleware for trustrail.

Requires: pip install trustrail[fastapi]
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from trustrail.models.enums import GuardStage

if TYPE_CHECKING:
    from trustrail.guard import Guard

logger = logging.getLogger("trustrail.fastapi")


class AegisRailMiddleware:
    """Starlette/FastAPI middleware that guards request/response bodies.

    Requires: pip install trustrail[fastapi]
    """

    def __init__(
        self,
        app: Any,
        guard: Guard,
        check_request_body: bool = True,
        check_response_body: bool = False,
        request_stage: GuardStage = GuardStage.USER_INPUT,
        response_stage: GuardStage = GuardStage.LLM_RESPONSE,
        block_status_code: int = 400,
    ) -> None:
        try:
            import starlette.middleware.base  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "FastAPI/Starlette is not installed. Run: pip install trustrail[fastapi]"
            ) from exc

        self.app = app
        self.guard = guard
        self.check_request_body = check_request_body
        self.check_response_body = check_response_body
        self.request_stage = request_stage
        self.response_stage = response_stage
        self.block_status_code = block_status_code

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if self.check_request_body:
            body = await self._read_body(receive)
            text = self._extract_text(body)
            if text:
                result = await self.guard.acheck(text, self.request_stage)
                if result.is_blocked:
                    await self._send_blocked(send, self.block_status_code)
                    return

            async def patched_receive() -> Any:
                return {"type": "http.request", "body": body, "more_body": False}

            await self.app(scope, patched_receive, send)
        else:
            await self.app(scope, receive, send)

    async def _read_body(self, receive: Callable[..., Any]) -> bytes:
        body = b""
        more = True
        while more:
            msg = await receive()
            body += msg.get("body", b"")
            more = msg.get("more_body", False)
        return body

    def _extract_text(self, body: bytes) -> str | None:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                return data.get("message") or data.get("text") or data.get("content")
        except (json.JSONDecodeError, ValueError):
            pass
        return body.decode("utf-8", errors="ignore") if body else None

    async def _send_blocked(self, send: Any, status_code: int) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"error":"Request blocked by trustrail guardrail"}',
            }
        )
