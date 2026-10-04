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

        downstream_receive = receive
        if self.check_request_body:
            body = await self._read_body(receive)
            text = self._extract_text(body)
            if text:
                result = await self.guard.acheck(text, self.request_stage)
                if result.is_blocked:
                    await self._send_blocked(send, self.block_status_code)
                    return

            body_sent = False

            async def patched_receive() -> Any:
                nonlocal body_sent
                if body_sent:
                    return {"type": "http.request", "body": b"", "more_body": False}
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}

            downstream_receive = patched_receive

        if not self.check_response_body:
            await self.app(scope, downstream_receive, send)
            return

        response_start: dict[str, Any] | None = None
        response_body_messages: list[dict[str, Any]] = []

        async def guarded_send(message: dict[str, Any]) -> None:
            nonlocal response_start
            message_type = message.get("type")
            if message_type == "http.response.start":
                response_start = message
                return
            if message_type != "http.response.body":
                await send(message)
                return

            response_body_messages.append(message)
            if message.get("more_body", False):
                return

            body = b"".join(item.get("body", b"") for item in response_body_messages)
            text = self._extract_text(body)
            if text:
                result = await self.guard.acheck(text, self.response_stage)
                if result.is_blocked:
                    await self._send_blocked(
                        send,
                        self.block_status_code,
                        error="Response blocked by trustrail guardrail",
                    )
                    return

            if response_start is not None:
                await send(response_start)
            for body_message in response_body_messages:
                await send(body_message)

        await self.app(scope, downstream_receive, guarded_send)

    async def _read_body(self, receive: Callable[..., Any]) -> bytes:
        body = b""
        more = True
        while more:
            msg = await receive()
            body += msg.get("body", b"")
            more = msg.get("more_body", False)
        return body

    def _extract_text(self, body: bytes) -> str | None:
        if not body:
            return None
        decoded = body.decode("utf-8", errors="ignore")
        try:
            data = json.loads(body)
            if isinstance(data, str):
                return data
            return json.dumps(
                data,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (UnicodeDecodeError, ValueError):
            pass
        return decoded

    async def _send_blocked(
        self,
        send: Any,
        status_code: int,
        *,
        error: str = "Request blocked by trustrail guardrail",
    ) -> None:
        body = json.dumps({"error": error}, separators=(",", ":")).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )
