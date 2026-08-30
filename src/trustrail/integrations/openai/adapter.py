"""OpenAI message/response adapter for trustrail.

Converts between OpenAI message format and trustrail's Message model.
"""

from __future__ import annotations

from typing import Any

from trustrail.exceptions import ConfigurationError
from trustrail.models.core import GuardResult, Message
from trustrail.models.enums import GuardStage

_OPENAI_ROLE_STAGES = {
    "system": GuardStage.SYSTEM_PROMPT,
    "developer": GuardStage.SYSTEM_PROMPT,
    "user": GuardStage.USER_INPUT,
    "assistant": GuardStage.LLM_RESPONSE,
    "tool": GuardStage.TOOL_RESPONSE,
}


def to_guard_messages(openai_messages: list[dict[str, Any]]) -> list[Message]:
    """Convert OpenAI message dicts to trustrail Message objects."""
    result = []
    for msg in openai_messages:
        content = msg.get("content", "")
        if isinstance(content, list):
            # Handle content blocks (vision, etc.)
            text_parts = [
                block.get("text", "")
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            content = " ".join(text_parts)
        result.append(
            Message(
                role=msg.get("role", "user"),
                content=str(content),
                name=msg.get("name"),
                tool_call_id=msg.get("tool_call_id"),
            )
        )
    return result


def from_guard_messages(messages: list[Message]) -> list[dict[str, Any]]:
    """Convert trustrail Message objects back to OpenAI message dicts."""
    result = []
    for msg in messages:
        d: dict[str, Any] = {"role": msg.role, "content": msg.content}
        if msg.name:
            d["name"] = msg.name
        if msg.tool_call_id:
            d["tool_call_id"] = msg.tool_call_id
        result.append(d)
    return result


async def check_openai_messages(
    messages: list[dict[str, Any]],
    guard: Any,  # Guard instance
) -> list[GuardResult]:
    """Check all OpenAI messages and return results."""
    guard_messages = to_guard_messages(messages)
    results = []
    for index, msg in enumerate(guard_messages):
        stage = _OPENAI_ROLE_STAGES.get(msg.role)
        if stage is None:
            raise ConfigurationError(f"Unknown OpenAI message role '{msg.role}' at index {index}")
        result = await guard.acheck(msg.content, stage)
        results.append(result)
    return results


async def protect_openai_messages(
    messages: list[dict[str, Any]],
    guard: Any,  # Guard instance
) -> list[dict[str, Any]]:
    """Protect an OpenAI conversation atomically, raising on any rejection."""
    guard_messages = to_guard_messages(messages)
    safe_messages = guard.protect_messages(guard_messages)
    return from_guard_messages(safe_messages)


async def filter_openai_messages(
    messages: list[dict[str, Any]],
    guard: Any,
) -> list[dict[str, Any]]:
    """Explicitly remove rejected OpenAI messages and return safe entries."""
    guard_messages = to_guard_messages(messages)
    safe_messages = guard.filter_messages(guard_messages)
    return from_guard_messages(safe_messages)


async def protect_openai_response(
    response_text: str,
    guard: Any,  # Guard instance
) -> str:
    """Protect an OpenAI response text."""
    result: str = await guard.aprotect(response_text, GuardStage.LLM_RESPONSE)
    return result
