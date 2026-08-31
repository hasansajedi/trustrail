"""OpenAI message/response adapter for trustrail.

Converts between OpenAI message format and trustrail's text-oriented Message
model without discarding fields that the guard does not interpret.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from pydantic import PrivateAttr

from trustrail.exceptions import (
    ApprovalRequiredError,
    ConfigurationError,
    GuardrailBlockedError,
)
from trustrail.models.core import GuardResult, Message, RiskScore
from trustrail.models.enums import GuardAction, GuardStage

_OPENAI_ROLE_STAGES = {
    "system": GuardStage.SYSTEM_PROMPT,
    "developer": GuardStage.SYSTEM_PROMPT,
    "user": GuardStage.USER_INPUT,
    "assistant": GuardStage.LLM_RESPONSE,
    "tool": GuardStage.TOOL_RESPONSE,
}

_SAFE_ACTIONS = {
    GuardAction.ALLOW,
    GuardAction.WARN,
    GuardAction.REDACT,
    GuardAction.TRANSFORM,
}

_ACTION_PRIORITY = {
    GuardAction.ALLOW: 0,
    GuardAction.TRANSFORM: 10,
    GuardAction.REDACT: 20,
    GuardAction.WARN: 30,
    GuardAction.RETRY: 40,
    GuardAction.REQUIRE_APPROVAL: 50,
    GuardAction.QUARANTINE: 60,
    GuardAction.BLOCK: 70,
}

_TEXT_BLOCK_FIELDS: dict[str, str] = {
    "text": "text",
    "input_text": "text",
    "output_text": "text",
    "refusal": "refusal",
}


@dataclass(frozen=True)
class _TextSegment:
    path: tuple[str | int, ...]
    value: str
    content_part_index: int | None = None


class _OpenAIMessage(Message):
    """Message projection that retains its source outside audit metadata."""

    _source: dict[str, Any] = PrivateAttr(default_factory=dict)
    _segments: tuple[_TextSegment, ...] = PrivateAttr(default=())
    _projection: str = PrivateAttr(default="")


def _role_and_stage(message: dict[str, Any], *, index: int) -> tuple[str, GuardStage]:
    role = message.get("role", "user")
    if not isinstance(role, str):
        raise ConfigurationError(f"OpenAI message role at index {index} must be a string")
    stage = _OPENAI_ROLE_STAGES.get(role)
    if stage is None:
        raise ConfigurationError(f"Unknown OpenAI message role '{role}' at index {index}")
    return role, stage


def _text_segments(message: dict[str, Any]) -> tuple[_TextSegment, ...]:
    segments: list[_TextSegment] = []
    content = message.get("content")
    if isinstance(content, str):
        segments.append(_TextSegment(path=("content",), value=content))
    elif isinstance(content, list):
        for index, block in enumerate(content):
            if not isinstance(block, dict):
                continue
            block_type = block.get("type")
            field = _TEXT_BLOCK_FIELDS.get(block_type) if isinstance(block_type, str) else None
            if field is not None and isinstance(block.get(field), str):
                segments.append(
                    _TextSegment(
                        path=("content", index, field),
                        value=block[field],
                        content_part_index=index,
                    )
                )

    refusal = message.get("refusal")
    if isinstance(refusal, str):
        segments.append(_TextSegment(path=("refusal",), value=refusal))
    return tuple(segments)


def _text_projection(segments: tuple[_TextSegment, ...]) -> str:
    return "\n".join(segment.value for segment in segments)


def to_guard_messages(openai_messages: list[dict[str, Any]]) -> list[Message]:
    """Create text projections while retaining exact OpenAI source messages.

    ``None`` content and messages containing only non-text parts project to an
    empty string. The original payload is held in a private model attribute, not
    guard context metadata, so an unmodified round trip remains lossless without
    copying message content into audit data.
    """
    result: list[Message] = []
    for index, source in enumerate(openai_messages):
        role, _ = _role_and_stage(source, index=index)
        segments = _text_segments(source)
        projection = _text_projection(segments)
        message = _OpenAIMessage(
            role=role,
            content=projection,
            name=source.get("name"),
            tool_call_id=source.get("tool_call_id"),
        )
        message._source = deepcopy(source)
        message._segments = segments
        message._projection = projection
        result.append(message)
    return result


def _set_path(message: dict[str, Any], path: tuple[str | int, ...], value: str) -> None:
    target: Any = message
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def from_guard_messages(messages: list[Message]) -> list[dict[str, Any]]:
    """Convert trustrail messages back to OpenAI dictionaries.

    Source-backed, unmodified messages round trip exactly. A transformed
    multipart projection is ambiguous when it represents more than one textual
    field, so callers must use ``protect_openai_messages`` for field-preserving
    multipart transformations.
    """
    result: list[dict[str, Any]] = []
    for message in messages:
        if isinstance(message, _OpenAIMessage):
            restored = deepcopy(message._source)
            if message.content != message._projection:
                if len(message._segments) != 1:
                    raise ConfigurationError(
                        "Cannot map a transformed aggregate projection to multiple OpenAI "
                        "text fields; use protect_openai_messages()"
                    )
                _set_path(restored, message._segments[0].path, message.content)
            result.append(restored)
            continue

        converted: dict[str, Any] = {"role": message.role, "content": message.content}
        if message.name is not None:
            converted["name"] = message.name
        if message.tool_call_id is not None:
            converted["tool_call_id"] = message.tool_call_id
        result.append(converted)
    return result


async def _evaluate_message(
    message: dict[str, Any],
    *,
    index: int,
    guard: Any,
) -> tuple[tuple[_TextSegment, ...], list[GuardResult], str, GuardStage]:
    role, stage = _role_and_stage(message, index=index)
    segments = _text_segments(message)
    scan_segments = segments or (_TextSegment(path=(), value=""),)
    results: list[GuardResult] = []
    for segment_index, segment in enumerate(scan_segments):
        metadata: dict[str, Any] = {
            "message_index": index,
            "message_role": role,
            "text_segment_index": segment_index,
        }
        if segment.content_part_index is not None:
            metadata["content_part_index"] = segment.content_part_index
        tool_call_id = message.get("tool_call_id")
        if isinstance(tool_call_id, str):
            metadata["tool_call_id"] = tool_call_id
        result = await guard.acheck(segment.value, stage, metadata=metadata)
        results.append(result)
    return segments, results, role, stage


def _combined_result(results: list[GuardResult]) -> GuardResult:
    if len(results) == 1:
        return results[0]
    highest = max(results, key=lambda item: _ACTION_PRIORITY[item.action])
    findings = [finding for result in results for finding in result.findings]
    output_values = [result.output_value for result in results]
    transformed = (
        "\n".join(output_values)
        if any(result.output_value != result.value for result in results)
        else None
    )
    max_score = max(result.score.value for result in results)
    score = RiskScore(
        value=max_score,
        block_at=highest.score.block_at,
        warn_at=highest.score.warn_at,
    )
    return highest.model_copy(
        update={
            "findings": findings,
            "score": score,
            "value": "\n".join(result.value for result in results),
            "transformed_value": transformed,
            "input_length": sum(result.input_length or 0 for result in results),
            "latency_ms": sum(result.latency_ms for result in results),
            "rules_evaluated": sum(result.rules_evaluated for result in results),
        }
    )


def _raise_for_rejection(
    results: list[GuardResult],
    *,
    message: dict[str, Any],
    message_index: int,
    role: str,
    stage: GuardStage,
) -> None:
    for segment_index, result in enumerate(results):
        details = {
            "message_index": message_index,
            "message_role": role,
            "text_segment_index": segment_index,
            "tool_call_id": message.get("tool_call_id"),
        }
        if result.action == GuardAction.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(
                f"OpenAI message at index {message_index} with role '{role}' requires approval",
                stage=stage,
                request_id=result.context.request_id if result.context else None,
                findings=result.findings,
                message_index=message_index,
                message_role=role,
                text_segment_index=segment_index,
                tool_call_id=message.get("tool_call_id"),
            )
        if result.action not in _SAFE_ACTIONS:
            raise GuardrailBlockedError(
                f"OpenAI message at index {message_index} with role '{role}' blocked",
                stage=stage,
                findings=result.findings,
                score=result.score.value,
                action=result.action.value,
                **details,
            )


def _apply_results(
    message: dict[str, Any],
    segments: tuple[_TextSegment, ...],
    results: list[GuardResult],
) -> dict[str, Any]:
    protected = deepcopy(message)
    for segment, result in zip(segments, results, strict=False):
        if result.output_value != segment.value:
            _set_path(protected, segment.path, result.output_value)
    return protected


async def check_openai_messages(
    messages: list[dict[str, Any]],
    guard: Any,
) -> list[GuardResult]:
    """Check every textual field and return one combined result per message."""
    results: list[GuardResult] = []
    for index, message in enumerate(messages):
        _, message_results, _, _ = await _evaluate_message(message, index=index, guard=guard)
        results.append(_combined_result(message_results))
    return results


async def protect_openai_messages(
    messages: list[dict[str, Any]],
    guard: Any,
) -> list[dict[str, Any]]:
    """Protect textual fields asynchronously and reject atomically."""
    protected: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        segments, results, role, stage = await _evaluate_message(
            message,
            index=index,
            guard=guard,
        )
        _raise_for_rejection(
            results,
            message=message,
            message_index=index,
            role=role,
            stage=stage,
        )
        protected.append(_apply_results(message, segments, results))
    return protected


async def filter_openai_messages(
    messages: list[dict[str, Any]],
    guard: Any,
) -> list[dict[str, Any]]:
    """Explicitly remove messages with any rejected textual field."""
    filtered: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        segments, results, _, _ = await _evaluate_message(message, index=index, guard=guard)
        if all(result.action in _SAFE_ACTIONS for result in results):
            filtered.append(_apply_results(message, segments, results))
    return filtered


async def protect_openai_response(
    response_text: str,
    guard: Any,
) -> str:
    """Protect an OpenAI response text."""
    result: str = await guard.aprotect(response_text, GuardStage.LLM_RESPONSE)
    return result
