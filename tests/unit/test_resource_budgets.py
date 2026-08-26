"""Unit tests for OWASP LLM10 typed resource-consumption controls."""

from __future__ import annotations

import gzip
import zlib

import pytest
from pydantic import ValidationError

from trustrail import (
    BoundedDecompressor,
    CompressedPayloadRequest,
    CompressionFormat,
    ConsumptionBudgetPolicy,
    ResourceBudgetError,
    ResourceBudgetManager,
    ResourceCompletionRequest,
    ResourceIdentity,
    ResourceLimitCode,
    ResourceOperationKind,
    ResourceReservationRequest,
)

INPUT = "Summarize the approved policy."


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _policy(**updates: object) -> ConsumptionBudgetPolicy:
    values: dict[str, object] = {
        "max_input_chars": 100,
        "max_input_bytes": 200,
        "max_input_tokens": 50,
        "max_output_chars": 100,
        "max_output_bytes": 200,
        "max_output_tokens": 50,
        "max_nesting_depth": 5,
        "max_session_tokens": 1_000,
        "max_requests_per_principal_window": 100,
        "max_requests_per_tenant_window": 100,
        "max_concurrent_operations_per_principal": 5,
        "max_concurrent_operations_per_tenant": 20,
    }
    values.update(updates)
    return ConsumptionBudgetPolicy(**values)


def _request(
    number: int = 1,
    *,
    principal_id: str = "user-1",
    tenant_id: str = "tenant-1",
    session_id: str = "session-1",
    operation_id: str | None = None,
    kind: ResourceOperationKind = ResourceOperationKind.MODEL,
    input_text: str = INPUT,
    input_tokens: int = 8,
    output_tokens: int = 10,
) -> ResourceReservationRequest:
    return ResourceReservationRequest(
        reservation_id=f"reservation-{number}",
        identity=ResourceIdentity(
            principal_id=principal_id,
            tenant_id=tenant_id,
            session_id=session_id,
            request_id=f"request-{number}",
            operation_id=operation_id or f"operation-{number}",
        ),
        kind=kind,
        input_text=input_text,
        input_tokens=input_tokens,
        requested_output_tokens=output_tokens,
    )


def _codes(result: object) -> set[ResourceLimitCode]:
    return {finding.code for finding in result.findings}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_reserves_and_completes_bounded_model_work_without_serializing_content():
    manager = ResourceBudgetManager(_policy())
    request = _request()

    lease = await manager.require_reservation(request)
    output = await manager.require_completion(
        ResourceCompletionRequest(
            lease_id=lease.lease_id,
            output_text="The policy summary is approved.",
            output_tokens=8,
        )
    )

    assert output == "The policy summary is approved."
    assert INPUT not in request.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("updates", "expected_code"),
    [
        ({"input_text": "a" * 101}, ResourceLimitCode.INPUT_CHARS_EXCEEDED),
        ({"input_text": "é" * 101}, ResourceLimitCode.INPUT_BYTES_EXCEEDED),
        ({"input_tokens": 51}, ResourceLimitCode.INPUT_TOKENS_EXCEEDED),
        ({"output_tokens": 51}, ResourceLimitCode.OUTPUT_TOKENS_EXCEEDED),
        ({"input_text": "[" * 6 + "]" * 6}, ResourceLimitCode.NESTING_DEPTH_EXCEEDED),
    ],
)
async def test_rejects_per_operation_input_and_requested_output_limits(
    updates: dict[str, object],
    expected_code: ResourceLimitCode,
):
    result = await ResourceBudgetManager(_policy()).reserve(_request(**updates))  # type: ignore[arg-type]

    assert result.is_blocked
    assert expected_code in _codes(result)


@pytest.mark.asyncio
async def test_json_string_brackets_do_not_trigger_nesting_limit():
    result = await ResourceBudgetManager(_policy()).reserve(
        _request(input_text='{"text": "[[[[[[[[[["}')
    )

    assert result.is_allowed


@pytest.mark.asyncio
async def test_enforces_principal_and_tenant_concurrency_then_releases_capacity():
    manager = ResourceBudgetManager(
        _policy(
            max_concurrent_operations_per_principal=1,
            max_concurrent_operations_per_tenant=2,
        )
    )
    first = await manager.reserve(_request(1))
    principal_denied = await manager.reserve(_request(2))
    second_principal = await manager.reserve(_request(3, principal_id="user-2"))
    tenant_denied = await manager.reserve(_request(4, principal_id="user-3"))

    assert first.lease is not None
    assert ResourceLimitCode.PRINCIPAL_CONCURRENCY_EXCEEDED in _codes(principal_denied)
    assert second_principal.lease is not None
    assert ResourceLimitCode.TENANT_CONCURRENCY_EXCEEDED in _codes(tenant_denied)

    assert await manager.cancel(first.lease.lease_id)
    allowed_after_release = await manager.reserve(_request(5))
    assert allowed_after_release.is_allowed


@pytest.mark.asyncio
async def test_counts_retries_by_operation_identity_instead_of_caller_reported_number():
    manager = ResourceBudgetManager(_policy(max_retries_per_operation=1))
    for number in (1, 2):
        result = await manager.reserve(_request(number, operation_id="same-operation"))
        assert result.lease is not None
        await manager.cancel(result.lease.lease_id)

    denied = await manager.reserve(_request(3, operation_id="same-operation"))

    assert ResourceLimitCode.RETRY_LIMIT_EXCEEDED in _codes(denied)


@pytest.mark.asyncio
async def test_caps_tool_loop_actions_and_session_token_budget_across_operations():
    tool_manager = ResourceBudgetManager(_policy(max_tool_actions_per_session=2))
    for number in (1, 2):
        result = await tool_manager.reserve(_request(number, kind=ResourceOperationKind.TOOL))
        assert result.lease is not None
        await tool_manager.cancel(result.lease.lease_id)
    loop_denied = await tool_manager.reserve(_request(3, kind=ResourceOperationKind.TOOL))

    token_manager = ResourceBudgetManager(_policy(max_session_tokens=20))
    first = await token_manager.reserve(_request(1, input_tokens=5, output_tokens=5))
    assert first.lease is not None
    await token_manager.cancel(first.lease.lease_id)
    second = await token_manager.reserve(_request(2, input_tokens=5, output_tokens=5))
    assert second.lease is not None
    await token_manager.cancel(second.lease.lease_id)
    token_denied = await token_manager.reserve(_request(3, input_tokens=1, output_tokens=1))

    assert ResourceLimitCode.TOOL_LOOP_LIMIT_EXCEEDED in _codes(loop_denied)
    assert ResourceLimitCode.SESSION_TOKEN_BUDGET_EXCEEDED in _codes(token_denied)


@pytest.mark.asyncio
async def test_session_duration_and_lease_expiration_fail_closed():
    clock = _Clock()
    manager = ResourceBudgetManager(
        _policy(max_session_duration_seconds=10, lease_timeout_seconds=2),
        clock=clock,
    )
    first = await manager.reserve(_request(1))
    assert first.lease is not None
    clock.advance(3)
    expired = await manager.complete(
        ResourceCompletionRequest(
            lease_id=first.lease.lease_id,
            output_text="late",
            output_tokens=1,
        )
    )
    clock.advance(8)
    duration_denied = await manager.reserve(_request(2))

    assert ResourceLimitCode.LEASE_EXPIRED in _codes(expired)
    assert ResourceLimitCode.SESSION_DURATION_EXCEEDED in _codes(duration_denied)


@pytest.mark.asyncio
async def test_detects_distributed_low_rate_abuse_across_session_ids():
    manager = ResourceBudgetManager(
        _policy(
            max_requests_per_principal_window=2,
            max_requests_per_tenant_window=3,
        )
    )
    for number in (1, 2):
        result = await manager.reserve(_request(number, session_id=f"session-{number}"))
        assert result.lease is not None
        await manager.cancel(result.lease.lease_id)
    principal_denied = await manager.reserve(
        _request(3, session_id="session-3", principal_id="user-1")
    )

    third_principal = await manager.reserve(
        _request(4, session_id="session-4", principal_id="user-2")
    )
    assert third_principal.lease is not None
    await manager.cancel(third_principal.lease.lease_id)
    tenant_denied = await manager.reserve(
        _request(5, session_id="session-5", principal_id="user-3")
    )

    assert ResourceLimitCode.PRINCIPAL_RATE_EXCEEDED in _codes(principal_denied)
    assert ResourceLimitCode.TENANT_RATE_EXCEEDED in _codes(tenant_denied)


@pytest.mark.asyncio
async def test_rejects_reservation_replay_and_tracking_capacity_exhaustion():
    manager = ResourceBudgetManager(_policy(max_tracked_sessions=1))
    first_request = _request(1)
    first = await manager.reserve(first_request)
    assert first.lease is not None
    await manager.cancel(first.lease.lease_id)

    replayed = await manager.reserve(first_request)
    capacity = await manager.reserve(_request(2, session_id="different-session"))

    assert ResourceLimitCode.RESERVATION_REPLAYED in _codes(replayed)
    assert ResourceLimitCode.TRACKING_CAPACITY_EXCEEDED in _codes(capacity)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("completion", "expected_code"),
    [
        ({"output_text": "a" * 101, "output_tokens": 1}, ResourceLimitCode.OUTPUT_CHARS_EXCEEDED),
        ({"output_text": "é" * 101, "output_tokens": 1}, ResourceLimitCode.OUTPUT_BYTES_EXCEEDED),
        ({"output_text": "short", "output_tokens": 51}, ResourceLimitCode.OUTPUT_TOKENS_EXCEEDED),
    ],
)
async def test_rejects_actual_output_that_violates_provider_contract(
    completion: dict[str, object],
    expected_code: ResourceLimitCode,
):
    manager = ResourceBudgetManager(_policy())
    lease = await manager.require_reservation(_request())
    result = await manager.complete(
        ResourceCompletionRequest(lease_id=lease.lease_id, **completion)  # type: ignore[arg-type]
    )

    assert expected_code in _codes(result)


@pytest.mark.asyncio
async def test_actual_output_cannot_exceed_smaller_per_operation_reservation():
    manager = ResourceBudgetManager(_policy(max_output_tokens=50))
    lease = await manager.require_reservation(_request(output_tokens=10))

    result = await manager.complete(
        ResourceCompletionRequest(
            lease_id=lease.lease_id,
            output_text="provider ignored its requested limit",
            output_tokens=11,
        )
    )

    assert ResourceLimitCode.OUTPUT_TOKENS_EXCEEDED in _codes(result)
    assert result.findings[0].limit == 10


@pytest.mark.asyncio
async def test_expired_session_state_is_reclaimed_without_evicting_active_leases():
    clock = _Clock()
    manager = ResourceBudgetManager(
        _policy(
            max_tracked_sessions=1,
            max_session_duration_seconds=2,
            lease_timeout_seconds=1,
        ),
        clock=clock,
    )
    first = await manager.require_reservation(_request())
    await manager.cancel(first.lease_id)
    clock.advance(4)

    replacement = await manager.reserve(_request(2, session_id="new-session"))

    assert replacement.is_allowed


@pytest.mark.asyncio
async def test_unknown_lease_and_denial_exception_are_content_free():
    manager = ResourceBudgetManager(_policy())
    unknown = await manager.complete(
        ResourceCompletionRequest(
            lease_id="unknown",
            output_text="private output",
            output_tokens=1,
        )
    )
    assert ResourceLimitCode.LEASE_UNKNOWN in _codes(unknown)

    with pytest.raises(ResourceBudgetError) as exc_info:
        await manager.require_reservation(_request(input_text="secret" * 100))
    assert "secret" not in exc_info.value.result.model_dump_json()


@pytest.mark.parametrize("format", list(CompressionFormat))
def test_bounded_decompressor_allows_single_valid_stream_without_serializing_bytes(
    format: CompressionFormat,
):
    content = b"reviewed payload"
    payload = gzip.compress(content) if format == CompressionFormat.GZIP else zlib.compress(content)
    request = CompressedPayloadRequest(request_id="decompress-1", format=format, payload=payload)

    result = BoundedDecompressor(_policy()).decompress(request)

    assert result.decompressed_payload == content
    assert content.decode() not in result.model_dump_json()


@pytest.mark.parametrize(
    ("payload", "policy", "expected_code"),
    [
        (
            gzip.compress(b"small"),
            _policy(max_compressed_bytes=1),
            ResourceLimitCode.COMPRESSED_BYTES_EXCEEDED,
        ),
        (
            gzip.compress(b"A" * 1_000),
            _policy(max_decompressed_bytes=100),
            ResourceLimitCode.DECOMPRESSED_BYTES_EXCEEDED,
        ),
        (
            gzip.compress(b"A" * 1_000),
            _policy(max_decompression_ratio=2),
            ResourceLimitCode.DECOMPRESSION_RATIO_EXCEEDED,
        ),
        (b"not-gzip", _policy(), ResourceLimitCode.INVALID_COMPRESSED_PAYLOAD),
        (
            gzip.compress(b"first") + gzip.compress(b"second"),
            _policy(),
            ResourceLimitCode.CONCATENATED_COMPRESSED_STREAM,
        ),
    ],
)
def test_bounded_decompressor_rejects_amplification_and_parser_bypasses(
    payload: bytes,
    policy: ConsumptionBudgetPolicy,
    expected_code: ResourceLimitCode,
):
    result = BoundedDecompressor(policy).decompress(
        CompressedPayloadRequest(
            request_id="decompress-attack",
            format=CompressionFormat.GZIP,
            payload=payload,
        )
    )

    assert result.is_blocked
    assert expected_code in _codes(result)


def test_policy_rejects_invalid_limits():
    with pytest.raises(ValidationError):
        ConsumptionBudgetPolicy(max_retries_per_operation=-1)
