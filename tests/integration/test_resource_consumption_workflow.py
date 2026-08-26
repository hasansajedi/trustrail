"""Integration coverage for bounded model and agent resource consumption."""

from __future__ import annotations

import gzip

import pytest

from trustrail import (
    BoundedDecompressor,
    CompressedPayloadRequest,
    CompressionFormat,
    ConsumptionBudgetPolicy,
    ResourceBudgetError,
    ResourceBudgetManager,
    ResourceCompletionRequest,
    ResourceIdentity,
    ResourceOperationKind,
    ResourceReservationRequest,
)


def _policy() -> ConsumptionBudgetPolicy:
    return ConsumptionBudgetPolicy(
        max_input_chars=1_000,
        max_input_bytes=2_000,
        max_input_tokens=256,
        max_output_chars=2_000,
        max_output_bytes=4_000,
        max_output_tokens=128,
        max_session_tokens=1_000,
        max_concurrent_operations_per_principal=1,
    )


def _request(reservation_id: str, operation_id: str) -> ResourceReservationRequest:
    return ResourceReservationRequest(
        reservation_id=reservation_id,
        identity=ResourceIdentity(
            principal_id="authenticated-user",
            tenant_id="tenant-a",
            session_id="chat-session",
            request_id=reservation_id,
            operation_id=operation_id,
        ),
        kind=ResourceOperationKind.MODEL,
        input_text="Summarize the approved policy.",
        input_tokens=8,
        requested_output_tokens=32,
    )


@pytest.mark.asyncio
async def test_model_call_is_reserved_completed_and_released_end_to_end():
    manager = ResourceBudgetManager(_policy())
    lease = await manager.require_reservation(_request("reservation-1", "operation-1"))

    with pytest.raises(ResourceBudgetError):
        await manager.require_reservation(_request("reservation-2", "operation-2"))

    safe_output = await manager.require_completion(
        ResourceCompletionRequest(
            lease_id=lease.lease_id,
            output_text="The approved policy has been summarized.",
            output_tokens=10,
        )
    )
    next_lease = await manager.require_reservation(_request("reservation-3", "operation-3"))

    assert safe_output == "The approved policy has been summarized."
    assert await manager.cancel(next_lease.lease_id)


def test_compressed_request_is_bounded_before_text_parsing_and_model_reservation():
    decompressor = BoundedDecompressor(_policy())
    compressed = gzip.compress(b'{"question":"Summarize the policy"}')

    payload = decompressor.require(
        CompressedPayloadRequest(
            request_id="upload-1",
            format=CompressionFormat.GZIP,
            payload=compressed,
        )
    )

    assert payload == b'{"question":"Summarize the policy"}'


@pytest.mark.asyncio
async def test_provider_output_overrun_releases_capacity_but_never_returns_output():
    manager = ResourceBudgetManager(_policy())
    lease = await manager.require_reservation(_request("reservation-1", "operation-1"))

    with pytest.raises(ResourceBudgetError) as exc_info:
        await manager.require_completion(
            ResourceCompletionRequest(
                lease_id=lease.lease_id,
                output_text="private generated output" * 100,
                output_tokens=129,
            )
        )

    assert "private generated output" not in exc_info.value.result.model_dump_json()
    replacement = await manager.require_reservation(_request("reservation-2", "operation-2"))
    assert await manager.cancel(replacement.lease_id)
