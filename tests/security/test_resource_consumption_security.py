"""Bypass-oriented security corpus for OWASP LLM10:2025."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from trustrail import (
    BoundedDecompressor,
    CompressedPayloadRequest,
    CompressionFormat,
    ConsumptionBudgetPolicy,
    GuardAction,
    ResourceBudgetManager,
    ResourceCompletionRequest,
    ResourceIdentity,
    ResourceLimitCode,
    ResourceOperationKind,
    ResourceReservationRequest,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "resource_consumption.json"
CASES: list[dict[str, str | None]] = json.loads(CORPUS_PATH.read_text())


def _policy() -> ConsumptionBudgetPolicy:
    return ConsumptionBudgetPolicy(
        max_input_chars=100,
        max_input_bytes=120,
        max_input_tokens=20,
        max_output_chars=100,
        max_output_bytes=120,
        max_output_tokens=20,
        max_nesting_depth=4,
        max_decompressed_bytes=2_000,
        max_decompression_ratio=5,
        max_concurrent_operations_per_principal=1,
        max_concurrent_operations_per_tenant=10,
        max_retries_per_operation=1,
        max_tool_actions_per_session=2,
        max_session_tokens=1_000,
        max_requests_per_principal_window=2,
        max_requests_per_tenant_window=3,
    )


def _request(
    number: int,
    *,
    principal: str = "user-1",
    session: str = "session-1",
    operation: str | None = None,
    kind: ResourceOperationKind = ResourceOperationKind.MODEL,
    text: str = "bounded input",
    input_tokens: int = 3,
) -> ResourceReservationRequest:
    return ResourceReservationRequest(
        reservation_id=f"reservation-{number}",
        identity=ResourceIdentity(
            principal_id=principal,
            tenant_id="tenant-1",
            session_id=session,
            request_id=f"request-{number}",
            operation_id=operation or f"operation-{number}",
        ),
        kind=kind,
        input_text=text,
        input_tokens=input_tokens,
        requested_output_tokens=5,
    )


async def _reserve_and_cancel(
    manager: ResourceBudgetManager,
    request: ResourceReservationRequest,
):
    result = await manager.reserve(request)
    if result.lease is not None:
        await manager.cancel(result.lease.lease_id)
    return result


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: str(case["name"]))
async def test_resource_consumption_security_corpus(case: dict[str, str | None]):
    mutation = case["mutation"]
    policy = _policy()

    if mutation in {"compression-ratio", "concatenated-stream"}:
        payload = gzip.compress(b"A" * 1_000)
        if mutation == "concatenated-stream":
            payload = gzip.compress(b"first") + gzip.compress(b"second")
        result = BoundedDecompressor(policy).decompress(
            CompressedPayloadRequest(
                request_id="compressed-request",
                format=CompressionFormat.GZIP,
                payload=payload,
            )
        )
    else:
        manager = ResourceBudgetManager(policy)
        request = _request(1)
        if mutation == "input-bytes":
            request = _request(1, text="é" * 70)
        elif mutation == "input-tokens":
            request = _request(1, input_tokens=21)
        elif mutation == "quoted-brackets":
            request = _request(1, text='{"value":"[[[[[[[[[["}')
        elif mutation == "nesting":
            request = _request(1, text="[" * 5 + "]" * 5)
        elif mutation == "concurrency":
            first = await manager.reserve(request)
            assert first.lease is not None
            request = _request(2)
        elif mutation == "retries":
            for number in (1, 2):
                await _reserve_and_cancel(manager, _request(number, operation="same-operation"))
            request = _request(3, operation="same-operation")
        elif mutation == "tool-loop":
            for number in (1, 2):
                await _reserve_and_cancel(
                    manager,
                    _request(number, kind=ResourceOperationKind.TOOL),
                )
            request = _request(3, kind=ResourceOperationKind.TOOL)
        elif mutation == "principal-window":
            for number in (1, 2):
                await _reserve_and_cancel(
                    manager,
                    _request(number, session=f"session-{number}"),
                )
            request = _request(3, session="session-3")
        elif mutation == "tenant-window":
            for number in (1, 2, 3):
                await _reserve_and_cancel(
                    manager,
                    _request(
                        number,
                        principal=f"user-{number}",
                        session=f"session-{number}",
                    ),
                )
            request = _request(4, principal="user-4", session="session-4")
        elif mutation == "replay":
            await _reserve_and_cancel(manager, request)
        elif mutation == "output-tokens":
            lease = await manager.require_reservation(request)
            result = await manager.complete(
                ResourceCompletionRequest(
                    lease_id=lease.lease_id,
                    output_text="bounded output",
                    output_tokens=21,
                )
            )
            request = None
        if request is not None:
            result = await manager.reserve(request)

    assert result.action == GuardAction(str(case["expected_action"]))
    expected_code = case["expected_code"]
    if expected_code is not None:
        assert ResourceLimitCode(expected_code) in {finding.code for finding in result.findings}
    assert "bounded input" not in result.model_dump_json()
