"""Reserve model resources and validate actual output before consumption."""

import asyncio
import gzip

from trustrail import (
    BoundedDecompressor,
    CompressedPayloadRequest,
    CompressionFormat,
    ConsumptionBudgetPolicy,
    ResourceBudgetManager,
    ResourceCompletionRequest,
    ResourceIdentity,
    ResourceOperationKind,
    ResourceReservationRequest,
)


async def main() -> None:
    manager = ResourceBudgetManager(
        ConsumptionBudgetPolicy(
            max_input_tokens=1_024,
            max_output_tokens=256,
            max_session_tokens=4_096,
            max_concurrent_operations_per_principal=1,
        )
    )
    request = ResourceReservationRequest(
        reservation_id="reservation-1",
        identity=ResourceIdentity(
            principal_id="authenticated-user",
            tenant_id="tenant-a",
            session_id="session-1",
            request_id="request-1",
            operation_id="operation-1",
        ),
        kind=ResourceOperationKind.MODEL,
        input_text="Summarize the approved policy.",
        input_tokens=8,
        requested_output_tokens=64,
    )
    lease = await manager.require_reservation(request)

    completed = False
    try:
        # Call the provider with requested_output_tokens and a deadline here.
        provider_output = "The approved policy has been summarized."
        safe_output = await manager.require_completion(
            ResourceCompletionRequest(
                lease_id=lease.lease_id,
                output_text=provider_output,
                output_tokens=10,
            )
        )
        completed = True
        print(safe_output)
    finally:
        # Release concurrency immediately if the provider call or completion
        # validation fails. Completed leases are already released.
        if not completed:
            await manager.cancel(lease.lease_id)

    compressed = gzip.compress(b'{"document":"small reviewed payload"}')
    decompressed = BoundedDecompressor(manager.policy).require(
        CompressedPayloadRequest(
            request_id="compressed-request-1",
            format=CompressionFormat.GZIP,
            payload=compressed,
        )
    )
    print(decompressed.decode())


asyncio.run(main())
