"""Integration coverage for a cross-agent, cross-MCP sensitive-data flow."""

from datetime import UTC, datetime, timedelta

from trustrail import (
    DataClassification,
    DataFlowTransformation,
    SensitiveDataDerivationRequest,
    SensitiveDataDestination,
    SensitiveDataFlowGuard,
    SensitiveDataFlowPropagator,
    SensitiveDataFlowSigner,
    SensitiveDataSink,
    SensitiveDataSurface,
    SensitiveDataTransferRequest,
    data_label_reference,
)


def test_retrieval_model_tool_memory_and_second_mcp_server_preserve_flow_policy():
    now = datetime(2026, 10, 18, 15, tzinfo=UTC)
    signer = SensitiveDataFlowSigner.generate(
        issuer_id="flow-control",
        allowed_tenant_ids=frozenset({"tenant-a"}),
    )
    source = signer.issue(
        label_id="retrieval-source",
        artifact_id="customer-record-42",
        surface=SensitiveDataSurface.RETRIEVAL_DOCUMENT,
        content_digest="a" * 64,
        origin_ids=frozenset({"crm-row-42"}),
        origin_trust_domains=frozenset({"crm.internal"}),
        tenant_id="tenant-a",
        user_id="user-42",
        allowed_purpose_ids=frozenset({"support"}),
        sensitivity=DataClassification.CONFIDENTIAL,
        allowed_sink_kinds=frozenset(
            {SensitiveDataSink.MODEL, SensitiveDataSink.MCP_SERVER, SensitiveDataSink.MEMORY}
        ),
        allowed_sink_ids=frozenset({"model-eu", "mcp-support", "memory-tenant-a"}),
        issued_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    propagator = SensitiveDataFlowPropagator(signer, (signer.trusted_key,))
    current = source
    steps = (
        (DataFlowTransformation.RETRIEVE, SensitiveDataSurface.RETRIEVAL_CONTEXT),
        (DataFlowTransformation.MODEL_GENERATE, SensitiveDataSurface.MODEL_OUTPUT),
        (DataFlowTransformation.TOOL_CALL, SensitiveDataSurface.TOOL_ARGUMENT),
        (DataFlowTransformation.TOOL_RESULT, SensitiveDataSurface.TOOL_RESULT),
        (DataFlowTransformation.MEMORY_STORE, SensitiveDataSurface.MEMORY_WRITE),
        (DataFlowTransformation.AGENT_TRANSFER, SensitiveDataSurface.AGENT_MESSAGE),
    )
    for index, (transformation, surface) in enumerate(steps, start=1):
        immediate_parent = current
        current = propagator.require_propagation(
            SensitiveDataDerivationRequest(
                request_id=f"hop-{index}",
                label_id=f"label-{index}",
                artifact_id=f"artifact-{index}",
                surface=surface,
                content_digest=f"{index + 1:x}" * 64,
                source_labels=(current,),
                transformation=transformation,
                issued_at=now,
            ),
            now=now,
        )

    guard = SensitiveDataFlowGuard((signer.trusted_key,))
    result = guard.authorize(
        SensitiveDataTransferRequest(
            request_id="second-mcp-hop",
            label=current,
            source_labels=(immediate_parent,),
            content_digest=current.content_digest,
            authenticated_tenant_id="tenant-a",
            authenticated_user_ref=data_label_reference("user-42"),
            purpose_id="support",
            destination=SensitiveDataDestination(
                sink_id="mcp-support",
                sink_kind=SensitiveDataSink.MCP_SERVER,
                tenant_id="tenant-a",
            ),
        ),
        now=now,
    )

    assert result.is_allowed
    assert current.lineage_depth == len(steps)
    assert len(current.ancestor_label_digests) == len(steps)
