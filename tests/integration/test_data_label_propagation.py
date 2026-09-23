"""End-to-end label flow through retrieval, model, tools, storage, logs, and delivery."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    DataBoundaryKind,
    DataBoundaryRequest,
    DataClassification,
    DataFlowSurface,
    DataHandlingRequirement,
    DataLabelDestination,
    DataLabelGuard,
    DataLabelJoinRequest,
    DataLabelPropagator,
    DataLabelSigner,
    DataTransformationKind,
    MemoryDataLabelAuditSink,
)

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
DESTINATIONS = {
    DataBoundaryKind.RETRIEVAL_ASSEMBLY: "rag-assembler-eu",
    DataBoundaryKind.PROVIDER_CALL: "model-provider-eu",
    DataBoundaryKind.PERSISTENCE: "object-store-eu",
    DataBoundaryKind.LOGGING: "audit-logger-eu",
    DataBoundaryKind.TOOL_INVOCATION: "case-tool-eu",
    DataBoundaryKind.OUTPUT_DELIVERY: "support-ui-eu",
}
HANDLING = frozenset(
    {
        DataHandlingRequirement.ENCRYPT_IN_TRANSIT,
        DataHandlingRequirement.ENCRYPT_AT_REST,
        DataHandlingRequirement.REDACT_LOGS,
        DataHandlingRequirement.NO_TRAINING,
    }
)


def _destination(kind: DataBoundaryKind) -> DataLabelDestination:
    return DataLabelDestination(
        destination_id=DESTINATIONS[kind],
        boundary_kind=kind,
        tenant_id="tenant-a",
        residency="eu",
        supported_classifications=frozenset(DataClassification),
        enforced_handling=HANDLING,
    )


def test_labels_propagate_and_enforce_every_required_boundary():
    signer = DataLabelSigner.generate(
        issuer_id="classification-control-plane",
        allowed_tenant_ids=frozenset({"tenant-a"}),
    )
    common = {
        "tenant_id": "tenant-a",
        "allowed_purpose_ids": frozenset({"support"}),
        "allowed_residencies": frozenset({"eu"}),
        "permitted_destination_ids": frozenset(DESTINATIONS.values()),
        "permitted_boundary_kinds": frozenset(DataBoundaryKind),
        "handling_requirements": HANDLING,
        "issued_at": NOW,
    }
    prompt = signer.issue(
        label_id="prompt-label",
        artifact_id="prompt-42",
        surface=DataFlowSurface.PROMPT,
        content_digest="a" * 64,
        classification=DataClassification.CONFIDENTIAL,
        retention_until=NOW + timedelta(days=14),
        **common,
    )
    retrieved = signer.issue(
        label_id="retrieved-label",
        artifact_id="document-17",
        surface=DataFlowSurface.RETRIEVED_DOCUMENT,
        content_digest="b" * 64,
        classification=DataClassification.RESTRICTED,
        retention_until=NOW + timedelta(days=7),
        **common,
    )
    audit = MemoryDataLabelAuditSink()
    propagator = DataLabelPropagator(
        signer,
        (signer.trusted_key,),
        audit_sink=audit,
    )
    guard = DataLabelGuard((signer.trusted_key,), audit_sink=audit)
    context = propagator.require_join(
        DataLabelJoinRequest(
            request_id="join-retrieval-context",
            label_id="context-label",
            artifact_id="context-42",
            surface=DataFlowSurface.RETRIEVAL_CONTEXT,
            content_digest="c" * 64,
            source_labels=(prompt, retrieved),
            transformation=DataTransformationKind.COMBINE,
            issued_at=NOW,
        ),
        now=NOW,
    )

    for index, boundary in enumerate(
        (DataBoundaryKind.RETRIEVAL_ASSEMBLY, DataBoundaryKind.PROVIDER_CALL)
    ):
        permit = guard.require(
            DataBoundaryRequest(
                request_id=f"context-boundary-{index}",
                label=context,
                source_labels=(prompt, retrieved),
                content_digest=context.content_digest,
                authenticated_tenant_id="tenant-a",
                purpose_id="support",
                destination=_destination(boundary),
            ),
            now=NOW,
        )
        assert permit.boundary_kind == boundary

    output = propagator.require_join(
        DataLabelJoinRequest(
            request_id="join-model-output",
            label_id="output-label",
            artifact_id="output-42",
            surface=DataFlowSurface.MODEL_OUTPUT,
            content_digest="d" * 64,
            source_labels=(context,),
            transformation=DataTransformationKind.SUMMARIZE,
            issued_at=NOW,
        ),
        now=NOW,
    )
    assert output.classification == DataClassification.RESTRICTED
    assert output.retention_until == NOW + timedelta(days=7)

    output_boundaries = (
        DataBoundaryKind.PERSISTENCE,
        DataBoundaryKind.LOGGING,
        DataBoundaryKind.TOOL_INVOCATION,
        DataBoundaryKind.OUTPUT_DELIVERY,
    )
    for index, boundary in enumerate(output_boundaries):
        permit = guard.require(
            DataBoundaryRequest(
                request_id=f"output-boundary-{index}",
                label=output,
                source_labels=(context,),
                content_digest=output.content_digest,
                authenticated_tenant_id="tenant-a",
                purpose_id="support",
                destination=_destination(boundary),
                requested_retention_until=(
                    NOW + timedelta(days=7) if boundary == DataBoundaryKind.PERSISTENCE else None
                ),
            ),
            now=NOW,
        )
        assert permit.boundary_kind == boundary

    assert len(audit.events) == 8
    assert all(event.action.value == "allow" for event in audit.events)
