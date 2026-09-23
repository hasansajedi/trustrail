"""Unit tests for end-to-end classification-label propagation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from trustrail import (
    DataBoundaryKind,
    DataBoundaryRequest,
    DataClassification,
    DataFlowSurface,
    DataHandlingRequirement,
    DataLabelCode,
    DataLabelDestination,
    DataLabelError,
    DataLabelGuard,
    DataLabelJoinRequest,
    DataLabelPropagator,
    DataLabelSigner,
    DataTransformationKind,
    GuardAction,
    MemoryDataLabelAuditSink,
)

NOW = datetime(2026, 9, 23, 10, tzinfo=UTC)
ALL_BOUNDARIES = frozenset(DataBoundaryKind)
ALL_CLASSIFICATIONS = frozenset(DataClassification)


def _signer(issuer_id: str = "classification-service") -> DataLabelSigner:
    return DataLabelSigner.generate(
        issuer_id=issuer_id,
        allowed_tenant_ids=frozenset({"tenant-a"}),
    )


def _label(signer: DataLabelSigner, **updates):
    values = {
        "label_id": "label-a",
        "artifact_id": "artifact-a",
        "surface": DataFlowSurface.PROMPT,
        "content_digest": "a" * 64,
        "tenant_id": "tenant-a",
        "classification": DataClassification.CONFIDENTIAL,
        "allowed_purpose_ids": frozenset({"support", "fraud-review"}),
        "allowed_residencies": frozenset({"eu", "de"}),
        "permitted_destination_ids": frozenset({"provider-eu", "support-ui"}),
        "permitted_boundary_kinds": ALL_BOUNDARIES,
        "handling_requirements": frozenset({DataHandlingRequirement.ENCRYPT_IN_TRANSIT}),
        "retention_until": NOW + timedelta(days=20),
        "issued_at": NOW,
    }
    values.update(updates)
    return signer.issue(**values)


def _destination(**updates):
    values = {
        "destination_id": "provider-eu",
        "boundary_kind": DataBoundaryKind.PROVIDER_CALL,
        "tenant_id": "tenant-a",
        "residency": "eu",
        "supported_classifications": ALL_CLASSIFICATIONS,
        "enforced_handling": frozenset(
            {
                DataHandlingRequirement.ENCRYPT_IN_TRANSIT,
                DataHandlingRequirement.ENCRYPT_AT_REST,
                DataHandlingRequirement.REDACT_LOGS,
            }
        ),
    }
    values.update(updates)
    return DataLabelDestination(**values)


def _request(label, **updates):
    values = {
        "request_id": "boundary-a",
        "label": label,
        "content_digest": label.content_digest if label is not None else "a" * 64,
        "authenticated_tenant_id": "tenant-a",
        "purpose_id": "support",
        "destination": _destination(),
    }
    values.update(updates)
    return DataBoundaryRequest(**values)


def test_origin_label_round_trip_authorizes_exact_provider_boundary():
    signer = _signer()
    label = _label(signer)
    audit = MemoryDataLabelAuditSink()
    guard = DataLabelGuard((signer.trusted_key,), audit_sink=audit)

    result = guard.authorize(_request(label), now=NOW)

    assert result.action == GuardAction.ALLOW
    assert result.permit is not None
    assert result.evidence is not None
    assert audit.events == [result.audit_event]
    serialized = result.audit_event.model_dump_json()
    assert "tenant-a" not in serialized
    assert "provider-eu" not in serialized
    assert "artifact-a" not in serialized


def test_missing_and_tampered_labels_fail_closed():
    signer = _signer()
    guard = DataLabelGuard((signer.trusted_key,))

    missing = guard.authorize(_request(None), now=NOW)
    tampered_label = _label(signer).model_copy(
        update={"allowed_purpose_ids": frozenset({"advertising"})}
    )
    tampered = guard.authorize(
        _request(tampered_label, purpose_id="advertising"),
        now=NOW,
    )

    assert missing.findings[0].code == DataLabelCode.LABEL_MISSING
    assert tampered.findings[0].code == DataLabelCode.LABEL_SIGNATURE_INVALID


def test_conservative_join_uses_strictest_source_constraints():
    signer = _signer()
    first = _label(
        signer,
        label_id="source-a",
        classification=DataClassification.INTERNAL,
        handling_requirements=frozenset({DataHandlingRequirement.ENCRYPT_IN_TRANSIT}),
        retention_until=NOW + timedelta(days=20),
    )
    second = _label(
        signer,
        label_id="source-b",
        artifact_id="artifact-b",
        content_digest="b" * 64,
        classification=DataClassification.RESTRICTED,
        allowed_purpose_ids=frozenset({"support"}),
        allowed_residencies=frozenset({"eu"}),
        permitted_destination_ids=frozenset({"provider-eu"}),
        permitted_boundary_kinds=frozenset(
            {DataBoundaryKind.PROVIDER_CALL, DataBoundaryKind.PERSISTENCE}
        ),
        handling_requirements=frozenset(
            {
                DataHandlingRequirement.ENCRYPT_AT_REST,
                DataHandlingRequirement.REDACT_LOGS,
            }
        ),
        retention_until=NOW + timedelta(days=5),
    )
    propagator = DataLabelPropagator(signer, (signer.trusted_key,))

    result = propagator.join(
        DataLabelJoinRequest(
            request_id="join-a",
            label_id="derived-a",
            artifact_id="context-a",
            surface=DataFlowSurface.RETRIEVAL_CONTEXT,
            content_digest="c" * 64,
            source_labels=(first, second),
            transformation=DataTransformationKind.COMBINE,
            issued_at=NOW,
        ),
        now=NOW,
    )

    assert result.is_allowed
    assert result.derived_label is not None
    joined = result.derived_label
    assert joined.classification == DataClassification.RESTRICTED
    assert joined.allowed_purpose_ids == frozenset({"support"})
    assert joined.allowed_residencies == frozenset({"eu"})
    assert joined.permitted_destination_ids == frozenset({"provider-eu"})
    assert joined.retention_until == NOW + timedelta(days=5)
    assert joined.handling_requirements == frozenset(
        {
            DataHandlingRequirement.ENCRYPT_IN_TRANSIT,
            DataHandlingRequirement.ENCRYPT_AT_REST,
            DataHandlingRequirement.REDACT_LOGS,
        }
    )
    assert joined.source_label_digests == tuple(sorted((first.label_digest, second.label_digest)))


def test_join_rejects_tenant_and_authority_conflicts():
    signer = _signer()
    other_signer = DataLabelSigner.generate(
        issuer_id="other-classifier",
        allowed_tenant_ids=frozenset({"tenant-b"}),
    )
    first = _label(signer)
    second = _label(
        other_signer,
        label_id="label-b",
        artifact_id="artifact-b",
        content_digest="b" * 64,
        tenant_id="tenant-b",
        allowed_purpose_ids=frozenset({"advertising"}),
    )
    propagator = DataLabelPropagator(
        signer,
        (signer.trusted_key, other_signer.trusted_key),
    )

    result = propagator.join(
        DataLabelJoinRequest(
            request_id="join-conflict",
            label_id="derived-conflict",
            artifact_id="context-conflict",
            surface=DataFlowSurface.RETRIEVAL_CONTEXT,
            content_digest="c" * 64,
            source_labels=(first, second),
            transformation=DataTransformationKind.COMBINE,
            issued_at=NOW,
        ),
        now=NOW,
    )

    codes = {finding.code for finding in result.findings}
    assert result.action == GuardAction.BLOCK
    assert DataLabelCode.TENANT_CONFLICT in codes
    assert DataLabelCode.LABEL_CONFLICT in codes


@pytest.mark.parametrize(
    ("request_update", "destination_update", "expected"),
    [
        ({"content_digest": "f" * 64}, {}, DataLabelCode.CONTENT_BINDING_INVALID),
        ({"authenticated_tenant_id": "tenant-b"}, {}, DataLabelCode.TENANT_CONFLICT),
        ({"purpose_id": "advertising"}, {}, DataLabelCode.PURPOSE_DENIED),
        ({}, {"residency": "us"}, DataLabelCode.RESIDENCY_DENIED),
        ({}, {"destination_id": "unknown-provider"}, DataLabelCode.DESTINATION_DENIED),
        (
            {},
            {"supported_classifications": frozenset({DataClassification.PUBLIC})},
            DataLabelCode.CLASSIFICATION_UNSUPPORTED,
        ),
        (
            {},
            {"enforced_handling": frozenset()},
            DataLabelCode.HANDLING_UNSUPPORTED,
        ),
        (
            {"requested_retention_until": NOW + timedelta(days=30)},
            {},
            DataLabelCode.RETENTION_DENIED,
        ),
    ],
)
def test_boundary_rejects_incompatible_destination(
    request_update,
    destination_update,
    expected,
):
    signer = _signer()
    label = _label(signer)
    request = _request(
        label,
        destination=_destination(**destination_update),
        **request_update,
    )

    result = DataLabelGuard((signer.trusted_key,)).authorize(request, now=NOW)

    assert result.action == GuardAction.BLOCK
    assert expected in {finding.code for finding in result.findings}


def test_derived_label_requires_exact_lineage_at_boundary():
    signer = _signer()
    source = _label(signer)
    derived = DataLabelPropagator(signer, (signer.trusted_key,)).require_join(
        DataLabelJoinRequest(
            request_id="join-lineage",
            label_id="derived-lineage",
            artifact_id="summary-a",
            surface=DataFlowSurface.MODEL_OUTPUT,
            content_digest="d" * 64,
            source_labels=(source,),
            transformation=DataTransformationKind.SUMMARIZE,
            issued_at=NOW,
        ),
        now=NOW,
    )
    guard = DataLabelGuard((signer.trusted_key,))

    missing = guard.authorize(_request(derived), now=NOW)
    exact = guard.authorize(_request(derived, source_labels=(source,)), now=NOW)

    assert missing.findings[0].code == DataLabelCode.LINEAGE_MISSING
    assert exact.is_allowed


def test_require_raises_typed_error():
    signer = _signer()
    guard = DataLabelGuard((signer.trusted_key,))

    with pytest.raises(DataLabelError) as exc_info:
        guard.require(_request(None), now=NOW)

    assert exc_info.value.result.findings[0].code == DataLabelCode.LABEL_MISSING
