"""Bypass-oriented security corpus for OWASP AISVS C5 label propagation."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    DataBoundaryKind,
    DataBoundaryRequest,
    DataClassification,
    DataFlowSurface,
    DataHandlingRequirement,
    DataLabelCode,
    DataLabelDestination,
    DataLabelGuard,
    DataLabelJoinRequest,
    DataLabelPropagator,
    DataLabelSigner,
    DataTransformationKind,
    GuardAction,
)

NOW = datetime(2026, 9, 23, 14, tzinfo=UTC)
CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "data_label_propagation.json"
CASES = json.loads(CORPUS_PATH.read_text())
HANDLING = frozenset(
    {
        DataHandlingRequirement.ENCRYPT_IN_TRANSIT,
        DataHandlingRequirement.REDACT_LOGS,
    }
)


def _fixture():
    signer = DataLabelSigner.generate(
        issuer_id="security-classifier",
        allowed_tenant_ids=frozenset({"tenant-a"}),
    )
    source = signer.issue(
        label_id="source-label",
        artifact_id="private-source",
        surface=DataFlowSurface.PROMPT,
        content_digest="a" * 64,
        tenant_id="tenant-a",
        classification=DataClassification.RESTRICTED,
        allowed_purpose_ids=frozenset({"support"}),
        allowed_residencies=frozenset({"eu"}),
        permitted_destination_ids=frozenset({"provider-eu"}),
        permitted_boundary_kinds=frozenset({DataBoundaryKind.PROVIDER_CALL}),
        handling_requirements=HANDLING,
        retention_until=NOW + timedelta(days=7),
        issued_at=NOW,
    )
    derived = DataLabelPropagator(signer, (signer.trusted_key,)).require_join(
        DataLabelJoinRequest(
            request_id="security-join",
            label_id="derived-label",
            artifact_id="private-derived",
            surface=DataFlowSurface.MODEL_OUTPUT,
            content_digest="b" * 64,
            source_labels=(source,),
            transformation=DataTransformationKind.SUMMARIZE,
            issued_at=NOW,
        ),
        now=NOW,
    )
    destination = DataLabelDestination(
        destination_id="provider-eu",
        boundary_kind=DataBoundaryKind.PROVIDER_CALL,
        tenant_id="tenant-a",
        residency="eu",
        supported_classifications=frozenset(DataClassification),
        enforced_handling=HANDLING,
    )
    return signer, source, derived, destination


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_label_bypass_corpus_fails_closed_without_raw_identifiers(case):
    signer, source, derived, destination = _fixture()
    mutation = case["mutation"]
    label = derived
    sources = (source,)
    content_digest = derived.content_digest
    tenant_id = "tenant-a"
    purpose_id = "support"
    requested_retention = None

    if mutation == "missing":
        label = None
        sources = ()
    elif mutation == "signature":
        label = derived.model_copy(update={"signature": "0" * 128})
    elif mutation == "content":
        content_digest = "f" * 64
    elif mutation == "tenant":
        tenant_id = "tenant-b"
    elif mutation == "purpose":
        purpose_id = "advertising"
    elif mutation == "residency":
        destination = destination.model_copy(update={"residency": "us"})
    elif mutation == "destination":
        destination = destination.model_copy(update={"destination_id": "provider-attacker"})
    elif mutation == "classification":
        destination = destination.model_copy(
            update={"supported_classifications": frozenset({DataClassification.PUBLIC})}
        )
    elif mutation == "handling":
        destination = destination.model_copy(update={"enforced_handling": frozenset()})
    elif mutation == "retention":
        requested_retention = NOW + timedelta(days=30)
    elif mutation == "lineage":
        sources = ()
    elif mutation == "downgrade":
        label = derived.model_copy(update={"classification": DataClassification.PUBLIC})

    result = DataLabelGuard((signer.trusted_key,)).authorize(
        DataBoundaryRequest(
            request_id=f"attack-{case['id']}",
            label=label,
            source_labels=sources,
            content_digest=content_digest,
            authenticated_tenant_id=tenant_id,
            purpose_id=purpose_id,
            destination=destination,
            requested_retention_until=requested_retention,
        ),
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert DataLabelCode(case["expected_code"]) in {finding.code for finding in result.findings}
    serialized = result.model_dump_json()
    assert "private-source" not in serialized
    assert "private-derived" not in serialized
    assert "provider-attacker" not in serialized
