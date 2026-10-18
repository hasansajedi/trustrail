"""Bypass corpus for OWASP MCP10 sensitive-data flow tracking."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    DataClassification,
    DataFlowTransformation,
    GuardAction,
    SensitiveDataDerivationRequest,
    SensitiveDataDestination,
    SensitiveDataFlowCode,
    SensitiveDataFlowGuard,
    SensitiveDataFlowPropagator,
    SensitiveDataFlowSigner,
    SensitiveDataSink,
    SensitiveDataSurface,
    SensitiveDataTransferRequest,
    data_label_reference,
)

NOW = datetime(2026, 10, 18, 16, tzinfo=UTC)
CORPUS = json.loads(
    (Path(__file__).parent.parent / "security_corpus" / "sensitive_data_flow.json").read_text()
)


def _fixture():
    signer = SensitiveDataFlowSigner.generate(
        issuer_id="flow-control",
        allowed_tenant_ids=frozenset({"tenant-a"}),
    )
    source = signer.issue(
        label_id="private-source-label",
        artifact_id="private-record-42",
        surface=SensitiveDataSurface.PROMPT,
        content_digest="a" * 64,
        origin_ids=frozenset({"private-origin-42"}),
        origin_trust_domains=frozenset({"trusted.internal"}),
        tenant_id="tenant-a",
        user_id="private-user-42",
        allowed_purpose_ids=frozenset({"support"}),
        sensitivity=DataClassification.RESTRICTED,
        allowed_sink_kinds=frozenset({SensitiveDataSink.MCP_SERVER}),
        allowed_sink_ids=frozenset({"trusted-mcp"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    alternate = signer.issue(
        label_id="alternate-source-label",
        artifact_id="alternate-record",
        surface=SensitiveDataSurface.PROMPT,
        content_digest="b" * 64,
        origin_ids=frozenset({"alternate-origin"}),
        origin_trust_domains=frozenset({"trusted.internal"}),
        tenant_id="tenant-a",
        user_id="private-user-42",
        allowed_purpose_ids=frozenset({"support"}),
        sensitivity=DataClassification.RESTRICTED,
        allowed_sink_kinds=frozenset({SensitiveDataSink.MCP_SERVER}),
        allowed_sink_ids=frozenset({"trusted-mcp"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    derived = SensitiveDataFlowPropagator(signer, (signer.trusted_key,)).require_propagation(
        SensitiveDataDerivationRequest(
            request_id="encode-request",
            label_id="encoded-label",
            artifact_id="base64-payload",
            surface=SensitiveDataSurface.TOOL_RESULT,
            content_digest="c" * 64,
            source_labels=(source,),
            transformation=DataFlowTransformation.ENCODE,
            issued_at=NOW,
        ),
        now=NOW,
    )
    return signer, source, alternate, derived


@pytest.mark.parametrize("case", CORPUS, ids=lambda case: case["id"])
def test_sensitive_flow_bypass_corpus_fails_closed_and_redacts(case):
    signer, source, alternate, derived = _fixture()
    label = derived
    sources = (source,)
    content_digest = derived.content_digest
    tenant = "tenant-a"
    user_ref = data_label_reference("private-user-42")
    purpose = "support"
    destination = SensitiveDataDestination(
        sink_id="trusted-mcp",
        sink_kind=SensitiveDataSink.MCP_SERVER,
        tenant_id="tenant-a",
    )
    mutation = case["mutation"]

    if mutation == "missing":
        label = None
        sources = ()
    elif mutation == "signature":
        label = derived.model_copy(update={"signature": "0" * 128})
    elif mutation == "content":
        content_digest = "f" * 64
    elif mutation == "tenant":
        tenant = "tenant-b"
    elif mutation == "user":
        user_ref = data_label_reference("attacker-user")
    elif mutation == "purpose":
        purpose = "advertising"
    elif mutation == "sink":
        destination = SensitiveDataDestination(
            sink_id="attacker.example",
            sink_kind=SensitiveDataSink.NETWORK,
            tenant_id="tenant-a",
        )
    elif mutation == "lineage_missing":
        sources = ()
    elif mutation == "lineage_swap":
        sources = (alternate,)
    elif mutation == "downgrade":
        label = derived.model_copy(update={"sensitivity": DataClassification.PUBLIC})
    elif mutation == "ancestor":
        label = derived.model_copy(
            update={
                "source_label_digests": ("0" * 64,),
                "ancestor_label_digests": ("0" * 64,),
            }
        )

    result = SensitiveDataFlowGuard((signer.trusted_key,)).authorize(
        SensitiveDataTransferRequest(
            request_id=f"attack-{case['id']}",
            label=label,
            source_labels=sources,
            content_digest=content_digest,
            authenticated_tenant_id=tenant,
            authenticated_user_ref=user_ref,
            purpose_id=purpose,
            destination=destination,
        ),
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert SensitiveDataFlowCode(case["expected_code"]) in {
        finding.code for finding in result.findings
    }
    serialized = result.model_dump_json()
    for secret in ("private-record-42", "private-origin-42", "private-user-42", "attacker.example"):
        assert secret not in serialized
