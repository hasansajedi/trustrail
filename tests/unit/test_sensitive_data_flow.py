"""Unit tests for OWASP MCP10 sensitive-data flow controls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from trustrail import (
    DataClassification,
    DataFlowTransformation,
    SensitiveDataDeclassificationRequest,
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

NOW = datetime(2026, 10, 18, 12, tzinfo=UTC)
ALL_SINKS = frozenset(SensitiveDataSink)


def _signer(*, declassifier: bool = False) -> SensitiveDataFlowSigner:
    return SensitiveDataFlowSigner.generate(
        issuer_id="privacy-review" if declassifier else "flow-control",
        allowed_tenant_ids=frozenset({"tenant-a"}),
        can_declassify=declassifier,
    )


def _origin(
    signer: SensitiveDataFlowSigner,
    *,
    label_id: str = "source-label",
    content_digest: str = "a" * 64,
    purposes: frozenset[str] = frozenset({"support", "fraud-review"}),
    sink_ids: frozenset[str] = frozenset({"model-eu", "mcp-support", "audit-log"}),
    sensitivity: DataClassification = DataClassification.RESTRICTED,
    user_id: str = "user-42",
):
    return signer.issue(
        label_id=label_id,
        artifact_id=f"artifact-{label_id}",
        surface=SensitiveDataSurface.PROMPT,
        content_digest=content_digest,
        origin_ids=frozenset({"crm-case-42"}),
        origin_trust_domains=frozenset({"crm.internal"}),
        tenant_id="tenant-a",
        user_id=user_id,
        allowed_purpose_ids=purposes,
        sensitivity=sensitivity,
        allowed_sink_kinds=ALL_SINKS,
        allowed_sink_ids=sink_ids,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _derive(
    propagator: SensitiveDataFlowPropagator,
    source_labels,
    *,
    transformation: DataFlowTransformation = DataFlowTransformation.MODEL_GENERATE,
    surface: SensitiveDataSurface = SensitiveDataSurface.MODEL_OUTPUT,
    content_digest: str = "b" * 64,
    label_id: str = "derived-label",
):
    return propagator.require_propagation(
        SensitiveDataDerivationRequest(
            request_id=f"derive-{label_id}",
            label_id=label_id,
            artifact_id=f"artifact-{label_id}",
            surface=surface,
            content_digest=content_digest,
            source_labels=tuple(source_labels),
            transformation=transformation,
            issued_at=NOW,
        ),
        now=NOW,
    )


def _transfer(label, *, source_labels=(), grants=(), **updates):
    values = {
        "request_id": "transfer-1",
        "label": label,
        "source_labels": tuple(source_labels),
        "declassification_grants": tuple(grants),
        "content_digest": label.content_digest,
        "authenticated_tenant_id": "tenant-a",
        "authenticated_user_ref": data_label_reference("user-42"),
        "purpose_id": "support",
        "destination": SensitiveDataDestination(
            sink_id="model-eu",
            sink_kind=SensitiveDataSink.MODEL,
            tenant_id="tenant-a",
        ),
    }
    values.update(updates)
    return SensitiveDataTransferRequest(**values)


def test_origin_label_integrity_protects_origin_user_purpose_and_sinks():
    signer = _signer()
    label = _origin(signer)

    assert label.origin_refs == frozenset({data_label_reference("crm-case-42")})
    assert label.user_ref == data_label_reference("user-42")
    assert label.last_transformation == DataFlowTransformation.ORIGIN
    assert label.signature is not None

    guard = SensitiveDataFlowGuard((signer.trusted_key,))
    assert guard.authorize(_transfer(label), now=NOW).is_allowed
    tampered = label.model_copy(update={"allowed_sink_ids": frozenset({"attacker"})})
    result = guard.authorize(
        _transfer(
            tampered,
            destination=SensitiveDataDestination(
                sink_id="attacker",
                sink_kind=SensitiveDataSink.NETWORK,
                tenant_id="tenant-a",
            ),
        ),
        now=NOW,
    )
    assert result.findings[0].code == SensitiveDataFlowCode.LABEL_SIGNATURE_INVALID


def test_aggregate_uses_most_sensitive_and_intersection_of_authority():
    signer = _signer()
    first = _origin(signer, sensitivity=DataClassification.CONFIDENTIAL)
    second = _origin(
        signer,
        label_id="second",
        content_digest="c" * 64,
        purposes=frozenset({"support"}),
        sink_ids=frozenset({"model-eu"}),
    )
    propagator = SensitiveDataFlowPropagator(signer, (signer.trusted_key,))

    derived = _derive(
        propagator,
        (first, second),
        transformation=DataFlowTransformation.AGGREGATE,
    )

    assert derived.sensitivity == DataClassification.RESTRICTED
    assert derived.allowed_purpose_ids == frozenset({"support"})
    assert derived.allowed_sink_ids == frozenset({"model-eu"})
    assert derived.origin_refs == first.origin_refs | second.origin_refs
    assert derived.lineage_depth == 1
    assert set(derived.source_label_digests).issubset(derived.ancestor_label_digests)


@pytest.mark.parametrize(
    ("transformation", "surface"),
    [
        (DataFlowTransformation.MODEL_GENERATE, SensitiveDataSurface.MODEL_OUTPUT),
        (DataFlowTransformation.STRUCTURED_EXTRACT, SensitiveDataSurface.STRUCTURED_EXTRACTION),
        (DataFlowTransformation.RETRIEVE, SensitiveDataSurface.RETRIEVAL_CONTEXT),
        (DataFlowTransformation.MEMORY_STORE, SensitiveDataSurface.MEMORY_WRITE),
        (DataFlowTransformation.MEMORY_RECALL, SensitiveDataSurface.MEMORY_READ),
        (DataFlowTransformation.TOOL_CALL, SensitiveDataSurface.TOOL_ARGUMENT),
        (DataFlowTransformation.TOOL_RESULT, SensitiveDataSurface.TOOL_RESULT),
        (DataFlowTransformation.AGENT_TRANSFER, SensitiveDataSurface.AGENT_MESSAGE),
        (DataFlowTransformation.STREAM, SensitiveDataSurface.STREAM_FRAGMENT),
    ],
)
def test_supported_agent_surfaces_preserve_restrictions(transformation, surface):
    signer = _signer()
    source = _origin(signer)
    derived = _derive(
        SensitiveDataFlowPropagator(signer, (signer.trusted_key,)),
        (source,),
        transformation=transformation,
        surface=surface,
    )

    assert derived.sensitivity == source.sensitivity
    assert derived.allowed_sink_ids == source.allowed_sink_ids
    assert transformation in derived.transformations_seen


def test_encoding_chunking_and_indirection_cannot_launder_restrictions():
    signer = _signer()
    propagator = SensitiveDataFlowPropagator(signer, (signer.trusted_key,))
    source = _origin(signer)
    encoded = _derive(
        propagator,
        (source,),
        transformation=DataFlowTransformation.ENCODE,
        content_digest="b" * 64,
        label_id="encoded",
    )
    chunk = _derive(
        propagator,
        (encoded,),
        transformation=DataFlowTransformation.CHUNK,
        surface=SensitiveDataSurface.STREAM_FRAGMENT,
        content_digest="c" * 64,
        label_id="chunk",
    )
    indirect = _derive(
        propagator,
        (chunk,),
        transformation=DataFlowTransformation.INDIRECT_REFERENCE,
        content_digest="d" * 64,
        label_id="indirect",
    )

    assert indirect.sensitivity == DataClassification.RESTRICTED
    assert indirect.lineage_depth == 3
    assert {
        DataFlowTransformation.ENCODE,
        DataFlowTransformation.CHUNK,
        DataFlowTransformation.INDIRECT_REFERENCE,
    }.issubset(indirect.transformations_seen)
    guard = SensitiveDataFlowGuard((signer.trusted_key,))
    result = guard.authorize(_transfer(indirect, source_labels=(chunk,)), now=NOW)
    assert result.is_allowed

    weakened = indirect.model_copy(update={"sensitivity": DataClassification.PUBLIC})
    blocked = guard.authorize(_transfer(weakened, source_labels=(chunk,)), now=NOW)
    assert SensitiveDataFlowCode.LABEL_SIGNATURE_INVALID in {f.code for f in blocked.findings}


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"content_digest": "f" * 64}, SensitiveDataFlowCode.CONTENT_BINDING_INVALID),
        ({"authenticated_tenant_id": "tenant-b"}, SensitiveDataFlowCode.TENANT_CONFLICT),
        ({"authenticated_user_ref": "sha256:" + "0" * 64}, SensitiveDataFlowCode.USER_CONFLICT),
        ({"purpose_id": "advertising"}, SensitiveDataFlowCode.PURPOSE_DENIED),
        (
            {
                "destination": SensitiveDataDestination(
                    sink_id="attacker",
                    sink_kind=SensitiveDataSink.NETWORK,
                    tenant_id="tenant-a",
                )
            },
            SensitiveDataFlowCode.SINK_DENIED,
        ),
    ],
)
def test_sink_guard_rejects_rebinding(updates, expected):
    signer = _signer()
    result = SensitiveDataFlowGuard((signer.trusted_key,)).authorize(
        _transfer(_origin(signer), **updates), now=NOW
    )
    assert expected in {finding.code for finding in result.findings}


def test_declassification_requires_independent_exact_grant_at_sink():
    signer = _signer()
    authority = _signer(declassifier=True)
    source = _origin(signer)
    grant = authority.issue_declassification(
        grant_id="privacy-review-1",
        source_label=source,
        output_content_digest="e" * 64,
        target_sensitivity=DataClassification.INTERNAL,
        allowed_purpose_ids=frozenset({"support"}),
        allowed_sink_kinds=frozenset({SensitiveDataSink.MESSAGE}),
        allowed_sink_ids=frozenset({"support-agent"}),
        justification_id="approved-redaction-review-8",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )
    propagator = SensitiveDataFlowPropagator(
        signer,
        (signer.trusted_key,),
        declassification_keys=(authority.trusted_key,),
    )
    declassified = propagator.require_declassification(
        SensitiveDataDeclassificationRequest(
            request_id="declassify-1",
            label_id="redacted-label",
            artifact_id="redacted-answer",
            surface=SensitiveDataSurface.AGENT_MESSAGE,
            source_label=source,
            output_content_digest="e" * 64,
            grant=grant,
            issued_at=NOW,
        ),
        now=NOW,
    )
    transfer = _transfer(
        declassified,
        source_labels=(source,),
        grants=(grant,),
        destination=SensitiveDataDestination(
            sink_id="support-agent",
            sink_kind=SensitiveDataSink.MESSAGE,
            tenant_id="tenant-a",
        ),
    )
    guard = SensitiveDataFlowGuard(
        (signer.trusted_key,), declassification_keys=(authority.trusted_key,)
    )

    assert guard.authorize(transfer, now=NOW).is_allowed
    missing = guard.authorize(transfer.model_copy(update={"declassification_grants": ()}), now=NOW)
    assert SensitiveDataFlowCode.DECLASSIFICATION_REQUIRED in {f.code for f in missing.findings}

    forwarded = _derive(
        propagator,
        (declassified,),
        transformation=DataFlowTransformation.AGENT_TRANSFER,
        surface=SensitiveDataSurface.AGENT_MESSAGE,
        content_digest="f" * 64,
        label_id="forwarded-redaction",
    )
    assert forwarded.declassification_grant_digests == (grant.grant_digest,)
    forwarded_transfer = _transfer(
        forwarded,
        source_labels=(declassified,),
        grants=(grant,),
        destination=SensitiveDataDestination(
            sink_id="support-agent",
            sink_kind=SensitiveDataSink.MESSAGE,
            tenant_id="tenant-a",
        ),
    )
    assert guard.authorize(forwarded_transfer, now=NOW).is_allowed
    no_evidence = guard.authorize(
        forwarded_transfer.model_copy(update={"declassification_grants": ()}), now=NOW
    )
    assert SensitiveDataFlowCode.DECLASSIFICATION_REQUIRED in {f.code for f in no_evidence.findings}


def test_propagation_rejects_cross_user_and_empty_shared_policy():
    signer = _signer()
    first = _origin(signer)
    second = _origin(
        signer,
        label_id="other-user",
        content_digest="c" * 64,
        purposes=frozenset({"billing"}),
        user_id="user-99",
    )
    result = SensitiveDataFlowPropagator(signer, (signer.trusted_key,)).propagate(
        SensitiveDataDerivationRequest(
            request_id="bad-join",
            label_id="bad-label",
            artifact_id="bad-artifact",
            surface=SensitiveDataSurface.MODEL_OUTPUT,
            content_digest="d" * 64,
            source_labels=(first, second),
            transformation=DataFlowTransformation.AGGREGATE,
            issued_at=NOW,
        ),
        now=NOW,
    )
    assert not result.is_allowed
    assert {SensitiveDataFlowCode.USER_CONFLICT, SensitiveDataFlowCode.PURPOSE_DENIED}.issubset(
        {finding.code for finding in result.findings}
    )


def test_evidence_and_audit_do_not_disclose_raw_identifiers():
    signer = _signer()
    label = _origin(signer)
    result = SensitiveDataFlowGuard((signer.trusted_key,)).authorize(_transfer(label), now=NOW)
    serialized = result.model_dump_json()

    assert "user-42" not in serialized
    assert "crm-case-42" not in serialized
    assert "model-eu" not in serialized
    assert "tenant-a" not in serialized


def test_future_dated_label_and_unauthorized_derivation_signer_fail_closed():
    signer = _signer()
    future = signer.issue(
        label_id="future-label",
        artifact_id="future-artifact",
        surface=SensitiveDataSurface.PROMPT,
        content_digest="f" * 64,
        origin_ids=frozenset({"future-origin"}),
        origin_trust_domains=frozenset({"crm.internal"}),
        tenant_id="tenant-a",
        user_id="user-42",
        allowed_purpose_ids=frozenset({"support"}),
        sensitivity=DataClassification.CONFIDENTIAL,
        allowed_sink_kinds=frozenset({SensitiveDataSink.MODEL}),
        allowed_sink_ids=frozenset({"model-eu"}),
        issued_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
    )
    result = SensitiveDataFlowGuard((signer.trusted_key,)).authorize(_transfer(future), now=NOW)
    assert SensitiveDataFlowCode.LABEL_NOT_YET_VALID in {f.code for f in result.findings}

    unauthorized = SensitiveDataFlowSigner.generate(
        issuer_id="wrong-tenant-deriver",
        allowed_tenant_ids=frozenset({"tenant-b"}),
    )
    source = _origin(signer)
    propagation = SensitiveDataFlowPropagator(
        unauthorized,
        (signer.trusted_key,),
    ).propagate(
        SensitiveDataDerivationRequest(
            request_id="unauthorized-derive",
            label_id="unauthorized-label",
            artifact_id="unauthorized-artifact",
            surface=SensitiveDataSurface.MODEL_OUTPUT,
            content_digest="e" * 64,
            source_labels=(source,),
            transformation=DataFlowTransformation.MODEL_GENERATE,
            issued_at=NOW,
        ),
        now=NOW,
    )
    assert not propagation.is_allowed
    assert SensitiveDataFlowCode.LINEAGE_MISMATCH in {f.code for f in propagation.findings}
