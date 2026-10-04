"""End-to-end runtime tool manifest enforcement workflow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    ToolCapabilityEffect,
    ToolCapabilityEnforcer,
    ToolDataClassification,
    ToolExecutionOutput,
    ToolExecutionRequest,
    ToolExecutorIdentity,
    ToolExecutorKind,
    ToolFilesystemCapability,
    ToolManifestSigner,
    ToolResourceLimits,
    ToolRuntimeEvidenceSigner,
)

NOW = datetime(2026, 10, 4, 15, tzinfo=UTC)


def test_dispatch_and_release_are_bound_to_the_same_verified_manifest():
    publisher = ToolManifestSigner.generate(authority_id="publisher")
    control = ToolManifestSigner.generate(authority_id="control-plane")
    runtime = ToolRuntimeEvidenceSigner.generate(authority_id="runtime")
    executor = ToolExecutorIdentity(
        kind=ToolExecutorKind.SERVICE,
        executor_id="customer.search.service",
        identity_digest="c" * 64,
    )
    filesystem = ToolFilesystemCapability()
    limits = ToolResourceLimits(
        cpu_millis=500,
        memory_bytes=16_000_000,
        duration_ms=2_000,
        output_bytes=1_024,
        network_bytes=10_000,
    )
    schema = {
        "type": "object",
        "properties": {"query": {"type": "string", "maxLength": 100}},
        "required": ["query"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "array",
        "items": {"type": "string", "maxLength": 100},
        "maxItems": 10,
    }
    manifest = publisher.sign_manifest(
        manifest_id="customer-search-v3",
        tool_id="customer.search",
        version="3.0.0",
        executor=executor,
        effects=frozenset({ToolCapabilityEffect.READ}),
        scopes=frozenset({"customers:read"}),
        filesystem=filesystem,
        resources=limits,
        input_schema=schema,
        output_schema=output_schema,
        input_classifications=frozenset({ToolDataClassification.CONFIDENTIAL}),
        max_output_classification=ToolDataClassification.CONFIDENTIAL,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    enforcer = ToolCapabilityEnforcer(
        manifest_keys=(publisher.trusted_key,),
        evidence_keys=(runtime.trusted_key,),
        control_signer=control,
    )
    discovery = enforcer.require_discovery(manifest, executor, now=NOW)
    approval = enforcer.require_approval(manifest, discovery, approved_by="platform-owner", now=NOW)
    request = ToolExecutionRequest(
        execution_id="customer-query-42",
        tool_id=manifest.tool_id,
        version=manifest.version,
        manifest_digest=manifest.manifest_digest,
        executor=executor,
        effects=frozenset({ToolCapabilityEffect.READ}),
        scopes=frozenset({"customers:read"}),
        filesystem=filesystem,
        resources=limits,
        input_classification=ToolDataClassification.CONFIDENTIAL,
        input_value={"query": "customer-42"},
    )
    evidence = runtime.sign(
        evidence_id="runtime-snapshot-42",
        manifest_digest=manifest.manifest_digest,
        executor=executor,
        filesystem=filesystem,
        egress=frozenset(),
        credential_references=frozenset(),
        resources=limits,
        issued_at=NOW,
    )

    lease = enforcer.require_authorization(manifest, approval, request, evidence, now=NOW)
    verified = enforcer.require_output(
        manifest,
        lease,
        ToolExecutionOutput(
            authorization_id=lease.authorization_id,
            execution_id=request.execution_id,
            manifest_digest=manifest.manifest_digest,
            value=["customer-42"],
            classification=ToolDataClassification.CONFIDENTIAL,
        ),
        now=NOW + timedelta(seconds=1),
    )

    assert verified.value == ["customer-42"]
