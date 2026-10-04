"""Bypass regression corpus for OWASP AISVS C9.3.3 and C9.3.4."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    ToolCapabilityEffect,
    ToolCapabilityEnforcer,
    ToolDataClassification,
    ToolEnforcementControl,
    ToolExecutionOutput,
    ToolExecutionRequest,
    ToolExecutorIdentity,
    ToolExecutorKind,
    ToolFilesystemCapability,
    ToolManifestCode,
    ToolManifestSigner,
    ToolResourceLimits,
    ToolRuntimeEvidenceSigner,
)

NOW = datetime(2026, 10, 4, 18, tzinfo=UTC)
CASES = json.loads(
    (
        Path(__file__).parent.parent / "security_corpus" / "tool_capability_manifests.json"
    ).read_text()
)


def _fixture():
    publisher = ToolManifestSigner.generate(authority_id="publisher")
    control = ToolManifestSigner.generate(authority_id="control")
    runtime = ToolRuntimeEvidenceSigner.generate(authority_id="runtime")
    executor = ToolExecutorIdentity(
        kind=ToolExecutorKind.EXECUTABLE,
        executor_id="records.read",
        identity_digest="d" * 64,
    )
    filesystem = ToolFilesystemCapability(read_roots=("/records",))
    limits = ToolResourceLimits(
        cpu_millis=500,
        memory_bytes=16_000_000,
        duration_ms=1_000,
        output_bytes=1_024,
        network_bytes=1_024,
    )
    object_schema = {
        "type": "object",
        "properties": {"record_id": {"type": "string"}},
        "required": ["record_id"],
        "additionalProperties": False,
    }
    manifest = publisher.sign_manifest(
        manifest_id="records-v1",
        tool_id="records.read",
        version="1.0.0",
        executor=executor,
        effects=frozenset({ToolCapabilityEffect.READ}),
        filesystem=filesystem,
        resources=limits,
        input_schema=object_schema,
        output_schema=object_schema,
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
    approval = enforcer.require_approval(manifest, discovery, approved_by="owner", now=NOW)
    request = ToolExecutionRequest(
        execution_id="execution-attack",
        tool_id=manifest.tool_id,
        version=manifest.version,
        manifest_digest=manifest.manifest_digest,
        executor=executor,
        effects=frozenset({ToolCapabilityEffect.READ}),
        filesystem=filesystem,
        resources=limits,
        input_classification=ToolDataClassification.CONFIDENTIAL,
        input_value={"record_id": "record-1"},
    )
    evidence = runtime.sign(
        evidence_id="evidence-attack",
        manifest_digest=manifest.manifest_digest,
        executor=executor,
        filesystem=filesystem,
        egress=frozenset(),
        credential_references=frozenset(),
        resources=limits,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    return runtime, enforcer, manifest, approval, request, evidence, executor


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_tool_capability_manifest_bypass_corpus(case):
    runtime, enforcer, manifest, approval, request, evidence, executor = _fixture()
    mutation = case["mutation"]

    if mutation == "manifest_signature":
        manifest = manifest.model_copy(update={"effects": frozenset({ToolCapabilityEffect.DELETE})})
        result = enforcer.discover(manifest, executor, now=NOW)
    elif mutation == "executor_substitution":
        substituted = executor.model_copy(update={"identity_digest": "e" * 64})
        result = enforcer.discover(manifest, substituted, now=NOW)
    elif mutation == "approval_substitution":
        approval = approval.model_copy(update={"manifest_digest": "f" * 64})
        result = enforcer.authorize(manifest, approval, request, evidence, now=NOW)
    elif mutation == "stale_evidence":
        result = enforcer.authorize(
            manifest,
            approval,
            request,
            evidence,
            now=NOW + timedelta(minutes=2),
        )
    elif mutation == "missing_controls":
        evidence = runtime.sign(
            evidence_id="missing-control",
            manifest_digest=manifest.manifest_digest,
            executor=executor,
            filesystem=manifest.filesystem,
            egress=frozenset(),
            credential_references=frozenset(),
            resources=manifest.resources,
            controls=frozenset({ToolEnforcementControl.EXECUTOR_IDENTITY}),
            issued_at=NOW,
        )
        result = enforcer.authorize(manifest, approval, request, evidence, now=NOW)
    elif mutation == "filesystem_widening":
        evidence = runtime.sign(
            evidence_id="widened-filesystem",
            manifest_digest=manifest.manifest_digest,
            executor=executor,
            filesystem=ToolFilesystemCapability(read_roots=("/",)),
            egress=frozenset(),
            credential_references=frozenset(),
            resources=manifest.resources,
            issued_at=NOW,
        )
        result = enforcer.authorize(manifest, approval, request, evidence, now=NOW)
    elif mutation == "untrusted_evidence":
        attacker = ToolRuntimeEvidenceSigner.generate(authority_id="attacker")
        evidence = attacker.sign(
            evidence_id="attacker-evidence",
            manifest_digest=manifest.manifest_digest,
            executor=executor,
            filesystem=manifest.filesystem,
            egress=frozenset(),
            credential_references=frozenset(),
            resources=manifest.resources,
            issued_at=NOW,
        )
        result = enforcer.authorize(manifest, approval, request, evidence, now=NOW)
    else:
        lease = enforcer.require_authorization(manifest, approval, request, evidence, now=NOW)
        result = enforcer.verify_output(
            manifest,
            lease,
            ToolExecutionOutput(
                authorization_id=lease.authorization_id,
                execution_id=request.execution_id,
                manifest_digest=manifest.manifest_digest,
                value={"secret": "undeclared"},
                classification=ToolDataClassification.CONFIDENTIAL,
            ),
            now=NOW,
        )

    expected = ToolManifestCode(case["expected_code"])
    assert expected in {finding.code for finding in result.findings}
    serialized = result.model_dump_json()
    assert "record-1" not in serialized
    assert "records.read" not in serialized
