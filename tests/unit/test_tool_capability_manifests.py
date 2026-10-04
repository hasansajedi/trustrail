"""Unit tests for signed runtime tool capability manifests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    GuardAction,
    ToolCapabilityEffect,
    ToolCapabilityEnforcer,
    ToolDataClassification,
    ToolEgressDestination,
    ToolEnforcementControl,
    ToolExecutionOutput,
    ToolExecutionRequest,
    ToolExecutorIdentity,
    ToolExecutorKind,
    ToolFilesystemCapability,
    ToolManifestCode,
    ToolManifestError,
    ToolManifestSigner,
    ToolResourceLimits,
    ToolRuntimeEvidenceSigner,
)

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)
EXECUTOR = ToolExecutorIdentity(
    kind=ToolExecutorKind.EXECUTABLE,
    executor_id="invoice.lookup",
    identity_digest="a" * 64,
)
FILESYSTEM = ToolFilesystemCapability(read_roots=("/sandbox/invoices",), write_roots=())
EGRESS = frozenset({ToolEgressDestination(host="api.example.com", port=443)})
LIMITS = ToolResourceLimits(
    cpu_millis=1_000,
    memory_bytes=64 * 1024 * 1024,
    duration_ms=5_000,
    output_bytes=4_096,
    network_bytes=1_000_000,
)
INPUT_SCHEMA = {
    "type": "object",
    "properties": {"invoice_id": {"type": "string", "pattern": "^inv-[0-9]+$"}},
    "required": ["invoice_id"],
    "additionalProperties": False,
}
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {"status": {"type": "string", "enum": ["open", "paid"]}},
    "required": ["status"],
    "additionalProperties": False,
}


def _fixture():
    publisher = ToolManifestSigner.generate(authority_id="tool-publisher")
    control = ToolManifestSigner.generate(authority_id="tool-control-plane")
    runtime = ToolRuntimeEvidenceSigner.generate(authority_id="sandbox-attestor")
    manifest = publisher.sign_manifest(
        manifest_id="invoice-lookup-v1",
        tool_id="invoice.lookup",
        version="1.0.0",
        executor=EXECUTOR,
        effects=frozenset({ToolCapabilityEffect.READ}),
        scopes=frozenset({"invoices:read"}),
        filesystem=FILESYSTEM,
        egress=EGRESS,
        credential_references=frozenset({"credential/invoice-api"}),
        resources=LIMITS,
        input_schema=INPUT_SCHEMA,
        output_schema=OUTPUT_SCHEMA,
        input_classifications=frozenset(
            {ToolDataClassification.INTERNAL, ToolDataClassification.CONFIDENTIAL}
        ),
        max_output_classification=ToolDataClassification.CONFIDENTIAL,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    enforcer = ToolCapabilityEnforcer(
        manifest_keys=(publisher.trusted_key,),
        evidence_keys=(runtime.trusted_key,),
        control_signer=control,
    )
    discovery = enforcer.require_discovery(manifest, EXECUTOR, now=NOW)
    approval = enforcer.require_approval(
        manifest,
        discovery,
        approved_by="security-reviewer",
        now=NOW,
    )
    request = ToolExecutionRequest(
        execution_id="execution-1",
        tool_id=manifest.tool_id,
        version=manifest.version,
        manifest_digest=manifest.manifest_digest,
        executor=EXECUTOR,
        effects=frozenset({ToolCapabilityEffect.READ}),
        scopes=frozenset({"invoices:read"}),
        filesystem=FILESYSTEM,
        egress=EGRESS,
        credential_references=frozenset({"credential/invoice-api"}),
        resources=LIMITS,
        input_classification=ToolDataClassification.CONFIDENTIAL,
        input_value={"invoice_id": "inv-42"},
    )
    evidence = runtime.sign(
        evidence_id="evidence-1",
        manifest_digest=manifest.manifest_digest,
        executor=EXECUTOR,
        filesystem=FILESYSTEM,
        egress=EGRESS,
        credential_references=frozenset({"credential/invoice-api"}),
        resources=LIMITS,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    return publisher, runtime, enforcer, manifest, discovery, approval, request, evidence


def test_complete_manifest_lifecycle_allows_contract_valid_output_once():
    _, _, enforcer, manifest, _, approval, request, evidence = _fixture()

    authorization = enforcer.require_authorization(manifest, approval, request, evidence, now=NOW)
    output = ToolExecutionOutput(
        authorization_id=authorization.authorization_id,
        execution_id=request.execution_id,
        manifest_digest=manifest.manifest_digest,
        value={"status": "paid"},
        classification=ToolDataClassification.CONFIDENTIAL,
    )

    verified = enforcer.require_output(manifest, authorization, output, now=NOW)
    replay = enforcer.verify_output(manifest, authorization, output, now=NOW)

    assert verified.value == {"status": "paid"}
    assert replay.action == GuardAction.QUARANTINE
    assert ToolManifestCode.AUTHORIZATION_REPLAYED in {item.code for item in replay.findings}


def test_tampered_manifest_and_substituted_executor_fail_discovery():
    _, _, enforcer, manifest, *_ = _fixture()
    tampered = manifest.model_copy(update={"scopes": frozenset({"admin:all"})})
    other_executor = EXECUTOR.model_copy(update={"identity_digest": "b" * 64})

    invalid_signature = enforcer.discover(tampered, EXECUTOR, now=NOW)
    substituted = enforcer.discover(manifest, other_executor, now=NOW)

    assert invalid_signature.findings[0].code == ToolManifestCode.MANIFEST_SIGNATURE_INVALID
    assert substituted.findings[0].code == ToolManifestCode.EXECUTOR_MISMATCH


def test_manifest_substitution_invalidates_discovery_and_approval_bindings():
    publisher, _, enforcer, _, discovery, approval, request, evidence = _fixture()
    replacement = publisher.sign_manifest(
        manifest_id="invoice-lookup-v2",
        tool_id="invoice.lookup",
        version="1.0.1",
        executor=EXECUTOR,
        effects=frozenset({ToolCapabilityEffect.READ}),
        filesystem=FILESYSTEM,
        resources=LIMITS,
        input_schema=INPUT_SCHEMA,
        output_schema=OUTPUT_SCHEMA,
        input_classifications=frozenset({ToolDataClassification.CONFIDENTIAL}),
        max_output_classification=ToolDataClassification.CONFIDENTIAL,
        issued_at=NOW,
    )

    approval_result = enforcer.approve(
        replacement, discovery, approved_by="security-reviewer", now=NOW
    )
    dispatch_result = enforcer.authorize(replacement, approval, request, evidence, now=NOW)

    assert ToolManifestCode.MANIFEST_SUBSTITUTION in {
        item.code for item in approval_result.findings
    }
    assert ToolManifestCode.MANIFEST_SUBSTITUTION in {
        item.code for item in dispatch_result.findings
    }


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("effect", ToolManifestCode.CAPABILITY_UNDECLARED),
        ("filesystem", ToolManifestCode.FILESYSTEM_WIDENED),
        ("egress", ToolManifestCode.EGRESS_WIDENED),
        ("credential", ToolManifestCode.CREDENTIAL_WIDENED),
        ("resource", ToolManifestCode.RESOURCE_LIMIT_WIDENED),
        ("classification", ToolManifestCode.DATA_CLASSIFICATION_DENIED),
        ("input", ToolManifestCode.INPUT_CONTRACT_INVALID),
    ],
)
def test_undeclared_or_widened_request_is_denied(mutation, expected):
    _, _, enforcer, manifest, _, approval, request, evidence = _fixture()
    updates = {
        "effect": {"effects": frozenset({ToolCapabilityEffect.DELETE})},
        "filesystem": {
            "filesystem": ToolFilesystemCapability(read_roots=("/etc",), write_roots=())
        },
        "egress": {"egress": frozenset({ToolEgressDestination(host="evil.example", port=443)})},
        "credential": {"credential_references": frozenset({"credential/admin"})},
        "resource": {
            "resources": LIMITS.model_copy(update={"memory_bytes": LIMITS.memory_bytes + 1})
        },
        "classification": {"input_classification": ToolDataClassification.RESTRICTED},
        "input": {"input_value": {"invoice_id": "../../secrets"}},
    }
    mutated = request.model_copy(update=updates[mutation])

    result = enforcer.authorize(manifest, approval, mutated, evidence, now=NOW)

    assert result.action == GuardAction.BLOCK
    assert expected in {item.code for item in result.findings}


def test_missing_stale_or_incomplete_runtime_evidence_fails_closed():
    _, runtime, enforcer, manifest, _, approval, request, evidence = _fixture()
    missing = enforcer.authorize(manifest, approval, request, None, now=NOW)
    stale = enforcer.authorize(
        manifest,
        approval,
        request,
        evidence,
        now=NOW + timedelta(minutes=2),
    )
    incomplete = runtime.sign(
        evidence_id="evidence-incomplete",
        manifest_digest=manifest.manifest_digest,
        executor=EXECUTOR,
        filesystem=FILESYSTEM,
        egress=EGRESS,
        credential_references=frozenset({"credential/invoice-api"}),
        resources=LIMITS,
        controls=frozenset({ToolEnforcementControl.EXECUTOR_IDENTITY}),
        issued_at=NOW,
    )
    incomplete_result = enforcer.authorize(manifest, approval, request, incomplete, now=NOW)

    assert missing.findings[0].code == ToolManifestCode.EVIDENCE_REQUIRED
    assert ToolManifestCode.EVIDENCE_STALE in {item.code for item in stale.findings}
    assert ToolManifestCode.ENFORCEMENT_CONTROL_MISSING in {
        item.code for item in incomplete_result.findings
    }


def test_runtime_evidence_cannot_widen_manifest_or_hide_narrower_enforcement():
    _, runtime, enforcer, manifest, _, approval, request, _ = _fixture()
    widened = runtime.sign(
        evidence_id="evidence-widened",
        manifest_digest=manifest.manifest_digest,
        executor=EXECUTOR,
        filesystem=ToolFilesystemCapability(read_roots=("/",), write_roots=()),
        egress=EGRESS,
        credential_references=frozenset({"credential/invoice-api"}),
        resources=LIMITS,
        issued_at=NOW,
    )
    narrower = runtime.sign(
        evidence_id="evidence-narrow",
        manifest_digest=manifest.manifest_digest,
        executor=EXECUTOR,
        filesystem=ToolFilesystemCapability(read_roots=("/sandbox/invoices/public",)),
        egress=EGRESS,
        credential_references=frozenset({"credential/invoice-api"}),
        resources=LIMITS,
        issued_at=NOW,
    )

    widened_result = enforcer.authorize(manifest, approval, request, widened, now=NOW)
    narrower_result = enforcer.authorize(manifest, approval, request, narrower, now=NOW)

    assert ToolManifestCode.FILESYSTEM_WIDENED in {item.code for item in widened_result.findings}
    assert ToolManifestCode.FILESYSTEM_WIDENED in {item.code for item in narrower_result.findings}


@pytest.mark.parametrize(
    ("value", "classification", "expected"),
    [
        (
            {"status": "forged"},
            ToolDataClassification.INTERNAL,
            ToolManifestCode.OUTPUT_CONTRACT_INVALID,
        ),
        (
            {"status": "paid", "secret": True},
            ToolDataClassification.INTERNAL,
            ToolManifestCode.OUTPUT_CONTRACT_INVALID,
        ),
        (
            {"status": "paid"},
            ToolDataClassification.RESTRICTED,
            ToolManifestCode.OUTPUT_CLASSIFICATION_DENIED,
        ),
    ],
)
def test_invalid_output_is_quarantined(value, classification, expected):
    _, _, enforcer, manifest, _, approval, request, evidence = _fixture()
    authorization = enforcer.require_authorization(manifest, approval, request, evidence, now=NOW)
    output = ToolExecutionOutput(
        authorization_id=authorization.authorization_id,
        execution_id=request.execution_id,
        manifest_digest=manifest.manifest_digest,
        value=value,
        classification=classification,
    )

    result = enforcer.verify_output(manifest, authorization, output, now=NOW)

    assert result.action == GuardAction.QUARANTINE
    assert expected in {item.code for item in result.findings}


def test_open_or_unsupported_contracts_are_rejected_at_manifest_creation():
    publisher = ToolManifestSigner.generate(authority_id="tool-publisher")
    values = {
        "manifest_id": "unsafe",
        "tool_id": "unsafe.tool",
        "version": "1",
        "executor": EXECUTOR,
        "effects": frozenset(),
        "filesystem": FILESYSTEM,
        "resources": LIMITS,
        "input_schema": INPUT_SCHEMA,
        "output_schema": {"type": "object", "properties": {}},
        "input_classifications": frozenset({ToolDataClassification.PUBLIC}),
        "max_output_classification": ToolDataClassification.PUBLIC,
        "issued_at": NOW,
    }

    with pytest.raises(ValidationError, match="additionalProperties"):
        publisher.sign_manifest(**values)

    values["output_schema"] = {"type": "object", "$ref": "https://evil/schema"}
    with pytest.raises(ValidationError, match="unsupported schema"):
        publisher.sign_manifest(**values)


def test_raise_api_does_not_expose_tool_input_in_exception_text():
    _, _, enforcer, manifest, _, approval, request, _ = _fixture()

    with pytest.raises(ToolManifestError) as raised:
        enforcer.require_authorization(manifest, approval, request, None, now=NOW)

    assert "inv-42" not in str(raised.value)
