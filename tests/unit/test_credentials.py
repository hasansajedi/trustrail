"""Unit tests for model-blind credential brokering."""

from __future__ import annotations

import base64
import pickle
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from trustrail import (
    AuthorizedCredentialExecution,
    CredentialBinding,
    CredentialBoundaryGuard,
    CredentialBroker,
    CredentialBrokerCode,
    CredentialBrokerError,
    CredentialBrokerPolicy,
    CredentialMaterial,
    CredentialReference,
    CredentialScope,
    CredentialSurface,
    GuardAction,
    MemoryCredentialAuditSink,
    StaticCredentialExecutionVerifier,
    StaticCredentialVault,
)

NOW = datetime(2026, 9, 28, 12, tzinfo=UTC)
SECRET = "canary-production-token-4d2fbc8136"


def _fixture():
    reference = CredentialReference(
        broker_id="production-broker",
        reference_id="credref_payments_primary_01",
    )
    scope = CredentialScope(
        tenant_id="tenant-a",
        tool_name="payments.charge",
        resource_id="merchant-account-7",
        operation="charge:create",
    )
    policy = CredentialBrokerPolicy(
        broker_id="production-broker",
        version=3,
        bindings=(
            CredentialBinding(
                reference=reference,
                scope=scope,
                credential_version="vault-version-7",
                maximum_ttl_seconds=30,
            ),
        ),
    )
    execution = AuthorizedCredentialExecution.create(
        execution_id="execution-42",
        authorization_id="authorization-42",
        request_digest="a" * 64,
        scope=scope,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
    )
    vault = StaticCredentialVault({reference.reference_id: ("vault-version-7", SECRET)})
    audit = MemoryCredentialAuditSink()
    broker = CredentialBroker(
        policy,
        vault=vault,
        execution_verifier=StaticCredentialExecutionVerifier(
            frozenset({execution.execution_digest})
        ),
        audit_sink=audit,
    )
    return reference, scope, policy, execution, vault, audit, broker


def test_exact_execution_resolves_once_without_serializing_secret():
    reference, _, _, execution, _, audit, broker = _fixture()

    capability = broker.require_capability(reference, execution, now=NOW)
    with broker.resolve(capability, execution, now=NOW) as material:
        assert material.reveal() == SECRET.encode()
        assert SECRET not in repr(material)
        assert SECRET not in str(material)

    with pytest.raises(CredentialBrokerError) as replay:
        broker.resolve(capability, execution, now=NOW)

    assert replay.value.decision.findings[0].code == CredentialBrokerCode.CAPABILITY_REPLAYED
    serialized = "".join(event.model_dump_json() for event in audit.events)
    assert SECRET not in serialized
    assert reference.reference_id not in serialized
    assert execution.execution_id not in serialized


@pytest.mark.parametrize(
    "scope_update",
    [
        {"tenant_id": "tenant-b"},
        {"tool_name": "payments.refund"},
        {"resource_id": "merchant-account-8"},
        {"operation": "charge:read"},
    ],
)
def test_capability_issue_rejects_scope_rebinding(scope_update):
    reference, scope, _, execution, _, _, broker = _fixture()
    rebound = AuthorizedCredentialExecution.create(
        execution_id=execution.execution_id,
        authorization_id=execution.authorization_id,
        request_digest=execution.request_digest,
        scope=scope.model_copy(update=scope_update),
        issued_at=execution.issued_at,
        expires_at=execution.expires_at,
    )

    result = broker.issue(reference, rebound, now=NOW)

    assert result.action == GuardAction.BLOCK
    assert result.findings[0].code == CredentialBrokerCode.SCOPE_MISMATCH


def test_forged_expired_and_unverified_execution_records_fail_closed():
    reference, _, _, execution, _, _, broker = _fixture()
    forged = execution.model_copy(update={"execution_digest": "0" * 64})
    expired = AuthorizedCredentialExecution.create(
        execution_id=execution.execution_id,
        authorization_id=execution.authorization_id,
        request_digest=execution.request_digest,
        scope=execution.scope,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW,
    )

    assert broker.issue(reference, forged, now=NOW).findings[0].code == (
        CredentialBrokerCode.EXECUTION_INVALID
    )
    assert broker.issue(reference, expired, now=NOW).findings[0].code == (
        CredentialBrokerCode.EXECUTION_EXPIRED
    )

    verifier_miss = CredentialBroker(
        broker.policy,
        vault=StaticCredentialVault({reference.reference_id: ("vault-version-7", SECRET)}),
        execution_verifier=StaticCredentialExecutionVerifier(frozenset()),
    )
    assert verifier_miss.issue(reference, execution, now=NOW).findings[0].code == (
        CredentialBrokerCode.EXECUTION_INVALID
    )


def test_rotation_and_revocation_invalidate_outstanding_capabilities():
    reference, _, _, execution, vault, _, broker = _fixture()
    old = broker.require_capability(reference, execution, now=NOW)
    vault.rotate(reference, "vault-version-8", "rotated-secret-value-88")
    assert broker.rotate(reference, credential_version="vault-version-8", now=NOW) == 1

    with pytest.raises(CredentialBrokerError) as changed:
        broker.resolve(old, execution, now=NOW)
    assert changed.value.decision.findings[0].code == CredentialBrokerCode.VERSION_CHANGED

    current = broker.require_capability(reference, execution, now=NOW)
    assert broker.revoke(reference, now=NOW) == 1
    with pytest.raises(CredentialBrokerError) as revoked:
        broker.resolve(current, execution, now=NOW)
    assert revoked.value.decision.findings[0].code == CredentialBrokerCode.REFERENCE_REVOKED


def test_expired_capability_is_rejected_before_vault_access():
    reference, _, _, execution, _, _, broker = _fixture()
    capability = broker.require_capability(reference, execution, ttl_seconds=1, now=NOW)

    with pytest.raises(CredentialBrokerError) as expired:
        broker.resolve(capability, execution, now=NOW + timedelta(seconds=1))

    assert expired.value.decision.findings[0].code == CredentialBrokerCode.CAPABILITY_EXPIRED


def test_concurrent_resolution_consumes_capability_exactly_once():
    reference, _, _, execution, _, _, broker = _fixture()
    capability = broker.require_capability(reference, execution, now=NOW)

    def resolve_once() -> bool:
        try:
            broker.resolve(capability, execution, now=NOW).close()
        except CredentialBrokerError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: resolve_once(), range(8)))

    assert outcomes.count(True) == 1


@pytest.mark.parametrize("surface", list(CredentialSurface))
def test_boundary_guard_allows_only_opaque_reference_on_every_surface(surface):
    reference, _, _, _, _, _, _ = _fixture()
    guard = CredentialBoundaryGuard([reference], leak_canaries=[SECRET])

    safe = guard.inspect({"credential": reference}, surface)
    unsafe = guard.inspect({"nested": [{"value": SECRET}]}, surface)

    assert safe.is_safe
    assert unsafe.findings[0].code == CredentialBrokerCode.RAW_CREDENTIAL


def test_boundary_guard_detects_encoded_nested_and_split_canaries():
    reference, _, _, _, _, _, _ = _fixture()
    guard = CredentialBoundaryGuard([reference], leak_canaries=[SECRET])

    encoded = base64.b64encode(SECRET.encode()).decode()
    assert not guard.inspect(
        {"result": {"encoded": encoded}}, CredentialSurface.MODEL_OUTPUT
    ).is_safe
    assert not guard.inspect_stream([SECRET[:9], SECRET[9:20], SECRET[20:]]).is_safe
    assert guard.inspect_stream(["ordinary ", "response"]).is_safe


def test_credential_material_rejects_copy_pickle_and_model_visible_use():
    reference, _, _, _, _, _, _ = _fixture()
    material = CredentialMaterial(SECRET)
    guard = CredentialBoundaryGuard([reference], leak_canaries=[SECRET])

    assert not guard.inspect({"value": material}, CredentialSurface.SERIALIZATION).is_safe
    with pytest.raises(TypeError):
        pickle.dumps(material)
    with pytest.raises(TypeError):
        bytes(material)


def test_suspicious_keys_and_connector_exceptions_are_content_free():
    reference, _, _, _, _, _, _ = _fixture()
    guard = CredentialBoundaryGuard([reference], leak_canaries=[SECRET])
    connector_error = RuntimeError(f"connector rejected Authorization: Bearer {SECRET}")

    key_result = guard.inspect({"client_secret": "invented-value"}, CredentialSurface.TOOL_SCHEMA)
    nested_key_result = guard.inspect(
        {"authorization": {"parameters": ["invented-value"]}},
        CredentialSurface.TOOL_SCHEMA,
    )
    serialized_reference = guard.inspect(
        {"credential": reference.model_dump(mode="json")},
        CredentialSurface.TOOL_ARGUMENTS,
    )
    error_result = guard.inspect(connector_error, CredentialSurface.CONNECTOR_ERROR)
    with pytest.raises(CredentialBrokerError) as blocked:
        guard.require_safe(connector_error, CredentialSurface.EXCEPTION)

    assert key_result.findings[0].code == CredentialBrokerCode.SUSPICIOUS_FIELD
    assert nested_key_result.findings[0].code == CredentialBrokerCode.SUSPICIOUS_FIELD
    assert serialized_reference.is_safe
    assert error_result.findings[0].code == CredentialBrokerCode.RAW_CREDENTIAL
    assert SECRET not in str(blocked.value)
    assert SECRET not in repr(blocked.value.decision)
