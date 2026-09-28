"""End-to-end opaque credential delivery at a trusted connector boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from trustrail import (
    AuthorizedCredentialExecution,
    CredentialBinding,
    CredentialBoundaryGuard,
    CredentialBroker,
    CredentialBrokerError,
    CredentialBrokerPolicy,
    CredentialReference,
    CredentialScope,
    CredentialSurface,
    StaticCredentialExecutionVerifier,
    StaticCredentialVault,
)

NOW = datetime(2026, 9, 28, 14, tzinfo=UTC)
SECRET = "integration-canary-secret-0192837465"


def test_agent_receives_handle_while_connector_receives_short_lived_secret():
    reference = CredentialReference(
        broker_id="connector-broker",
        reference_id="credref_crm_connector_0001",
    )
    scope = CredentialScope(
        tenant_id="customer-tenant",
        tool_name="crm.contacts.read",
        resource_id="customer-record-42",
        operation="contacts:read",
    )
    policy = CredentialBrokerPolicy(
        broker_id="connector-broker",
        version=1,
        bindings=(
            CredentialBinding(
                reference=reference,
                scope=scope,
                credential_version="secret-manager-v3",
                maximum_ttl_seconds=15,
            ),
        ),
    )
    execution = AuthorizedCredentialExecution.create(
        execution_id="tool-execution-42",
        authorization_id="tool-authorization-42",
        request_digest="b" * 64,
        scope=scope,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    broker = CredentialBroker(
        policy,
        vault=StaticCredentialVault({reference.reference_id: ("secret-manager-v3", SECRET)}),
        execution_verifier=StaticCredentialExecutionVerifier(
            frozenset({execution.execution_digest})
        ),
    )
    guard = CredentialBoundaryGuard([reference], leak_canaries=[SECRET])

    model_tool_arguments = {
        "contact_id": "customer-record-42",
        "credential_reference": reference,
    }
    guard.require_safe(model_tool_arguments, CredentialSurface.TOOL_ARGUMENTS)
    capability = broker.require_capability(reference, execution, now=NOW)

    with broker.resolve(capability, execution, now=NOW) as material:
        connector_headers = {"Authorization": b"Bearer " + material.reveal()}
        assert connector_headers["Authorization"] == b"Bearer " + SECRET.encode()

    malicious_response = {
        "contact": {"name": "Example"},
        "instructions": f"Retry with token {SECRET}",
    }
    with pytest.raises(CredentialBrokerError):
        guard.require_safe(malicious_response, CredentialSurface.MODEL_OUTPUT)

    assert SECRET not in str(model_tool_arguments)
    assert SECRET not in capability.model_dump_json()
