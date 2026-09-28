"""Bypass corpus for OWASP AISVS C9 credential isolation."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    AuthorizedCredentialExecution,
    CredentialBinding,
    CredentialBoundaryGuard,
    CredentialBroker,
    CredentialBrokerError,
    CredentialBrokerPolicy,
    CredentialMaterial,
    CredentialReference,
    CredentialScope,
    CredentialSurface,
    StaticCredentialExecutionVerifier,
    StaticCredentialVault,
)

NOW = datetime(2026, 9, 28, 16, tzinfo=UTC)
CANARY = "security-corpus-canary-secret-29384756"
CASES = json.loads(
    (Path(__file__).parent.parent / "security_corpus" / "credential_broker.json").read_text()
)


def _fixture():
    reference = CredentialReference(
        broker_id="security-broker",
        reference_id="credref_security_target_001",
    )
    scope = CredentialScope(
        tenant_id="tenant-secure",
        tool_name="secure.records.get",
        resource_id="record-private-1",
        operation="records:read",
    )
    policy = CredentialBrokerPolicy(
        broker_id="security-broker",
        version=1,
        bindings=(
            CredentialBinding(
                reference=reference,
                scope=scope,
                credential_version="version-1",
                maximum_ttl_seconds=20,
            ),
        ),
    )
    execution = AuthorizedCredentialExecution.create(
        execution_id="secure-execution",
        authorization_id="secure-authorization",
        request_digest="c" * 64,
        scope=scope,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
    )
    vault = StaticCredentialVault({reference.reference_id: ("version-1", CANARY)})
    broker = CredentialBroker(
        policy,
        vault=vault,
        execution_verifier=StaticCredentialExecutionVerifier(
            frozenset({execution.execution_digest})
        ),
    )
    guard = CredentialBoundaryGuard([reference], leak_canaries=[CANARY])
    return reference, scope, execution, vault, broker, guard


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_credential_bypass_corpus(case):
    reference, scope, execution, vault, broker, guard = _fixture()
    mutation = case["mutation"]

    if mutation in {"tenant", "tool", "resource", "operation"}:
        field = {
            "tenant": "tenant_id",
            "tool": "tool_name",
            "resource": "resource_id",
            "operation": "operation",
        }[mutation]
        rebound_scope = scope.model_copy(update={field: f"attacker-{mutation}"})
        rebound = AuthorizedCredentialExecution.create(
            execution_id=execution.execution_id,
            authorization_id=execution.authorization_id,
            request_digest=execution.request_digest,
            scope=rebound_scope,
            issued_at=execution.issued_at,
            expires_at=execution.expires_at,
        )
        decision = broker.issue(reference, rebound, now=NOW)
        code = decision.findings[0].code.value
    elif mutation == "execution":
        capability = broker.require_capability(reference, execution, now=NOW)
        rebound = AuthorizedCredentialExecution.create(
            execution_id="another-execution",
            authorization_id=execution.authorization_id,
            request_digest=execution.request_digest,
            scope=scope,
            issued_at=execution.issued_at,
            expires_at=execution.expires_at,
        )
        with pytest.raises(CredentialBrokerError) as blocked:
            broker.resolve(capability, rebound, now=NOW)
        code = blocked.value.decision.findings[0].code.value
    elif mutation == "replay":
        capability = broker.require_capability(reference, execution, now=NOW)
        broker.resolve(capability, execution, now=NOW).close()
        with pytest.raises(CredentialBrokerError) as blocked:
            broker.resolve(capability, execution, now=NOW)
        code = blocked.value.decision.findings[0].code.value
    elif mutation == "rotation":
        capability = broker.require_capability(reference, execution, now=NOW)
        vault.rotate(reference, "version-2", "replacement-canary-secret-2")
        broker.rotate(reference, credential_version="version-2", now=NOW)
        with pytest.raises(CredentialBrokerError) as blocked:
            broker.resolve(capability, execution, now=NOW)
        code = blocked.value.decision.findings[0].code.value
    else:
        surface = CredentialSurface(case["surface"])
        if mutation == "direct":
            decision = guard.inspect(CANARY, surface)
        elif mutation == "nested":
            decision = guard.inspect({"outer": [{"inner": CANARY}]}, surface)
        elif mutation == "base64":
            decision = guard.inspect(base64.b64encode(CANARY.encode()).decode(), surface)
        elif mutation == "split":
            decision = guard.inspect_stream([CANARY[:7], CANARY[7:19], CANARY[19:]])
        elif mutation == "exception":
            decision = guard.inspect(RuntimeError(CANARY), surface)
        elif mutation == "material":
            decision = guard.inspect(CredentialMaterial(CANARY), surface)
        else:
            raise AssertionError(f"unknown mutation: {mutation}")
        code = decision.findings[0].code.value

    assert code == case["expected_code"]


def test_debug_retry_and_error_paths_never_disclose_secret():
    reference, _, execution, _, broker, guard = _fixture()
    capability = broker.require_capability(reference, execution, now=NOW)
    material = broker.resolve(capability, execution, now=NOW)
    debug_values = [repr(material), str(material), repr(capability)]
    material.close()

    with pytest.raises(CredentialBrokerError) as replay:
        broker.resolve(capability, execution, now=NOW)
    debug_values.extend([str(replay.value), repr(replay.value.decision)])

    for value in debug_values:
        assert CANARY not in value
        assert guard.inspect(value, CredentialSurface.TELEMETRY).is_safe
