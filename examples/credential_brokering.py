"""Resolve a single-use credential only inside a trusted tool connector."""

from datetime import UTC, datetime, timedelta

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
    MemoryCredentialAuditSink,
    StaticCredentialExecutionVerifier,
    StaticCredentialVault,
)

now = datetime.now(tz=UTC)
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
    version=1,
    bindings=(
        CredentialBinding(
            reference=reference,
            scope=scope,
            credential_version="vault-version-7",
            maximum_ttl_seconds=30,
        ),
    ),
)

# Build this record from trusted tool-authorization state, never from arguments
# supplied by the model. The static adapters below are for examples and tests.
execution = AuthorizedCredentialExecution.create(
    execution_id="execution-42",
    authorization_id="authorization-42",
    request_digest="a" * 64,
    scope=scope,
    issued_at=now - timedelta(seconds=1),
    expires_at=now + timedelta(minutes=1),
)
demo_secret = "example-only-downstream-token"
audit = MemoryCredentialAuditSink()
broker = CredentialBroker(
    policy,
    vault=StaticCredentialVault({reference.reference_id: ("vault-version-7", demo_secret)}),
    execution_verifier=StaticCredentialExecutionVerifier(frozenset({execution.execution_digest})),
    audit_sink=audit,
)

# Model-visible structures contain only the opaque reference. A boundary guard
# can also scan schemas, arguments, output, memory, telemetry, and exceptions.
boundary = CredentialBoundaryGuard([reference], leak_canaries=[demo_secret])
boundary.require_safe(
    {"credential": reference.model_dump(mode="json")},
    CredentialSurface.TOOL_ARGUMENTS,
)

capability = broker.require_capability(
    reference,
    execution,
    ttl_seconds=15,
    now=now,
)


def trusted_payment_connector(token: bytes) -> int:
    """Stand in for an HTTP client that never exposes its auth header."""
    if not token:
        raise RuntimeError("credential was empty")
    return 202


# Resolve after model processing and close the managed buffer immediately. Do
# not return material, headers, prepared requests, or debug objects to the agent.
with broker.resolve(capability, execution, now=now) as material:
    status = trusted_payment_connector(material.reveal())

print("Downstream status:", status)
print("Content-free broker events:", len(audit.events))

# A capability is consumed before vault resolution and cannot be replayed.
try:
    broker.resolve(capability, execution, now=now)
except CredentialBrokerError as exc:
    print("Replay blocked:", exc.decision.findings[0].code.value)

# The same canary is blocked if it appears on a model-visible boundary.
leak = boundary.inspect(
    {"authorization": demo_secret},
    CredentialSurface.MODEL_OUTPUT,
)
print("Credential leak allowed:", leak.is_safe)
