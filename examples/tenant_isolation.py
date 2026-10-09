"""Bind AI cache and state access to a signed tenant security context."""

import secrets
from datetime import UTC, datetime, timedelta

from trustrail import (
    MemoryTenantIsolationAuditSink,
    TenantContextSigner,
    TenantIsolationGuard,
    TenantIsolationPolicy,
    TenantStateAccessRequest,
    TenantStateKeyBuilder,
    TenantStateKind,
    TenantStateOperation,
)

now = datetime.now(tz=UTC)
signer = TenantContextSigner.generate(
    issuer_id="identity-control-plane",
    allowed_tenant_ids=frozenset({"tenant-a"}),
)
context = signer.issue(
    context_id="authenticated-request-42",
    tenant_id="tenant-a",
    principal_id="user-7",
    session_id="session-42",
    allowed_state_kinds=frozenset({TenantStateKind.PROMPT_CACHE}),
    issued_at=now,
    expires_at=now + timedelta(minutes=15),
    nonce="context-nonce-1234567890",
)

# Load this HMAC key from protected configuration in production and use shared,
# durable claim state when requests can be handled by multiple workers.
key_builder = TenantStateKeyBuilder(
    secrets.token_bytes(32),
    namespace="production-ai",
)
audit = MemoryTenantIsolationAuditSink()
guard = TenantIsolationGuard(
    TenantIsolationPolicy.strict(policy_id="tenant-state-policy"),
    key_builder,
    (signer.trusted_key,),
    audit_sink=audit,
)

state_key = key_builder.build(
    context,
    state_kind=TenantStateKind.PROMPT_CACHE,
    artifact_id="prompt-hash-42",
)
write = guard.require_state(
    TenantStateAccessRequest(
        request_id="cache-write-42",
        context=context,
        state_kind=TenantStateKind.PROMPT_CACHE,
        operation=TenantStateOperation.WRITE,
        artifact_id="prompt-hash-42",
        state_key=state_key,
        requested_expires_at=now + timedelta(minutes=5),
    ),
    now=now,
)
assert write.binding is not None

# Store the returned binding beside the cache entry. Reads must present the
# exact same tenant-bound key and binding; cross-tenant reuse fails closed.
read = guard.require_state(
    TenantStateAccessRequest(
        request_id="cache-read-42",
        context=context,
        state_kind=TenantStateKind.PROMPT_CACHE,
        operation=TenantStateOperation.READ,
        artifact_id="prompt-hash-42",
        state_key=state_key,
        observed_binding=write.binding,
    ),
    now=now + timedelta(seconds=1),
)

print("Tenant-bound state authorized:", read.storage_key == write.storage_key)
print("Content-free isolation events:", len(audit.events))
