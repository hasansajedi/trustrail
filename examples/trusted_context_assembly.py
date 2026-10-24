"""Assemble typed trust zones and verify the exact request before dispatch."""

from hashlib import sha256

from trustrail import (
    ContextAssemblyPolicy,
    ContextOrigin,
    ContextProviderProfile,
    ContextRole,
    ContextSegment,
    InstructionPermission,
    TrustedContextAssembler,
    TrustLevel,
)

tenant_id = "tenant-42"  # Derive this from authenticated server-side state.
purpose = "customer-support"
assembler = TrustedContextAssembler(
    sha256(b"replace this demo secret with a secret-manager key").digest(),
    ContextAssemblyPolicy(provider_profile=ContextProviderProfile.OPENAI),
)

segments = [
    ContextSegment(
        segment_id="retrieval:document-7:chunk-2",
        ordinal=30,
        content="The customer's plan renews monthly.",
        origin=ContextOrigin.RETRIEVAL,
        role=ContextRole.DATA,
        trust_level=TrustLevel.UNTRUSTED,
        tenant_id=tenant_id,
        purpose=purpose,
        provenance_id="index:support-docs:v12/document-7/chunk-2",
        instruction_permission=InstructionPermission.NONE,
    ),
    ContextSegment(
        segment_id="request:user",
        ordinal=20,
        content="When does my plan renew?",
        origin=ContextOrigin.USER,
        role=ContextRole.USER,
        trust_level=TrustLevel.UNTRUSTED,
        tenant_id=tenant_id,
        purpose=purpose,
        provenance_id="authenticated-request-body",
        instruction_permission=InstructionPermission.USER,
    ),
    ContextSegment(
        segment_id="policy:2026-10",
        ordinal=0,
        content="Answer only from supplied support data.",
        origin=ContextOrigin.SYSTEM_POLICY,
        role=ContextRole.SYSTEM,
        trust_level=TrustLevel.TRUSTED,
        tenant_id=tenant_id,
        purpose=purpose,
        provenance_id="policy-store:support:2026-10",
        instruction_permission=InstructionPermission.SYSTEM,
    ),
]

request, manifest = assembler.require_assembly(
    segments,
    request_id="request-123",
    tenant_id=tenant_id,
    purpose=purpose,
)

# Perform this verification immediately before the provider SDK call. Dispatch
# these returned messages, not an earlier or reconstructed value.
verified = assembler.require_provider_request(
    request,
    manifest,
    request_id="request-123",
    tenant_id=tenant_id,
    purpose=purpose,
)
provider_messages = verified.provider_messages()
print([message["role"] for message in provider_messages])
print(provider_messages[-1]["content"].splitlines()[0])
