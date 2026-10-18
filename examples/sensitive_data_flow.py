"""Track sensitive content through a model/tool flow and authorize its sink."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from trustrail import (
    DataClassification,
    DataFlowTransformation,
    SensitiveDataDerivationRequest,
    SensitiveDataDestination,
    SensitiveDataFlowGuard,
    SensitiveDataFlowPropagator,
    SensitiveDataFlowSigner,
    SensitiveDataSink,
    SensitiveDataSurface,
    SensitiveDataTransferRequest,
    data_label_reference,
)

now = datetime.now(UTC)
signer = SensitiveDataFlowSigner.generate(
    issuer_id="flow-control-plane",
    allowed_tenant_ids=frozenset({"tenant-a"}),
)

retrieved_bytes = b"customer support record"
retrieval_label = signer.issue(
    label_id="retrieval-label-42",
    artifact_id="crm-record-42",
    surface=SensitiveDataSurface.RETRIEVAL_DOCUMENT,
    content_digest=sha256(retrieved_bytes).hexdigest(),
    origin_ids=frozenset({"crm-row-42"}),
    origin_trust_domains=frozenset({"crm.internal"}),
    tenant_id="tenant-a",
    user_id="user-42",
    allowed_purpose_ids=frozenset({"customer-support"}),
    sensitivity=DataClassification.CONFIDENTIAL,
    allowed_sink_kinds=frozenset({SensitiveDataSink.MODEL, SensitiveDataSink.MCP_SERVER}),
    allowed_sink_ids=frozenset({"model-eu", "mcp-support"}),
    issued_at=now,
    expires_at=now + timedelta(minutes=30),
)

# A transformation never removes restrictions merely because the bytes changed.
model_output = b"summarized support response"
propagator = SensitiveDataFlowPropagator(signer, (signer.trusted_key,))
output_label = propagator.require_propagation(
    SensitiveDataDerivationRequest(
        request_id="model-output-42",
        label_id="output-label-42",
        artifact_id="model-output-42",
        surface=SensitiveDataSurface.MODEL_OUTPUT,
        content_digest=sha256(model_output).hexdigest(),
        source_labels=(retrieval_label,),
        transformation=DataFlowTransformation.MODEL_GENERATE,
        issued_at=now,
    ),
    now=now,
)

# Gate the exact bytes immediately before dispatch to the MCP server.
guard = SensitiveDataFlowGuard((signer.trusted_key,))
permit = guard.require(
    SensitiveDataTransferRequest(
        request_id="mcp-dispatch-42",
        label=output_label,
        source_labels=(retrieval_label,),
        content_digest=sha256(model_output).hexdigest(),
        authenticated_tenant_id="tenant-a",
        authenticated_user_ref=data_label_reference("user-42"),
        purpose_id="customer-support",
        destination=SensitiveDataDestination(
            sink_id="mcp-support",
            sink_kind=SensitiveDataSink.MCP_SERVER,
            tenant_id="tenant-a",
        ),
    ),
    now=now,
)

print(f"authorized={permit.authorization_id[:12]} sink={permit.sink_kind}")
