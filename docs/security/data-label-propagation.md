# End-to-end data-classification labels

`DataLabelSigner`, `DataLabelPropagator`, and `DataLabelGuard` implement
integrity-protected classification propagation for OWASP AISVS C5.2.7. They
carry sensitivity, tenant, purpose, residency, retention, permitted destination,
and handling requirements through prompts, retrieval, embeddings, caches, model
outputs, tool data, logs, and persisted artifacts.

These controls complement `DataLifecycleManager`: lifecycle records inventory
and delete copies, while data labels travel with in-memory and cross-service
content and are checked immediately before each boundary crossing.

## Issue trusted origin labels

Keep the Ed25519 private key in a classification control plane. Runtime workers
receive public `DataLabelTrustedKey` records through an authenticated key
registry. Never let users, retrieved content, tools, or models choose their own
labels.

```python
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from trustrail import (
    DataBoundaryKind,
    DataClassification,
    DataFlowSurface,
    DataHandlingRequirement,
    DataLabelSigner,
)

now = datetime.now(UTC)
signer = DataLabelSigner.generate(
    issuer_id="classification-control-plane",
    allowed_tenant_ids=frozenset({"tenant-a"}),
)
prompt_label = signer.issue(
    label_id="prompt-label-42",
    artifact_id="prompt-42",
    surface=DataFlowSurface.PROMPT,
    content_digest=sha256(prompt_bytes).hexdigest(),
    tenant_id="tenant-a",
    classification=DataClassification.CONFIDENTIAL,
    allowed_purpose_ids=frozenset({"customer-support"}),
    allowed_residencies=frozenset({"eu"}),
    permitted_destination_ids=frozenset(
        {"rag-assembler-eu", "model-provider-eu", "support-ui-eu"}
    ),
    permitted_boundary_kinds=frozenset(
        {
            DataBoundaryKind.RETRIEVAL_ASSEMBLY,
            DataBoundaryKind.PROVIDER_CALL,
            DataBoundaryKind.OUTPUT_DELIVERY,
        }
    ),
    handling_requirements=frozenset(
        {
            DataHandlingRequirement.ENCRYPT_IN_TRANSIT,
            DataHandlingRequirement.REDACT_LOGS,
            DataHandlingRequirement.NO_TRAINING,
        }
    ),
    retention_until=now + timedelta(days=14),
    issued_at=now,
)
```

The signature binds every field plus an opaque artifact reference and exact
content digest. Trusted keys bind each issuer to an explicit tenant set and can
carry activation, expiry, and revocation state.

## Join labels conservatively

Every combine, transform, summary, embedding, cache, or tool-result operation
must create a new label. `DataLabelPropagator` verifies all source signatures
and then applies a deterministic join:

- the highest source classification;
- the intersection of purposes, residencies, destination identities, and
  boundary kinds;
- the union of required handling controls;
- the earliest retention deadline; and
- sorted exact source-label digests.

Cross-tenant sources, duplicate sources, or sources with no common authority are
rejected.

```python
from trustrail import (
    DataLabelJoinRequest,
    DataLabelPropagator,
    DataTransformationKind,
)

propagator = DataLabelPropagator(
    signer,
    (signer.trusted_key,),  # production: authenticated public-key registry
)
context_label = propagator.require_join(
    DataLabelJoinRequest(
        request_id="join-context-42",
        label_id="context-label-42",
        artifact_id="context-42",
        surface=DataFlowSurface.RETRIEVAL_CONTEXT,
        content_digest=sha256(context_bytes).hexdigest(),
        source_labels=(prompt_label, retrieved_document_label),
        transformation=DataTransformationKind.COMBINE,
        issued_at=now,
    ),
    now=now,
)
```

The resulting label is signed by the configured derivation authority. If a
trusted-but-buggy producer constructs a weaker derived label, the boundary guard
recomputes the conservative constraints from the supplied source labels and
rejects the downgrade.

## Enforce every data boundary

Create destination capabilities from authenticated deployment configuration,
not request or model output. Call `require()` immediately before:

- provider/model calls;
- retrieval-context assembly;
- cache, database, memory, or artifact persistence;
- trace or application logging;
- tool invocation; and
- output delivery to a user, agent, or external service.

```python
from trustrail import (
    DataBoundaryRequest,
    DataLabelDestination,
    DataLabelGuard,
)

guard = DataLabelGuard((signer.trusted_key,))
destination = DataLabelDestination(
    destination_id="model-provider-eu",
    boundary_kind=DataBoundaryKind.PROVIDER_CALL,
    tenant_id="tenant-a",
    residency="eu",
    supported_classifications=frozenset(
        {
            DataClassification.PUBLIC,
            DataClassification.INTERNAL,
            DataClassification.CONFIDENTIAL,
        }
    ),
    enforced_handling=frozenset(
        {
            DataHandlingRequirement.ENCRYPT_IN_TRANSIT,
            DataHandlingRequirement.REDACT_LOGS,
            DataHandlingRequirement.NO_TRAINING,
        }
    ),
)
permit = guard.require(
    DataBoundaryRequest(
        request_id="provider-call-42",
        label=context_label,
        source_labels=(prompt_label, retrieved_document_label),
        content_digest=sha256(context_bytes).hexdigest(),
        authenticated_tenant_id="tenant-a",
        purpose_id="customer-support",
        destination=destination,
    ),
    now=now,
)
# Dispatch only after the exact request receives a permit.
```

The guard fails closed on missing, unsigned, expired, forged, content-swapped,
cross-tenant, unsupported, or downgraded labels; missing or mismatched lineage;
and unauthorized purposes, residencies, destinations, handling, or retention.
`DataLabelDecision.evidence` and `DataLabelAuditEvent` contain one-way references
and structural metadata, not artifact, tenant, destination, or content values.

## Security assumptions and residual risk

- Complete mediation is required. Direct SDK, network, vector-store, cache,
  logger, tool, filesystem, or response paths that bypass `DataLabelGuard` also
  bypass this control. Enforce routing and egress at infrastructure and service
  boundaries.
- Labels are only as accurate as the trusted classifier. Signatures prove who
  issued metadata and that it was not changed; they do not prove that content was
  classified correctly. Use reviewed rules, DLP/classifiers, and human escalation.
- Content digests do not provide confidentiality. Encrypt content and metadata in
  transit and at rest, isolate tenants, protect keys, and avoid exposing labels
  where tenant or policy metadata is sensitive.
- `MemoryDataLabelAuditSink` is process-local. Production systems need protected,
  durable audit storage and authenticated key distribution, rotation, and
  revocation. Clock synchronization is required for lifetime enforcement.
- Immediate source digests make each hop verifiable only when callers provide the
  source labels. Retain or resolve full transitive lineage in a durable catalog;
  do not accept a derived label without its required evidence.
- Destination declarations describe capabilities; they do not enforce encryption,
  regional routing, provider retention/training settings, redaction, access
  control, or deletion. Validate those properties independently and continuously.
- Label enforcement cannot revoke already disclosed data or remove existing
  copies. Continue lifecycle/deletion controls, least privilege, output filtering,
  incident response, and downstream contractual controls.

See [GenAI data lifecycle and verified deletion](data-lifecycle.md),
[vector and embedding security](vector-embedding-security.md), and
[sensitive-data controls](sensitive-data.md) for complementary safeguards.
