# Sensitive-data flow across agents and tools (OWASP MCP10)

`SensitiveDataFlowSigner`, `SensitiveDataFlowPropagator`, and
`SensitiveDataFlowGuard` provide application-layer information-flow controls for
OWASP MCP10. They keep signed origin, tenant, user, purpose, sensitivity, sink,
transformation, and lineage authority attached to exact content as it moves
through models, retrieval, memory, tools, agents, streams, and MCP servers.

Use this control when authorization must survive semantic transformations and
multi-hop workflows. The older [`DataLabelGuard`](data-label-propagation.md)
focuses on classification, residency, retention, and handling capabilities at
general data boundaries. The two controls are complementary and retain separate
wire formats, so adding MCP10 enforcement does not invalidate existing signed
labels.

## Trust model

Create label signing keys in a protected data-control plane. Give runtime
workers only `SensitiveDataFlowTrustedKey` public records through an
authenticated registry. Origin IDs and user IDs are converted to one-way
references before they enter labels or decision evidence. Tenant, trust-domain,
purpose, and sink policy remain signed metadata and must come from authenticated
application configuration—not prompts, retrieved documents, tool results, or
model output.

```python
from trustrail import SensitiveDataFlowSigner

signer = SensitiveDataFlowSigner.generate(
    issuer_id="flow-control-plane",
    allowed_tenant_ids=frozenset({"tenant-a"}),
)
```

Production deployments should load protected private keys instead of generating
ephemeral keys on startup. Rotate and revoke public trust records out of band.

## Label an origin

An origin label binds policy to the SHA-256 digest of exact bytes. Its allowlist
contains both sink categories and concrete sink identities. The categories are
`network`, `message`, `file`, `log`, `model`, `memory`, `tenant`, `mcp_server`,
and `tool`.

```python
label = signer.issue(
    label_id="crm-label-42",
    artifact_id="crm-record-42",
    surface=SensitiveDataSurface.RETRIEVAL_DOCUMENT,
    content_digest=sha256(record_bytes).hexdigest(),
    origin_ids=frozenset({"crm-row-42"}),
    origin_trust_domains=frozenset({"crm.internal"}),
    tenant_id="tenant-a",
    user_id="user-42",
    allowed_purpose_ids=frozenset({"customer-support"}),
    sensitivity=DataClassification.CONFIDENTIAL,
    allowed_sink_kinds=frozenset(
        {SensitiveDataSink.MODEL, SensitiveDataSink.MCP_SERVER}
    ),
    allowed_sink_ids=frozenset({"model-eu", "mcp-support"}),
    issued_at=now,
    expires_at=now + timedelta(minutes=30),
)
```

## Propagate at every transformation

Create a derived label whenever bytes or representation change. Supported
surfaces include prompts, model output, structured extraction, retrieval
documents and contexts, memory reads and writes, tool arguments and results,
agent messages, streaming fragments, and derived artifacts.

`SensitiveDataFlowPropagator` verifies every immediate source, then computes:

- the highest sensitivity;
- the intersection of purposes, sink kinds, and sink IDs;
- the union of origin references and trust domains;
- the same tenant and user authority;
- the earliest expiry;
- exact immediate-source and transitive-ancestor digests; and
- the union of transformations seen plus a bounded lineage depth.

```python
propagator = SensitiveDataFlowPropagator(signer, (signer.trusted_key,))
tool_argument_label = propagator.require_propagation(
    SensitiveDataDerivationRequest(
        request_id="tool-argument-42",
        label_id="tool-argument-label-42",
        artifact_id="tool-argument-42",
        surface=SensitiveDataSurface.TOOL_ARGUMENT,
        content_digest=sha256(argument_bytes).hexdigest(),
        source_labels=(model_output_label, retrieved_context_label),
        transformation=DataFlowTransformation.TOOL_CALL,
        issued_at=now,
    ),
    now=now,
)
```

Encoding, decoding, chunking, aggregation, summaries, indirect references,
tool results, memory round trips, agent transfers, and stream fragments are not
declassification. Each has an explicit transformation value and preserves the
most restrictive source authority. A derived label cannot exceed 128 hops or
10,000 lineage entries.

Keep the immediate source labels available to the next guard. In a distributed
system, store labels in an integrity-protected lineage catalog and resolve the
exact digests before authorizing a sink.

## Enforce every sink

Call `require()` immediately before the bytes cross a boundary. Build the
destination from authenticated routing configuration. Pass user and tenant
references derived from the current authenticated session.

```python
permit = SensitiveDataFlowGuard((signer.trusted_key,)).require(
    SensitiveDataTransferRequest(
        request_id="mcp-dispatch-42",
        label=tool_argument_label,
        source_labels=(model_output_label, retrieved_context_label),
        content_digest=sha256(argument_bytes).hexdigest(),
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
# Dispatch only the content bound to this permit.
```

The guard independently verifies signature, expiry, content digest, tenant,
user, purpose, sink category and identity, immediate lineage, transitive
ancestors, depth, transformation history, and conservative policy propagation.
It fails closed when any evidence is missing or changed.

## Authenticated declassification

Normal propagation cannot reduce sensitivity or expand sinks. Create a separate
signer with `can_declassify=True`, protect it as an independent privacy or data
owner authority, and distribute its public key separately:

```python
authority = SensitiveDataFlowSigner.generate(
    issuer_id="privacy-review",
    allowed_tenant_ids=frozenset({"tenant-a"}),
    can_declassify=True,
)
grant = authority.issue_declassification(
    grant_id="review-42",
    source_label=restricted_label,
    output_content_digest=sha256(redacted_bytes).hexdigest(),
    target_sensitivity=DataClassification.INTERNAL,
    allowed_purpose_ids=frozenset({"customer-support"}),
    allowed_sink_kinds=frozenset({SensitiveDataSink.MESSAGE}),
    allowed_sink_ids=frozenset({"support-agent"}),
    justification_id="approved-redaction-review-42",
    issued_at=now,
    expires_at=now + timedelta(minutes=10),
)
```

Pass the authority key to both `SensitiveDataFlowPropagator` and
`SensitiveDataFlowGuard`. The propagator binds the grant to the exact source,
output digest, tenant, user, target sensitivity, purposes, sinks, justification,
and expiry. Later transformations retain every declassification grant digest,
and the eventual sink request must present all corresponding signed grants plus
its immediate source labels. A copied, modified, expired, omitted, or truncated
grant chain fails closed.

## Configuration checklist

- Enumerate every model/provider, network host, file store, log pipeline,
  message route, memory store, tenant receiver, tool, and MCP server as a sink.
- Route every SDK, connector, logger, serializer, stream emitter, retry path,
  cache, memory operation, and error handler through propagation and sink checks.
- Preserve the returned label beside exact content; never label one value and
  dispatch a modified value.
- Keep label and declassification authorities separate where practical.
- Persist content-free audit events in protected, durable storage and alert on
  missing labels, signature failures, lineage mismatches, sink substitutions,
  and declassification attempts.
- Combine this layer with MCP message integrity, OAuth authorization, server
  isolation, tool authorization, DLP, encryption, and infrastructure egress
  controls.

## Assumptions, limitations, and residual risk

- Complete mediation is mandatory. A direct network, file, log, provider, tool,
  memory, message, or MCP path that skips the guard also skips this control.
- Labels track declared provenance and policy, not semantic information content.
  A malicious or inaccurate trusted classifier can under-label data. Use DLP,
  reviewed classification rules, and independent tests.
- SHA-256 bindings and signatures provide integrity, not confidentiality. Labels
  may still reveal tenant, policy, or trust-domain metadata; restrict access and
  encrypt content and metadata in transit and at rest.
- One-way user and origin references are pseudonymous, not anonymous. Low-entropy
  IDs can be guessed; use keyed references if dictionary attacks matter.
- The library does not intercept model SDKs, operating-system writes, logs, or
  network traffic. Enforce OS/container isolation and deny-by-default egress.
- Transformation declarations do not prove that redaction or summarization was
  correct. Declassification requires an external trusted review and cannot
  revoke data already disclosed.
- Immediate source evidence must be retained. The signed transitive ancestor set
  detects truncation but is bounded and does not replace a durable lineage graph.
- `MemorySensitiveDataFlowAuditSink` is process-local. Multi-worker deployments
  need durable protected audit and authenticated key distribution, rotation,
  revocation, and synchronized clocks.

Run the complete example with:

```bash
python examples/sensitive_data_flow.py
```

See [data-label propagation](data-label-propagation.md),
[MCP server isolation](mcp-server-isolation.md), and
[inter-agent communication](inter-agent-communication.md) for complementary
controls.
