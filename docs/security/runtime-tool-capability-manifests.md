# Runtime tool capability manifests

`ToolCapabilityEnforcer` implements application-layer controls for OWASP AISVS
C9.3.3 and C9.3.4. It makes a tool's actual executor and runtime boundaries part
of authorization instead of trusting only its name, description, or arguments.

## Security workflow

1. A publisher uses `ToolManifestSigner` to sign a canonical manifest for one
   exact executable digest or authenticated service identity. The manifest
   declares effects, scopes, filesystem roots, exact egress destinations,
   opaque credential references, resource ceilings, closed input/output
   contracts, and permitted data classifications.
2. The application calls `require_discovery()` with the independently measured
   live executor. trustrail verifies the publisher key, signature, lifetime,
   and identity, then signs a discovery binding in the control plane.
3. `require_approval()` signs approval over the exact manifest, executor, and
   discovery digest. Replacing any of them invalidates approval.
4. Immediately before every dispatch, the runtime enforcement service provides
   short-lived `ToolRuntimeEvidence`. `require_authorization()` verifies its
   trusted signature and proves the active filesystem, egress, credential, and
   resource policies are no wider than the manifest and still cover the exact
   request. Missing, stale, incomplete, or unavailable evidence fails closed.
5. The application executes only with the returned single-use
   `AuthorizedToolExecution`. It keeps output quarantined until
   `require_output()` validates the manifest-bound output schema, byte ceiling,
   and classification.

Use this control together with semantic authorization, downstream service
authorization, and credential brokering. A valid capability manifest says what
one implementation may do; it does not establish that the user's intent allows
the action.

## Configuration example

```python
from datetime import UTC, datetime, timedelta

from trustrail import (
    ToolCapabilityEffect,
    ToolCapabilityEnforcer,
    ToolDataClassification,
    ToolExecutionRequest,
    ToolExecutorIdentity,
    ToolExecutorKind,
    ToolFilesystemCapability,
    ToolManifestPolicy,
    ToolManifestSigner,
    ToolResourceLimits,
    ToolRuntimeEvidenceSigner,
)

publisher = ToolManifestSigner.generate(authority_id="tool-publisher")
control_plane = ToolManifestSigner.generate(authority_id="tool-control-plane")
runtime_attestor = ToolRuntimeEvidenceSigner.generate(authority_id="sandbox-attestor")
now = datetime.now(UTC)

executor = ToolExecutorIdentity(
    kind=ToolExecutorKind.EXECUTABLE,
    executor_id="invoice.lookup",
    # Measure the deployed executable independently; do not accept this from the model.
    identity_digest="a" * 64,
)
filesystem = ToolFilesystemCapability(read_roots=("/sandbox/invoices",))
limits = ToolResourceLimits(
    cpu_millis=1_000,
    memory_bytes=64 * 1024 * 1024,
    duration_ms=5_000,
    output_bytes=4_096,
    network_bytes=1,  # Fields are explicit and must be positive.
)
manifest = publisher.sign_manifest(
    manifest_id="invoice-lookup-v1",
    tool_id="invoice.lookup",
    version="1.0.0",
    executor=executor,
    effects=frozenset({ToolCapabilityEffect.READ}),
    scopes=frozenset({"invoices:read"}),
    filesystem=filesystem,
    resources=limits,
    input_schema={
        "type": "object",
        "properties": {"invoice_id": {"type": "string"}},
        "required": ["invoice_id"],
        "additionalProperties": False,
    },
    output_schema={
        "type": "object",
        "properties": {"status": {"type": "string"}},
        "required": ["status"],
        "additionalProperties": False,
    },
    input_classifications=frozenset({ToolDataClassification.CONFIDENTIAL}),
    max_output_classification=ToolDataClassification.CONFIDENTIAL,
    issued_at=now,
    expires_at=now + timedelta(hours=1),
)
enforcer = ToolCapabilityEnforcer(
    manifest_keys=(publisher.trusted_key,),
    evidence_keys=(runtime_attestor.trusted_key,),
    control_signer=control_plane,
    policy=ToolManifestPolicy(max_evidence_age_seconds=30),
)

discovery = enforcer.require_discovery(manifest, executor, now=now)
approval = enforcer.require_approval(
    manifest, discovery, approved_by="security-reviewer", now=now
)
request = ToolExecutionRequest(
    execution_id="operation-42",
    tool_id=manifest.tool_id,
    version=manifest.version,
    manifest_digest=manifest.manifest_digest,
    executor=executor,
    effects=frozenset({ToolCapabilityEffect.READ}),
    scopes=frozenset({"invoices:read"}),
    filesystem=filesystem,
    resources=limits,
    input_classification=ToolDataClassification.CONFIDENTIAL,
    input_value={"invoice_id": "inv-42"},
)

# Obtain this from the trusted enforcement service immediately before dispatch.
evidence = runtime_attestor.sign(
    evidence_id="runtime-snapshot-42",
    manifest_digest=manifest.manifest_digest,
    executor=executor,
    filesystem=filesystem,
    egress=frozenset(),
    credential_references=frozenset(),
    resources=limits,
    issued_at=now,
    expires_at=now + timedelta(seconds=30),
)
authorization = enforcer.require_authorization(
    manifest, approval, request, evidence, now=now
)
# Dispatch here, then pass a ToolExecutionOutput to require_output before release.
```

In production, load public keys from protected configuration. Keep publisher,
control-plane, and runtime-attestor private keys in separate KMS/HSM or workload
identity boundaries. Do not generate them during application startup.

## Supported contracts

Input and output contracts use a deliberately bounded JSON Schema subset:
`type`, closed object `properties`/`required`, homogeneous array `items`,
`enum`, `const`, string and array lengths, numeric bounds, and regular-expression
`pattern`. Object schemas must set `additionalProperties` to `false`.
References, combinators, conditionals, remote schemas, and unknown keywords are
rejected when a manifest is created. This makes validation local and
deterministic; convert richer schemas to this subset or enforce them in a
separate trusted validator as an additional control.

## Assumptions and limitations

- Executor identity, runtime evidence, and key configuration must come from
  trusted infrastructure outside model/tool control. trustrail verifies signed
  claims; it does not measure binaries, authenticate services, or configure OS,
  container, network, credential, or compute enforcement.
- Every discovery, approval, dispatch, retry, fallback, and output path must be
  mediated. A direct SDK, shell, plugin, or connector path can bypass this
  library.
- The built-in authorization store is process-local. Multi-worker deployments
  need a shared atomic single-use lease store before treating replay protection
  as distributed.
- Exact host/port declarations do not prevent DNS rebinding, proxy tunneling,
  protocol smuggling, redirects, or downstream authorization failures. Enforce
  resolved-address policy and TLS/service identity in the network layer.
- Filesystem checks compare normalized POSIX roots. The sandbox must prevent
  symlink, mount, device, namespace, and time-of-check/time-of-use escapes.
- Resource evidence declares configured ceilings, not observed consumption.
  The runtime must terminate overruns and independently report/monitor usage.
- Signatures provide integrity and authenticity, not confidentiality. Keep tool
  input and output out of findings, logs, and approval metadata; protect payload
  storage and transport separately.
- Clock synchronization, key rotation/revocation distribution, durable approval
  records, availability policy, monitoring, and incident response remain the
  deployer's responsibility. Verification and attestation outages must remain
  fail closed.

Residual risk includes a trusted publisher signing an over-privileged manifest,
a compromised runtime attestor lying about enforcement, a correctly identified
but malicious executor operating within its declared powers, semantic schema
abuse, side channels, and infrastructure bypass outside the mediated path.
