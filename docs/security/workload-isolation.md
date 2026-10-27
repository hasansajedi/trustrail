# Runtime isolation and safe model loading (OWASP AISVS C4)

Model files are active inputs to a runtime. Pickle-family formats, custom model
code, loader plugins, shared filesystems, ambient credentials, network access,
and accelerator memory can turn a model deployment into arbitrary code
execution or cross-tenant disclosure. Content scanning alone cannot establish
that the process or hardware boundary is safe.

`WorkloadAdmissionGuard` is a policy and evidence boundary. It does **not** load
a model, create a container or microVM, enforce a mount, partition a device,
clear memory, or prove hardware isolation. Those controls must be implemented by
an external runtime broker and authenticated through the verifier hooks.

## Declare the complete workload

Bind the exact artifact and immutable loader to its tenant, environment,
purpose, sandbox profile, host mounts, egress, opaque credential references,
device partitions, resource ceilings, and teardown requirements:

```python
from trustrail import (
    ModelArtifact,
    ModelLoader,
    ModelSerializationFormat,
    WorkloadManifest,
    WorkloadSandboxKind,
)

loader = ModelLoader(
    loader_id="safetensors-loader-v3",
    implementation_digest=trusted_loader_sha256,
    supported_formats=frozenset({ModelSerializationFormat.SAFETENSORS}),
)
manifest = WorkloadManifest.create(
    workload_id="support-inference",
    tenant_id=authenticated_tenant.id,
    environment_id="production-eu",
    purpose_id="customer-support",
    artifact=ModelArtifact(
        artifact_id="support-model-v3",
        digest=verified_model_sha256,
        format=ModelSerializationFormat.SAFETENSORS,
        size_bytes=verified_model_size,
    ),
    loader_id=loader.loader_id,
    loader_digest=loader.implementation_digest,
    sandbox_kind=WorkloadSandboxKind.MICROVM,
    sandbox_profile_id="model-serving-v3",
)
```

All fields are included in `manifest_digest`. Use authenticated application
state for the tenant and environment; never accept those values from model
metadata or a prompt.

Host mounts, network destinations, credential references, and devices are
default-deny. An empty policy set means none are allowed. When needed, use exact
`HostMount`, `WorkloadEgressRule`, `WorkloadCredential`, and `WorkloadDevice`
objects in both the manifest and the policy. Prefer no host mounts, no egress,
short-lived workload identity, read-only/no-exec mounts, and an exclusive
accelerator partition.

## Default-deny executable model formats

The safe-format allowlist accepts only non-executable formats. Pickle, PyTorch
pickle, joblib, Keras H5, and custom-code artifacts cannot be added to
`allowed_safe_formats`. Those formats—and a `ModelLoader` with
`can_execute_arbitrary_code=True`, regardless of format—require an
`ExecutableLoadApproval` bound to one tenant, artifact digest, format, loader ID
and digest, sandbox profile, reviewer, and expiry:

```python
from datetime import timedelta
from trustrail import ExecutableLoadApproval

exception = ExecutableLoadApproval(
    approval_ref="risk-acceptance-42",
    tenant_id=manifest.tenant_id,
    artifact_digest=manifest.artifact.digest,
    format=manifest.artifact.format,
    loader_id=manifest.loader_id,
    loader_digest=manifest.loader_digest,
    sandbox_profile_id=manifest.sandbox_profile_id,
    approved_by="security-reviewer",
    expires_at=now + timedelta(hours=1),
)
```

An exception acknowledges risk; it does not make deserialization safe. Load the
artifact only inside the disposable attested runtime, with the narrowest
possible privileges, and migrate to a non-executable format.

## Require infrastructure evidence and external enforcement

Configure an exact loader inventory and resource ceiling, then authenticate the
runtime provider's evidence:

```python
from trustrail import WorkloadAdmissionGuard, WorkloadAdmissionPolicy

policy = WorkloadAdmissionPolicy(
    loaders=(loader,),
    allowed_sandbox_profiles=frozenset({"model-serving-v3"}),
    trusted_attestation_providers=frozenset({"production-runtime"}),
)
guard = WorkloadAdmissionGuard(
    policy,
    attestation_verifier=runtime_control_plane,
    teardown_verifier=runtime_control_plane,
    enforcement_hooks=(organization_admission_controller,),
)
authorization = guard.require(manifest, runtime_attestation)
```

`WorkloadAttestation` binds the exact manifest, workload, tenant, environment,
sandbox mechanism/profile, and runtime instance. It declares environment
separation, a dedicated tenant runtime, memory/cache isolation, and each
required control. Missing, expired, tampered, replayed, rebound, untrusted, or
unverifiable evidence blocks admission. Enforcement hooks receive the exact
manifest and attestation; denial or an exception fails closed.

Dispatch the original manifest and returned short-lived authorization only to
the attested external broker. Never call `pickle.load`, framework auto-loaders,
dynamic imports, or custom model code before authorization.

## Verify teardown

After the workload terminates, call `require_teardown()` with authenticated
`WorkloadTeardownEvidence`. The evidence must bind the authorization, manifest,
and runtime instance and confirm runtime destruction, credential revocation,
network-policy removal, mount detachment, RAM/accelerator-memory clearing, and
cache clearing. Incomplete or unverifiable cleanup is quarantined; do not reuse
the runtime or device for another tenant.

## Security assumptions, limitations, and residual risk

- Serialization labels and SHA-256 digests do not establish provenance or
  safety. Verify artifacts and loader binaries through a trusted supply chain,
  scan them, sign them, and protect the approved inventory.
- Attestation digests detect field mutation but are not signatures. Production
  verifiers must authenticate signed evidence or protected control-plane state.
  Static verifiers are for tests and examples only.
- Containers share a host kernel; microVM, WASM, and dedicated-host labels do
  not prove the implementation is correctly isolated. Enforce namespaces,
  syscall policy, immutable images, rootless/no-new-privilege execution,
  storage/network controls, and sandbox escape testing outside trustrail.
- Device IDs and cleanup booleans are declarations. Only trusted infrastructure
  telemetry, device partitioning/reset facilities, and hardware attestation can
  establish physical separation or memory clearing. Some accelerators and
  caches cannot provide strong multi-tenant erasure guarantees.
- A read-only or no-exec mount can still disclose data, and DNS, redirects,
  proxies, metadata services, side channels, shared caches, driver bugs, and
  compromised brokers remain risks. Apply controls at the kernel, network, IAM,
  scheduler, and hardware layers.
- Replay and active-lease state is process-local. Multi-worker deployments need
  a shared atomic store and durable audit trail with equivalent fail-closed
  behavior.
- Cleanup cannot undo prior exfiltration, execution, or external side effects.
  Use disposable credentials, egress denial, service-side authorization,
  monitoring, incident response, and tenant-specific blast-radius limits.

See the runnable
[`workload_isolation.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/workload_isolation.py)
example and [AI supply-chain controls](supply-chain.md).
