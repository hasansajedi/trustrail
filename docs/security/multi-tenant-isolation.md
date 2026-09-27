# Multi-tenant AI state isolation

`TenantIsolationGuard` prevents tenant-owned AI state from being addressed, read,
restored, reused, or batched without a short-lived tenant security context. It
implements application-layer controls for OWASP AISVS C5.3.1 and exposes
verifiable deployment claims for C5.3.2. It does not create process, hardware,
confidential-computing, or network isolation.

## Protected state

A `TenantIsolationPolicy` must contain exactly one rule for every supported
category. Incomplete and duplicate policies are rejected during configuration.

| State category | Examples |
| --- | --- |
| `prompt_cache` | normalized prompts and prompt prefixes |
| `response_cache` | exact response caches |
| `semantic_cache` | similarity-based prompt and response caches |
| `kv_cache` | model-serving key/value caches and prefix state |
| `embedding` | vectors, indices, and embedding lookup state |
| `memory` | agent and conversation memory |
| `adapter` | fine-tune, LoRA, and tenant-specific model adapters |
| `session` | conversation, connection, and execution sessions |
| `budget` | quotas, counters, rate limits, and spend state |
| `audit` | tenant security and operational audit state |

## Configure the control plane

Tenant IDs from headers, prompts, tool arguments, or model output are not trusted.
An identity control plane must first authenticate the principal, check current
tenant membership, and issue a signed context. Keep the signing key and state-key
secret outside the model and application request path.

```python
import base64
import os
from datetime import UTC, datetime, timedelta

from trustrail import (
    TenantContextSigner,
    TenantIsolationGuard,
    TenantIsolationPolicy,
    TenantStateKeyBuilder,
    TenantStateKind,
)

now = datetime.now(UTC)
context_signer = TenantContextSigner.generate(
    issuer_id="identity-control-plane",
    allowed_tenant_ids=frozenset({"tenant-a"}),
)
context = context_signer.issue(
    context_id="request-42",
    tenant_id="tenant-a",
    principal_id="user-17",
    session_id="session-42",
    allowed_state_kinds=frozenset(TenantStateKind),
    issued_at=now,
    expires_at=now + timedelta(minutes=15),
    nonce="identity-token-jti-42",
)

# Load this stable secret from a KMS or secret manager. Rotating it changes keys.
key_builder = TenantStateKeyBuilder(
    base64.b64decode(os.environ["TRUSTRAIL_TENANT_KEY_B64"]),
    namespace="production-eu-ai-state",
)
policy = TenantIsolationPolicy.strict(
    policy_id="production-tenant-policy",
    hardware_isolated=frozenset({TenantStateKind.KV_CACHE}),
    process_isolated=frozenset({TenantStateKind.ADAPTER}),
    dedicated_tenant=frozenset(
        {TenantStateKind.KV_CACHE, TenantStateKind.ADAPTER}
    ),
)
guard = TenantIsolationGuard(
    policy,
    key_builder,
    (context_signer.trusted_key,),
)
```

In production, inject an implementation of `TenantKeyClaimStore` that performs an
atomic compare-and-set in shared durable storage. `MemoryTenantKeyClaimStore` is
process-local and is intended for development, tests, and single-worker use only.

## Write and reuse tenant state

Generate every persisted or cached key through `TenantStateKeyBuilder`. Its HMAC
input is domain-separated by namespace, tenant, state kind, partition, and
artifact. Raw tenant and artifact identifiers do not appear in the key.

```python
from trustrail import (
    TenantStateAccessRequest,
    TenantStateOperation,
)

state_key = key_builder.build(
    context,
    state_kind=TenantStateKind.SEMANTIC_CACHE,
    artifact_id="normalized-prompt-digest",
)
write = guard.require_state(
    TenantStateAccessRequest(
        request_id="cache-write-42",
        context=context,
        state_kind=TenantStateKind.SEMANTIC_CACHE,
        operation=TenantStateOperation.WRITE,
        artifact_id="normalized-prompt-digest",
        state_key=state_key,
        requested_expires_at=now + timedelta(minutes=10),
    ),
    now=now,
)

# Persist write.binding atomically beside the cache value.
assert write.binding is not None
hit = guard.require_state(
    TenantStateAccessRequest(
        request_id="cache-hit-42",
        context=context,
        state_kind=TenantStateKind.SEMANTIC_CACHE,
        operation=TenantStateOperation.CACHE_HIT,
        artifact_id="normalized-prompt-digest",
        state_key=state_key,
        observed_binding=write.binding,
    ),
    now=now,
)
```

The same pattern applies to reads, adapter use, and restoration. The guard checks
the signed context, policy, exact derived key, integrity-protected ownership
binding, tenant, state category, artifact, expiry, and atomic key claim. Missing
metadata never falls back to an unscoped operation.

## Check inference batches

Call `require_batch` before enqueueing or sending an inference batch. The default
strict policy rejects a batch if its signed contexts name more than one tenant.

```python
from trustrail import TenantBatchRequest

batch_permit = guard.require_batch(
    TenantBatchRequest(
        request_id="provider-batch-7",
        contexts=(context,),
        state_kind=TenantStateKind.KV_CACHE,
    ),
    now=now,
)
```

A permit authorizes only the supplied context digests, tenant reference, and state
kind. Recheck when composition changes.

## Deployment isolation attestations

Rules that require process or hardware isolation fail closed unless the request
contains a current `DeploymentIsolationAttestation` signed by a pinned external
attestor. The attestation binds the deployment, claimed isolation level, covered
state kinds, optional dedicated tenant, measurement digest, and lifetime.

`DeploymentAttestationEvidence.infrastructure_verified` is always `False` and its
validation scope is `signature_and_claims_only`. Trustrail can verify who signed a
claim and whether it matches policy; it cannot inspect a hypervisor, GPU, enclave,
container, process boundary, scheduler, or cloud control plane. Operators must
obtain and independently validate those guarantees from their deployment and
attestation systems.

## Failure behavior and audit

The guard blocks missing, unsigned, forged, expired, or unauthorized contexts;
unscoped or substituted keys; conflicting atomic key claims; missing, modified,
expired, or cross-tenant state bindings; mixed-tenant batches; cross-tenant cache
hits, adapter reuse, and restoration; excessive retention; and missing, forged,
mis-scoped, expired, or insufficient deployment attestations.

Decisions and `TenantIsolationAuditEvent` use keyed or one-way references rather
than raw tenant, principal, session, artifact, and deployment identifiers. Store
the operational mapping separately under appropriate access control when incident
response requires it.

## Security assumptions, limitations, and residual risk

- The context issuer must authenticate the principal and verify current tenant
  membership. A valid signature cannot correct a false or stale membership claim.
- Every cache, storage, batching, adapter, restore, model-serving, budget, session,
  and audit path must call the guard. Unmediated paths bypass this library.
- Protect and rotate signing keys, HMAC secrets, trusted-key configuration, policy,
  bindings, and the claim store. Plan key migration before rotating the HMAC secret.
- Multi-worker and multi-region deployments need a shared atomic claim store.
  Process-local claims cannot detect collisions created by another worker.
- Persist bindings atomically with values and apply tenant authorization again in
  databases, vector stores, queues, object stores, caches, and downstream services.
- Opaque domain-separated keys reduce keying mistakes and identifier disclosure;
  they do not encrypt values or prevent disclosure by a compromised backend.
- Signed deployment attestations are claims. Hardware partitioning, confidential
  computing, dedicated compute, process isolation, GPU memory clearing, scheduler
  behavior, and side-channel resistance require independent infrastructure controls.
- Timing, cache-probing, resource-contention, speculative-execution, and other
  shared-compute side channels remain possible. Apply capacity isolation, quotas,
  constant-time or partitioned serving where appropriate, monitoring, and testing.
- Budget and rate-limit isolation still requires atomic backend updates. A safe key
  alone does not prevent races, quota evasion, or noisy-neighbor denial of service.
- Tenant offboarding requires revoking context authority and independently deleting
  state, backups, adapters, snapshots, provider copies, and audit data according to
  lifecycle policy. Already disclosed data cannot be recovered by this control.

This control complements data-classification propagation and lifecycle enforcement;
it does not replace them.
