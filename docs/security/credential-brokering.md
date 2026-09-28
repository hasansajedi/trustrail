# Model-blind credential brokering

`CredentialBroker` keeps agent credentials outside prompts, memory, model
outputs, tool schemas and arguments, approval views, traces, logs, and errors.
Agents receive only a `CredentialReference`. Trusted connector code exchanges an
execution-bound `CredentialCapability` for short-lived credential material after
the model-facing part of the tool call is complete.

This is an application-layer control for OWASP AISVS C9.5.4 and OWASP MCP01.
Redacting a secret after it entered a context window is not equivalent: the
model provider, cache, trace, or a later generated tool call may already have
observed it.

## Define an exact binding

Create references in trusted configuration. A reference is an opaque handle,
not a vault path, secret name, token, or encoded credential. Each binding names
one tenant, tool, resource, operation, credential version, and maximum lifetime.

```python
from trustrail import (
    CredentialBinding,
    CredentialBrokerPolicy,
    CredentialReference,
    CredentialScope,
)

payment_credential = CredentialReference(
    broker_id="production-broker",
    reference_id="credref_payments_primary_01",
)
payment_scope = CredentialScope(
    tenant_id="tenant-a",
    tool_name="payments.charge",
    resource_id="merchant-account-7",
    operation="charge:create",
)
policy = CredentialBrokerPolicy(
    broker_id="production-broker",
    version=3,
    bindings=(
        CredentialBinding(
            reference=payment_credential,
            scope=payment_scope,
            credential_version="secret-manager-version-7",
            maximum_ttl_seconds=30,
        ),
    ),
)
```

The policy is closed: unknown references and any tenant, tool, resource, or
operation substitution are denied. `CredentialReference`, capabilities,
decisions, findings, and audit events contain no credential bytes.

## Connect trusted infrastructure

Configure the broker with three adapters:

- `CredentialVault` reads a current version and resolves material from a KMS,
  HSM, workload-identity exchange, or secrets manager;
- `CredentialExecutionVerifier` authenticates the exact execution record from
  server-side tool authorization state;
- `CredentialCapabilityStore` atomically registers, consumes, and revokes
  single-use capabilities.

`StaticCredentialVault`, `StaticCredentialExecutionVerifier`, and
`MemoryCredentialCapabilityStore` are for tests, examples, or single-worker
development. Production deployments need a remote vault and shared durable,
atomic capability state. Do not initialize the static vault from model-visible
configuration.

```python
from trustrail import CredentialBroker

broker = CredentialBroker(
    policy,
    vault=production_secret_manager_adapter,
    execution_verifier=tool_authorization_adapter,
    state_store=shared_atomic_capability_store,
    audit_sink=content_free_audit_sink,
)
```

Adapters must fail closed. Vault and verifier exceptions are converted to
content-free broker decisions; the original connector exception is not attached.

## Bind resolution to authorized execution

Construct `AuthorizedCredentialExecution` only from trusted server-side state,
after normal identity, intent, scope, approval, resource ownership, and tool
authorization checks succeed.

```python
from trustrail import AuthorizedCredentialExecution

execution = AuthorizedCredentialExecution.create(
    execution_id=authorized_tool_call.execution_id,
    authorization_id=authorized_tool_call.authorization_id,
    request_digest=authorized_tool_call.request_digest,
    scope=payment_scope,
    issued_at=issued_at,
    expires_at=expires_at,
)

capability = broker.require_capability(
    payment_credential,
    execution,
    ttl_seconds=15,
)
```

The capability binds the opaque reference, exact scope, execution digest,
policy digest, credential version, issue time, expiry, and one-time state. It is
authority, not a secret; keep it out of prompts anyway.

Resolve only inside the trusted connector adapter and close material promptly:

```python
with broker.resolve(capability, execution) as material:
    response = await trusted_http_client.post(
        destination_from_server_policy,
        headers={"Authorization": b"Bearer " + material.reveal()},
        json=validated_non_secret_arguments,
    )
```

Never return `material`, headers, a prepared request, or connector debug objects
to the agent. `CredentialMaterial` has redacted string representations, rejects
implicit byte conversion, copying, and pickling, and overwrites its managed
buffer on close. Python and third-party libraries may retain other copies, so
the connector must disable body/header logging and use a credential-safe HTTP
stack.

Capabilities are consumed before vault resolution. If resolution or the
downstream call fails, obtain a fresh capability for a reviewed retry. This
prevents replay, but does not make the downstream operation idempotent; provide
idempotency keys and authoritative retry state separately.

## Guard every model-visible boundary

`CredentialBoundaryGuard` rejects `CredentialMaterial`, known leak canaries,
common raw-credential patterns, and raw values under credential-bearing fields.
It recursively inspects nested Pydantic models, mappings, sequences,
dataclasses, byte strings, and exceptions. Unknown object types and inspection
limit exhaustion fail closed.

```python
from trustrail import CredentialBoundaryGuard, CredentialSurface

boundary_guard = CredentialBoundaryGuard(
    [payment_credential],
    leak_canaries=credential_canaries_from_trusted_test_setup,
)

boundary_guard.require_safe(tool_schema, CredentialSurface.TOOL_SCHEMA)
boundary_guard.require_safe(tool_arguments, CredentialSurface.TOOL_ARGUMENTS)
boundary_guard.require_safe(model_response, CredentialSurface.MODEL_OUTPUT)
boundary_guard.require_safe(memory_record, CredentialSurface.MEMORY)
boundary_guard.require_safe(trace_attributes, CredentialSurface.TELEMETRY)

# Buffer and inspect before releasing output so split tokens cannot bypass it.
stream_decision = boundary_guard.inspect_stream(stream_chunks)
```

Apply the guard before every prompt/model request, approval render, persistence
write, serialization, telemetry export, and user/model-visible error. Inspect
complete buffered streams before release. If low-latency incremental release is
required, use a hold-back buffer at least as large as the longest supported
credential detector and never emit unchecked bytes.

Canaries should be non-production values placed at each credential source and
exercised in security regression tests. Canary matching covers direct, hex,
Base64, nested, byte, exception, and cross-chunk values. Pattern matching is
defense in depth; it cannot recognize every new credential format.

## Rotation, revocation, and audit

After the external vault has committed a new version, call `rotate()` with that
version. Rotation invalidates all outstanding capabilities. Call `revoke()` for
incident response, account disablement, or connector removal. A revoked
reference cannot issue or resolve capabilities until an explicit rotation
activates a new version.

Audit events retain only SHA-256 references for credential, execution, and
capability IDs plus phase, outcome code, surface, and timestamp. They exclude
secret bytes, raw tenant/resource identifiers, connector errors, arguments, and
results.

## Security assumptions, limitations, and residual risk

- Complete mediation is required. A direct vault, environment-variable,
  metadata-service, SDK default-credential, log, debugger, crash-dump, or
  connector path bypasses this control.
- The execution verifier, vault, policy, capability store, clocks, adapters, and
  trusted connector process must be authenticated and protected from the agent.
- Use workload identity and provider-native token exchange where possible. A
  long-lived secret behind a short-lived capability remains long-lived at rest.
- A shared atomic store is required across workers and regions. The in-memory
  store cannot stop cross-process replay and loses revocations on restart.
- Reference opacity is not secrecy or authorization. Do not encode vault paths,
  account names, tenant data, or access tokens in a reference ID.
- `CredentialMaterial.close()` is best-effort. Python runtimes, TLS libraries,
  HTTP clients, operating systems, debuggers, and crash handlers may retain
  copies outside its buffer.
- Leak scanning is bounded and signature/canary based. It does not prove that
  transformed, novel-format, side-channel, or unbuffered credentials are absent.
- Disable request/header/body capture and exception chaining in connectors.
  Treat any suspected context exposure as compromise and revoke/rotate at the
  authoritative credential provider.
- Downstream services must still authorize tenant, resource, operation, and
  effects. Possession of resolved material must not become ambient authority.

These APIs reduce credential exposure paths; they do not certify a vault,
connector, agent runtime, model provider, or deployment as compliant.
