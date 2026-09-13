# Authenticated inter-agent communication

`InterAgentMessageSigner` and `InterAgentMessageVerifier` protect JSON messages
between agents and orchestrators. They provide application-layer integrity,
authenticated sender identity, explicit audience and route authorization,
delegation binding, transformation provenance, freshness, replay prevention, and
per-task ordering. Verification fails closed before the receiver consumes the
payload.

This control addresses OWASP Agentic ASI07. It complements transport security;
it does not replace TLS, workload authentication, or authorization by the
service that ultimately performs an action.

## Protected envelope

Every Ed25519 signature covers the complete canonical envelope, including:

- sender identity and pinned key; recipient set and tenant;
- session, goal digest, task, purpose, message type, and required scope;
- exact current delegation-chain digest;
- canonical payload digest, nonce, sequence, issue time, and expiry; and
- the ordered list of independently signed payload transformations.

JSON is normalized to NFC and deterministically serialized. Duplicate keys
created by normalization, non-finite numbers, unknown model fields, invalid
identifiers, and malformed digests are rejected by the typed models.

## Configure, sign, and verify

Create one explicit route for each allowed sender, recipient, scope, and message
type. Provision public keys from an authenticated registry rather than accepting
keys from the message or model.

```python
from trustrail import (
    InterAgentMessagePolicy,
    InterAgentMessageSigner,
    InterAgentMessageType,
    InterAgentMessageVerifier,
    InterAgentRoute,
    InterAgentVerificationContext,
)

policy = InterAgentMessagePolicy(
    routes=(
        InterAgentRoute(
            sender_id="worker-agent",
            recipient_id="review-agent",
            allowed_scopes=frozenset({"messages:send"}),
            allowed_message_types=frozenset({InterAgentMessageType.TASK_RESULT}),
        ),
    ),
    max_fanout=1,
    max_ttl_seconds=60,
)

signer = InterAgentMessageSigner.generate(identity=worker_identity, policy=policy)
envelope = signer.sign(
    {"status": "complete"},
    message_type=InterAgentMessageType.TASK_RESULT,
    recipient_ids=("review-agent",),
    session_id="session-42",
    goal_digest=authorized_goal_digest,
    task_id="task-7",
    purpose_id="case-review",
    message_scope="messages:send",
    delegation_chain=current_delegation_chain,
    sequence=0,
)

# Build this at the receiver from authenticated local state, not message fields.
context = InterAgentVerificationContext(
    sender_id="worker-agent",
    recipient=reviewer_identity,
    tenant_id="tenant-a",
    session_id="session-42",
    goal_digest=authorized_goal_digest,
    task_id="task-7",
    purpose_id="case-review",
    delegation_chain=current_delegation_chain,
)
verifier = InterAgentMessageVerifier(
    (signer.trusted_key,),  # production: load from an authenticated registry
    identity_authorizer=delegated_identity_authorizer,
    policy=policy,
    state_store=shared_atomic_state_store,
    audit_sink=content_free_audit_sink,
)
verified = verifier.require(envelope, context)
consume(verified.payload)
```

`verify()` returns a typed content-free decision. `require()` raises
`InterAgentMessageError` on every denial and is the safer choice at a delivery
boundary. Do not read or act on `envelope.payload` before it succeeds.

## Delegation and fan-out

The receiver supplies the current `DelegationChain`. Its digest must match the
signed envelope, its leaf must be the sender, and
`DelegatedIdentityAuthorizer` rechecks every capability and ancestor revocation.
For fan-out, every recipient needs both an explicit policy route and delegated
audience/scope authorization. One unauthorized destination rejects the complete
message; split independent deliveries when partial success is intended.

`max_fanout=1` is the conservative default. Increase it only for a reviewed use
case. Audience checks prevent a valid message intended for one agent from being
forwarded to another agent or tenant.

## Replay and ordering

The verifier atomically claims a hashed nonce/message reference and the exact
next sequence for each recipient/sender/session/task/tenant stream. The first
message uses sequence `0`, followed by `1`, `2`, and so on. Duplicate nonces,
duplicate or stale sequences, and skipped sequences fail closed. A skipped
message therefore blocks later messages until the application recovers or opens
a new task stream deliberately.

`MemoryInterAgentStateStore` is bounded, thread-safe, and suitable only for a
single process. In a distributed deployment, implement `InterAgentStateStore`
with one atomic transaction or script and shared durable state. A per-worker
store permits replay and ordering bypass between replicas. Treat store errors or
capacity exhaustion as denial; do not retry through an unprotected path.

## Verifiable transformations

When a coordinator summarizes, redacts, translates, or otherwise changes a
payload, call `attest_transformation()` with the input and output payloads. Each
attestation binds the transformer identity/key, operation, hop index, time, and
input/output digests. Pass the ordered attestations and original source digest
to `sign()`.

The receiver verifies every transformation key and signature, tenant, time,
continuous digest link, and authorization as a delegation participant or an
explicit `trusted_transformer_ids` entry. This proves who attested to each byte
transition; it does not prove that a summary is truthful or a redaction is
complete. Apply domain-specific semantic validation before trusting transformed
content.

## Audit and operations

Audit events contain stable one-way references and metadata only: result code,
message type, sequence, and transformation count. They omit payloads and raw
identity, tenant, session, goal, and task values. Send them to protected durable
storage and alert on replay, signature, delegation, route, and cross-context
denials.

Production deployments must also:

- authenticate key registration, rotation, and revocation, and protect private
  keys in a workload identity or key-management system;
- use mutually authenticated encrypted transport and bind its peer identity to
  `InterAgentVerificationContext.sender_id`;
- synchronize clocks and keep message TTLs short;
- verify every hop, including brokers, orchestrators, retries, resumes, and
  transformed messages—never add an unsigned compatibility fallback;
- use shared atomic state, bounded queues, rate limits, timeouts, and durable
  content-safe audit; and
- continue prompt-injection scanning, schema validation, least-privilege tool
  authorization, output handling, and sandboxing after message verification.

Signatures cannot prevent a compromised authorized agent from sending harmful
but correctly signed content, cannot provide confidentiality, and cannot revoke
already accepted effects. Recovery, idempotency, transaction controls, key
compromise response, behavior monitoring, and human approval for high-impact
actions remain application responsibilities.

See the [delegated agent identity](delegated-agent-identity.md),
[agent goal integrity](agent-goal-integrity.md), and
[semantic tool authorization](tool-misuse.md) controls for the boundaries that
issue message authority and constrain resulting actions.
