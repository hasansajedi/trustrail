# Delegated agent identity (OWASP ASI03:2026)

trustrail's delegated identity boundary addresses
[OWASP ASI03:2026 Identity and Privilege Abuse](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
An agent name in a prompt is not an authenticated identity, and copying a user's
credential into every sub-agent gives each component more authority than its job
requires. Use `DelegatedIdentityAuthorizer` before every privileged tool or
service operation to bind the presenting workload to short-lived, narrowed
authority from a trusted human or service.

## Model the delegation chain

`AgentIdentity` distinguishes human, service, agent, and sub-agent identities.
`DelegatedCapability` binds an issuer and exact subject to a tenant, scopes,
delegatable scopes, audiences, purpose, validity window, and maximum depth. Every
child binds its parent's ID and digest and may only narrow those fields.

```python
from datetime import UTC, datetime, timedelta

from trustrail import AgentIdentity, AgentIdentityKind, DelegatedCapability, DelegationChain

now = datetime.now(tz=UTC)
user = AgentIdentity(
    identity_id="customer-42",
    kind=AgentIdentityKind.HUMAN,
    tenant_id="shop-eu",
)
agent = AgentIdentity(
    identity_id="shopping-agent",
    kind=AgentIdentityKind.AGENT,
    tenant_id="shop-eu",
)
subagent = AgentIdentity(
    identity_id="order-reader",
    kind=AgentIdentityKind.SUB_AGENT,
    tenant_id="shop-eu",
)
root = DelegatedCapability.create(
    capability_id="cap-session",
    issuer=user,
    subject=agent,
    scopes=frozenset({"orders:read"}),
    delegatable_scopes=frozenset({"orders:read"}),
    audiences=frozenset({"tool:orders.read"}),
    purpose_id="show-selected-order",
    issued_at=now,
    not_before=now,
    expires_at=now + timedelta(minutes=5),
    max_delegation_depth=1,
)
leaf = DelegatedCapability.create(
    capability_id="cap-order-reader",
    issuer=agent,
    subject=subagent,
    scopes=frozenset({"orders:read"}),
    audiences=frozenset({"tool:orders.read"}),
    purpose_id="show-selected-order",
    issued_at=now,
    not_before=now,
    expires_at=now + timedelta(minutes=2),
    delegation_depth=1,
    max_delegation_depth=1,
    parent=root,
)
chain = DelegationChain(capabilities=(root, leaf))
```

The digest detects mutation but is not a signature. A production
`DelegatedCapabilityVerifier` must authenticate every exact capability against a
signed token, protected issuance database, or identity service. Missing or
failing verification blocks access. `StaticDelegatedCapabilityVerifier` exists
only for deterministic examples and tests.

## Authorize the presenting workload

Construct the presenter from authenticated workload state, not an agent message
or tool argument. The authorizer verifies every ancestor, the trusted root,
expiry and maximum lifetime, delegation depth, presenter, tenant, audience,
purpose, requested scopes, authenticity, and revocation status.

```python
from trustrail import (
    DelegatedAccessPolicy,
    DelegatedAccessRequest,
    DelegatedIdentityAuthorizer,
)

identity_authorizer = DelegatedIdentityAuthorizer(
    DelegatedAccessPolicy(
        trusted_root_issuer_ids=frozenset({"customer-42"}),
        allowed_audiences=frozenset({"tool:orders.read"}),
        max_capability_lifetime_seconds=300,
        max_delegation_depth=1,
        authorization_ttl_seconds=30,
    ),
    capability_verifier=production_capability_verifier,
    revocation_provider=shared_revocation_provider,
)
request = DelegatedAccessRequest(
    presenter=authenticated_workload_identity,
    chain=chain,
    audience="tool:orders.read",
    purpose_id="show-selected-order",
    requested_scopes=frozenset({"orders:read"}),
    tenant_id="shop-eu",
    operation_id="read-order-123456",
)
access = identity_authorizer.require(request)
tool_principal = identity_authorizer.to_tool_principal(access)
```

Pass the resulting principal to `ToolAuthorizationRequest`, then enforce the
tool capability, trusted intent, resource ownership, budget, and semantic
postconditions with `ToolAuthorizer`. Do not forward the original capability or
the initiating user's credential to the downstream tool. Exchange the verified
snapshot server-side for a narrowly scoped, audience-bound service credential
when the downstream system requires one.

Call `revoke()` for process-local operation or supply a
`DelegationRevocationProvider` backed by shared authoritative state. Revoking any
ancestor rejects the complete chain. Provider errors fail closed because an
unknown revocation state is not proof of access.

## Step-up authentication and just-in-time access

Put high-impact scopes in `step_up_required_scopes`, `jit_required_scopes`, or
both. The first decision returns `GuardAction.REQUIRE_APPROVAL`. An independent
identity or policy service then authenticates the user and issues a
`DelegatedAccessGrant` bound to the exact `request.request_digest`, presenter,
tenant, required scopes, and short validity window.

```python
from trustrail import (
    DelegatedAccessGrant,
    DelegatedAccessGrantKind,
    DelegatedAccessRequest,
)

payment_request = DelegatedAccessRequest(
    presenter=authenticated_workload_identity,
    chain=payment_chain,
    audience="tool:payments.send",
    purpose_id="pay-approved-invoice",
    requested_scopes=frozenset({"payments:send"}),
    tenant_id="shop-eu",
    operation_id="pay-invoice-123456",
)
pending = identity_authorizer.authorize(payment_request, now=now)
assert pending.requires_elevation

step_up = DelegatedAccessGrant(
    grant_id="step-up-8472",
    kind=DelegatedAccessGrantKind.STEP_UP,
    request_digest=payment_request.request_digest,
    subject_id=payment_request.presenter.identity_id,
    tenant_id=payment_request.tenant_id,
    approved_scopes=frozenset({"payments:send"}),
    assurance_level=3,
    issued_at=now,
    expires_at=now + timedelta(minutes=2),
)
request_with_grant = payment_request.model_copy(update={"grants": (step_up,)})
access = identity_authorizer.require(request_with_grant, now=now)
```

Configure a `DelegatedAccessGrantVerifier` that authenticates the approval
service's record or signature. Grants cannot add scopes absent from the leaf
capability, and unnecessary, over-broad, expired, rebound, low-assurance, or
replayed grants are rejected. Consumption is atomic within one authorizer.

## Security assumptions, limitations, and residual risk

- Identity IDs, tenant, presenter, policy, capability issuance, grants, and
  revocation state must come from authenticated application infrastructure.
  Typed models establish shape and integrity relationships, not truth.
- Completely mediate every privileged operation and reauthorize after an
  authorization snapshot expires. A previous snapshot does not automatically
  observe a later revocation; keep its TTL short and check again immediately
  before high-impact work.
- Local revocations and grant replay state are process-local. Multi-worker or
  distributed deployments need shared, atomic revocation and single-use grant
  storage with equivalent failure behavior.
- Use proof-of-possession workload credentials, protected token exchange, and
  secure transport to reduce bearer-token theft. This library does not issue
  OAuth tokens, manage keys, authenticate workloads, or stop direct SDK bypasses.
- Scope and audience strings carry application-defined meaning. Downstream
  services must independently enforce tenant isolation, least privilege,
  resource ownership, egress/value limits, and postconditions.
- Step-up and JIT grants reduce standing privilege; they do not make an unsafe
  operation safe. Keep human approval independent of model-controlled content
  and use transactions, idempotency, monitoring, and recovery controls.

See the runnable
[`delegated_identity.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/delegated_identity.py)
example and
[semantic tool authorization](tool-misuse.md) for complete tool mediation.
