# Excessive agency

trustrail provides a complete-mediation boundary for
[OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).
It treats model output as an untrusted proposal. Application-owned identity,
intent, resource ownership, capability policy, approval evidence, and execution
state determine whether a tool may run.

Content scanning and the legacy `ToolPolicy` remain useful defense-in-depth, but
names and arguments that merely look safe are not authorization evidence.
Call `ToolAuthorizer` immediately before every downstream invocation.

## Declare the minimum capability

Expose a narrow function instead of an open shell, generic HTTP client, or broad
database executor:

```python
from trustrail import (
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationPolicy,
    ToolAuthorizer,
    ToolCapability,
    ToolEffect,
)

read_order = ToolCapability(
    name="orders.read",
    version="v3",  # exact deployed tool contract
    effects=frozenset({ToolEffect.READ}),
    required_scopes=frozenset({"orders:read"}),
    arguments={
        "order_id": ToolArgumentConstraint(
            kind=ToolArgumentKind.STRING,
            pattern=r"order-[0-9]{6}",
        )
    },
    required_arguments=frozenset({"order_id"}),
    resource_id_argument="order_id",
    require_owned_resource=True,
    allow_autonomous=True,
)
policy = ToolAuthorizationPolicy(
    capabilities=(read_order,),
    max_tool_calls=20,
    max_chain_actions=5,
    max_retries_per_operation=1,
    max_parallel_calls=2,
    max_autonomous_actions=5,
)
authorizer = ToolAuthorizer(policy)
budget = authorizer.new_budget("session-123")
```

Capability names and versions match exactly. Unknown arguments, missing required
arguments, incorrect scalar types, and values outside allowlists, regular
expressions, lengths, or numeric bounds fail closed. Only scalar JSON arguments
are supported by this deterministic contract; put complex input behind a narrow,
application-validated identifier rather than accepting arbitrary nested objects.

## Bind the action to identity, intent, and ownership

Construct these records from authenticated application state. Never copy a
principal, scope, tenant, ownership label, intent, or resource record from model
output or untrusted tool arguments.

```python
from datetime import UTC, datetime, timedelta

from trustrail import (
    ToolAuthorizationRequest,
    ToolIntent,
    ToolPrincipal,
    ToolResource,
)

request = ToolAuthorizationRequest(
    tool_name=model_call.name,
    tool_version=deployed_tool_version,
    arguments=model_call.arguments,
    principal=ToolPrincipal(
        actor_id="shopping-agent",
        subject_id=authenticated_user.id,
        tenant_id=authenticated_user.tenant_id,
        scopes=frozenset(oauth_token.scopes),
    ),
    intent=ToolIntent(
        intent_id="show-selected-order",
        subject_id=authenticated_user.id,
        tenant_id=authenticated_user.tenant_id,
        allowed_tools=frozenset({"orders.read"}),
        purpose="Show the order selected by the user",
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
        max_calls=1,
    ),
    resource=ToolResource(
        resource_id=order.id,
        owner_id=order.customer_id,
        tenant_id=order.tenant_id,
    ),
    requested_scopes=frozenset(),
    session_id="session-123",
    chain_id="show-order-chain",
    operation_id="read-order-once",
)
authorization = authorizer.require(request, budget)
try:
    result = await orders_client.read(authorization.arguments["order_id"])
finally:
    authorizer.complete(authorization, budget)
```

The exact resource argument must match the trusted ownership lookup, and its
owner and tenant must match the end-user principal. Required scopes must already
exist on the principal. `requested_scopes` must also be held by the principal
and explicitly listed as delegatable by the capability, preventing scope or role
expansion through arguments or agent planning.

Use the end user's short-lived downstream credential wherever possible. The
authorizer cannot reduce permissions embedded in a shared administrator token.

## Approve high-impact actions out of band

Delete, external-communication, and permission-change effects require approval
by default. `require_approval=True` can protect any additional capability.
When no grant is present, the result is `REQUIRE_APPROVAL`, which is not
permission to execute.

After a human reviews the exact action, issue `ToolApprovalGrant` from a trusted
approval service. Bind it to `request.approval_digest`, authenticate it through
a `ToolApprovalVerifier`, and resubmit the unchanged request. Grants expire and
are single-use within the execution budget. Changed arguments, identity,
resource, tool version, scope, or intent produce a different digest.

```python
grant = ToolApprovalGrant(
    approval_id=approval_record.id,
    request_digest=request.approval_digest,
    approver_id=approval_record.reviewer_id,
    expires_at=approval_record.expires_at,
)
approved_request = request.model_copy(update={"approval": grant})
authorization = authorizer.require(approved_request, budget)
```

`StaticToolApprovalVerifier` is provided for tests and small examples. Production
verifiers should validate a server-side approval record or a signed grant whose
keys and issuance path are inaccessible to the model and agent.

## Bound autonomous execution

`ToolExecutionBudget` enforces cumulative tool calls, actions in one chain,
retries of the same operation, outstanding parallel leases, actions marked
autonomous, and each intent's own call limit. Keep one application-owned budget
for the entire agent session. Replacing it, changing chain/operation identifiers,
or failing to retain state across workers defeats those limits.

`authorize()` reserves a parallel lease only after every check succeeds and
returns a canonical argument snapshot; execute `authorization.arguments`, not
the mutable proposal object.
Always call `complete()` in a `finally` block after success, failure, timeout, or
cancellation. Treat a budget denial as terminal for that chain; do not silently
start a new session, chain, or operation to retry it.

`AgentSession` separately caps steps, total tool checks, recursion, and duration.
Use both layers when an orchestration loop needs those broader controls.

## Security assumptions, limitations, and residual risk

- Policy, principal, intent, resource evidence, approval verifier, deployed tool
  version, session/chain/operation IDs, and execution budget must be controlled
  by trusted application code. Pydantic validation establishes shape, not truth.
- Authorization is complete only if every path to the downstream system passes
  through the authorizer. Direct SDK calls, alternate plugins, background jobs,
  and confused-deputy services can bypass an application-only check.
- Approval binding prevents mutation and in-session replay; authenticity depends
  on the configured verifier and its storage or signature controls. Distributed
  deployments need shared atomic replay and budget state.
- In-memory counters are process-local and are not a distributed rate limiter.
  Enforce quotas and concurrency again at the downstream service or gateway.
- Regular expressions and scalar constraints are not semantic validation. Resolve
  resource ownership through an authoritative data store and enforce database,
  filesystem, network-egress, and OAuth permissions downstream.
- A correctly authorized tool can still contain implementation vulnerabilities,
  race conditions, unsafe side effects, or compromised dependencies. Use
  idempotency keys, transactions, timeouts, cancellation, rollback, sandboxing,
  audit logs, and service-level least privilege.
- Completing a lease records neither success nor rollback. Applications must
  separately audit the proposed action, authorization ID, outcome, and affected
  resource without logging secrets or sensitive argument values.

The `EA-*`, `TL-*`, and `AG-*` rules detect suspicious content and orchestration
metadata, but do not replace this deterministic boundary or downstream access
control.
