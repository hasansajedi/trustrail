# Tamper-resistant high-impact approvals

`HighImpactApprovalGate` makes a human decision refer to the exact action plan
that an executor will receive. It is intended for destructive, financial,
administrative, code-execution, externally visible, and data-disclosure actions
where a plausible but incomplete model summary is not an adequate approval
boundary.

The gate addresses OWASP Agentic ASI09. It complements `ToolAuthorizer`, goal
integrity, downstream service authorization, and transactional controls; it
does not replace them.

## Security guarantee

Application-owned `HighImpactActionPolicy` records provide the trusted action
classification. An agent may propose parameter values, but it cannot choose the
impact, reversibility, display schema, side effects, external-visibility flag,
data-disclosure categories, approval requirement, allowed reviewers, or policy
version.

For every complete ordered plan, the gate:

- rejects unknown actions, hidden parameters, missing required fields, and type
  substitutions;
- renders every parameter without ellipsis or length truncation and highlights
  recipients, amounts, permission scopes, commands, diffs, external visibility,
  and disclosed data according to trusted schema;
- includes actor, represented subject, tenant, session, goal, task, chain,
  environment, policy/version/digest, and exact plan digest;
- derives overall impact from trusted action classifications and escalates a
  multi-action chain when it reaches the configured composition threshold;
- binds approval to the rendered preview, full plan, actor, tenant, execution
  context, policy, approver, validity window, and nonce; and
- atomically rejects nonce replay, excessive prompt frequency, repeated prompts,
  unavailable approval verification, and state capacity/failure.

The returned `AuthorizedHighImpactPlan` contains the exact canonical plan
snapshot. Execute `authorization.plan`; do not return to the earlier proposal or
reconstruct parameters from model output after approval.

## Workflow

Construct identity and execution context from authenticated orchestration state,
not agent-controlled fields:

```python
from trustrail import (
    ApprovalActor,
    ApprovalExecutionContext,
    HighImpactApprovalGrant,
    ProposedHighImpactAction,
    ProposedHighImpactPlan,
)

plan = ProposedHighImpactPlan(
    plan_id="payment-plan-42",
    actor=ApprovalActor(
        actor_id=authenticated_agent_id,
        subject_id=authenticated_user_id,
        tenant_id=authenticated_tenant_id,
    ),
    context=ApprovalExecutionContext(
        tenant_id=authenticated_tenant_id,
        session_id=session_id,
        goal_digest=authorized_goal_digest,
        task_id=task_id,
        chain_id=chain_id,
        environment="production",
    ),
    actions=(
        ProposedHighImpactAction(
            action_instance_id="transfer-1",
            action_id="wire-transfer",
            parameters={
                "recipient": "DE89-3704-0044-0532-0130-00",
                "amount": "1250.00 EUR",
            },
        ),
    ),
)

pending = approval_gate.prepare(plan)
if not pending.requires_approval or pending.preview is None:
    raise RuntimeError("Plan was blocked or did not enter the expected review flow")

# Send the complete pending.preview.rendered_text and its digest to an
# independent, authenticated, non-spoofable approval service. Never let the
# agent render, truncate, summarize, or mark its own preview as approved.
record = approval_service.request_exact_approval(pending.preview)

grant = HighImpactApprovalGrant(
    approval_id=record.approval_id,
    nonce=record.single_use_nonce,
    preview_digest=pending.preview.preview_digest,
    plan_digest=plan.plan_digest,
    actor_id=plan.actor.actor_id,
    tenant_id=plan.actor.tenant_id,
    policy_id=approval_gate.policy.policy_id,
    policy_version=approval_gate.policy.policy_version,
    policy_digest=approval_gate.policy.policy_digest,
    execution_context_digest=plan.context.context_digest,
    approver_id=record.authenticated_approver_id,
    issued_at=record.issued_at,
    expires_at=record.expires_at,
)

authorization = approval_gate.require(plan, grant)
for action in authorization.plan.actions:
    executor.execute(action.action_id, action.parameters)
```

`HighImpactApprovalVerifier` must authenticate the grant against server-side
state or a protected signature. `StaticHighImpactApprovalVerifier` is only for
tests and small examples. A verifier exception, missing verifier, denial, or
state-store error blocks execution.

## Canonical previews and plan impact

Canonical JSON normalizes Unicode to NFC, sorts object keys, rejects duplicate
keys created by normalization and non-finite numbers, and never accepts unknown
model fields. Human-facing JSON escapes control and formatting characters so an
invisible or bidirectional character cannot silently alter the display.

Parameter order comes from policy, not the agent. Optional absent parameters are
shown as `[NOT PROVIDED]`. Static effects, reversibility, external visibility,
and disclosure categories are always shown, including explicit `NONE` states.
If a complete preview exceeds `max_preview_bytes`, the gate blocks it; it never
returns a shortened preview. The approval UI must also render every byte and
must authenticate the digest of the exact displayed text.

Overall impact is the highest trusted action impact. When an ordered plan has at
least `chain_escalation_action_count` actions, the gate raises that level once,
up to `CRITICAL`. This prevents a chain of individually plausible steps from
being presented as a low-impact decision. The full ordered plan shares one
approval digest, so adding, removing, reordering, or changing any action requires
a new review.

## Fatigue and replay state

`prepare()` records prompts per actor, tenant, and session. It blocks both total
prompt volume and repetitions of the same preview within the configured window.
This is a deterministic abuse signal, not proof of malicious intent. Design the
product to stop automation, notify the reviewer, and require deliberate recovery
instead of retrying the same prompt through another channel.

`authorize()` consumes a nonce atomically after all bindings and grant
authenticity have passed. `MemoryHighImpactApprovalStateStore` is bounded and
thread-safe but process-local. Multi-worker and multi-region deployments must
implement `HighImpactApprovalStateStore` with shared durable state and a single
atomic operation for each prompt record and nonce claim. Per-worker state permits
cross-replica replay and fatigue bypass.

## Audit and privacy

Audit events contain only decision codes, counts, impact classification, and
one-way references for the plan, actor, tenant, session, policy, preview, and
approval. They do not contain recipient, amount, scope, diff, command, or
disclosed data values. Protect and retain these events independently of the
agent.

The approval preview itself necessarily contains the details a user must review.
Treat it as sensitive: encrypt transport and storage, minimize retention, prevent
agent access to reviewer sessions, and avoid copying previews into ordinary
telemetry or exception messages.

## Assumptions and residual risk

- The approval UI must be non-spoofable, accessible, independent from the agent,
  and able to display the complete exact preview. The library cannot prove that
  a UI actually showed every byte.
- Strong reviewer authentication, allowed-reviewer policy, separation of duties,
  and protected policy/configuration are application responsibilities.
- A valid approval proves an authenticated decision over exact bytes; it does
  not prove comprehension, informed consent, legality, or that the action is
  safe. Social engineering and reviewer compromise remain possible.
- Downstream services must enforce their own identity, tenant, scope, ownership,
  transaction/value, egress, and concurrency controls. Never treat approval as
  authorization beyond the exact plan.
- Use idempotency, conditional writes, transactions, and verified outcomes.
  Compensation cannot undo disclosure, sent messages, transferred assets, or
  other irreversible real-world effects.
- A compromised executor can ignore the approved snapshot. Keep complete
  mediation at the execution boundary and compare trusted outcomes with the
  authorized plan.

See [excessive agency](excessive-agency.md),
[semantic tool authorization](tool-misuse.md), and
[agent goal integrity](agent-goal-integrity.md) for adjacent controls.
