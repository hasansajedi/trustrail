# Semantic tool authorization (OWASP ASI02:2026)

trustrail's semantic tool boundary addresses
[OWASP ASI02:2026 Tool Misuse and Exploitation](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
A JSON-schema-valid call is still only an untrusted proposal: a transfer can use
the wrong recipient, a mail tool can exfiltrate retrieved data, and a successful
API response can hide side effects outside the user's request.

Use `ToolSemanticAuthorizationPolicy` with `ToolAuthorizer` when the meaning,
sequence, data provenance, or observed result of a call affects authorization.
The existing capability policy continues to enforce tool identity, scopes,
scalar argument shape, ownership, approval, and budgets.

## Declare semantic controls

Each semantic operation has three typed layers:

- `ToolPreconditionPolicy` requires application-owned facts and binds proposed
  arguments exactly to those facts;
- `ToolInvariantPolicy` identifies approved destination arguments,
  tool-derived arguments that require provenance, and an affected-resource cap;
- `ToolPostconditionPolicy` requires executor-observed facts, exact effects, and
  evidence that the expected resource was affected.

```python
from trustrail import (
    ToolArgumentBinding,
    ToolDataFlowRule,
    ToolInvariantPolicy,
    ToolPostconditionPolicy,
    ToolPreconditionPolicy,
    ToolSemanticAuthorizationPolicy,
    ToolSemanticOperationPolicy,
    ToolSequenceTransition,
)

semantic_policy = ToolSemanticAuthorizationPolicy(
    operations=(
        ToolSemanticOperationPolicy(
            tool_name="documents.read",
            preconditions=ToolPreconditionPolicy(
                expected_facts={"account_active": True},
                argument_bindings=(
                    ToolArgumentBinding(
                        argument="document_id",
                        trusted_fact="selected_document_id",
                    ),
                ),
            ),
            postconditions=ToolPostconditionPolicy(
                expected_facts={"retrieved": True},
            ),
        ),
        ToolSemanticOperationPolicy(
            tool_name="messages.send",
            preconditions=ToolPreconditionPolicy(
                expected_facts={"user_confirmed": True},
                argument_bindings=(
                    ToolArgumentBinding(
                        argument="address",
                        trusted_fact="approved_recipient",
                    ),
                ),
            ),
            invariants=ToolInvariantPolicy(
                destination_arguments=frozenset({"address"}),
                provenance_required_arguments=frozenset({"body"}),
                max_affected_resources=1,
            ),
            postconditions=ToolPostconditionPolicy(
                required_facts=frozenset({"message_id"}),
                expected_facts={"delivered": True},
            ),
        ),
    ),
    allowed_transitions=(
        ToolSequenceTransition(
            source_tool="documents.read",
            target_tool="messages.send",
        ),
    ),
    data_flow_rules=(
        ToolDataFlowRule(
            source_tool="documents.read",
            target_tool="messages.send",
            target_argument="body",
            allowed_labels=frozenset({"document_summary"}),
        ),
    ),
)

authorizer = ToolAuthorizer(
    capability_policy,
    semantic_policy=semantic_policy,
    compensator=production_compensator,
)
```

The semantic policy must cover every capability in its `ToolAuthorizer`, and all
referenced arguments are checked against that capability manifest at construction
time. This prevents an unobserved capability-only call from being inserted into
a protected sequence. Adjacent transitions and data flows deny unlisted
combinations by default. Calls in one chain are serialized so a second call
cannot race ahead before the first outcome is verified. Use a separate
capability-only authorizer only for workflows that do not need semantic history.

## Supply trusted intent and provenance

Build `ToolSemanticContext` from authenticated UI choices, policy services,
ownership lookups, and previous verified execution records. Do not ask the model
whether a fact is true or copy an approval field from its tool call.

```python
from trustrail import ToolDataFlowReference, ToolEffect, ToolSemanticContext

semantic_context = ToolSemanticContext(
    trusted_facts={
        "user_confirmed": confirmation.confirmed,
        "approved_recipient": confirmation.email,
    },
    expected_effects=frozenset({ToolEffect.EXTERNAL_COMMUNICATION}),
    approved_destinations=frozenset({confirmation.email}),
    expected_resource_ids=frozenset({document.id}),
    data_flows=(
        ToolDataFlowReference.bind(
            source_authorization_id=verified_read.authorization_id,
            target_argument="body",
            label="document_summary",
            value=verified_summary,
        ),
    ),
)
request = request.model_copy(update={"semantic_context": semantic_context})
authorization = authorizer.require(request, budget)
```

The semantic context is included in the authorization/approval digest. Data-flow
references must point to a successful execution already verified in the same
chain; their output label, source/target tools, target argument, intent, resource
boundary, and cumulative use count must satisfy a declared `ToolDataFlowRule`.
Flows are single-use by default; increase `max_uses` only when repeated use is an
explicit part of the authorized workflow. The source execution report must bind
the same label to the same exact value without retaining that value in history:

```python
source_report = source_report.model_copy(
    update={
        "output_labels": frozenset({"document_summary"}),
        "output_value_digests": {
            "document_summary": ToolDataFlowReference.digest_value(verified_summary)
        },
    }
)
```

Authorization rejects a copied label whose digest does not match both the
verified source report and the actual proposed target argument.

## Verify outcomes before continuing

Execute only `authorization.arguments`. A trusted adapter—not the model and not
raw tool text—must translate the downstream response and authoritative state
into `ToolExecutionReport`.

```python
from trustrail import ToolExecutionReport, ToolExecutionStatus

gateway_result = await messages.send(**authorization.arguments)
report = ToolExecutionReport(
    authorization_id=authorization.authorization_id,
    request_digest=authorization.request_digest,
    session_id=request.session_id,
    tool_name=request.tool_name,
    status=ToolExecutionStatus.SUCCEEDED,
    observed_effects=frozenset({ToolEffect.EXTERNAL_COMMUNICATION}),
    affected_resource_ids=frozenset({document.id}),
    destinations=frozenset({gateway_result.recipient}),
    facts={
        "message_id": gateway_result.message_id,
        "delivered": gateway_result.delivered,
    },
    output_labels=frozenset({"delivery_receipt"}),
)
outcome = authorizer.verify_completion(authorization, report, budget)
if not outcome.is_verified:
    raise RuntimeError("tool outcome quarantined")
```

`complete()` deliberately returns `False` for semantic leases. Call
`verify_completion()` even after failure. An unknown/unverifiable result,
mismatched lease binding, undeclared effect/resource/destination, missing fact,
or failed postcondition closes the lease, quarantines that chain, and returns
`GuardAction.QUARANTINE`. Do not continue the chain merely because compensation
succeeded.

A `ToolCompensator` receives a content-minimized `ToolCompensationRequest` with
identifiers and finding codes, not model content or sensitive arguments. The
hook should use an application-owned transaction, idempotency key, undo token,
or domain-specific compensating action. `compensation_succeeded=None` means no
hook was configured; `False` means the hook failed or raised. Alert and reconcile
both cases out of band.

## Security assumptions, limitations, and residual risk

- Capability policy, semantic policy, principal, intent, semantic facts,
  ownership evidence, execution budget, reports, and compensation code must be
  application-controlled. Typed validation establishes shape, not truth.
- Every tool path and every tool-to-tool value must pass this boundary. If an
  orchestrator omits provenance, invents reports, or calls an SDK directly, the
  library cannot observe the bypass.
- A report should come from authoritative state or an authenticated tool adapter.
  Model-authored claims such as `delivered=true` are not postcondition evidence.
- The in-memory budget and history are process-local. Distributed agents need a
  shared, atomic execution ledger that provides equivalent serialization,
  replay protection, quarantine, and transition checks.
- Compensation is not rollback. External messages, disclosed data, physical
  actions, trades, and destructive operations can be irreversible. Prefer
  staged writes, previews, transactions, idempotency, narrow service credentials,
  egress allowlists, value limits, and human approval before execution.
- Exact fact and argument bindings do not infer natural-language meaning. The
  application must convert user intent into narrow, authenticated facts; high
  impact or ambiguous requests still need domain policy and human review.
- Time-of-check/time-of-use races remain possible when ownership or eligibility
  changes after authorization. Recheck invariants in the downstream service and
  use transactional conditional writes where possible.

See [excessive agency](excessive-agency.md) for the base capability boundary and
[agent goal integrity](agent-goal-integrity.md) for protecting plans before they
become tool calls.
