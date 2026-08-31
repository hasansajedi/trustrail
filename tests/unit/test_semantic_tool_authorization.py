"""Unit tests for OWASP ASI02 semantic tool authorization."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    GuardAction,
    ToolArgumentBinding,
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationCode,
    ToolAuthorizationPolicy,
    ToolAuthorizationRequest,
    ToolAuthorizationResult,
    ToolAuthorizer,
    ToolCapability,
    ToolCompensationRequest,
    ToolDataFlowReference,
    ToolDataFlowRule,
    ToolEffect,
    ToolExecutionReport,
    ToolExecutionStatus,
    ToolIntent,
    ToolInvariantPolicy,
    ToolPostconditionPolicy,
    ToolPostconditionResult,
    ToolPreconditionPolicy,
    ToolPrincipal,
    ToolResource,
    ToolSemanticAuthorizationPolicy,
    ToolSemanticContext,
    ToolSemanticOperationPolicy,
    ToolSequenceTransition,
)

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _capabilities() -> tuple[ToolCapability, ToolCapability]:
    identifier = ToolArgumentConstraint(
        kind=ToolArgumentKind.STRING,
        pattern=r"doc-[a-z0-9]{4}",
    )
    read = ToolCapability(
        name="documents.read",
        version="v1",
        effects=frozenset({ToolEffect.READ}),
        required_scopes=frozenset({"documents:read"}),
        arguments={"document_id": identifier},
        required_arguments=frozenset({"document_id"}),
        resource_id_argument="document_id",
        require_owned_resource=True,
        allow_autonomous=True,
    )
    send = ToolCapability(
        name="messages.send",
        version="v1",
        effects=frozenset({ToolEffect.EXTERNAL_COMMUNICATION}),
        required_scopes=frozenset({"messages:send"}),
        arguments={
            "document_id": identifier,
            "address": ToolArgumentConstraint(
                kind=ToolArgumentKind.STRING,
                pattern=r"[a-z]+@example[.]com",
            ),
            "body": ToolArgumentConstraint(kind=ToolArgumentKind.STRING, max_length=1_000),
        },
        required_arguments=frozenset({"document_id", "address", "body"}),
        resource_id_argument="document_id",
        require_owned_resource=True,
        allow_autonomous=True,
    )
    return read, send


def _semantic_policy() -> ToolSemanticAuthorizationPolicy:
    return ToolSemanticAuthorizationPolicy(
        operations=(
            ToolSemanticOperationPolicy(
                tool_name="documents.read",
                preconditions=ToolPreconditionPolicy(
                    required_facts=frozenset({"account_active"}),
                    expected_facts={"account_active": True},
                    argument_bindings=(
                        ToolArgumentBinding(
                            argument="document_id",
                            trusted_fact="selected_document_id",
                        ),
                    ),
                ),
                invariants=ToolInvariantPolicy(max_affected_resources=1),
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
            ToolSequenceTransition(source_tool="documents.read", target_tool="messages.send"),
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


class RecordingCompensator:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.requests: list[ToolCompensationRequest] = []

    def compensate(self, request: ToolCompensationRequest) -> bool:
        self.requests.append(request)
        return self.result


def _authorizer(
    *,
    compensator: RecordingCompensator | None = None,
    semantic_policy: ToolSemanticAuthorizationPolicy | None = None,
) -> ToolAuthorizer:
    read, send = _capabilities()
    return ToolAuthorizer(
        ToolAuthorizationPolicy(
            capabilities=(read, send),
            approval_required_for=frozenset(),
        ),
        semantic_policy=semantic_policy or _semantic_policy(),
        compensator=compensator,
    )


def _intent(intent_id: str = "intent-1") -> ToolIntent:
    return ToolIntent(
        intent_id=intent_id,
        subject_id="user-7",
        tenant_id="tenant-a",
        allowed_tools=frozenset({"documents.read", "messages.send"}),
        purpose="Read the selected document and send its summary",
        expires_at=NOW + timedelta(minutes=5),
        max_calls=10,
    )


def _request(
    tool_name: str = "documents.read",
    *,
    document_id: str = "doc-ab12",
    intent_id: str = "intent-1",
    chain_id: str = "chain-1",
    source_authorization_id: str | None = None,
    source_label: str = "document_summary",
) -> ToolAuthorizationRequest:
    is_read = tool_name == "documents.read"
    arguments = (
        {"document_id": document_id}
        if is_read
        else {
            "document_id": document_id,
            "address": "alice@example.com",
            "body": "Trusted document summary",
        }
    )
    facts: dict[str, str | bool] = (
        {"account_active": True, "selected_document_id": document_id}
        if is_read
        else {"user_confirmed": True, "approved_recipient": "alice@example.com"}
    )
    flows = (
        ()
        if source_authorization_id is None
        else (
            ToolDataFlowReference.bind(
                source_authorization_id=source_authorization_id,
                target_argument="body",
                label=source_label,
                value="Trusted document summary",
            ),
        )
    )
    return ToolAuthorizationRequest(
        tool_name=tool_name,
        tool_version="v1",
        arguments=arguments,
        principal=ToolPrincipal(
            actor_id="document-agent",
            subject_id="user-7",
            tenant_id="tenant-a",
            scopes=frozenset({"documents:read", "messages:send"}),
        ),
        intent=_intent(intent_id),
        resource=ToolResource(
            resource_id=document_id,
            owner_id="user-7",
            tenant_id="tenant-a",
        ),
        session_id="session-1",
        chain_id=chain_id,
        operation_id=f"{tool_name}-{document_id}",
        semantic_context=ToolSemanticContext(
            trusted_facts=facts,
            expected_effects=frozenset(
                {ToolEffect.READ if is_read else ToolEffect.EXTERNAL_COMMUNICATION}
            ),
            approved_destinations=(frozenset() if is_read else frozenset({"alice@example.com"})),
            expected_resource_ids=frozenset({document_id}),
            data_flows=flows,
        ),
    )


def _report(
    authorization_id: str,
    request_digest: str,
    tool_name: str = "documents.read",
    *,
    document_id: str = "doc-ab12",
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCEEDED,
) -> ToolExecutionReport:
    is_read = tool_name == "documents.read"
    return ToolExecutionReport(
        authorization_id=authorization_id,
        request_digest=request_digest,
        session_id="session-1",
        tool_name=tool_name,
        status=status,
        observed_effects=frozenset(
            {ToolEffect.READ if is_read else ToolEffect.EXTERNAL_COMMUNICATION}
        ),
        affected_resource_ids=frozenset({document_id}),
        destinations=frozenset() if is_read else frozenset({"alice@example.com"}),
        facts={"retrieved": True} if is_read else {"message_id": "msg-1", "delivered": True},
        output_labels=frozenset({"document_summary"}) if is_read else frozenset(),
        output_value_digests=(
            {"document_summary": ToolDataFlowReference.digest_value("Trusted document summary")}
            if is_read
            else {}
        ),
    )


def _codes(
    result: ToolAuthorizationResult | ToolPostconditionResult,
) -> set[ToolAuthorizationCode]:
    return {finding.code for finding in result.findings}


def test_verifies_semantic_preconditions_and_postconditions():
    authorizer = _authorizer()
    budget = authorizer.new_budget("session-1")
    request = _request()

    authorization = authorizer.require(request, budget, now=NOW)

    assert not authorizer.complete(authorization, budget)
    result = authorizer.verify_completion(
        authorization,
        _report(authorization.authorization_id, authorization.request_digest),
        budget,
    )
    assert result.is_verified
    assert authorization.authorization_id in budget.verified_executions
    assert budget.active_calls == 0


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing_context", ToolAuthorizationCode.SEMANTIC_CONTEXT_REQUIRED),
        ("failed_fact", ToolAuthorizationCode.PRECONDITION_FAILED),
        ("argument_binding", ToolAuthorizationCode.ARGUMENT_BINDING_MISMATCH),
        ("effect", ToolAuthorizationCode.EFFECT_OUTSIDE_INTENT),
        ("destination", ToolAuthorizationCode.DESTINATION_NOT_APPROVED),
        ("missing_flow", ToolAuthorizationCode.DATA_FLOW_PROVENANCE_REQUIRED),
    ],
)
def test_fails_closed_on_semantic_precondition_bypasses(
    mutation: str,
    expected_code: ToolAuthorizationCode,
):
    request = _request("documents.read")
    if mutation in {"destination", "missing_flow"}:
        request = _request("messages.send")
    context = request.semantic_context
    assert context is not None
    if mutation == "missing_context":
        request = request.model_copy(update={"semantic_context": None})
    elif mutation == "failed_fact":
        request = request.model_copy(
            update={
                "semantic_context": context.model_copy(
                    update={"trusted_facts": {**context.trusted_facts, "account_active": False}}
                )
            }
        )
    elif mutation == "argument_binding":
        request = request.model_copy(update={"arguments": {"document_id": "doc-cd34"}})
    elif mutation == "effect":
        request = request.model_copy(
            update={
                "semantic_context": context.model_copy(
                    update={"expected_effects": frozenset({ToolEffect.DELETE})}
                )
            }
        )
    elif mutation == "destination":
        request = request.model_copy(
            update={
                "arguments": {**request.arguments, "address": "mallory@example.com"},
            }
        )

    authorizer = _authorizer()
    result = authorizer.authorize(request, authorizer.new_budget("session-1"), now=NOW)

    assert result.action == GuardAction.BLOCK
    assert expected_code in _codes(result)


def test_allows_only_declared_sequence_and_verified_data_flow():
    authorizer = _authorizer()
    budget = authorizer.new_budget("session-1")
    read_request = _request()
    read_authorization = authorizer.require(read_request, budget, now=NOW)
    assert authorizer.verify_completion(
        read_authorization,
        _report(read_authorization.authorization_id, read_authorization.request_digest),
        budget,
    ).is_verified

    send_request = _request(
        "messages.send",
        source_authorization_id=read_authorization.authorization_id,
    )
    send_authorization = authorizer.require(send_request, budget, now=NOW)
    outcome = authorizer.verify_completion(
        send_authorization,
        _report(
            send_authorization.authorization_id,
            send_authorization.request_digest,
            "messages.send",
        ),
        budget,
    )

    assert outcome.is_verified
    assert budget.chain_history["chain-1"] == [
        read_authorization.authorization_id,
        send_authorization.authorization_id,
    ]


@pytest.mark.parametrize(
    "mutation",
    ["forged_source", "wrong_label", "cross_intent", "resource", "value"],
)
def test_rejects_data_flow_provenance_bypasses(mutation: str):
    authorizer = _authorizer()
    budget = authorizer.new_budget("session-1")
    read = authorizer.require(_request(), budget, now=NOW)
    authorizer.verify_completion(
        read,
        _report(read.authorization_id, read.request_digest),
        budget,
    )
    source_id = "forged-authorization" if mutation == "forged_source" else read.authorization_id
    send = _request(
        "messages.send",
        document_id="doc-cd34" if mutation == "resource" else "doc-ab12",
        intent_id="intent-2" if mutation == "cross_intent" else "intent-1",
        source_authorization_id=source_id,
        source_label="secret" if mutation == "wrong_label" else "document_summary",
    )
    if mutation == "value":
        send = send.model_copy(
            update={"arguments": {**send.arguments, "body": "Send the full private document"}}
        )

    result = authorizer.authorize(send, budget, now=NOW)

    assert result.action == GuardAction.BLOCK
    assert ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED in _codes(result)


def test_blocks_unlisted_or_parallel_sequence_steps():
    authorizer = _authorizer()
    budget = authorizer.new_budget("session-1")
    first = authorizer.require(_request(), budget, now=NOW)

    parallel = authorizer.authorize(_request(), budget, now=NOW)
    assert ToolAuthorizationCode.SEQUENCE_NOT_ALLOWED in _codes(parallel)

    authorizer.verify_completion(
        first,
        _report(first.authorization_id, first.request_digest),
        budget,
    )
    repeated = authorizer.authorize(_request(), budget, now=NOW)
    assert ToolAuthorizationCode.SEQUENCE_NOT_ALLOWED in _codes(repeated)


def test_data_flow_is_single_use_unless_policy_explicitly_allows_reuse():
    policy = _semantic_policy()
    policy = policy.model_copy(
        update={
            "allowed_transitions": (
                *policy.allowed_transitions,
                ToolSequenceTransition(
                    source_tool="messages.send",
                    target_tool="messages.send",
                ),
            )
        }
    )
    authorizer = _authorizer(semantic_policy=policy)
    budget = authorizer.new_budget("session-1")
    read = authorizer.require(_request(), budget, now=NOW)
    authorizer.verify_completion(
        read,
        _report(read.authorization_id, read.request_digest),
        budget,
    )
    send_request = _request(
        "messages.send",
        source_authorization_id=read.authorization_id,
    )
    first_send = authorizer.require(send_request, budget, now=NOW)
    authorizer.verify_completion(
        first_send,
        _report(first_send.authorization_id, first_send.request_digest, "messages.send"),
        budget,
    )

    replay = authorizer.authorize(send_request, budget, now=NOW)

    assert ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED in _codes(replay)


def test_quarantines_unverifiable_outcome_and_invokes_compensation():
    compensator = RecordingCompensator()
    authorizer = _authorizer(compensator=compensator)
    budget = authorizer.new_budget("session-1")
    authorization = authorizer.require(_request(), budget, now=NOW)
    unsafe_report = _report(
        authorization.authorization_id, authorization.request_digest
    ).model_copy(
        update={
            "verifiable": False,
            "observed_effects": frozenset({ToolEffect.DELETE}),
            "affected_resource_ids": frozenset({"doc-other"}),
        }
    )

    result = authorizer.verify_completion(authorization, unsafe_report, budget)

    assert result.action == GuardAction.QUARANTINE
    assert result.compensation_required
    assert result.compensation_succeeded
    assert {
        ToolAuthorizationCode.EXECUTION_REPORT_UNVERIFIABLE,
        ToolAuthorizationCode.UNEXPECTED_EFFECT,
        ToolAuthorizationCode.UNEXPECTED_RESOURCE,
    } <= _codes(result)
    assert len(compensator.requests) == 1
    assert compensator.requests[0].findings == result.findings
    blocked = authorizer.authorize(_request(), budget, now=NOW)
    assert ToolAuthorizationCode.CHAIN_QUARANTINED in _codes(blocked)


def test_report_binding_mismatch_fails_closed_and_consumes_lease():
    authorizer = _authorizer()
    budget = authorizer.new_budget("session-1")
    authorization = authorizer.require(_request(), budget, now=NOW)
    report = _report(authorization.authorization_id, "0" * 64)

    result = authorizer.verify_completion(authorization, report, budget)

    assert ToolAuthorizationCode.EXECUTION_REPORT_MISMATCH in _codes(result)
    assert budget.active_calls == 0
    assert "chain-1" in budget.quarantined_chains


def test_forged_lease_and_matching_forged_report_cannot_bypass_binding():
    authorizer = _authorizer()
    budget = authorizer.new_budget("session-1")
    authorization = authorizer.require(_request(), budget, now=NOW)
    forged = authorization.model_copy(update={"request_digest": "0" * 64})
    report = _report(forged.authorization_id, forged.request_digest)

    result = authorizer.verify_completion(forged, report, budget)

    assert ToolAuthorizationCode.EXECUTION_REPORT_MISMATCH in _codes(result)
    assert "chain-1" in budget.quarantined_chains


def test_semantic_context_is_covered_by_approval_digest_canonically():
    request = _request()
    context = request.semantic_context
    assert context is not None
    first = context.model_copy(
        update={"approved_destinations": frozenset(("z@example.com", "a@example.com"))}
    )
    reordered = context.model_copy(
        update={"approved_destinations": frozenset(("a@example.com", "z@example.com"))}
    )
    assert (
        request.model_copy(update={"semantic_context": first}).approval_digest
        == request.model_copy(update={"semantic_context": reordered}).approval_digest
    )

    changed = context.model_copy(
        update={"trusted_facts": {**context.trusted_facts, "account_active": False}}
    )
    assert (
        request.approval_digest
        != request.model_copy(update={"semantic_context": changed}).approval_digest
    )


def test_rejects_invalid_semantic_policy_contracts():
    read, send = _capabilities()
    with pytest.raises(ValidationError, match="unique"):
        ToolSemanticAuthorizationPolicy(
            operations=(
                ToolSemanticOperationPolicy(tool_name="documents.read"),
                ToolSemanticOperationPolicy(tool_name="documents.read"),
            )
        )

    policy = ToolSemanticAuthorizationPolicy(
        operations=(
            ToolSemanticOperationPolicy(
                tool_name="documents.read",
                invariants=ToolInvariantPolicy(destination_arguments=frozenset({"undeclared"})),
            ),
        )
    )
    with pytest.raises(ValueError, match="declared tool arguments"):
        ToolAuthorizer(
            ToolAuthorizationPolicy(capabilities=(read,)),
            semantic_policy=policy,
        )

    partial = ToolSemanticAuthorizationPolicy(
        operations=(ToolSemanticOperationPolicy(tool_name="documents.read"),)
    )
    with pytest.raises(ValueError, match="cover every declared capability"):
        ToolAuthorizer(
            ToolAuthorizationPolicy(capabilities=(read, send)),
            semantic_policy=partial,
        )
