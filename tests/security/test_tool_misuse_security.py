"""Bypass corpus for OWASP ASI02 tool misuse and exploitation."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    GuardAction,
    ToolArgumentBinding,
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationPolicy,
    ToolAuthorizationRequest,
    ToolAuthorizer,
    ToolCapability,
    ToolEffect,
    ToolExecutionReport,
    ToolExecutionStatus,
    ToolIntent,
    ToolInvariantPolicy,
    ToolPostconditionPolicy,
    ToolPreconditionPolicy,
    ToolPrincipal,
    ToolResource,
    ToolSemanticAuthorizationPolicy,
    ToolSemanticContext,
    ToolSemanticOperationPolicy,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "tool_misuse.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _authorizer() -> ToolAuthorizer:
    capability = ToolCapability(
        name="payments.transfer",
        version="v4",
        effects=frozenset({ToolEffect.UPDATE}),
        required_scopes=frozenset({"payments:transfer"}),
        arguments={
            "account_id": ToolArgumentConstraint(
                kind=ToolArgumentKind.STRING,
                pattern=r"acct-[a-z0-9]{4}",
            ),
            "recipient": ToolArgumentConstraint(
                kind=ToolArgumentKind.STRING,
                pattern=r"acct-[a-z0-9]{4}",
            ),
            "amount": ToolArgumentConstraint(
                kind=ToolArgumentKind.NUMBER,
                minimum=1,
                maximum=10_000,
            ),
        },
        required_arguments=frozenset({"account_id", "recipient", "amount"}),
        resource_id_argument="account_id",
        require_owned_resource=True,
        allow_autonomous=True,
    )
    semantic_policy = ToolSemanticAuthorizationPolicy(
        operations=(
            ToolSemanticOperationPolicy(
                tool_name="payments.transfer",
                preconditions=ToolPreconditionPolicy(
                    expected_facts={"user_confirmed": True},
                    argument_bindings=(
                        ToolArgumentBinding(
                            argument="recipient",
                            trusted_fact="approved_recipient",
                        ),
                        ToolArgumentBinding(argument="amount", trusted_fact="approved_amount"),
                    ),
                ),
                invariants=ToolInvariantPolicy(
                    destination_arguments=frozenset({"recipient"}),
                    max_affected_resources=1,
                ),
                postconditions=ToolPostconditionPolicy(
                    required_facts=frozenset({"transaction_id"}),
                    expected_facts={"ledger_committed": True},
                ),
            ),
        )
    )
    return ToolAuthorizer(
        ToolAuthorizationPolicy(
            capabilities=(capability,),
            approval_required_for=frozenset(),
        ),
        semantic_policy=semantic_policy,
    )


def _request() -> ToolAuthorizationRequest:
    return ToolAuthorizationRequest(
        tool_name="payments.transfer",
        tool_version="v4",
        arguments={
            "account_id": "acct-aa11",
            "recipient": "acct-bb22",
            "amount": 100.0,
        },
        principal=ToolPrincipal(
            actor_id="payments-agent",
            subject_id="user-a",
            tenant_id="tenant-a",
            scopes=frozenset({"payments:transfer"}),
        ),
        intent=ToolIntent(
            intent_id="confirmed-transfer",
            subject_id="user-a",
            tenant_id="tenant-a",
            allowed_tools=frozenset({"payments.transfer"}),
            purpose="Send 100 USD to account acct-bb22",
            expires_at=NOW + timedelta(minutes=5),
        ),
        resource=ToolResource(
            resource_id="acct-aa11",
            owner_id="user-a",
            tenant_id="tenant-a",
        ),
        session_id="security-session",
        chain_id="transfer-chain",
        operation_id="transfer-once",
        semantic_context=ToolSemanticContext(
            trusted_facts={
                "user_confirmed": True,
                "approved_recipient": "acct-bb22",
                "approved_amount": 100.0,
            },
            expected_effects=frozenset({ToolEffect.UPDATE}),
            approved_destinations=frozenset({"acct-bb22"}),
            expected_resource_ids=frozenset({"acct-aa11"}),
        ),
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_semantic_tool_misuse_corpus(case: dict[str, str]):
    authorizer = _authorizer()
    budget = authorizer.new_budget("security-session")
    request = _request()
    context = request.semantic_context
    assert context is not None

    if case["phase"] == "authorize":
        if case["mutation"] == "recipient":
            request = request.model_copy(
                update={"arguments": {**request.arguments, "recipient": "acct-cc33"}}
            )
        elif case["mutation"] == "amount":
            request = request.model_copy(
                update={"arguments": {**request.arguments, "amount": 9_999.0}}
            )
        elif case["mutation"] == "effect":
            request = request.model_copy(
                update={
                    "semantic_context": context.model_copy(
                        update={"expected_effects": frozenset({ToolEffect.READ})}
                    )
                }
            )
        elif case["mutation"] == "destination":
            request = request.model_copy(
                update={
                    "semantic_context": context.model_copy(
                        update={"approved_destinations": frozenset({"acct-cc33"})}
                    )
                }
            )
        result = authorizer.authorize(request, budget, now=NOW)
    else:
        authorization = authorizer.require(request, budget, now=NOW)
        report = ToolExecutionReport(
            authorization_id=authorization.authorization_id,
            request_digest=authorization.request_digest,
            session_id=request.session_id,
            tool_name=request.tool_name,
            status=ToolExecutionStatus.SUCCEEDED,
            observed_effects=frozenset({ToolEffect.UPDATE}),
            affected_resource_ids=frozenset({"acct-aa11"}),
            destinations=frozenset({"acct-bb22"}),
            facts={"transaction_id": "txn-1", "ledger_committed": True},
        )
        if case["mutation"] == "unverifiable":
            report = report.model_copy(update={"verifiable": False})
        elif case["mutation"] == "effect":
            report = report.model_copy(update={"observed_effects": frozenset({ToolEffect.DELETE})})
        elif case["mutation"] == "resource":
            report = report.model_copy(update={"affected_resource_ids": frozenset({"acct-victim"})})
        elif case["mutation"] == "postcondition":
            report = report.model_copy(
                update={"facts": {"transaction_id": "txn-1", "ledger_committed": False}}
            )
        result = authorizer.verify_completion(authorization, report, budget)

    assert result.action in {GuardAction.BLOCK, GuardAction.QUARANTINE}
    assert case["expected_code"] in {finding.code.value for finding in result.findings}
