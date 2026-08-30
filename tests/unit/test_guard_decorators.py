"""Regression tests for bound and transformed guard decorators."""

from __future__ import annotations

import json
from typing import ClassVar

import pytest

from trustrail import (
    ApprovalRequiredError,
    ConfigurationError,
    Guard,
    GuardAction,
    GuardConfig,
    GuardContext,
    GuardPolicy,
    GuardrailBlockedError,
    GuardStage,
    ResourceLimitError,
    RuleCategory,
    RuleConfig,
)
from trustrail.models.core import GuardDecision
from trustrail.rules.base import BaseRule


class ApprovalTestRule(BaseRule):
    rule_id: ClassVar[str] = "TEST-DECORATOR-APPROVAL"
    rule_name: ClassVar[str] = "Decorator approval test"
    category: ClassVar[RuleCategory] = RuleCategory.CONTENT_SAFETY

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        del context
        if "needs approval" in value:
            return self._block("Approval required", action=GuardAction.REQUIRE_APPROVAL)
        return self._allow()


def test_input_forwards_normalized_positional_argument() -> None:
    guard = Guard.silent()

    @guard.input()
    def handle(sequence: int, payload: str) -> str:
        return f"{sequence}:{payload}"

    assert handle(7, "safe\u200bmessage") == "7:safemessage"


def test_input_binds_and_transforms_default_argument() -> None:
    guard = Guard.silent()

    @guard.input()
    def handle(sequence: int, payload: str = "safe\u200bdefault") -> str:
        return f"{sequence}:{payload}"

    assert handle(7) == "7:safedefault"


def test_input_binds_and_transforms_variadic_argument() -> None:
    guard = Guard.silent()

    @guard.input()
    def handle(*values: object) -> tuple[object, ...]:
        return values

    assert handle(7, "safe\u200bmessage") == (7, "safemessage")


def test_input_binds_and_transforms_keyword_only_argument() -> None:
    guard = Guard.silent()

    @guard.input()
    def handle(*, payload: str) -> str:
        return payload

    assert handle(payload="safe\u200bmessage") == "safemessage"


def test_input_excludes_method_self() -> None:
    guard = Guard.silent()

    class Handler:
        @guard.input()
        def handle(self, payload: str) -> str:
            return payload

    assert Handler().handle("safe\u200bmessage") == "safemessage"


def test_input_forwards_redacted_argument() -> None:
    guard = Guard(
        GuardConfig(sensitive_data_mode="redact", audit_enabled=False),
    )

    @guard.input(raise_on_block=False)
    def handle(payload: str) -> str:
        return payload

    output = handle("Contact alice@example.com")
    assert "alice@example.com" not in output
    assert "[EMAIL]" in output


def test_input_selector_serializer_rebuilds_multiple_rag_fields() -> None:
    guard = Guard.silent()

    @guard.input(
        stage=GuardStage.RAG_DOCUMENT,
        selector=lambda arguments: ("query", "document"),
        serializer=lambda payload: json.dumps(payload, ensure_ascii=False, sort_keys=True),
        deserializer=json.loads,
    )
    def retrieve(query: str, document: dict[str, str]) -> tuple[str, dict[str, str]]:
        return query, document

    query, document = retrieve("safe\u200bquery", {"content": "safe\u200bcontext"})
    assert query == "safequery"
    assert document == {"content": "safecontext"}


def test_input_selector_can_choose_variadic_keyword_argument() -> None:
    guard = Guard.silent()

    @guard.input(selector="payload")
    def handle(**values: str) -> str:
        return values["payload"]

    assert handle(payload="safe\u200bmessage") == "safemessage"


def test_input_requires_deserializer_for_transformed_structured_payload() -> None:
    guard = Guard.silent()

    @guard.input(selector="payload")
    def handle(payload: dict[str, str]) -> dict[str, str]:
        return payload

    with pytest.raises(ConfigurationError, match="deserializer"):
        handle({"content": "safe\u200bmessage"})


def test_input_rejects_unknown_selector_and_oversized_payload() -> None:
    guard = Guard.silent()

    @guard.input(selector="missing")
    def unknown(payload: str) -> str:
        return payload

    with pytest.raises(ConfigurationError, match="unknown argument"):
        unknown("safe")

    @guard.input(max_serialized_chars=5)
    def bounded(payload: str) -> str:
        return payload

    with pytest.raises(ResourceLimitError, match="limit is 5"):
        bounded("too long")


def test_input_handles_approval_without_executing_callable() -> None:
    guard = Guard(
        GuardConfig(audit_enabled=False),
        extra_rules=[ApprovalTestRule()],
    )
    executed = False

    @guard.input()
    def handle(payload: str) -> str:
        nonlocal executed
        executed = True
        return payload

    with pytest.raises(ApprovalRequiredError):
        handle("needs approval")
    assert not executed


@pytest.mark.asyncio
async def test_async_input_matches_sync_transformation_and_approval() -> None:
    guard = Guard(
        GuardConfig(audit_enabled=False),
        extra_rules=[ApprovalTestRule()],
    )

    @guard.input()
    async def handle(payload: str) -> str:
        return payload

    assert await handle("safe\u200bmessage") == "safemessage"
    with pytest.raises(ApprovalRequiredError):
        await handle("needs approval")


@pytest.mark.parametrize(
    "invoke",
    [
        lambda tool: tool("; rm -rf /important"),
        lambda tool: tool(query="; rm -rf /important"),
        lambda tool: tool("safe", "; rm -rf /important"),
        lambda tool: tool("safe", option="; rm -rf /important"),
    ],
)
def test_tool_binds_positional_keyword_and_variadic_arguments(invoke: object) -> None:
    guard = Guard.silent()

    @guard.tool()
    def database_query(*queries: str, query: str = "safe", **options: str) -> str:
        return "executed"

    with pytest.raises(GuardrailBlockedError):
        invoke(database_query)  # type: ignore[operator]


def test_tool_binds_default_arguments() -> None:
    guard = Guard.silent()

    @guard.tool()
    def database_query(query: str = "; rm -rf /important") -> str:
        return query

    with pytest.raises(GuardrailBlockedError):
        database_query()


def test_tool_excludes_method_self_and_allows_safe_call() -> None:
    guard = Guard.silent()

    class Database:
        @guard.tool()
        def query(self, statement: str) -> str:
            return statement

    assert Database().query("select 1") == "select 1"


def test_tool_selects_configured_policy_and_rejects_unknown_policy() -> None:
    guard = Guard(
        GuardConfig(
            audit_enabled=False,
            policies={
                "tools": GuardPolicy(params={"allowlist": ["approved_tool"]}),
            },
        )
    )

    @guard.tool(policy="tools")
    def unapproved_tool() -> str:
        return "executed"

    with pytest.raises(GuardrailBlockedError):
        unapproved_tool()

    with pytest.raises(ConfigurationError, match="Unknown tool decorator policy"):

        @guard.tool(policy="strict")
        def invalid_policy() -> str:
            return "executed"


def test_tool_handles_approval_without_execution() -> None:
    guard = Guard(
        GuardConfig(
            audit_enabled=False,
            policies={"tools": GuardPolicy(params={"allowlist": ["different_tool"]})},
            rule_overrides={
                "TL-001": RuleConfig(action=GuardAction.REQUIRE_APPROVAL),
            },
        )
    )
    executed = False

    @guard.tool(policy="tools")
    def approval_tool() -> str:
        nonlocal executed
        executed = True
        return "executed"

    with pytest.raises(ApprovalRequiredError):
        approval_tool()
    assert not executed


@pytest.mark.asyncio
async def test_async_tool_blocks_bound_positional_argument() -> None:
    guard = Guard.silent()

    @guard.tool()
    async def database_query(query: str) -> str:
        return query

    with pytest.raises(GuardrailBlockedError):
        await database_query("; rm -rf /important")
