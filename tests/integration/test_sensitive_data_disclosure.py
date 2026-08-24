"""Integration tests for sensitive-data boundaries and protected context."""

import pytest

from trustrail import (
    Document,
    Guard,
    GuardConfig,
    GuardStage,
    ProtectedData,
    SensitiveDataMode,
)
from trustrail.exceptions import GuardrailBlockedError
from trustrail.integrations.llamaindex.observer import AegisRailObserver
from trustrail.models.enums import GuardAction

PRIVATE_CONTEXT = (
    "Project Borealis will acquire Northwind Labs on 14 September for 42 million euros."
)


def test_protected_context_blocks_verbatim_output_by_default():
    result = Guard.silent().check(
        f"The private record says: {PRIVATE_CONTEXT}",
        GuardStage.FINAL_OUTPUT,
        protected_data=[ProtectedData(value=PRIVATE_CONTEXT)],
    )

    assert result.action == GuardAction.BLOCK
    assert any(finding.rule_id == "SD-017" for finding in result.findings)


def test_protected_context_can_be_redacted_with_flexible_whitespace():
    guard = Guard(config=GuardConfig(sensitive_data_mode=SensitiveDataMode.REDACT))
    protected = ProtectedData(value="Customer 7421 has confidential renewal terms")

    result = guard.check(
        "CUSTOMER 7421 has   confidential renewal terms",
        GuardStage.FINAL_OUTPUT,
        protected_data=[protected],
    )

    assert result.action == GuardAction.REDACT
    assert result.output_value == "[PROTECTED_DATA]"


def test_protected_data_value_is_not_serializable_or_repr_visible():
    protected = ProtectedData(value=PRIVATE_CONTEXT)

    assert PRIVATE_CONTEXT not in repr(protected)
    assert "value" not in protected.model_dump()
    assert PRIVATE_CONTEXT not in protected.model_dump_json()


def test_unrelated_output_is_allowed_with_protected_context():
    result = Guard.silent().check(
        "Here is a public summary with no private details.",
        GuardStage.FINAL_OUTPUT,
        protected_data=[ProtectedData(value=PRIVATE_CONTEXT)],
    )

    assert result.action == GuardAction.ALLOW


def test_protect_exception_does_not_reproduce_protected_context():
    with pytest.raises(GuardrailBlockedError) as exc_info:
        Guard.silent().protect(
            PRIVATE_CONTEXT,
            GuardStage.FINAL_OUTPUT,
            protected_data=[ProtectedData(value=PRIVATE_CONTEXT)],
        )

    assert PRIVATE_CONTEXT not in str(exc_info.value)
    assert PRIVATE_CONTEXT not in "".join(
        finding.model_dump_json() for finding in exc_info.value.findings
    )


def test_rag_documents_are_sensitive_data_scanned():
    envelope = Guard.silent().build_rag_context(
        [Document(content="Owner email: user@example.com", source="private-crm")]
    )

    assert "user@example.com" not in envelope.segments[0].content
    assert "[EMAIL]" in envelope.segments[0].content


def test_llamaindex_retrieved_node_receives_redacted_content():
    class Node:
        text = "Owner email: user@example.com"

    node = Node()
    safe_nodes = AegisRailObserver(Guard.silent()).on_retrieve([node])

    assert safe_nodes == [node]
    assert node.text == "Owner email: [EMAIL]"


@pytest.mark.parametrize(
    "stage",
    [
        GuardStage.RAG_DOCUMENT,
        GuardStage.EXTERNAL_CONTENT,
        GuardStage.TOOL_REQUEST,
        GuardStage.AGENT_ACTION,
    ],
)
def test_sensitive_data_policy_covers_indirect_boundaries(stage: GuardStage):
    result = Guard.silent().check("Contact user@example.com", stage)

    assert "user@example.com" not in result.output_value
    assert any(finding.rule_id == "SD-001" for finding in result.findings)
