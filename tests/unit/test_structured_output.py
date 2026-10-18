"""Unit tests for strict, lifecycle-bound structured model output."""

from __future__ import annotations

from typing import Annotated, Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field

from trustrail import (
    GuardAction,
    MemoryStructuredOutputAuditSink,
    StructuredOutputCode,
    StructuredOutputContract,
    StructuredOutputError,
    StructuredOutputPolicy,
    StructuredOutputUse,
    StructuredOutputValidator,
)


class Citation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    document_id: str
    passage: str


class SearchStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["search"]
    query: str


class AnswerStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["answer"]
    answer: str


class AnswerPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    citations: list[Citation] = Field(max_length=4)
    next_step: Annotated[SearchStep | AnswerStep, Field(discriminator="kind")]


def _validator(
    *,
    uses: frozenset[StructuredOutputUse] | None = None,
    audit_sink: MemoryStructuredOutputAuditSink | None = None,
    policy: StructuredOutputPolicy | None = None,
) -> StructuredOutputValidator[AnswerPlan]:
    return StructuredOutputValidator(
        StructuredOutputContract(
            schema_id="support.answer-plan",
            schema_version="2026-10-18",
            model=AnswerPlan,
            allowed_uses=uses
            or frozenset(
                {
                    StructuredOutputUse.APPROVAL,
                    StructuredOutputUse.DISPLAY,
                    StructuredOutputUse.PERSISTENCE,
                }
            ),
            policy=policy or StructuredOutputPolicy(),
        ),
        audit_sink=audit_sink,
    )


VALID_JSON = (
    '{"summary":"Safe answer","confidence":0.9,'
    '"citations":[{"document_id":"doc-1","passage":"Evidence"}],'
    '"next_step":{"kind":"answer","answer":"Done"}}'
)


def _assert_code(exc_info: pytest.ExceptionInfo[StructuredOutputError], code: StructuredOutputCode):
    decision = exc_info.value.decision
    assert decision.action == GuardAction.BLOCK
    assert decision.findings[0].code == code


def test_validates_complete_json_and_authorizes_an_exact_use():
    validator = _validator()

    validated = validator.validate_json(VALID_JSON)
    binding = validator.bind(
        validated,
        use=StructuredOutputUse.DISPLAY,
        context_id="response:request-123",
    )
    authorized = validator.authorize(
        validated,
        binding,
        use=StructuredOutputUse.DISPLAY,
        context_id="response:request-123",
    )

    assert authorized.value.summary == "Safe answer"
    assert binding.object_digest == validated.object_digest
    assert binding.schema_digest == validator.schema_digest


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (
            '{"summary":"one","summary":"two","confidence":0.9,"citations":[],'
            '"next_step":{"kind":"answer","answer":"Done"}}',
            StructuredOutputCode.DUPLICATE_KEY,
        ),
        (
            '{"summary":"x","confidence":NaN,"citations":[],'
            '"next_step":{"kind":"answer","answer":"Done"}}',
            StructuredOutputCode.NON_FINITE_NUMBER,
        ),
        (VALID_JSON + " ignored", StructuredOutputCode.TRAILING_DATA),
        ("\ufeff" + VALID_JSON, StructuredOutputCode.AMBIGUOUS_ENCODING),
        ("not-json", StructuredOutputCode.INVALID_JSON),
    ],
)
def test_rejects_ambiguous_json_before_schema_validation(value: str, code: StructuredOutputCode):
    with pytest.raises(StructuredOutputError) as exc_info:
        _validator().validate_json(value)

    _assert_code(exc_info, code)


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (
            '{"summary":"x","confidence":"0.9","citations":[],'
            '"next_step":{"kind":"answer","answer":"Done"}}',
            StructuredOutputCode.IMPLICIT_COERCION,
        ),
        (
            '{"summary":"x","confidence":0.9,"citations":[],"extra":true,'
            '"next_step":{"kind":"answer","answer":"Done"}}',
            StructuredOutputCode.UNDECLARED_FIELD,
        ),
        (
            '{"summary":"x","confidence":2.0,"citations":[],'
            '"next_step":{"kind":"answer","answer":"Done"}}',
            StructuredOutputCode.SCHEMA_MISMATCH,
        ),
    ],
)
def test_rejects_schema_bypasses_without_retaining_partial_values(
    value: str,
    code: StructuredOutputCode,
):
    marker = "private-invalid-marker"
    with pytest.raises(StructuredOutputError) as exc_info:
        _validator().validate_json(value.replace('"x"', f'"{marker}"'))

    _assert_code(exc_info, code)
    assert marker not in repr(exc_info.value.decision)
    assert "partial" not in exc_info.value.decision.model_dump()


def test_rejects_parser_and_schema_disagreement_from_default_insertion():
    class WithDefault(BaseModel):
        model_config = ConfigDict(extra="forbid", frozen=True)

        answer: str
        reviewed: bool = False

    validator = StructuredOutputValidator(
        StructuredOutputContract(
            schema_id="answer-with-default",
            schema_version="1",
            model=WithDefault,
            allowed_uses=frozenset({StructuredOutputUse.DISPLAY}),
        )
    )

    with pytest.raises(StructuredOutputError) as exc_info:
        validator.validate_json('{"answer":"ok"}')

    _assert_code(exc_info, StructuredOutputCode.SCHEMA_PARSER_DISAGREEMENT)


def test_rejects_open_objects_unbounded_arrays_and_ambiguous_unions():
    class OpenObject(BaseModel):
        value: str

    class UnboundedArray(BaseModel):
        model_config = ConfigDict(extra="forbid")
        values: list[str]

    class AmbiguousUnion(BaseModel):
        model_config = ConfigDict(extra="forbid")
        value: str | int

    for schema in (OpenObject, UnboundedArray, AmbiguousUnion):
        with pytest.raises(ValueError):
            StructuredOutputValidator(
                StructuredOutputContract(
                    schema_id=f"invalid-{schema.__name__}",
                    schema_version="1",
                    model=schema,
                    allowed_uses=frozenset({StructuredOutputUse.DISPLAY}),
                )
            )


def test_schema_keyword_field_names_are_not_mistaken_for_schema_nodes():
    class KeywordFields(BaseModel):
        model_config = ConfigDict(extra="forbid", frozen=True)

        anyOf: str  # noqa: N815 - exercise a JSON Schema keyword field name
        items: str
        properties: str

    validator = StructuredOutputValidator(
        StructuredOutputContract(
            schema_id="keyword-fields",
            schema_version="1",
            model=KeywordFields,
            allowed_uses=frozenset({StructuredOutputUse.DISPLAY}),
        )
    )

    validated = validator.validate_json('{"anyOf":"data","items":"data","properties":"data"}')

    assert validated.object_digest


def test_rejects_runtime_depth_array_and_node_limit_bypasses():
    small_policy = StructuredOutputPolicy(max_depth=2, max_nodes=8, max_array_items=2)
    with pytest.raises(ValueError):
        _validator(policy=small_policy)

    validator = _validator(policy=StructuredOutputPolicy(max_depth=3, max_array_items=4))
    too_deep = VALID_JSON.replace('"Done"', '{"nested":{"nested":"Done"}}')
    with pytest.raises(StructuredOutputError) as exc_info:
        validator.validate_json(too_deep)
    _assert_code(exc_info, StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED)


def test_binding_rejects_context_use_schema_and_object_substitution():
    validator = _validator()
    validated = validator.validate_json(VALID_JSON)
    binding = validator.bind(
        validated,
        use=StructuredOutputUse.DISPLAY,
        context_id="response:123",
    )

    for use, context_id in (
        (StructuredOutputUse.PERSISTENCE, "response:123"),
        (StructuredOutputUse.DISPLAY, "response:other"),
    ):
        with pytest.raises(StructuredOutputError) as exc_info:
            validator.authorize(validated, binding, use=use, context_id=context_id)
        _assert_code(exc_info, StructuredOutputCode.BINDING_MISMATCH)

    changed = validator.validate_json(VALID_JSON.replace("Safe answer", "Changed answer"))
    with pytest.raises(StructuredOutputError) as exc_info:
        validator.authorize(
            changed,
            binding,
            use=StructuredOutputUse.DISPLAY,
            context_id="response:123",
        )
    _assert_code(exc_info, StructuredOutputCode.BINDING_MISMATCH)


def test_disallowed_use_fails_before_a_binding_is_issued():
    validator = _validator(uses=frozenset({StructuredOutputUse.DISPLAY}))
    validated = validator.validate_json(VALID_JSON)

    with pytest.raises(StructuredOutputError) as exc_info:
        validator.bind(
            validated,
            use=StructuredOutputUse.EXECUTION,
            context_id="tool-call:123",
        )

    _assert_code(exc_info, StructuredOutputCode.USE_NOT_ALLOWED)


def test_mutated_nested_value_is_detected_before_use():
    validator = _validator()
    validated = validator.validate_json(VALID_JSON)
    binding = validator.bind(
        validated,
        use=StructuredOutputUse.DISPLAY,
        context_id="response:123",
    )
    validated._value.citations.append(Citation(document_id="doc-2", passage="Changed"))

    with pytest.raises(StructuredOutputError) as exc_info:
        validator.authorize(
            validated,
            binding,
            use=StructuredOutputUse.DISPLAY,
            context_id="response:123",
        )

    _assert_code(exc_info, StructuredOutputCode.VALIDATED_OBJECT_CHANGED)


def test_typed_output_is_serialized_and_strictly_revalidated():
    validator = _validator()
    typed = AnswerPlan.model_validate_json(VALID_JSON, strict=True)

    validated = validator.validate_typed(typed)

    assert validated.object_digest
    forged = AnswerPlan.model_construct(
        summary="x",
        confidence="0.9",
        citations=[],
        next_step=AnswerStep(kind="answer", answer="done"),
    )
    with pytest.raises(StructuredOutputError):
        validator.validate_typed(forged)


def test_repair_loop_is_explicit_bounded_and_closes_after_success():
    session = _validator().new_repair_session(max_attempts=2)

    with pytest.raises(StructuredOutputError) as first:
        session.validate_json('{"summary":"partial"}')
    assert first.value.decision.findings[0].code == StructuredOutputCode.SCHEMA_MISMATCH
    assert session.remaining_attempts == 1

    validated = session.validate_json(VALID_JSON)
    assert validated.object_digest
    assert session.remaining_attempts == 0
    with pytest.raises(StructuredOutputError) as closed:
        session.validate_json(VALID_JSON)
    _assert_code(closed, StructuredOutputCode.REPAIR_SESSION_CLOSED)


def test_repair_loop_reports_exhaustion_without_returning_invalid_output():
    session = _validator().new_repair_session(max_attempts=1)

    with pytest.raises(StructuredOutputError) as exc_info:
        session.validate_json('{"summary":"partial"}')

    _assert_code(exc_info, StructuredOutputCode.REPAIR_EXHAUSTED)
    assert exc_info.value.decision.object_digest is None


def test_audit_events_are_content_free_and_cover_validation_binding_and_use():
    audit = MemoryStructuredOutputAuditSink()
    validator = _validator(audit_sink=audit)
    validated = validator.validate_json(VALID_JSON)
    binding = validator.bind(
        validated,
        use=StructuredOutputUse.PERSISTENCE,
        context_id="record:123",
    )
    validator.authorize(
        validated,
        binding,
        use=StructuredOutputUse.PERSISTENCE,
        context_id="record:123",
    )

    assert [event.code for event in audit.events] == [
        StructuredOutputCode.VALIDATED,
        StructuredOutputCode.BOUND,
        StructuredOutputCode.USE_AUTHORIZED,
    ]
    assert "Safe answer" not in str([event.model_dump() for event in audit.events])
