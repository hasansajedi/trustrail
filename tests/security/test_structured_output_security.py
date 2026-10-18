"""Adversarial regression tests for OWASP AISVS C7 output enforcement."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, Field

from trustrail import (
    StructuredOutputCode,
    StructuredOutputContract,
    StructuredOutputError,
    StructuredOutputPolicy,
    StructuredOutputUse,
    StructuredOutputValidator,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "structured_output.json"


class SecurityPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    count: int = Field(ge=0, le=10)
    tags: list[str] = Field(max_length=2)


def _cases() -> list[dict[str, str]]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def _validator() -> StructuredOutputValidator[SecurityPayload]:
    return StructuredOutputValidator(
        StructuredOutputContract(
            schema_id="security.corpus-payload",
            schema_version="1",
            model=SecurityPayload,
            allowed_uses=frozenset(
                {StructuredOutputUse.PERSISTENCE, StructuredOutputUse.EXECUTION}
            ),
            policy=StructuredOutputPolicy(max_array_items=2),
        )
    )


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_structured_output_security_corpus_fails_closed(case: dict[str, str]):
    marker = "private-corpus-marker"
    with pytest.raises(StructuredOutputError) as exc_info:
        _validator().validate_json(case["payload"].replace('"x"', f'"{marker}"'))

    decision = exc_info.value.decision
    assert decision.findings[0].code == StructuredOutputCode(case["expected_code"])
    assert marker not in decision.model_dump_json()


def test_invalid_utf8_and_overlong_numbers_fail_before_model_validation():
    with pytest.raises(StructuredOutputError) as invalid_utf8:
        _validator().validate_json(b'{"name":"\xff","count":1,"tags":[]}')
    assert invalid_utf8.value.decision.findings[0].code == (StructuredOutputCode.AMBIGUOUS_ENCODING)

    validator = StructuredOutputValidator(
        StructuredOutputContract(
            schema_id="security.number-limit",
            schema_version="1",
            model=SecurityPayload,
            allowed_uses=frozenset({StructuredOutputUse.EXECUTION}),
            policy=StructuredOutputPolicy(max_array_items=2, max_number_chars=3),
        )
    )
    with pytest.raises(StructuredOutputError) as huge_number:
        validator.validate_json('{"name":"x","count":1234,"tags":[]}')
    assert huge_number.value.decision.findings[0].code == StructuredOutputCode.NON_FINITE_NUMBER


def test_schema_identity_and_context_cannot_be_swapped_at_execution_boundary():
    validator = _validator()
    validated = validator.validate_json('{"name":"x","count":1,"tags":[]}')
    binding = validator.bind(
        validated,
        use=StructuredOutputUse.EXECUTION,
        context_id="execution:tenant-a:request-1",
    )

    tampered_bindings = (
        binding.model_copy(update={"schema_id": "attacker.schema"}),
        binding.model_copy(update={"schema_version": "0"}),
        binding.model_copy(update={"object_digest": "0" * 64}),
        binding.model_copy(update={"use": StructuredOutputUse.PERSISTENCE}),
    )
    for tampered in tampered_bindings:
        with pytest.raises(StructuredOutputError) as exc_info:
            validator.authorize(
                validated,
                tampered,
                use=StructuredOutputUse.EXECUTION,
                context_id="execution:tenant-a:request-1",
            )
        assert exc_info.value.decision.findings[0].code == StructuredOutputCode.BINDING_MISMATCH

    with pytest.raises(StructuredOutputError):
        validator.authorize(
            validated,
            binding,
            use=StructuredOutputUse.EXECUTION,
            context_id="execution:tenant-b:request-1",
        )


def test_forged_validated_metadata_and_payload_are_revalidated_before_binding():
    validator = _validator()
    validated = validator.validate_json('{"name":"x","count":1,"tags":[]}')
    for forged in (
        replace(validated, schema_digest="0" * 64),
        replace(validated, object_digest="0" * 64),
        replace(validated, _canonical_json='{"name":"changed","count":1,"tags":[]}'),
    ):
        with pytest.raises(StructuredOutputError) as exc_info:
            validator.bind(
                forged,
                use=StructuredOutputUse.EXECUTION,
                context_id="execution:request-1",
            )
        assert exc_info.value.decision.findings[0].code == (
            StructuredOutputCode.VALIDATED_OBJECT_CHANGED
        )


def test_deep_recursion_and_wide_runtime_structures_are_bounded():
    deep = "[" * 2_000 + "]" * 2_000
    with pytest.raises(StructuredOutputError) as deep_error:
        _validator().validate_json(deep)
    assert deep_error.value.decision.findings[0].code in {
        StructuredOutputCode.INVALID_JSON,
        StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED,
    }

    wide = '{"name":"x","count":1,"tags":[' + ",".join('"x"' for _ in range(3)) + "]}"
    with pytest.raises(StructuredOutputError) as wide_error:
        _validator().validate_json(wide)
    assert wide_error.value.decision.findings[0].code == (
        StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED
    )
