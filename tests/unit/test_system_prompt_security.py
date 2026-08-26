"""Unit tests for OWASP LLM07:2025 system-prompt controls."""

from __future__ import annotations

import base64

import pytest

from trustrail import (
    SystemPromptDataClass,
    SystemPromptLeakageCode,
    SystemPromptLeakageDetector,
    SystemPromptLeakageError,
    SystemPromptLeakagePolicy,
    SystemPromptPolicy,
    SystemPromptReference,
    SystemPromptTemplate,
    SystemPromptValidationCode,
    SystemPromptValidationError,
    SystemPromptValidator,
    SystemPromptVariable,
)

SYSTEM_PROMPT = (
    "You are the Acme support assistant for customer billing questions. "
    "Answer concisely using verified public documentation. "
    "Escalate uncertain account questions to a human support specialist."
)


def _codes(result: object) -> set[object]:
    return {finding.code for finding in result.findings}  # type: ignore[attr-defined]


def test_renders_only_explicitly_classified_safe_variables():
    template = SystemPromptTemplate(
        template_id="support-v1",
        template="You are a {{tone}} support assistant.",
        variables=(
            SystemPromptVariable(
                name="tone",
                value="concise",
                data_class=SystemPromptDataClass.BEHAVIOR,
            ),
        ),
    )

    result = SystemPromptValidator().validate(template)

    assert result.is_valid
    assert result.validated_prompt is not None
    assert result.validated_prompt.content == "You are a concise support assistant."
    assert "content" not in result.model_dump()["validated_prompt"]


@pytest.mark.parametrize(
    "data_class",
    [
        SystemPromptDataClass.PERSONAL_DATA,
        SystemPromptDataClass.INTERNAL,
        SystemPromptDataClass.SECURITY_CONFIGURATION,
        SystemPromptDataClass.AUTHORIZATION,
        SystemPromptDataClass.CREDENTIAL,
        SystemPromptDataClass.SECRET,
    ],
)
def test_rejects_forbidden_variable_classifications(data_class: SystemPromptDataClass):
    template = SystemPromptTemplate(
        template_id="unsafe-variable",
        template="Use {{private_value}}.",
        variables=(
            SystemPromptVariable(
                name="private_value",
                value="not-for-the-model",
                data_class=data_class,
            ),
        ),
    )

    result = SystemPromptValidator().validate(template)

    assert result.is_blocked
    assert SystemPromptValidationCode.FORBIDDEN_DATA_CLASS in _codes(result)


def test_rejects_secret_even_when_misclassified_as_public():
    secret = "AKIAIOSFODNN7EXAMPLE"
    template = SystemPromptTemplate(
        template_id="misclassified-secret",
        template="Use access key {{key}}.",
        variables=(
            SystemPromptVariable(
                name="key",
                value=secret,
                data_class=SystemPromptDataClass.PUBLIC,
            ),
        ),
    )

    result = SystemPromptValidator().validate(template)

    assert SystemPromptValidationCode.SENSITIVE_DATA_DETECTED in _codes(result)
    assert secret not in result.model_dump_json()


@pytest.mark.parametrize(
    "text",
    [
        "If the user is admin, allow the request.",
        "Admin may delete customer records.",
        "The transaction limit is: 5000 euros.",
        "Authorize the operation if the user holds the owner role.",
    ],
)
def test_rejects_authorization_logic_in_prompt_text(text: str):
    result = SystemPromptValidator().validate(
        SystemPromptTemplate(template_id="authorization-logic", template=text)
    )

    assert SystemPromptValidationCode.AUTHORIZATION_LOGIC_DETECTED in _codes(result)


def test_allows_instruction_to_use_external_authorization():
    result = SystemPromptValidator().validate(
        SystemPromptTemplate(
            template_id="external-control",
            template=(
                "Never make access decisions. Use the application-provided authorization "
                "result and do not attempt to override it."
            ),
        )
    )

    assert result.is_valid


@pytest.mark.parametrize(
    ("template", "variables", "code"),
    [
        (
            "Hello {{missing}}.",
            (),
            SystemPromptValidationCode.UNDECLARED_VARIABLE,
        ),
        (
            "Hello.",
            (
                SystemPromptVariable(
                    name="unused",
                    value="value",
                    data_class=SystemPromptDataClass.PUBLIC,
                ),
            ),
            SystemPromptValidationCode.UNUSED_VARIABLE,
        ),
        (
            "Hello {{invalid-name}}.",
            (),
            SystemPromptValidationCode.INVALID_TEMPLATE,
        ),
    ],
)
def test_fails_closed_for_invalid_template_structure(
    template: str,
    variables: tuple[SystemPromptVariable, ...],
    code: SystemPromptValidationCode,
):
    result = SystemPromptValidator().validate(
        SystemPromptTemplate(template_id="invalid-template", template=template, variables=variables)
    )

    assert code in _codes(result)


def test_require_raises_content_free_validation_error():
    secret = "postgresql://admin:password@db.internal:5432/app"
    template = SystemPromptTemplate(template_id="database-secret", template=secret)

    with pytest.raises(SystemPromptValidationError) as caught:
        SystemPromptValidator().require(template)

    assert secret not in str(caught.value)
    assert secret not in caught.value.result.model_dump_json()


def test_detects_partial_system_prompt_reproduction():
    detector = SystemPromptLeakageDetector()
    reference = SystemPromptReference(prompt_id="support-v1", content=SYSTEM_PROMPT)

    result = detector.detect(
        "The hidden policy says: Answer concisely using verified public documentation.",
        [reference],
    )

    assert result.is_blocked
    assert SystemPromptLeakageCode.VERBATIM_FRAGMENT in _codes(result)


def test_detects_base64_encoded_system_prompt_reproduction():
    detector = SystemPromptLeakageDetector()
    reference = SystemPromptReference(prompt_id="support-v1", content=SYSTEM_PROMPT)
    encoded = base64.b64encode(SYSTEM_PROMPT.encode()).decode()

    result = detector.detect(encoded, [reference])

    assert SystemPromptLeakageCode.ENCODED_FRAGMENT in _codes(result)


def test_detects_structured_echo_without_copying_output():
    leaked_output = "Here is my complete system prompt: confidential material follows"

    result = SystemPromptLeakageDetector().detect(leaked_output, [])

    assert SystemPromptLeakageCode.STRUCTURED_ECHO in _codes(result)
    assert leaked_output not in result.model_dump_json()


def test_allows_unrelated_generated_output():
    result = SystemPromptLeakageDetector().detect(
        "Your invoice is available from the billing page.",
        [SystemPromptReference(prompt_id="support-v1", content=SYSTEM_PROMPT)],
    )

    assert result.is_safe


def test_prompt_reference_is_not_serializable_or_repr_visible():
    reference = SystemPromptReference(prompt_id="support-v1", content=SYSTEM_PROMPT)

    assert SYSTEM_PROMPT not in repr(reference)
    assert "content" not in reference.model_dump()
    assert SYSTEM_PROMPT not in reference.model_dump_json()


def test_require_safe_raises_content_free_leakage_error():
    reference = SystemPromptReference(prompt_id="support-v1", content=SYSTEM_PROMPT)

    with pytest.raises(SystemPromptLeakageError) as caught:
        SystemPromptLeakageDetector().require_safe(SYSTEM_PROMPT, [reference])

    assert SYSTEM_PROMPT not in str(caught.value)
    assert SYSTEM_PROMPT not in caught.value.result.model_dump_json()


def test_leakage_detector_fails_closed_when_output_exceeds_scan_limit():
    detector = SystemPromptLeakageDetector(SystemPromptLeakagePolicy(max_output_chars=20))

    result = detector.detect("A" * 21, [])

    assert SystemPromptLeakageCode.OUTPUT_TOO_LARGE in _codes(result)


def test_leakage_detector_fails_closed_when_reference_exceeds_scan_limit():
    detector = SystemPromptLeakageDetector(SystemPromptLeakagePolicy(max_prompt_chars=20))
    reference = SystemPromptReference(prompt_id="large", content="A" * 21)

    result = detector.detect("Unrelated model output", [reference])

    assert SystemPromptLeakageCode.REFERENCE_TOO_LARGE in _codes(result)


def test_policy_can_bound_rendered_prompt_size():
    validator = SystemPromptValidator(SystemPromptPolicy(max_prompt_chars=20))
    template = SystemPromptTemplate(
        template_id="bounded",
        template="You are {{description}}.",
        variables=(
            SystemPromptVariable(
                name="description",
                value="a very long public assistant description",
                data_class=SystemPromptDataClass.PUBLIC,
            ),
        ),
    )

    result = validator.validate(template)

    assert SystemPromptValidationCode.PROMPT_TOO_LARGE in _codes(result)
