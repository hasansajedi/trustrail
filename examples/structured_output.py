"""Validate and bind a complete model response before a downstream boundary."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from trustrail import (
    MemoryStructuredOutputAuditSink,
    StructuredOutputContract,
    StructuredOutputUse,
    StructuredOutputValidator,
)


class SearchStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["search"]
    query: str


class AnswerStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["answer"]
    text: str


class SupportPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    tags: list[str] = Field(max_length=5)
    next_step: Annotated[SearchStep | AnswerStep, Field(discriminator="kind")]


audit = MemoryStructuredOutputAuditSink()
validator = StructuredOutputValidator(
    StructuredOutputContract(
        schema_id="support.plan",
        schema_version="1",
        model=SupportPlan,
        allowed_uses=frozenset({StructuredOutputUse.APPROVAL, StructuredOutputUse.PERSISTENCE}),
    ),
    audit_sink=audit,
)

# Treat the provider response as untrusted. The complete value is parsed once,
# rejects coercion/extra keys, and must exactly agree with the Pydantic model.
model_output = (
    '{"case_id":"case-42","tags":["billing"],'
    '"next_step":{"kind":"answer","text":"The credit is ready."}}'
)
validated = validator.validate_json(model_output)

# Bind the exact schema and object digests to one application-owned operation.
binding = validator.bind(
    validated,
    use=StructuredOutputUse.PERSISTENCE,
    context_id="support-cases:case-42:revision-3",
)
authorized = validator.authorize(
    validated,
    binding,
    use=StructuredOutputUse.PERSISTENCE,
    context_id="support-cases:case-42:revision-3",
)

# Only the authorized wrapper releases a defensive value copy to this boundary.
print(authorized.value.model_dump(mode="json"))
print([event.code.value for event in audit.events])
