# Strict structured model output

JSON mode and function calling constrain syntax; they do not establish that a
complete response has the application-required meaning. Duplicate keys,
coercion, unknown fields, recursive values, ambiguous unions, or a changed value
between approval and execution can still bypass downstream policy.

`StructuredOutputValidator` provides the OWASP AISVS C7 boundary:

1. the application owns a versioned Pydantic schema;
2. the schema must close every object, bound every array, and discriminate every
   non-null union;
3. one complete JSON value is parsed and strictly validated without coercion;
4. the schema identity and canonical object digest are bound to an exact
   downstream use and application context; and
5. the value is released only after that binding is rechecked.

## Define a strict application schema

```python
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from trustrail import (
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


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    citations: list[str] = Field(max_length=10)
    next_step: Annotated[
        SearchStep | AnswerStep,
        Field(discriminator="kind"),
    ]


validator = StructuredOutputValidator(
    StructuredOutputContract(
        schema_id="support.plan",
        schema_version="3",
        model=Plan,
        allowed_uses=frozenset(
            {StructuredOutputUse.APPROVAL, StructuredOutputUse.EXECUTION}
        ),
    )
)
```

Construction fails if an object omits `extra="forbid"`, an array omits
`max_length`, or a non-null union has no discriminator with literal tags. Plain
`dict` fields are open objects and are rejected; model their keys explicitly.
Nullable fields are permitted, but the response must include the value when a
default would otherwise change the parsed object.

## Validate, bind, and use

```python
validated = validator.validate_json(provider_response)

approval_binding = validator.bind(
    validated,
    use=StructuredOutputUse.APPROVAL,
    context_id="approval:workflow-17:step-2",
)
approved = validator.authorize(
    validated,
    approval_binding,
    use=StructuredOutputUse.APPROVAL,
    context_id="approval:workflow-17:step-2",
)

# Pass approved.value to this approval boundary only.
show_approval_preview(approved.value)
```

Create a separate binding for execution. Reusing an approval binding for
execution, changing the context, switching the object, changing the schema or
policy, and mutating a nested model value all fail closed. Supported uses are
`AUTHORIZATION`, `APPROVAL`, `DISPLAY`, `PERSISTENCE`, `RENDERING`, and
`EXECUTION`.

The `context_id` is application-owned and should identify the exact request,
tenant, workflow step, record, renderer, or execution. Do not accept it from the
model. Audit events store only a one-way context reference, schema metadata,
object digest, outcome, and attempt number.

`validate_typed()` applies the same serialize, parse, strict-validation, and
agreement checks to an existing instance. It catches unsafe instances created
with Pydantic's `model_construct()` or changed nested containers.

## Bounded repair

A repair is a new complete response, not a patch and not a partial parse:

```python
from trustrail import StructuredOutputError

repair = validator.new_repair_session(max_attempts=2)
try:
    validated = repair.validate_json(first_complete_response)
except StructuredOutputError:
    # Ask the provider for a complete replacement. Never use fields from the
    # failed response in a UI, database, approval, or tool call.
    validated = repair.validate_json(second_complete_response)
```

The configured maximum cannot be exceeded. A successful or exhausted session
closes permanently, and exceptions contain a content-free decision rather than
raw or partially parsed output.

## Parser and policy limits

`StructuredOutputPolicy` controls independent input and runtime limits:

```python
from trustrail import StructuredOutputPolicy

policy = StructuredOutputPolicy(
    max_input_bytes=250_000,
    max_input_chars=250_000,
    max_depth=16,
    max_nodes=5_000,
    max_array_items=100,
    max_object_properties=100,
    max_number_chars=64,
    max_repair_attempts=2,
)
```

The parser rejects invalid UTF-8, byte-order marks, unpaired surrogates,
non-NFC text, control characters, duplicate keys, non-finite or oversized
numbers, trailing values, excessive structure, and undeclared fields. Pydantic
validation runs with `strict=True`; the parsed JSON and validated model must
have identical canonical JSON, preventing validators, defaults, or coercion
from silently changing the meaning.

## Combining output controls

This API validates structure and lifecycle identity. It does not replace
content checks or destination encoding:

- scan generated text and string fields with `Guard` where applicable;
- pass display strings through `SafeOutputHandler` for the actual HTML,
  Markdown, URL, or path context;
- apply service-side authorization, tenant checks, approval, rate limits,
  credential scoping, and tool capability enforcement;
- use prepared statements and fixed executables; and
- sandbox generated code and high-risk tools.

The older `SafeOutputHandler.parse_json()` is a compatibility parser. Use the
structured-output lifecycle whenever a value will be displayed, persisted,
approved, authorized, rendered, or executed.

## Assumptions, limitations, and residual risk

- Schema IDs, versions, policies, context IDs, and allowed uses are trusted
  application configuration. A model must not select them.
- Object and binding digests detect substitution and confused-deputy mistakes;
  they are not signatures, capabilities, replay protection, or proof that the
  model's claims are true. Use authenticated approval and authorization systems.
- Python code in the same process can intentionally bypass an API or inspect
  memory. Isolate untrusted code and protect process integrity.
- Pydantic validators should be deterministic and side-effect free. The exact
  canonical agreement check rejects transformations; business invariants still
  need explicit validators and tests.
- Limits reduce parser denial-of-service risk but do not replace request-size,
  CPU, memory, concurrency, timeout, and provider-budget enforcement.
- The validated object remains sensitive application data in memory. Audit
  records are content-free, but application logging and exception handling must
  also avoid raw responses.
- Schema validation proves shape and declared invariants, not factual accuracy,
  safe rendering, authorization, or harmless tool effects.

See the runnable
[`structured_output.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/structured_output.py)
example and the [OWASP mapping](../owasp-mapping.md).
