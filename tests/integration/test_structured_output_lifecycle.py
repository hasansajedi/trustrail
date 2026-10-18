"""Integration tests for structured output across real application boundaries."""

from __future__ import annotations

import json
import sqlite3
from typing import Annotated, Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field

from trustrail import (
    StructuredOutputContract,
    StructuredOutputError,
    StructuredOutputUse,
    StructuredOutputValidator,
)


class StoreRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: str
    labels: list[str] = Field(max_length=5)


class ReadOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["read"]
    record_id: str


class NotifyOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["notify"]
    recipient_id: str
    message: str


class ToolPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operations: list[Annotated[ReadOperation | NotifyOperation, Field(discriminator="kind")]] = (
        Field(max_length=3)
    )


def test_persistence_boundary_consumes_only_context_bound_validated_value():
    validator = StructuredOutputValidator(
        StructuredOutputContract(
            schema_id="records.store",
            schema_version="1",
            model=StoreRecord,
            allowed_uses=frozenset({StructuredOutputUse.PERSISTENCE}),
        )
    )
    validated = validator.validate_json('{"record_id":"r-1","labels":["safe"]}')
    binding = validator.bind(
        validated,
        use=StructuredOutputUse.PERSISTENCE,
        context_id="database:records:r-1",
    )
    authorized = validator.authorize(
        validated,
        binding,
        use=StructuredOutputUse.PERSISTENCE,
        context_id="database:records:r-1",
    )

    database = sqlite3.connect(":memory:")
    try:
        database.execute("CREATE TABLE records (id TEXT PRIMARY KEY, payload TEXT)")
        database.execute(
            "INSERT INTO records(id, payload) VALUES (?, ?)",
            (
                authorized.value.record_id,
                json.dumps(authorized.value.model_dump(mode="json")),
            ),
        )
        stored = database.execute("SELECT payload FROM records WHERE id = ?", ("r-1",)).fetchone()
    finally:
        database.close()

    assert stored is not None
    assert json.loads(stored[0]) == {"record_id": "r-1", "labels": ["safe"]}
    with pytest.raises(StructuredOutputError):
        validator.authorize(
            validated,
            binding,
            use=StructuredOutputUse.PERSISTENCE,
            context_id="database:records:r-2",
        )


def test_tool_plan_requires_full_schema_validation_then_exact_execution_binding():
    executed: list[ReadOperation | NotifyOperation] = []
    validator = StructuredOutputValidator(
        StructuredOutputContract(
            schema_id="agent.tool-plan",
            schema_version="2",
            model=ToolPlan,
            allowed_uses=frozenset({StructuredOutputUse.APPROVAL, StructuredOutputUse.EXECUTION}),
        )
    )
    raw_plan = (
        '{"operations":[{"kind":"read","record_id":"r-1"},'
        '{"kind":"notify","recipient_id":"u-1","message":"Ready"}]}'
    )

    validated = validator.validate_json(raw_plan)
    approval = validator.bind(
        validated,
        use=StructuredOutputUse.APPROVAL,
        context_id="approval:workflow-7:step-2",
    )
    approved = validator.authorize(
        validated,
        approval,
        use=StructuredOutputUse.APPROVAL,
        context_id="approval:workflow-7:step-2",
    )
    assert len(approved.value.operations) == 2
    assert executed == []

    execution = validator.bind(
        validated,
        use=StructuredOutputUse.EXECUTION,
        context_id="execution:workflow-7:step-2",
    )
    executable = validator.authorize(
        validated,
        execution,
        use=StructuredOutputUse.EXECUTION,
        context_id="execution:workflow-7:step-2",
    )
    executed.extend(executable.value.operations)

    assert [operation.kind for operation in executed] == ["read", "notify"]


def test_repair_revalidates_a_complete_replacement_and_never_uses_invalid_plan():
    executed: list[ReadOperation | NotifyOperation] = []
    validator = StructuredOutputValidator(
        StructuredOutputContract(
            schema_id="agent.repaired-tool-plan",
            schema_version="1",
            model=ToolPlan,
            allowed_uses=frozenset({StructuredOutputUse.EXECUTION}),
        )
    )
    repair = validator.new_repair_session(max_attempts=2)

    with pytest.raises(StructuredOutputError):
        repair.validate_json('{"operations":[{"kind":"notify"}]}')
    assert executed == []

    validated = repair.validate_json('{"operations":[{"kind":"read","record_id":"r-9"}]}')
    binding = validator.bind(
        validated,
        use=StructuredOutputUse.EXECUTION,
        context_id="execution:workflow-9:step-1",
    )
    authorized = validator.authorize(
        validated,
        binding,
        use=StructuredOutputUse.EXECUTION,
        context_id="execution:workflow-9:step-1",
    )
    executed.extend(authorized.value.operations)

    assert executed == [ReadOperation(kind="read", record_id="r-9")]
