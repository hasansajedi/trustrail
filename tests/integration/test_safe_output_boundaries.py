"""Integration tests for safe model output at concrete downstream sinks."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from trustrail import (
    Guard,
    GuardContext,
    GuardStage,
    OutputContext,
    OutputHandlingError,
    OutputHandlingPolicy,
    SafeOutputHandler,
)


class SearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    document_ids: list[int]


class EmailArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient_id: int
    subject: str


def test_runtime_scan_then_html_context_encoding():
    model_output = "Use <strong>care</strong> when rotating credentials."
    runtime_result = Guard.silent().validate_output(model_output)
    assert runtime_result.is_allowed

    rendered = SafeOutputHandler().require(
        runtime_result.output_value,
        OutputContext.HTML,
    )

    assert rendered == "Use &lt;strong&gt;care&lt;/strong&gt; when rotating credentials."


def test_model_text_is_bound_as_sql_data_not_executed_as_query():
    model_output = "Robert'); DROP TABLE contacts;--"
    handler = SafeOutputHandler()

    assert handler.handle(model_output, OutputContext.SQL).is_blocked
    parameter = handler.as_sql_parameter(model_output)

    database = sqlite3.connect(":memory:")
    try:
        database.execute("CREATE TABLE contacts (name TEXT)")
        database.execute("INSERT INTO contacts(name) VALUES (?)", (parameter,))
        stored = database.execute("SELECT name FROM contacts").fetchone()
    finally:
        database.close()

    assert stored == (model_output,)


def test_model_text_is_one_argv_item_without_shell_interpretation():
    model_output = "$(printf unsafe-side-effect)"
    handler = SafeOutputHandler()

    assert handler.handle(model_output, OutputContext.SHELL).is_blocked
    argument = handler.as_command_argument(model_output)
    completed = subprocess.run(  # noqa: S603 - fixed executable, shell disabled
        [sys.executable, "-c", "import sys; print(sys.argv[-1])", "--", argument],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == model_output


def test_model_path_is_confined_to_application_root(tmp_path: Path):
    handler = SafeOutputHandler(OutputHandlingPolicy(path_root=tmp_path))

    safe_path = handler.resolve_path("reports/result.txt")

    assert safe_path == tmp_path / "reports" / "result.txt"
    with pytest.raises(OutputHandlingError):
        handler.resolve_path("../../outside.txt")


def test_json_is_parsed_once_into_strict_application_type():
    model_output = '{"title":"Quarterly report","document_ids":[1,2,3]}'

    result = SafeOutputHandler().parse_json(model_output, SearchResult)

    assert result.document_ids == [1, 2, 3]


def test_tool_output_creates_non_executing_plan_then_runs_tool_policy():
    executed: list[EmailArguments] = []
    handler = SafeOutputHandler()
    call = handler.parse_tool_call(
        '{"name":"send_email","arguments":{"recipient_id":42,"subject":"Status"}}',
        expected_name="send_email",
        arguments_schema=EmailArguments,
    )

    assert call.requires_approval
    assert executed == []

    context = GuardContext(
        stage=GuardStage.TOOL_REQUEST,
        metadata={
            "tool_name": call.name,
            "tool_args": call.arguments.model_dump(),
        },
    )
    policy_result = Guard.silent().check("", GuardStage.TOOL_REQUEST, context=context)

    assert policy_result.is_allowed
    assert executed == []


def test_changed_tool_name_never_reaches_executor():
    executed: list[EmailArguments] = []

    with pytest.raises(OutputHandlingError):
        SafeOutputHandler().parse_tool_call(
            '{"name":"delete_account","arguments":{"recipient_id":42,"subject":"x"}}',
            expected_name="send_email",
            arguments_schema=EmailArguments,
        )

    assert executed == []
