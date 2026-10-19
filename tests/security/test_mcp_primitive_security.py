"""Bypass-oriented security corpus for MCP context primitives."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustrail import (
    MCPCompletionDefinition,
    MCPCompletionMetadata,
    MCPIcon,
    MCPPrimitiveAnnotations,
    MCPPrimitiveCode,
    MCPPrimitiveGuard,
    MCPPromptArgument,
    MCPPromptDefinition,
    MCPResourceContent,
    MCPResourceDefinition,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "mcp_primitives.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
KEY = b"mcp-primitive-security-corpus-key-32-bytes"


def _resource(**updates: object) -> MCPResourceDefinition:
    value = MCPResourceDefinition(
        server_id="trusted.example",
        name="record",
        description="A reviewed public record.",
        provenance_id="trusted-origin",
        uri="https://trusted.example/resource",
        mimeType="text/plain",
    )
    return value.model_copy(update=updates)


def _definition_result(case: dict[str, str]):
    surface = case["surface"]
    resource = _resource()
    if surface == "resource_description":
        resource = resource.model_copy(update={"description": case["payload"]})
    elif surface == "annotation_key":
        resource = resource.model_copy(
            update={"annotations": MCPPrimitiveAnnotations(metadata={case["payload"]: "value"})}
        )
    elif surface == "icon_uri":
        resource = resource.model_copy(update={"icons": (MCPIcon(src=case["payload"]),)})
    elif surface == "resource_uri":
        resource = resource.model_copy(update={"uri": case["payload"]})
    elif surface == "prompt_argument":
        prompt = MCPPromptDefinition(
            server_id="trusted.example",
            name="review",
            description="Review one public record.",
            provenance_id="trusted-origin",
            arguments=(MCPPromptArgument(name="record", description=case["payload"]),),
        )
        return MCPPrimitiveGuard(KEY).inspect((prompt,))
    return MCPPrimitiveGuard(KEY).inspect((resource,))


def _live_result(case: dict[str, str]):
    guard = MCPPrimitiveGuard(KEY)
    if case["surface"] == "completion_value":
        definition = MCPCompletionDefinition(
            server_id="trusted.example",
            name="record-completion",
            description="Complete a reviewed record identifier.",
            provenance_id="trusted-origin",
            reference_kind="prompt",
            reference_name="review",
            argument_name="record",
        )
        prompt = MCPPromptDefinition(
            server_id="trusted.example",
            name="review",
            description="Review one public record.",
            provenance_id="trusted-origin",
            arguments=(
                MCPPromptArgument(name="record", description="The selected record identifier."),
            ),
        )
        definitions = (prompt, definition)
        discovery = guard.require_discovery(definitions)
        approval = guard.require_approval(definitions, discovery, approved_by="reviewer")
        metadata = MCPCompletionMetadata(
            server_id=definition.server_id,
            reference_kind=definition.reference_kind,
            reference_name=definition.reference_name,
            argument_name=definition.argument_name,
            values=(case["payload"],),
            provenance_id=definition.provenance_id,
        )
        return guard.validate_completion(definition, metadata, approval)
    definition = _resource()
    discovery = guard.require_discovery((definition,))
    approval = guard.require_approval((definition,), discovery, approved_by="reviewer")
    content = MCPResourceContent(
        server_id=definition.server_id,
        uri=definition.uri,
        mimeType=definition.mime_type,
        data=case["payload"].encode(),
        provenance_id=definition.provenance_id,
    )
    return guard.validate_resource_content(definition, content, approval)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_mcp_primitive_attack_corpus_is_rejected_without_echoing_payload(case: dict[str, str]):
    result = (
        _live_result(case)
        if case["surface"] in {"completion_value", "resource_bytes"}
        else _definition_result(case)
    )

    assert MCPPrimitiveCode(case["expected_code"]) in {finding.code for finding in result.findings}
    assert case["payload"] not in result.model_dump_json()
