"""Bypass-oriented security corpus for OWASP LLM06:2025."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    GuardAction,
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationPolicy,
    ToolAuthorizationRequest,
    ToolAuthorizer,
    ToolCapability,
    ToolEffect,
    ToolIntent,
    ToolPrincipal,
    ToolResource,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "excessive_agency.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 8, 26, tzinfo=UTC)


def _authorizer() -> ToolAuthorizer:
    capability = ToolCapability(
        name="vault.read_note",
        version="sha256:7a91",
        effects=frozenset({ToolEffect.READ}),
        required_scopes=frozenset({"notes:read"}),
        arguments={
            "note_id": ToolArgumentConstraint(
                kind=ToolArgumentKind.STRING,
                pattern=r"note-[a-z0-9]{8}",
            )
        },
        required_arguments=frozenset({"note_id"}),
        resource_id_argument="note_id",
        require_owned_resource=True,
        allow_autonomous=True,
    )
    return ToolAuthorizer(ToolAuthorizationPolicy(capabilities=(capability,)))


def _request() -> ToolAuthorizationRequest:
    return ToolAuthorizationRequest(
        tool_name="vault.read_note",
        tool_version="sha256:7a91",
        arguments={"note_id": "note-ab12cd34"},
        principal=ToolPrincipal(
            actor_id="notes-agent",
            subject_id="user-a",
            tenant_id="tenant-a",
            scopes=frozenset({"notes:read"}),
        ),
        intent=ToolIntent(
            intent_id="intent-read-note",
            subject_id="user-a",
            tenant_id="tenant-a",
            allowed_tools=frozenset({"vault.read_note"}),
            purpose="Read the note explicitly selected by the user",
            expires_at=NOW + timedelta(minutes=5),
        ),
        resource=ToolResource(
            resource_id="note-ab12cd34",
            owner_id="user-a",
            tenant_id="tenant-a",
        ),
        requested_scopes=frozenset(),
        session_id="security-session",
        chain_id="security-chain",
        operation_id="security-operation",
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_excessive_agency_bypass_corpus(case: dict[str, str]):
    request = _request()
    mutation = case["mutation"]
    if mutation == "tool_name":
        request = request.model_copy(update={"tool_name": "vault.read_note.evil"})
    elif mutation == "version":
        request = request.model_copy(update={"tool_version": "latest"})
    elif mutation == "argument":
        request = request.model_copy(
            update={"arguments": {"note_id": "note-ab12cd34", "role": "admin"}}
        )
    elif mutation == "owner":
        request = request.model_copy(
            update={"resource": request.resource.model_copy(update={"owner_id": "user-b"})}
        )
    elif mutation == "tenant":
        request = request.model_copy(
            update={"resource": request.resource.model_copy(update={"tenant_id": "tenant-b"})}
        )
    elif mutation == "intent":
        request = request.model_copy(
            update={
                "intent": request.intent.model_copy(
                    update={"allowed_tools": frozenset({"vault.list_notes"})}
                )
            }
        )
    elif mutation == "scope":
        request = request.model_copy(update={"requested_scopes": frozenset({"notes:delete"})})

    authorizer = _authorizer()
    result = authorizer.authorize(
        request,
        authorizer.new_budget("security-session"),
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert case["expected_code"] in {finding.code.value for finding in result.findings}
