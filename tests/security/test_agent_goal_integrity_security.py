"""Bypass-oriented security corpus for OWASP ASI01 agent goal hijacking."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    GoalApprovalContext,
    GoalConstraint,
    GoalConstraintKind,
    GoalInputSource,
    GoalIntegrityGuard,
    GoalManifest,
    GoalOwner,
    GoalPrincipal,
    ProposedPlanStep,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "agent_goal_hijacking.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _manifest() -> GoalManifest:
    return GoalManifest.create(
        manifest_id="security-goal",
        execution_id="execution-a",
        session_id="session-a",
        owner=GoalOwner(owner_id="user-a", tenant_id="tenant-a"),
        primary_actor_id="primary-agent",
        objective="Summarize the document explicitly selected by the user",
        constraints=(
            GoalConstraint(
                constraint_id="selected-document-only",
                kind=GoalConstraintKind.BOUNDARY,
                description="Only read the selected document",
            ),
        ),
        allowed_action_ids=frozenset({"documents.read"}),
        allowed_delegate_ids=frozenset({"approved-delegate"}),
        approval_context=GoalApprovalContext(
            context_id="security-context",
            authorized_by="user-a",
            allowed_approver_ids=frozenset({"reviewer-a"}),
            issued_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(hours=1),
        ),
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
    )


def _step(
    manifest: GoalManifest,
    *,
    step_id: str = "step-1",
    sequence: int = 1,
    description: str = "Read the selected document",
    **updates: object,
) -> ProposedPlanStep:
    values: dict[str, object] = {
        "step_id": step_id,
        "sequence": sequence,
        "execution_id": manifest.execution_id,
        "session_id": manifest.session_id,
        "principal": GoalPrincipal(
            actor_id="primary-agent",
            owner_id="user-a",
            tenant_id="tenant-a",
        ),
        "source": GoalInputSource.RETRIEVED_CONTENT,
        "action_id": "documents.read",
        "description": description,
        "expected_manifest_digest": manifest.manifest_digest,
        "constraint_ids": manifest.constraint_ids,
    }
    values.update(updates)
    return ProposedPlanStep(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_goal_hijacking_bypass_corpus(case: dict[str, str]) -> None:
    manifest = _manifest()
    guard = GoalIntegrityGuard()
    state = guard.new_state(manifest)
    kind = case["kind"]
    updates: dict[str, object] = {}

    if kind == "description":
        step = _step(manifest, description=case["payload"])
    elif kind == "split":
        first = _step(manifest, description=case["first"])
        assert guard.validate_step(manifest, first, state, now=NOW).is_authorized
        step = _step(
            manifest,
            step_id="step-2",
            sequence=2,
            description=case["payload"],
        )
    else:
        mutation = case["mutation"]
        if mutation == "session":
            updates["session_id"] = "session-b"
        elif mutation == "manifest_digest":
            updates["expected_manifest_digest"] = "0" * 64
        elif mutation == "constraints":
            updates["constraint_ids"] = frozenset()
        elif mutation == "action":
            updates["action_id"] = "admin.export"
        elif mutation == "delegate":
            updates["delegated_to"] = "attacker-agent"
        step = _step(manifest, **updates)

    result = guard.validate_step(manifest, step, state, now=NOW)

    assert result.is_blocked
    assert case["expected_code"] in {finding.code.value for finding in result.findings}
