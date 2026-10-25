"""Security-corpus tests for distributed jailbreak campaigns."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict

import pytest

from trustrail import (
    CampaignAction,
    CampaignSignalKind,
    JailbreakCampaignDetector,
    JailbreakCampaignEvent,
    JailbreakCampaignPolicy,
    MemoryCampaignStateStore,
)


class CampaignCase(TypedDict):
    name: str
    turns: list[str]
    expected_signal: str | None
    expected_action: str


CORPUS: list[CampaignCase] = json.loads(
    (Path(__file__).parents[1] / "security_corpus" / "jailbreak_campaigns.json").read_text()
)


@pytest.mark.parametrize("case", CORPUS, ids=[case["name"] for case in CORPUS])
def test_distributed_campaign_corpus(case: CampaignCase) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryCampaignStateStore()
    detector = JailbreakCampaignDetector(
        JailbreakCampaignPolicy(
            policy_version="security-corpus-v1",
            example_markers=2,
            boundary_probes=2,
            policy_erosion_markers=2,
            retry_markers=2,
            encoding_kinds=3,
        ),
        b"campaign-security-corpus-key-32bytes",
        state_store=store,
    )

    result = None
    for sequence, content in enumerate(case["turns"]):
        result = detector.assess(
            JailbreakCampaignEvent(
                event_id=f"corpus-{sequence}",
                tenant_id="tenant-security",
                user_id="user-security",
                session_id="session-security",
                sequence=sequence,
                occurred_at=now + timedelta(seconds=sequence),
                content=content,
            ),
            now=now + timedelta(seconds=sequence),
        )

    assert result is not None
    assert result.action == CampaignAction(case["expected_action"])
    kinds = {signal.kind for signal in result.signals}
    if case["expected_signal"] is None:
        assert not kinds
    else:
        assert CampaignSignalKind(case["expected_signal"]) in kinds

    # Neither decisions nor persisted state may contain raw prompts or identifiers.
    decision_json = result.model_dump_json()
    state = store.read(result.scope_ref, now=now + timedelta(seconds=len(case["turns"])))
    assert state is not None
    state_json = state.model_dump_json()
    for content in case["turns"]:
        assert content not in decision_json
        assert content not in state_json
    for identifier in ("tenant-security", "user-security", "session-security"):
        assert identifier not in decision_json
        assert identifier not in state_json
