"""JSON-driven browser and computer-use bypass regression tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    BrowserActionRequest,
    BrowserActionReviewField,
    BrowserActionType,
    BrowserDataFlow,
    BrowserDataSource,
    BrowserElementObservation,
    BrowserIsolationCode,
    BrowserIsolationGuard,
    BrowserIsolationPolicy,
    BrowserObservation,
    BrowserObservationKind,
    BrowserOrigin,
    BrowserSessionConfig,
    BrowserSessionSigner,
    browser_digest,
)

NOW = datetime(2026, 10, 25, 16, tzinfo=UTC)
KEY = b"browser-isolation-security-key-32b"
APP = BrowserOrigin(scheme="https", host="app.example")
ATTACKER = BrowserOrigin(scheme="https", host="attacker.example")
CORPUS = json.loads(
    (Path(__file__).parents[1] / "security_corpus" / "browser_isolation.json").read_text()
)


class _SecurityObservationVerifier:
    def verify_observation(self, observation: BrowserObservation) -> bool:
        return observation.extractor_id == "security-instrumentation"


def _runtime(*, origins: tuple[BrowserOrigin, ...] = (APP, ATTACKER)):
    policy = BrowserIsolationPolicy(policy_version="browser-security-v1")
    config = BrowserSessionConfig(
        session_id="security-session",
        tenant_id="tenant-a",
        actor_id="actor-a",
        identity_id="identity-a",
        profile_id="profile-a",
        policy_version=policy.policy_version,
        current_origin=APP,
        allowed_origins=origins,
        allowed_actions=frozenset(BrowserActionType),
        sandbox_controls=policy.required_controls,
        authentication_state_digest=browser_digest({"authenticated": False}),
        nonce="security-nonce",
        expires_at=NOW + timedelta(minutes=5),
    )
    manifest = BrowserSessionSigner("security-key", KEY).issue(config, now=NOW)
    return (
        BrowserIsolationGuard(
            policy,
            {"security-key": KEY},
            observation_verifier=_SecurityObservationVerifier(),
        ),
        manifest,
    )


def _observation(
    payload: str,
    *,
    visible: bool = True,
    occluded: bool = False,
    hint: BrowserActionType | None = None,
    captured_at: datetime = NOW,
) -> BrowserObservation:
    return BrowserObservation(
        observation_id="observation-attack",
        session_id="security-session",
        origin=APP,
        url="https://app.example/",
        kind=BrowserObservationKind.PIXELS,
        content=payload,
        elements=(
            BrowserElementObservation(
                element_ref="target",
                origin=APP,
                frame_origin=APP,
                role="button",
                label=payload,
                visible=visible,
                enabled=True,
                occluded=occluded,
                viewport_fraction=1.0 if visible else 0.0,
                sensitive_action_hint=hint,
            ),
        ),
        captured_at=captured_at,
        extractor_id="security-instrumentation",
    )


@pytest.mark.parametrize("case", CORPUS, ids=[case["name"] for case in CORPUS])
def test_browser_isolation_bypass_corpus_fails_closed(case: dict[str, str]):
    scenario = case["scenario"]
    private = BrowserOrigin(scheme="http", host="127.0.0.1", port=8080)
    origins = (APP, ATTACKER, private) if scenario == "private_origin" else (APP, ATTACKER)
    guard, manifest = _runtime(origins=origins)
    action = BrowserActionType.NAVIGATE
    target_origin = APP
    target_url = "https://app.example/"
    extra: dict[str, object] = {}

    if scenario == "target_url":
        target_url = case["payload"]
    elif scenario == "private_origin":
        target_origin = private
        target_url = case["payload"]
    elif scenario in {"page_approval", "hidden", "occluded", "classification"}:
        action = (
            BrowserActionType.PURCHASE if scenario != "classification" else BrowserActionType.CLICK
        )
        observation = _observation(
            case["payload"],
            visible=scenario != "hidden",
            occluded=scenario == "occluded",
            hint=(
                BrowserActionType.PURCHASE
                if scenario in {"page_approval", "hidden", "occluded", "classification"}
                else None
            ),
        )
        extra.update(
            element_ref="target",
            observation=guard.require_observation(manifest, observation, now=NOW),
        )
        if action == BrowserActionType.PURCHASE:
            extra["review_fields"] = (
                BrowserActionReviewField(
                    field_id="total",
                    label="Total",
                    value="EUR 999.00",
                    highlight=True,
                ),
            )
    elif scenario == "cross_origin":
        target_origin = ATTACKER
        target_url = "https://attacker.example/collect"
        extra["data_flows"] = (
            BrowserDataFlow(
                source=BrowserDataSource.PAGE_OBSERVATION,
                source_origin=APP,
                destination_origin=ATTACKER,
                content_digest=browser_digest(case["payload"]),
                contains_sensitive_data=True,
            ),
        )
    elif scenario == "secret_action":
        action = BrowserActionType.COOKIE_READ
    elif scenario == "host_secret":
        extra["data_flows"] = (
            BrowserDataFlow(
                source=BrowserDataSource.HOST_SECRET,
                destination_origin=APP,
                content_digest=browser_digest(case["payload"]),
                contains_sensitive_data=True,
            ),
        )
    elif scenario == "upload":
        action = BrowserActionType.UPLOAD
        observation = _observation(case["payload"], hint=BrowserActionType.UPLOAD)
        extra.update(
            element_ref="target",
            observation=guard.require_observation(manifest, observation, now=NOW),
            file_ref="missing-file-grant",
        )
    elif scenario == "clipboard":
        action = BrowserActionType.CLIPBOARD_READ
    elif scenario == "stale":
        result = guard.inspect_observation(
            manifest,
            _observation(case["payload"], captured_at=NOW - timedelta(minutes=1)),
            now=NOW,
        )
        assert BrowserIsolationCode(case["expected"]) in {
            finding.code for finding in result.findings
        }
        assert case["payload"] not in result.model_dump_json()
        return

    request = BrowserActionRequest(
        request_id="attack-request",
        session_id="security-session",
        tenant_id="tenant-a",
        actor_id="actor-a",
        action=action,
        target_url=target_url,
        target_origin=target_origin,
        requested_at=NOW,
        **extra,
    )
    result = guard.preview_action(manifest, request, now=NOW)

    assert BrowserIsolationCode(case["expected"]) in {finding.code for finding in result.findings}
    assert case["payload"] not in result.model_dump_json()
