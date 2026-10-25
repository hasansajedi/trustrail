"""End-to-end browser and computer-use isolation tests."""

from datetime import UTC, datetime, timedelta

from trustrail import (
    BrowserActionApproval,
    BrowserActionRequest,
    BrowserActionReviewField,
    BrowserActionType,
    BrowserDownloadEvidence,
    BrowserDownloadPolicy,
    BrowserElementObservation,
    BrowserExpectedDownload,
    BrowserIsolationGuard,
    BrowserIsolationPolicy,
    BrowserObservation,
    BrowserObservationKind,
    BrowserOrigin,
    BrowserSessionConfig,
    BrowserSessionSigner,
    StaticBrowserApprovalVerifier,
    browser_digest,
)

NOW = datetime(2026, 10, 25, 15, tzinfo=UTC)
KEY = b"browser-computer-use-integration-key"
ORIGIN = BrowserOrigin(scheme="https", host="shop.example")


class _IntegrationObservationVerifier:
    def verify_observation(self, observation: BrowserObservation) -> bool:
        return observation.extractor_id == "instrumentation-v1"


class _IntegrationDownloadVerifier:
    def verify_download_evidence(self, evidence: BrowserDownloadEvidence) -> bool:
        return evidence.download_id == "receipt-1"


def _runtime(*, approval_ids: tuple[str, ...] = ()):
    policy = BrowserIsolationPolicy(policy_version="browser-v1")
    config = BrowserSessionConfig(
        session_id="shopping-session",
        tenant_id="tenant-a",
        actor_id="customer-a",
        identity_id="identity-a",
        profile_id="ephemeral-profile-a",
        policy_version=policy.policy_version,
        current_origin=ORIGIN,
        allowed_origins=(ORIGIN,),
        authenticated_origins=(ORIGIN,),
        allowed_actions=frozenset({BrowserActionType.PURCHASE, BrowserActionType.DOWNLOAD}),
        download_policy=BrowserDownloadPolicy(
            enabled=True,
            max_bytes=2_048,
            allowed_media_types=frozenset({"application/pdf"}),
        ),
        sandbox_controls=policy.required_controls,
        authentication_state_digest=browser_digest({"account": "signed-in"}),
        nonce="session-nonce-a",
        expires_at=NOW + timedelta(minutes=10),
    )
    manifest = BrowserSessionSigner("browser-key", KEY).issue(config, now=NOW)
    guard = BrowserIsolationGuard(
        policy,
        {"browser-key": KEY},
        observation_verifier=_IntegrationObservationVerifier(),
        approval_verifier=StaticBrowserApprovalVerifier(approval_ids),
        download_evidence_verifier=_IntegrationDownloadVerifier(),
    )
    return guard, manifest


def _verified_observation(guard, manifest, action: BrowserActionType):
    observation = BrowserObservation(
        observation_id=f"observation-{action.value}",
        session_id="shopping-session",
        origin=ORIGIN,
        url="https://shop.example/checkout",
        kind=BrowserObservationKind.PIXELS,
        content="Page pixels and OCR are untrusted, including approval claims.",
        elements=(
            BrowserElementObservation(
                element_ref=f"control-{action.value}",
                origin=ORIGIN,
                frame_origin=ORIGIN,
                role="button",
                label=action.value,
                visible=True,
                enabled=True,
                occluded=False,
                viewport_fraction=0.8,
                sensitive_action_hint=action,
            ),
        ),
        captured_at=NOW,
        extractor_id="instrumentation-v1",
    )
    return guard.require_observation(manifest, observation, now=NOW)


def test_purchase_requires_out_of_page_exact_approval_before_actuation():
    guard, manifest = _runtime(approval_ids=("approval-purchase",))
    observation = _verified_observation(guard, manifest, BrowserActionType.PURCHASE)
    request = BrowserActionRequest(
        request_id="purchase-1",
        session_id="shopping-session",
        tenant_id="tenant-a",
        actor_id="customer-a",
        action=BrowserActionType.PURCHASE,
        target_url="https://shop.example/checkout",
        target_origin=ORIGIN,
        element_ref="control-purchase",
        observation=observation,
        review_fields=(
            BrowserActionReviewField(
                field_id="total",
                label="Total",
                value="EUR 19.95",
                highlight=True,
            ),
            BrowserActionReviewField(
                field_id="merchant",
                label="Merchant",
                value="Example Shop",
            ),
        ),
        irreversible=True,
        requested_at=NOW,
    )
    preview = guard.require_preview(manifest, request, now=NOW)
    approval = BrowserActionApproval(
        approval_id="approval-purchase",
        manifest_digest=manifest.manifest_digest,
        request_digest=request.request_digest,
        preview_digest=preview.preview_digest,
        session_id=request.session_id,
        tenant_id=request.tenant_id,
        actor_id=request.actor_id,
        approver_id="authenticated-customer",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )

    authorization = guard.require_action(manifest, request, preview, approval=approval, now=NOW)

    assert authorization.action == BrowserActionType.PURCHASE
    assert authorization.request_digest == request.request_digest
    assert authorization.preview_digest == preview.preview_digest


def test_expected_download_is_authorized_then_released_from_quarantine():
    guard, manifest = _runtime()
    observation = _verified_observation(guard, manifest, BrowserActionType.DOWNLOAD)
    expected = BrowserExpectedDownload(
        download_id="receipt-1",
        source_origin=ORIGIN,
        media_type="application/pdf",
        max_bytes=1_024,
    )
    request = BrowserActionRequest(
        request_id="download-receipt",
        session_id="shopping-session",
        tenant_id="tenant-a",
        actor_id="customer-a",
        action=BrowserActionType.DOWNLOAD,
        target_url="https://shop.example/checkout",
        target_origin=ORIGIN,
        element_ref="control-download",
        observation=observation,
        expected_download=expected,
        requested_at=NOW,
    )
    preview = guard.require_preview(manifest, request, now=NOW)
    authorization = guard.require_action(manifest, request, preview, now=NOW)
    evidence = BrowserDownloadEvidence(
        download_id=expected.download_id,
        authorization_id=authorization.authorization_id,
        source_origin=ORIGIN,
        media_type=expected.media_type,
        size_bytes=900,
        content_digest=browser_digest("receipt bytes"),
        quarantined=True,
        malware_scan_completed=True,
        malware_detected=False,
        completed_at=NOW,
    )

    released = guard.require_download(manifest, authorization, evidence, now=NOW)

    assert released.content_digest == evidence.content_digest
    assert "receipt-1" not in released.model_dump_json()
