"""Fail-closed browser and computer-use isolation enforcement."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import threading
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast

from pydantic import JsonValue

from trustrail.exceptions import BrowserIsolationError
from trustrail.models.browser_isolation import (
    BrowserActionApproval,
    BrowserActionAuthorization,
    BrowserActionPreview,
    BrowserActionRequest,
    BrowserActionType,
    BrowserDataFlow,
    BrowserDataSource,
    BrowserDownloadEvidence,
    BrowserIsolationCode,
    BrowserIsolationFinding,
    BrowserIsolationPhase,
    BrowserIsolationPolicy,
    BrowserIsolationResult,
    BrowserObservation,
    BrowserOrigin,
    BrowserSessionConfig,
    BrowserSessionManifest,
    VerifiedBrowserDownload,
    VerifiedBrowserObservation,
    browser_digest,
    browser_manifest_signing_payload,
    browser_reference,
    canonical_browser_json,
)
from trustrail.models.enums import GuardAction, Severity

_SECRET_READ_ACTIONS = {
    BrowserActionType.COOKIE_READ,
    BrowserActionType.STORAGE_READ,
    BrowserActionType.HOST_SECRET_READ,
}


class BrowserApprovalVerifier(Protocol):
    """Authenticate an approval produced by a trusted review service."""

    def verify_approval(self, approval: BrowserActionApproval) -> bool:
        """Return whether the approval record is authentic and active."""
        ...


class BrowserObservationVerifier(Protocol):
    """Authenticate browser instrumentation before binding its observation."""

    def verify_observation(self, observation: BrowserObservation) -> bool:
        """Return whether the exact observation came from trusted instrumentation."""
        ...


class BrowserDownloadEvidenceVerifier(Protocol):
    """Authenticate exact quarantine evidence from the browser broker."""

    def verify_download_evidence(self, evidence: BrowserDownloadEvidence) -> bool:
        """Return whether the exact download evidence is authentic."""
        ...


class BrowserAuthorizationStateStore(Protocol):
    """Atomically claim authorization identities until expiry."""

    def claim_many(self, claims: Mapping[str, datetime], *, now: datetime) -> bool:
        """Claim every key or none; return false if a live key already exists."""
        ...


class MemoryBrowserAuthorizationStateStore:
    """Thread-safe process-local replay store for tests and single-worker apps."""

    def __init__(self) -> None:
        self._claims: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def claim_many(self, claims: Mapping[str, datetime], *, now: datetime) -> bool:
        with self._lock:
            expired = [claim for claim, expiry in self._claims.items() if expiry <= now]
            for claim in expired:
                del self._claims[claim]
            if any(key in self._claims for key in claims):
                return False
            self._claims.update(claims)
            return True


class StaticBrowserApprovalVerifier:
    """Deterministic approval verifier for tests and offline examples."""

    def __init__(self, approval_ids: Iterable[str]) -> None:
        self._approval_ids = frozenset(approval_ids)

    def verify_approval(self, approval: BrowserActionApproval) -> bool:
        return approval.approval_id in self._approval_ids


class StaticBrowserObservationVerifier:
    """Exact deterministic observation verifier for tests and offline examples."""

    def __init__(self, observations: Iterable[tuple[str, str]]) -> None:
        self._observations = frozenset(observations)

    def verify_observation(self, observation: BrowserObservation) -> bool:
        return (observation.observation_id, observation.observation_digest) in self._observations


class StaticBrowserDownloadEvidenceVerifier:
    """Exact deterministic download verifier for tests and offline examples."""

    def __init__(self, evidence: Iterable[tuple[str, str]]) -> None:
        self._evidence = frozenset(evidence)

    def verify_download_evidence(self, evidence: BrowserDownloadEvidence) -> bool:
        return (evidence.download_id, evidence.evidence_digest) in self._evidence


class BrowserSessionSigner:
    """Seal trusted session configuration with a domain-separated HMAC."""

    def __init__(self, key_id: str, signing_key: bytes) -> None:
        if not key_id or len(key_id) > 256:
            raise ValueError("key_id must contain 1 to 256 characters")
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        self._key_id = key_id
        self._key = bytes(signing_key)

    def issue(
        self,
        config: BrowserSessionConfig,
        *,
        now: datetime | None = None,
    ) -> BrowserSessionManifest:
        """Issue an integrity-bound session manifest from trusted configuration."""
        issued_at = _current_time(now)
        unsigned = BrowserSessionManifest(
            config=config,
            key_id=self._key_id,
            issued_at=issued_at,
            signature="0" * 64,
        )
        return unsigned.model_copy(update={"signature": _signature(unsigned, self._key)})


class BrowserIsolationGuard:
    """Separate untrusted browser observations from authorized browser actions."""

    def __init__(
        self,
        policy: BrowserIsolationPolicy,
        trusted_keys: Mapping[str, bytes],
        *,
        observation_verifier: BrowserObservationVerifier | None = None,
        approval_verifier: BrowserApprovalVerifier | None = None,
        download_evidence_verifier: BrowserDownloadEvidenceVerifier | None = None,
        state_store: BrowserAuthorizationStateStore | None = None,
    ) -> None:
        if not trusted_keys:
            raise ValueError("at least one trusted browser manifest key is required")
        if any(not key_id or len(key) < 32 for key_id, key in trusted_keys.items()):
            raise ValueError("trusted manifest keys require an ID and at least 32 bytes")
        self._policy = policy.model_copy(deep=True)
        self._keys = {key_id: bytes(key) for key_id, key in trusted_keys.items()}
        self._observation_verifier = observation_verifier
        self._approval_verifier = approval_verifier
        self._download_evidence_verifier = download_evidence_verifier
        self._state_store = state_store or MemoryBrowserAuthorizationStateStore()

    @property
    def policy(self) -> BrowserIsolationPolicy:
        return self._policy.model_copy(deep=True)

    def inspect_observation(
        self,
        manifest: BrowserSessionManifest,
        observation: BrowserObservation,
        *,
        now: datetime | None = None,
    ) -> BrowserIsolationResult:
        """Bind model-visible browser data to a valid session without trusting it."""
        current = _current_time(now)
        findings = self._manifest_findings(manifest, current)
        config = manifest.config
        try:
            authentic = self._observation_verifier is not None and (
                self._observation_verifier.verify_observation(observation)
            )
        except Exception:
            authentic = False
        if not authentic:
            findings.append(
                self._finding(
                    BrowserIsolationCode.OBSERVATION_INVALID,
                    "Browser observation could not be authenticated",
                    references=(observation.observation_id,),
                )
            )
        if observation.session_id != config.session_id:
            findings.append(
                self._finding(
                    BrowserIsolationCode.SESSION_MISMATCH,
                    "Browser observation belongs to another session",
                    references=(observation.observation_id,),
                )
            )
        if observation.origin.canonical != config.current_origin.canonical:
            findings.append(
                self._finding(
                    BrowserIsolationCode.ORIGIN_CHANGED,
                    "Browser origin changed without a new trusted session manifest",
                    references=(observation.observation_id,),
                )
            )
        parsed_origin = self._parse_url_origin(observation.url)
        if parsed_origin is None or parsed_origin.canonical != observation.origin.canonical:
            findings.append(
                self._finding(
                    BrowserIsolationCode.URL_INVALID,
                    "Observation URL does not match its declared origin",
                    references=(observation.observation_id,),
                    field_paths=("/url",),
                )
            )
        if not self._origin_allowed(observation.origin, config.allowed_origins):
            findings.append(
                self._finding(
                    BrowserIsolationCode.ORIGIN_DENIED,
                    "Observation origin is not allowed for this session",
                    references=(observation.observation_id,),
                )
            )
        if _is_private_origin(observation.origin) and not self._policy.allow_private_origins:
            findings.append(
                self._finding(
                    BrowserIsolationCode.PRIVATE_ORIGIN_DENIED,
                    "Private or local browser origins are denied",
                    references=(observation.observation_id,),
                )
            )
        if len(observation.content) > self._policy.max_observation_chars:
            findings.append(
                self._finding(
                    BrowserIsolationCode.OBSERVATION_INVALID,
                    "Browser observation exceeds its content limit",
                    references=(observation.observation_id,),
                    field_paths=("/content",),
                )
            )
        if observation.captured_at > current or current - observation.captured_at > timedelta(
            seconds=self._policy.max_observation_age_seconds
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.OBSERVATION_STALE,
                    "Browser observation is stale or future-dated",
                    references=(observation.observation_id,),
                )
            )
        for index, element in enumerate(observation.elements):
            if not self._origin_allowed(
                element.origin, config.allowed_origins
            ) or not self._origin_allowed(element.frame_origin, config.allowed_origins):
                findings.append(
                    self._finding(
                        BrowserIsolationCode.ORIGIN_DENIED,
                        "Observed element crosses an unapproved origin",
                        references=(element.element_ref,),
                        field_paths=(f"/elements/{index}",),
                    )
                )
        if findings:
            return self._result(BrowserIsolationPhase.OBSERVATION, findings=findings)
        unsigned = VerifiedBrowserObservation(
            observation_id=observation.observation_id,
            observation_digest=observation.observation_digest,
            manifest_digest=manifest.manifest_digest,
            session_ref=browser_reference(config.session_id),
            origin=observation.origin,
            kind=observation.kind,
            content=observation.content,
            elements=observation.elements,
            captured_at=observation.captured_at,
            integrity_tag="0" * 64,
        )
        key = self._keys[manifest.key_id]
        verified = unsigned.model_copy(
            update={
                "integrity_tag": _integrity_tag(
                    "trustrail.browser-observation.v1",
                    unsigned,
                    key,
                    exclude={"integrity_tag"},
                )
            }
        )
        return self._result(BrowserIsolationPhase.OBSERVATION, observation=verified)

    def require_observation(
        self,
        manifest: BrowserSessionManifest,
        observation: BrowserObservation,
        *,
        now: datetime | None = None,
    ) -> VerifiedBrowserObservation:
        result = self.inspect_observation(manifest, observation, now=now)
        if not result.is_allowed or result.observation is None:
            raise BrowserIsolationError(result)
        return result.observation

    def preview_action(
        self,
        manifest: BrowserSessionManifest,
        request: BrowserActionRequest,
        *,
        now: datetime | None = None,
    ) -> BrowserIsolationResult:
        """Validate a proposal and construct the exact out-of-page review preview."""
        current = _current_time(now)
        findings = self._manifest_findings(manifest, current)
        findings.extend(self._request_findings(manifest, request, current))
        if findings:
            return self._result(BrowserIsolationPhase.ACTION_PREVIEW, findings=findings)
        approval_required = (
            request.action in self._policy.sensitive_actions
            or request.irreversible
            or any(flow.contains_sensitive_data for flow in request.data_flows)
        )
        preview = self._preview(manifest, request, approval_required=approval_required)
        findings_out: tuple[BrowserIsolationFinding, ...] = ()
        if approval_required:
            findings_out = (
                self._finding(
                    BrowserIsolationCode.APPROVAL_REQUIRED,
                    "Browser action requires fresh approval of the exact canonical preview",
                    severity=Severity.HIGH,
                    references=(request.request_id,),
                ),
            )
        return BrowserIsolationResult(
            phase=BrowserIsolationPhase.ACTION_PREVIEW,
            action=GuardAction.REQUIRE_APPROVAL if approval_required else GuardAction.ALLOW,
            findings=findings_out,
            preview=preview,
        )

    def require_preview(
        self,
        manifest: BrowserSessionManifest,
        request: BrowserActionRequest,
        *,
        now: datetime | None = None,
    ) -> BrowserActionPreview:
        result = self.preview_action(manifest, request, now=now)
        if result.action == GuardAction.BLOCK or result.preview is None:
            raise BrowserIsolationError(result)
        return result.preview

    def authorize_action(
        self,
        manifest: BrowserSessionManifest,
        request: BrowserActionRequest,
        preview: BrowserActionPreview,
        *,
        approval: BrowserActionApproval | None = None,
        now: datetime | None = None,
    ) -> BrowserIsolationResult:
        """Authorize the unchanged preview once, immediately before actuation."""
        current = _current_time(now)
        preview_result = self.preview_action(manifest, request, now=current)
        findings = list(preview_result.findings)
        expected = preview_result.preview
        findings = [
            finding
            for finding in findings
            if finding.code != BrowserIsolationCode.APPROVAL_REQUIRED
        ]
        if expected is None:
            return self._result(BrowserIsolationPhase.ACTION_AUTHORIZATION, findings=findings)
        if preview != expected:
            findings.append(
                self._finding(
                    BrowserIsolationCode.PREVIEW_MISMATCH,
                    "Browser action or canonical preview changed before authorization",
                    references=(request.request_id,),
                )
            )
        if expected.approval_required:
            findings.extend(self._approval_findings(manifest, request, expected, approval, current))
        elif approval is not None:
            findings.append(
                self._finding(
                    BrowserIsolationCode.APPROVAL_INVALID,
                    "Approval was supplied for an action that does not require it",
                    references=(approval.approval_id,),
                )
            )
        if findings:
            return self._result(BrowserIsolationPhase.ACTION_AUTHORIZATION, findings=findings)

        expiry = min(
            manifest.config.expires_at,
            current + timedelta(seconds=self._policy.max_authorization_seconds),
        )
        authorization_id = browser_digest(
            cast(
                dict[str, JsonValue],
                {
                    "domain": "trustrail.browser-action-authorization.v1",
                    "manifest_digest": manifest.manifest_digest,
                    "request_digest": request.request_digest,
                    "preview_digest": expected.preview_digest,
                    "issued_at": current.isoformat(),
                },
            )
        )
        claims = {f"action:{manifest.config.session_id}:{request.request_id}": expiry}
        if approval is not None:
            claims[f"approval:{approval.approval_id}"] = approval.expires_at
        try:
            claimed = self._state_store.claim_many(claims, now=current)
        except Exception:
            return self._result(
                BrowserIsolationPhase.ACTION_AUTHORIZATION,
                findings=[
                    self._finding(
                        BrowserIsolationCode.STATE_STORE_ERROR,
                        "Browser authorization state is unavailable",
                    )
                ],
            )
        if not claimed:
            return self._result(
                BrowserIsolationPhase.ACTION_AUTHORIZATION,
                findings=[
                    self._finding(
                        BrowserIsolationCode.APPROVAL_REPLAYED,
                        "Browser action request was already authorized",
                        references=(request.request_id,),
                    )
                ],
            )
        unsigned = BrowserActionAuthorization(
            authorization_id=authorization_id,
            manifest_digest=manifest.manifest_digest,
            request_digest=request.request_digest,
            preview_digest=expected.preview_digest,
            action=request.action,
            target_origin=request.target_origin,
            expected_download=request.expected_download,
            issued_at=current,
            expires_at=expiry,
            integrity_tag="0" * 64,
        )
        key = self._keys[manifest.key_id]
        authorization = unsigned.model_copy(
            update={
                "integrity_tag": _integrity_tag(
                    "trustrail.browser-action.v1",
                    unsigned,
                    key,
                    exclude={"integrity_tag"},
                )
            }
        )
        return self._result(
            BrowserIsolationPhase.ACTION_AUTHORIZATION,
            authorization=authorization,
        )

    def require_action(
        self,
        manifest: BrowserSessionManifest,
        request: BrowserActionRequest,
        preview: BrowserActionPreview,
        *,
        approval: BrowserActionApproval | None = None,
        now: datetime | None = None,
    ) -> BrowserActionAuthorization:
        result = self.authorize_action(
            manifest,
            request,
            preview,
            approval=approval,
            now=now,
        )
        if not result.is_allowed or result.authorization is None:
            raise BrowserIsolationError(result)
        return result.authorization

    def verify_download(
        self,
        manifest: BrowserSessionManifest,
        authorization: BrowserActionAuthorization,
        evidence: BrowserDownloadEvidence,
        *,
        now: datetime | None = None,
    ) -> BrowserIsolationResult:
        """Release only the expected, bounded, quarantined, scanned download."""
        current = _current_time(now)
        findings = self._manifest_findings(manifest, current)
        expected = authorization.expected_download
        policy = manifest.config.download_policy
        key = self._keys.get(manifest.key_id)
        valid_authorization = key is not None and hmac.compare_digest(
            authorization.integrity_tag,
            _integrity_tag(
                "trustrail.browser-action.v1",
                authorization,
                key or b"",
                exclude={"integrity_tag"},
            ),
        )
        if (
            not valid_authorization
            or authorization.issued_at > current
            or authorization.manifest_digest != manifest.manifest_digest
            or authorization.action != BrowserActionType.DOWNLOAD
            or expected is None
            or evidence.authorization_id != authorization.authorization_id
            or authorization.expires_at <= current
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.DOWNLOAD_UNEXPECTED,
                    "Download does not have a live exact action authorization",
                    references=(evidence.download_id,),
                )
            )
        try:
            authentic_evidence = self._download_evidence_verifier is not None and (
                self._download_evidence_verifier.verify_download_evidence(evidence)
            )
        except Exception:
            authentic_evidence = False
        if (
            not authentic_evidence
            or evidence.completed_at > current
            or evidence.completed_at < authorization.issued_at
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.DOWNLOAD_UNSAFE,
                    "Download evidence is unauthenticated or has an invalid completion time",
                    references=(evidence.download_id,),
                )
            )
        if expected is not None and (
            evidence.download_id != expected.download_id
            or evidence.source_origin.canonical != expected.source_origin.canonical
            or evidence.media_type != expected.media_type
            or evidence.size_bytes > expected.max_bytes
            or evidence.size_bytes > policy.max_bytes
            or evidence.media_type not in policy.allowed_media_types
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.DOWNLOAD_UNEXPECTED,
                    "Downloaded artifact does not match its explicit expectation",
                    references=(evidence.download_id,),
                )
            )
        if (policy.require_quarantine and not evidence.quarantined) or (
            policy.require_malware_scan
            and (not evidence.malware_scan_completed or evidence.malware_detected)
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.DOWNLOAD_UNSAFE,
                    "Download quarantine or malware-scan evidence is insufficient",
                    references=(evidence.download_id,),
                )
            )
        if findings:
            return self._result(BrowserIsolationPhase.DOWNLOAD_VERIFICATION, findings=findings)
        verified = VerifiedBrowserDownload(
            download_ref=browser_reference(evidence.download_id),
            authorization_id=authorization.authorization_id,
            content_digest=evidence.content_digest,
            media_type=evidence.media_type,
            size_bytes=evidence.size_bytes,
            verified_at=current,
        )
        return self._result(BrowserIsolationPhase.DOWNLOAD_VERIFICATION, download=verified)

    def require_download(
        self,
        manifest: BrowserSessionManifest,
        authorization: BrowserActionAuthorization,
        evidence: BrowserDownloadEvidence,
        *,
        now: datetime | None = None,
    ) -> VerifiedBrowserDownload:
        result = self.verify_download(manifest, authorization, evidence, now=now)
        if not result.is_allowed or result.download is None:
            raise BrowserIsolationError(result)
        return result.download

    def _manifest_findings(
        self,
        manifest: BrowserSessionManifest,
        now: datetime,
    ) -> list[BrowserIsolationFinding]:
        findings: list[BrowserIsolationFinding] = []
        key = self._keys.get(manifest.key_id)
        if key is None or not hmac.compare_digest(manifest.signature, _signature(manifest, key)):
            return [
                self._finding(
                    BrowserIsolationCode.MANIFEST_INVALID,
                    "Browser session manifest signature is invalid",
                )
            ]
        if (
            manifest.issued_at > now
            or manifest.config.expires_at <= now
            or manifest.config.expires_at - manifest.issued_at
            > timedelta(seconds=self._policy.max_session_seconds)
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.MANIFEST_EXPIRED,
                    "Browser session manifest is expired, future-dated, or overlong",
                )
            )
        if manifest.config.policy_version != self._policy.policy_version:
            findings.append(
                self._finding(
                    BrowserIsolationCode.POLICY_MISMATCH,
                    "Browser session manifest was issued for another policy version",
                )
            )
        missing = self._policy.required_controls - manifest.config.sandbox_controls
        if missing:
            findings.append(
                self._finding(
                    BrowserIsolationCode.SANDBOX_CONTROL_MISSING,
                    "Browser worker does not assert every required isolation control",
                    field_paths=("/config/sandbox_controls",),
                )
            )
        return findings

    def _request_findings(
        self,
        manifest: BrowserSessionManifest,
        request: BrowserActionRequest,
        now: datetime,
    ) -> list[BrowserIsolationFinding]:
        findings: list[BrowserIsolationFinding] = []
        config = manifest.config
        refs = (request.request_id,)
        if (
            request.session_id != config.session_id
            or request.tenant_id != config.tenant_id
            or request.actor_id != config.actor_id
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.SESSION_MISMATCH,
                    "Browser action identity, tenant, or session does not match",
                    references=refs,
                )
            )
        if request.requested_at > now or now - request.requested_at > timedelta(
            seconds=self._policy.max_request_age_seconds
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.OBSERVATION_STALE,
                    "Browser action request is stale or future-dated",
                    references=refs,
                )
            )
        if request.action not in config.allowed_actions:
            findings.append(
                self._finding(
                    BrowserIsolationCode.ACTION_DENIED,
                    "Browser action is not allowed by the session manifest",
                    references=refs,
                )
            )
        if request.action in _SECRET_READ_ACTIONS:
            findings.append(
                self._finding(
                    BrowserIsolationCode.SECRET_ACCESS_DENIED,
                    "Direct browser or host secret reads are never model-authorized",
                    references=refs,
                )
            )
        parsed_origin = self._parse_url_origin(request.target_url)
        if parsed_origin is None or parsed_origin.canonical != request.target_origin.canonical:
            findings.append(
                self._finding(
                    BrowserIsolationCode.URL_INVALID,
                    "Browser action URL and declared target origin do not match",
                    references=refs,
                    field_paths=("/target_url",),
                )
            )
        if not self._origin_allowed(request.target_origin, config.allowed_origins):
            findings.append(
                self._finding(
                    BrowserIsolationCode.ORIGIN_DENIED,
                    "Browser action target origin is not allowed",
                    references=refs,
                )
            )
        if _is_private_origin(request.target_origin) and not self._policy.allow_private_origins:
            findings.append(
                self._finding(
                    BrowserIsolationCode.PRIVATE_ORIGIN_DENIED,
                    "Private or local action targets are denied",
                    references=refs,
                )
            )
        if request.action == BrowserActionType.CREDENTIAL_USE and not self._origin_allowed(
            request.target_origin, config.authenticated_origins
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.SECRET_ACCESS_DENIED,
                    "Credential use is restricted to an authenticated origin",
                    references=refs,
                )
            )
        if request.action == BrowserActionType.CLIPBOARD_READ and not config.clipboard_read_enabled:
            findings.append(
                self._finding(
                    BrowserIsolationCode.CLIPBOARD_DENIED,
                    "Clipboard reads are disabled for this session",
                    references=refs,
                )
            )
        if (
            request.action == BrowserActionType.CLIPBOARD_WRITE
            and not config.clipboard_write_enabled
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.CLIPBOARD_DENIED,
                    "Clipboard writes are disabled for this session",
                    references=refs,
                )
            )
        findings.extend(self._file_findings(config, request, now))
        findings.extend(self._download_findings(config, request))
        findings.extend(self._observation_findings(manifest, request, now))
        findings.extend(
            self._data_flow_findings(
                config,
                request.data_flows,
                request.target_origin,
                request.action,
            )
        )
        return findings

    def _file_findings(
        self,
        config: BrowserSessionConfig,
        request: BrowserActionRequest,
        now: datetime,
    ) -> list[BrowserIsolationFinding]:
        if (
            request.action == BrowserActionType.LOCAL_FILE_READ
            and not config.local_file_read_enabled
        ):
            return [
                self._finding(
                    BrowserIsolationCode.LOCAL_FILE_DENIED,
                    "Local file reads are disabled for this browser session",
                    references=(request.request_id,),
                )
            ]
        if request.action not in {BrowserActionType.UPLOAD, BrowserActionType.LOCAL_FILE_READ}:
            return []
        grants = (
            config.upload_grants
            if request.action == BrowserActionType.UPLOAD
            else config.local_file_grants
        )
        grant = next((item for item in grants if item.file_ref == request.file_ref), None)
        if (
            grant is None
            or grant.expires_at <= now
            or grant.destination.canonical != request.target_origin.canonical
        ):
            return [
                self._finding(
                    BrowserIsolationCode.UPLOAD_DENIED
                    if request.action == BrowserActionType.UPLOAD
                    else BrowserIsolationCode.LOCAL_FILE_DENIED,
                    "File action lacks a live content-bound grant for this origin",
                    references=(request.request_id,),
                )
            ]
        return []

    def _download_findings(
        self,
        config: BrowserSessionConfig,
        request: BrowserActionRequest,
    ) -> list[BrowserIsolationFinding]:
        if request.action != BrowserActionType.DOWNLOAD:
            return []
        policy = config.download_policy
        expected = request.expected_download
        if (
            not policy.enabled
            or expected is None
            or expected.source_origin.canonical != request.target_origin.canonical
            or expected.max_bytes > policy.max_bytes
            or expected.media_type not in policy.allowed_media_types
        ):
            return [
                self._finding(
                    BrowserIsolationCode.DOWNLOAD_DENIED,
                    "Download is disabled or outside its explicit policy bounds",
                    references=(request.request_id,),
                )
            ]
        return []

    def _observation_findings(
        self,
        manifest: BrowserSessionManifest,
        request: BrowserActionRequest,
        now: datetime,
    ) -> list[BrowserIsolationFinding]:
        observation = request.observation
        if observation is None:
            return []
        findings: list[BrowserIsolationFinding] = []
        key = self._keys.get(manifest.key_id)
        if (
            key is None
            or not hmac.compare_digest(
                observation.integrity_tag,
                _integrity_tag(
                    "trustrail.browser-observation.v1",
                    observation,
                    key or b"",
                    exclude={"integrity_tag"},
                ),
            )
            or observation.manifest_digest != manifest.manifest_digest
            or observation.session_ref != browser_reference(manifest.config.session_id)
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.OBSERVATION_INVALID,
                    "Browser observation is not bound to this session manifest",
                    references=(observation.observation_id,),
                )
            )
        if observation.captured_at > now or now - observation.captured_at > timedelta(
            seconds=self._policy.max_observation_age_seconds
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.OBSERVATION_STALE,
                    "Browser action relies on a stale or future observation",
                    references=(observation.observation_id,),
                )
            )
        element = next(
            (item for item in observation.elements if item.element_ref == request.element_ref),
            None,
        )
        if request.element_ref is not None and element is None:
            findings.append(
                self._finding(
                    BrowserIsolationCode.OBSERVATION_INVALID,
                    "Target element is absent from the exact verified observation",
                    references=(request.request_id,),
                )
            )
            return findings
        if element is None:
            return findings
        if (
            element.origin.canonical != request.target_origin.canonical
            or element.frame_origin.canonical != observation.origin.canonical
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.CROSS_ORIGIN_FLOW_DENIED,
                    "Target element origin or frame does not match the proposed action",
                    references=(element.element_ref,),
                )
            )
        if not element.visible or element.viewport_fraction <= 0:
            findings.append(
                self._finding(
                    BrowserIsolationCode.TARGET_HIDDEN,
                    "Target browser control is hidden or outside the viewport",
                    references=(element.element_ref,),
                )
            )
        if element.occluded:
            findings.append(
                self._finding(
                    BrowserIsolationCode.TARGET_OVERLAID,
                    "Target browser control is obscured by another element",
                    references=(element.element_ref,),
                )
            )
        if not element.enabled:
            findings.append(
                self._finding(
                    BrowserIsolationCode.TARGET_DISABLED,
                    "Target browser control is disabled",
                    references=(element.element_ref,),
                )
            )
        if (
            element.sensitive_action_hint is not None
            and element.sensitive_action_hint != request.action
        ):
            findings.append(
                self._finding(
                    BrowserIsolationCode.ACTION_CLASSIFICATION_MISMATCH,
                    "Page control indicates a more specific sensitive action type",
                    references=(element.element_ref,),
                )
            )
        return findings

    def _data_flow_findings(
        self,
        config: BrowserSessionConfig,
        flows: tuple[BrowserDataFlow, ...],
        target: BrowserOrigin,
        action: BrowserActionType,
    ) -> list[BrowserIsolationFinding]:
        findings: list[BrowserIsolationFinding] = []
        for index, flow in enumerate(flows):
            if flow.destination_origin.canonical != target.canonical:
                findings.append(
                    self._finding(
                        BrowserIsolationCode.CROSS_ORIGIN_FLOW_DENIED,
                        "Data-flow destination does not match the browser action target",
                        field_paths=(f"/data_flows/{index}",),
                    )
                )
                continue
            if flow.source in {
                BrowserDataSource.HOST_SECRET,
                BrowserDataSource.CREDENTIAL,
            } and (
                flow.source == BrowserDataSource.HOST_SECRET
                or action != BrowserActionType.CREDENTIAL_USE
            ):
                findings.append(
                    self._finding(
                        BrowserIsolationCode.SECRET_ACCESS_DENIED,
                        "Host secrets cannot flow through model-controlled browser data",
                        field_paths=(f"/data_flows/{index}",),
                    )
                )
                continue
            if flow.source == BrowserDataSource.CLIPBOARD and not config.clipboard_read_enabled:
                findings.append(
                    self._finding(
                        BrowserIsolationCode.CLIPBOARD_DENIED,
                        "Clipboard data flow is disabled",
                        field_paths=(f"/data_flows/{index}",),
                    )
                )
            if flow.source == BrowserDataSource.LOCAL_FILE and not config.local_file_read_enabled:
                findings.append(
                    self._finding(
                        BrowserIsolationCode.LOCAL_FILE_DENIED,
                        "Local-file data flow is disabled",
                        field_paths=(f"/data_flows/{index}",),
                    )
                )
            if flow.source_origin is None or flow.source_origin.canonical == target.canonical:
                continue
            edge = next(
                (
                    item
                    for item in config.cross_origin_flows
                    if item.source.canonical == flow.source_origin.canonical
                    and item.destination.canonical == target.canonical
                    and flow.source in item.allowed_sources
                ),
                None,
            )
            if edge is None or (flow.contains_sensitive_data and not edge.allow_sensitive):
                findings.append(
                    self._finding(
                        BrowserIsolationCode.CROSS_ORIGIN_FLOW_DENIED,
                        "Cross-origin data flow is not explicitly approved",
                        field_paths=(f"/data_flows/{index}",),
                    )
                )
        return findings

    def _approval_findings(
        self,
        manifest: BrowserSessionManifest,
        request: BrowserActionRequest,
        preview: BrowserActionPreview,
        approval: BrowserActionApproval | None,
        now: datetime,
    ) -> list[BrowserIsolationFinding]:
        if approval is None or self._approval_verifier is None:
            return [
                self._finding(
                    BrowserIsolationCode.APPROVAL_REQUIRED,
                    "A trusted approval verifier and exact approval are required",
                    references=(request.request_id,),
                    severity=Severity.HIGH,
                )
            ]
        if (
            approval.manifest_digest != manifest.manifest_digest
            or approval.request_digest != request.request_digest
            or approval.preview_digest != preview.preview_digest
            or approval.session_id != request.session_id
            or approval.tenant_id != request.tenant_id
            or approval.actor_id != request.actor_id
        ):
            return [
                self._finding(
                    BrowserIsolationCode.APPROVAL_INVALID,
                    "Approval does not match the exact browser action context",
                    references=(approval.approval_id,),
                )
            ]
        if (
            approval.issued_at > now
            or approval.expires_at <= now
            or now - approval.issued_at > timedelta(seconds=self._policy.max_approval_age_seconds)
        ):
            return [
                self._finding(
                    BrowserIsolationCode.APPROVAL_EXPIRED,
                    "Browser action approval is expired, stale, or future-dated",
                    references=(approval.approval_id,),
                )
            ]
        try:
            authentic = self._approval_verifier.verify_approval(approval)
        except Exception:
            authentic = False
        if not authentic:
            return [
                self._finding(
                    BrowserIsolationCode.APPROVAL_INVALID,
                    "Browser action approval could not be authenticated",
                    references=(approval.approval_id,),
                )
            ]
        return []

    @staticmethod
    def _preview(
        manifest: BrowserSessionManifest,
        request: BrowserActionRequest,
        *,
        approval_required: bool,
    ) -> BrowserActionPreview:
        unsigned = BrowserActionPreview(
            manifest_digest=manifest.manifest_digest,
            request_digest=request.request_digest,
            action=request.action,
            target_origin=request.target_origin.canonical,
            target_url=request.target_url,
            element_ref=request.element_ref,
            text=request.text,
            credential_ref=request.credential_ref,
            file_ref=request.file_ref,
            expected_download=request.expected_download,
            review_fields=request.review_fields,
            data_flows=request.data_flows,
            irreversible=request.irreversible,
            approval_required=approval_required,
            preview_digest="0" * 64,
        )
        digest = browser_digest(
            cast(
                dict[str, JsonValue],
                unsigned.model_dump(mode="json", exclude={"preview_digest"}),
            )
        )
        return unsigned.model_copy(update={"preview_digest": digest})

    @staticmethod
    def _origin_allowed(origin: BrowserOrigin, allowed: tuple[BrowserOrigin, ...]) -> bool:
        return origin.canonical in {item.canonical for item in allowed}

    @staticmethod
    def _parse_url_origin(value: str) -> BrowserOrigin | None:
        try:
            return BrowserOrigin.from_url(value)
        except ValueError:
            return None

    @staticmethod
    def _finding(
        code: BrowserIsolationCode,
        message: str,
        *,
        severity: Severity = Severity.CRITICAL,
        references: tuple[str, ...] = (),
        field_paths: tuple[str, ...] = (),
    ) -> BrowserIsolationFinding:
        return BrowserIsolationFinding(
            code=code,
            severity=severity,
            message=message,
            references=tuple(browser_reference(item) for item in references),
            field_paths=field_paths,
        )

    @staticmethod
    def _result(
        phase: BrowserIsolationPhase,
        *,
        findings: Iterable[BrowserIsolationFinding] = (),
        observation: VerifiedBrowserObservation | None = None,
        authorization: BrowserActionAuthorization | None = None,
        download: VerifiedBrowserDownload | None = None,
    ) -> BrowserIsolationResult:
        finding_tuple = tuple(findings)
        return BrowserIsolationResult(
            phase=phase,
            action=GuardAction.BLOCK if finding_tuple else GuardAction.ALLOW,
            findings=finding_tuple,
            observation=observation,
            authorization=authorization,
            download=download,
        )


def _current_time(value: datetime | None) -> datetime:
    current = value or datetime.now(tz=UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return current


def _signature(manifest: BrowserSessionManifest, key: bytes) -> str:
    payload = canonical_browser_json(browser_manifest_signing_payload(manifest)).encode()
    return hmac.new(key, b"trustrail.browser-session.v1\x00" + payload, hashlib.sha256).hexdigest()


def _integrity_tag(
    domain: str,
    value: BrowserActionAuthorization | VerifiedBrowserObservation,
    key: bytes,
    *,
    exclude: set[str],
) -> str:
    payload = canonical_browser_json(
        cast(dict[str, JsonValue], value.model_dump(mode="json", exclude=exclude))
    ).encode()
    return hmac.new(key, domain.encode() + b"\x00" + payload, hashlib.sha256).hexdigest()


def _is_private_origin(origin: BrowserOrigin) -> bool:
    host = origin.host.casefold()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )
