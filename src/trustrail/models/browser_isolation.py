"""Typed models for isolated browser and computer-use agent execution."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import unicodedata
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
_DIGEST = r"^[0-9a-f]{64}$"
_SIGNATURE = r"^[0-9a-f]{64}$"


def _canonicalize(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("object keys must remain unique after Unicode normalization")
            normalized[normalized_key] = _canonicalize(item)
        return normalized
    return value


def canonical_browser_json(value: JsonValue) -> str:
    """Return deterministic NFC-normalized JSON for browser integrity controls."""
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def browser_digest(value: JsonValue) -> str:
    """Return the SHA-256 digest of canonical browser-control JSON."""
    return hashlib.sha256(canonical_browser_json(value).encode()).hexdigest()


def browser_reference(value: str) -> str:
    """Return a content-safe reference for an application identity."""
    return f"sha256:{hashlib.sha256(unicodedata.normalize('NFC', value).encode()).hexdigest()}"


def _aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class BrowserSandboxControl(StrEnum):
    """Isolation controls asserted for the browser worker."""

    PROCESS_ISOLATION = "process_isolation"
    EPHEMERAL_PROFILE = "ephemeral_profile"
    NETWORK_EGRESS_FILTER = "network_egress_filter"
    CREDENTIAL_BROKER = "credential_broker"
    DOWNLOAD_QUARANTINE = "download_quarantine"
    UPLOAD_BROKER = "upload_broker"
    CLIPBOARD_BROKER = "clipboard_broker"
    LOCAL_FILE_BROKER = "local_file_broker"
    SCREEN_CAPTURE_REDACTION = "screen_capture_redaction"
    CLEANUP_ON_EXIT = "cleanup_on_exit"


class BrowserObservationKind(StrEnum):
    """Untrusted browser surfaces exposed to a computer-use agent."""

    RENDERED_TEXT = "rendered_text"
    PIXELS = "pixels"
    ACCESSIBILITY_TREE = "accessibility_tree"
    PAGE_METADATA = "page_metadata"
    DOWNLOAD_METADATA = "download_metadata"


class BrowserActionType(StrEnum):
    """Actions a trusted actuator can perform after authorization."""

    NAVIGATE = "navigate"
    CLICK = "click"
    ENTER_TEXT = "enter_text"
    SUBMIT = "submit"
    PURCHASE = "purchase"
    SEND_MESSAGE = "send_message"
    PERMISSION_CHANGE = "permission_change"
    IRREVERSIBLE = "irreversible"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    CREDENTIAL_USE = "credential_use"
    CLIPBOARD_READ = "clipboard_read"
    CLIPBOARD_WRITE = "clipboard_write"
    LOCAL_FILE_READ = "local_file_read"
    COOKIE_READ = "cookie_read"
    STORAGE_READ = "storage_read"
    HOST_SECRET_READ = "host_secret_read"  # noqa: S105 -- action identifier


class BrowserDataSource(StrEnum):
    """Origins of data proposed for movement into or out of a page."""

    USER_INPUT = "user_input"
    PAGE_OBSERVATION = "page_observation"
    CLIPBOARD = "clipboard"
    LOCAL_FILE = "local_file"
    DOWNLOAD = "download"
    CREDENTIAL = "credential"
    HOST_SECRET = "host_secret"  # noqa: S105 -- data-source identifier


class BrowserIsolationPhase(StrEnum):
    """Browser boundary that emitted a decision."""

    OBSERVATION = "observation"
    ACTION_PREVIEW = "action_preview"
    ACTION_AUTHORIZATION = "action_authorization"
    DOWNLOAD_VERIFICATION = "download_verification"


class BrowserIsolationCode(StrEnum):
    """Stable machine-readable browser isolation findings."""

    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_EXPIRED = "manifest_expired"
    SESSION_MISMATCH = "session_mismatch"
    POLICY_MISMATCH = "policy_mismatch"
    SANDBOX_CONTROL_MISSING = "sandbox_control_missing"
    ORIGIN_DENIED = "origin_denied"
    ORIGIN_CHANGED = "origin_changed"
    URL_INVALID = "url_invalid"
    PRIVATE_ORIGIN_DENIED = "private_origin_denied"
    ACTION_DENIED = "action_denied"
    ACTION_CLASSIFICATION_MISMATCH = "action_classification_mismatch"
    OBSERVATION_INVALID = "observation_invalid"
    OBSERVATION_STALE = "observation_stale"
    TARGET_HIDDEN = "target_hidden"
    TARGET_OVERLAID = "target_overlaid"
    TARGET_DISABLED = "target_disabled"
    CROSS_ORIGIN_FLOW_DENIED = "cross_origin_flow_denied"
    SECRET_ACCESS_DENIED = "secret_access_denied"  # noqa: S105 -- finding code
    CLIPBOARD_DENIED = "clipboard_denied"
    LOCAL_FILE_DENIED = "local_file_denied"
    UPLOAD_DENIED = "upload_denied"
    DOWNLOAD_DENIED = "download_denied"
    DOWNLOAD_UNEXPECTED = "download_unexpected"
    DOWNLOAD_UNSAFE = "download_unsafe"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_REPLAYED = "approval_replayed"
    PREVIEW_MISMATCH = "preview_mismatch"
    STATE_STORE_ERROR = "state_store_error"


class BrowserOrigin(BaseModel):
    """Canonical web origin without userinfo, paths, queries, or fragments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["http", "https"]
    host: str = Field(min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65_535)

    @field_validator("host")
    @classmethod
    def canonicalize_host(cls, value: str) -> str:
        if value != value.strip() or any(character in value for character in "/@?#\\\x00"):
            raise ValueError("origin host must not contain URL delimiters")
        normalized = value.rstrip(".").casefold()
        try:
            address = ipaddress.ip_address(normalized.strip("[]"))
        except ValueError:
            try:
                normalized = normalized.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("origin host must be a valid IDNA name") from exc
            labels = normalized.split(".")
            if any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in label
                )
                for label in labels
            ):
                raise ValueError("origin host contains an invalid DNS label") from None
            return normalized
        return address.compressed

    @property
    def canonical(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        port = "" if self.port in {None, default_port} else f":{self.port}"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}{port}"

    @classmethod
    def from_url(cls, value: str) -> BrowserOrigin:
        """Parse an absolute HTTP(S) URL into its canonical origin."""
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("URL contains an invalid origin") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("URL must use an absolute HTTP(S) origin without userinfo")
        return cls(
            scheme=cast(Literal["http", "https"], parsed.scheme), host=parsed.hostname, port=port
        )


class BrowserOriginFlow(BaseModel):
    """One explicitly approved page-to-page data-flow edge."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: BrowserOrigin
    destination: BrowserOrigin
    allowed_sources: frozenset[BrowserDataSource] = Field(min_length=1)
    allow_sensitive: bool = False


class BrowserFileGrant(BaseModel):
    """Content-bound upload or local-file grant created outside the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_ref: str = Field(pattern=_IDENTIFIER)
    content_digest: str = Field(pattern=_DIGEST)
    media_type: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=0, le=10_000_000_000)
    destination: BrowserOrigin
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        return _aware(value, "expires_at")


class BrowserDownloadPolicy(BaseModel):
    """Expected-download and quarantine requirements for one session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    require_explicit_expectation: bool = True
    require_quarantine: bool = True
    require_malware_scan: bool = True
    max_bytes: int = Field(default=0, ge=0, le=10_000_000_000)
    allowed_media_types: frozenset[str] = Field(default_factory=frozenset, max_length=256)


class BrowserSessionConfig(BaseModel):
    """Trusted application configuration sealed into a session manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str = Field(pattern=_IDENTIFIER)
    tenant_id: str = Field(pattern=_IDENTIFIER)
    actor_id: str = Field(pattern=_IDENTIFIER)
    identity_id: str = Field(pattern=_IDENTIFIER)
    profile_id: str = Field(pattern=_IDENTIFIER)
    policy_version: str = Field(pattern=_IDENTIFIER)
    current_origin: BrowserOrigin
    allowed_origins: tuple[BrowserOrigin, ...] = Field(min_length=1, max_length=1_000)
    authenticated_origins: tuple[BrowserOrigin, ...] = Field(default=(), max_length=1_000)
    allowed_actions: frozenset[BrowserActionType] = Field(min_length=1)
    cross_origin_flows: tuple[BrowserOriginFlow, ...] = Field(default=(), max_length=1_000)
    upload_grants: tuple[BrowserFileGrant, ...] = Field(default=(), max_length=1_000)
    local_file_grants: tuple[BrowserFileGrant, ...] = Field(default=(), max_length=1_000)
    download_policy: BrowserDownloadPolicy = Field(default_factory=BrowserDownloadPolicy)
    clipboard_read_enabled: bool = False
    clipboard_write_enabled: bool = False
    local_file_read_enabled: bool = False
    sandbox_controls: frozenset[BrowserSandboxControl] = Field(min_length=1)
    authentication_state_digest: str = Field(pattern=_DIGEST)
    nonce: str = Field(pattern=_IDENTIFIER)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        return _aware(value, "expires_at")

    @model_validator(mode="after")
    def validate_origin_sets(self) -> BrowserSessionConfig:
        allowed = [origin.canonical for origin in self.allowed_origins]
        authenticated = [origin.canonical for origin in self.authenticated_origins]
        if len(allowed) != len(set(allowed)) or len(authenticated) != len(set(authenticated)):
            raise ValueError("session origins must be unique")
        if self.current_origin.canonical not in allowed:
            raise ValueError("current_origin must be allowed")
        if not set(authenticated).issubset(allowed):
            raise ValueError("authenticated origins must be allowed")
        upload_refs = [grant.file_ref for grant in self.upload_grants]
        local_refs = [grant.file_ref for grant in self.local_file_grants]
        if len(upload_refs) != len(set(upload_refs)):
            raise ValueError("upload grants must be unique")
        if len(local_refs) != len(set(local_refs)):
            raise ValueError("local-file grants must be unique")
        return self

    @property
    def config_digest(self) -> str:
        return browser_digest(cast(dict[str, JsonValue], self.model_dump(mode="json")))


class BrowserSessionManifest(BaseModel):
    """Integrity-sealed browser session and capability declaration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    config: BrowserSessionConfig
    key_id: str = Field(pattern=_IDENTIFIER)
    issued_at: datetime
    signature: str = Field(pattern=_SIGNATURE)

    @field_validator("issued_at")
    @classmethod
    def validate_issued_at(cls, value: datetime) -> datetime:
        return _aware(value, "issued_at")

    @property
    def manifest_digest(self) -> str:
        return browser_digest(cast(dict[str, JsonValue], self.model_dump(mode="json")))


class BrowserElementObservation(BaseModel):
    """Trusted instrumentation state plus untrusted model-visible labels."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    element_ref: str = Field(pattern=_IDENTIFIER)
    origin: BrowserOrigin
    frame_origin: BrowserOrigin
    role: str = Field(min_length=1, max_length=128)
    label: str = Field(default="", max_length=16_384, repr=False)
    visible: bool
    enabled: bool
    occluded: bool
    viewport_fraction: float = Field(ge=0.0, le=1.0)
    sensitive_action_hint: BrowserActionType | None = None


class BrowserObservation(BaseModel):
    """A browser surface captured by trusted instrumentation but treated as data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    origin: BrowserOrigin
    url: str = Field(min_length=1, max_length=8_192, repr=False)
    kind: BrowserObservationKind
    content: str = Field(max_length=5_000_000, repr=False)
    elements: tuple[BrowserElementObservation, ...] = Field(default=(), max_length=10_000)
    captured_at: datetime
    extractor_id: str = Field(pattern=_IDENTIFIER)
    untrusted: Literal[True] = True

    @field_validator("captured_at")
    @classmethod
    def validate_captured_at(cls, value: datetime) -> datetime:
        return _aware(value, "captured_at")

    @model_validator(mode="after")
    def validate_elements(self) -> BrowserObservation:
        refs = [element.element_ref for element in self.elements]
        if len(refs) != len(set(refs)):
            raise ValueError("observed element references must be unique")
        return self

    @property
    def observation_digest(self) -> str:
        return browser_digest(cast(dict[str, JsonValue], self.model_dump(mode="json")))


class VerifiedBrowserObservation(BaseModel):
    """Manifest-bound observation that remains explicitly untrusted model data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_id: str = Field(pattern=_IDENTIFIER)
    observation_digest: str = Field(pattern=_DIGEST)
    manifest_digest: str = Field(pattern=_DIGEST)
    session_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    origin: BrowserOrigin
    kind: BrowserObservationKind
    content: str = Field(repr=False)
    elements: tuple[BrowserElementObservation, ...] = ()
    captured_at: datetime
    untrusted: Literal[True] = True
    integrity_tag: str = Field(pattern=_SIGNATURE)

    @field_validator("captured_at")
    @classmethod
    def validate_captured_at(cls, value: datetime) -> datetime:
        return _aware(value, "captured_at")


class BrowserDataFlow(BaseModel):
    """One explicit data movement associated with an action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: BrowserDataSource
    source_origin: BrowserOrigin | None = None
    destination_origin: BrowserOrigin
    content_digest: str = Field(pattern=_DIGEST)
    contains_sensitive_data: bool = False


class BrowserExpectedDownload(BaseModel):
    """Exact download expectation authorized before bytes arrive."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    download_id: str = Field(pattern=_IDENTIFIER)
    source_origin: BrowserOrigin
    media_type: str = Field(min_length=1, max_length=255)
    max_bytes: int = Field(ge=1, le=10_000_000_000)


class BrowserActionReviewField(BaseModel):
    """Application-owned material field rendered in trusted approval UI."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field_id: str = Field(pattern=_IDENTIFIER)
    label: str = Field(min_length=1, max_length=256)
    value: str = Field(max_length=100_000, repr=False)
    highlight: bool = False


class BrowserActionRequest(BaseModel):
    """Exact proposed browser action; no page field carries authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    tenant_id: str = Field(pattern=_IDENTIFIER)
    actor_id: str = Field(pattern=_IDENTIFIER)
    action: BrowserActionType
    target_url: str = Field(min_length=1, max_length=8_192, repr=False)
    target_origin: BrowserOrigin
    element_ref: str | None = Field(default=None, pattern=_IDENTIFIER)
    text: str | None = Field(default=None, max_length=1_000_000, repr=False)
    credential_ref: str | None = Field(default=None, pattern=_IDENTIFIER)
    file_ref: str | None = Field(default=None, pattern=_IDENTIFIER)
    expected_download: BrowserExpectedDownload | None = None
    review_fields: tuple[BrowserActionReviewField, ...] = Field(
        default=(), max_length=100, repr=False
    )
    observation: VerifiedBrowserObservation | None = Field(default=None, repr=False)
    data_flows: tuple[BrowserDataFlow, ...] = Field(default=(), max_length=1_000)
    irreversible: bool = False
    requested_at: datetime

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at(cls, value: datetime) -> datetime:
        return _aware(value, "requested_at")

    @model_validator(mode="after")
    def validate_action_shape(self) -> BrowserActionRequest:
        element_actions = {
            BrowserActionType.CLICK,
            BrowserActionType.ENTER_TEXT,
            BrowserActionType.SUBMIT,
            BrowserActionType.PURCHASE,
            BrowserActionType.SEND_MESSAGE,
            BrowserActionType.PERMISSION_CHANGE,
            BrowserActionType.IRREVERSIBLE,
            BrowserActionType.UPLOAD,
            BrowserActionType.DOWNLOAD,
            BrowserActionType.CREDENTIAL_USE,
        }
        if self.action in element_actions and (
            self.element_ref is None or self.observation is None
        ):
            raise ValueError("element actions require an exact verified observation")
        if self.action in {BrowserActionType.ENTER_TEXT, BrowserActionType.SEND_MESSAGE}:
            if self.text is None:
                raise ValueError("text actions require text")
        elif self.text is not None:
            raise ValueError("text is allowed only for text-entry actions")
        if self.action == BrowserActionType.CREDENTIAL_USE:
            if self.credential_ref is None:
                raise ValueError("credential use requires an opaque credential reference")
        elif self.credential_ref is not None:
            raise ValueError("credential_ref is allowed only for credential use")
        if self.action in {BrowserActionType.UPLOAD, BrowserActionType.LOCAL_FILE_READ}:
            if self.file_ref is None:
                raise ValueError("file action requires a file grant reference")
        elif self.file_ref is not None:
            raise ValueError("file_ref is allowed only for file actions")
        if self.action == BrowserActionType.DOWNLOAD:
            if self.expected_download is None:
                raise ValueError("download requires an explicit expectation")
        elif self.expected_download is not None:
            raise ValueError("expected_download is allowed only for downloads")
        review_actions = {
            BrowserActionType.SUBMIT,
            BrowserActionType.PURCHASE,
            BrowserActionType.SEND_MESSAGE,
            BrowserActionType.PERMISSION_CHANGE,
            BrowserActionType.IRREVERSIBLE,
            BrowserActionType.CLIPBOARD_WRITE,
        }
        if (self.action in review_actions or self.irreversible) and not self.review_fields:
            raise ValueError("sensitive material actions require canonical review fields")
        review_ids = [field.field_id for field in self.review_fields]
        if len(review_ids) != len(set(review_ids)):
            raise ValueError("review field IDs must be unique")
        return self

    @property
    def request_digest(self) -> str:
        return browser_digest(cast(dict[str, JsonValue], self.model_dump(mode="json")))


class BrowserActionPreview(BaseModel):
    """Canonical complete action preview shown outside page-controlled UI."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_digest: str = Field(pattern=_DIGEST)
    request_digest: str = Field(pattern=_DIGEST)
    action: BrowserActionType
    target_origin: str
    target_url: str = Field(repr=False)
    element_ref: str | None = None
    text: str | None = Field(default=None, repr=False)
    credential_ref: str | None = None
    file_ref: str | None = None
    expected_download: BrowserExpectedDownload | None = None
    review_fields: tuple[BrowserActionReviewField, ...] = Field(default=(), repr=False)
    data_flows: tuple[BrowserDataFlow, ...] = ()
    irreversible: bool
    approval_required: bool
    preview_digest: str = Field(pattern=_DIGEST)


class BrowserActionApproval(BaseModel):
    """Externally authenticated approval for one exact canonical preview."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(pattern=_IDENTIFIER)
    manifest_digest: str = Field(pattern=_DIGEST)
    request_digest: str = Field(pattern=_DIGEST)
    preview_digest: str = Field(pattern=_DIGEST)
    session_id: str = Field(pattern=_IDENTIFIER)
    tenant_id: str = Field(pattern=_IDENTIFIER)
    actor_id: str = Field(pattern=_IDENTIFIER)
    approver_id: str = Field(pattern=_IDENTIFIER)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_window(self) -> BrowserActionApproval:
        if self.expires_at <= self.issued_at:
            raise ValueError("approval must expire after issuance")
        return self


class BrowserActionAuthorization(BaseModel):
    """Single-use exact authorization returned to the trusted browser actuator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_DIGEST)
    manifest_digest: str = Field(pattern=_DIGEST)
    request_digest: str = Field(pattern=_DIGEST)
    preview_digest: str = Field(pattern=_DIGEST)
    action: BrowserActionType
    target_origin: BrowserOrigin
    expected_download: BrowserExpectedDownload | None = None
    issued_at: datetime
    expires_at: datetime
    integrity_tag: str = Field(pattern=_SIGNATURE)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_window(self) -> BrowserActionAuthorization:
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization must expire after issuance")
        return self


class BrowserDownloadEvidence(BaseModel):
    """Authenticated download result held in quarantine before release."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    download_id: str = Field(pattern=_IDENTIFIER)
    authorization_id: str = Field(pattern=_DIGEST)
    source_origin: BrowserOrigin
    media_type: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=0, le=10_000_000_000)
    content_digest: str = Field(pattern=_DIGEST)
    quarantined: bool
    malware_scan_completed: bool
    malware_detected: bool
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _aware(value, "completed_at")

    @property
    def evidence_digest(self) -> str:
        return browser_digest(cast(dict[str, JsonValue], self.model_dump(mode="json")))


class VerifiedBrowserDownload(BaseModel):
    """Content-free release evidence for an expected safe download."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    download_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authorization_id: str = Field(pattern=_DIGEST)
    content_digest: str = Field(pattern=_DIGEST)
    media_type: str
    size_bytes: int
    verified_at: datetime


class BrowserIsolationPolicy(BaseModel):
    """Application-owned limits and approval requirements."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str = Field(pattern=_IDENTIFIER)
    required_controls: frozenset[BrowserSandboxControl] = Field(
        default_factory=lambda: frozenset(
            {
                BrowserSandboxControl.PROCESS_ISOLATION,
                BrowserSandboxControl.EPHEMERAL_PROFILE,
                BrowserSandboxControl.NETWORK_EGRESS_FILTER,
                BrowserSandboxControl.CREDENTIAL_BROKER,
                BrowserSandboxControl.DOWNLOAD_QUARANTINE,
                BrowserSandboxControl.UPLOAD_BROKER,
                BrowserSandboxControl.CLIPBOARD_BROKER,
                BrowserSandboxControl.LOCAL_FILE_BROKER,
                BrowserSandboxControl.CLEANUP_ON_EXIT,
            }
        )
    )
    sensitive_actions: frozenset[BrowserActionType] = Field(
        default_factory=lambda: frozenset(
            {
                BrowserActionType.SUBMIT,
                BrowserActionType.PURCHASE,
                BrowserActionType.SEND_MESSAGE,
                BrowserActionType.PERMISSION_CHANGE,
                BrowserActionType.IRREVERSIBLE,
                BrowserActionType.UPLOAD,
                BrowserActionType.CREDENTIAL_USE,
                BrowserActionType.CLIPBOARD_WRITE,
            }
        )
    )
    max_session_seconds: int = Field(default=3_600, ge=1, le=86_400)
    max_observation_age_seconds: int = Field(default=5, ge=1, le=300)
    max_request_age_seconds: int = Field(default=10, ge=1, le=300)
    max_approval_age_seconds: int = Field(default=300, ge=1, le=3_600)
    max_authorization_seconds: int = Field(default=10, ge=1, le=300)
    allow_private_origins: bool = False
    max_observation_chars: int = Field(default=1_000_000, ge=1, le=5_000_000)

    @property
    def policy_digest(self) -> str:
        return browser_digest(cast(dict[str, JsonValue], self.model_dump(mode="json")))


class BrowserIsolationFinding(BaseModel):
    """Content-safe browser isolation diagnostic."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: BrowserIsolationCode
    severity: Severity
    message: str
    references: tuple[str, ...] = ()
    field_paths: tuple[str, ...] = ()


class BrowserIsolationResult(BaseModel):
    """Decision from observation, preview, authorization, or download verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: BrowserIsolationPhase
    action: GuardAction
    findings: tuple[BrowserIsolationFinding, ...] = ()
    observation: VerifiedBrowserObservation | None = Field(default=None, repr=False)
    preview: BrowserActionPreview | None = Field(default=None, repr=False)
    authorization: BrowserActionAuthorization | None = None
    download: VerifiedBrowserDownload | None = None

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW


def browser_manifest_signing_payload(manifest: BrowserSessionManifest) -> dict[str, JsonValue]:
    """Return exactly the manifest fields covered by its integrity signature."""
    return cast(
        dict[str, JsonValue],
        manifest.model_dump(mode="json", exclude={"signature"}),
    )
