"""Trusted context assembly and exact pre-provider manifest verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from trustrail.exceptions import ContextAssemblyError
from trustrail.models.context import (
    ContextAssemblyCode,
    ContextAssemblyFinding,
    ContextAssemblyPolicy,
    ContextAssemblyResult,
    ContextManifest,
    ContextMessage,
    ContextOrigin,
    ContextProviderProfile,
    ContextRole,
    ContextSegment,
    ContextSegmentFingerprint,
    InstructionPermission,
    ProviderContextRequest,
    ReservedTokenMode,
    canonical_context_json,
    context_digest,
    manifest_signing_payload,
)
from trustrail.models.enums import GuardAction, Severity, TrustLevel

_DATA_BEGIN = "[TRUSTRAIL_DATA_V1]"
_DATA_END = "[/TRUSTRAIL_DATA_V1]"
_GENERIC_RESERVED = (
    _DATA_BEGIN,
    _DATA_END,
    "<|system|>",
    "<|developer|>",
    "<|user|>",
    "<|assistant|>",
    "<|tool|>",
)
_PROFILE_RESERVED = {
    ContextProviderProfile.GENERIC: _GENERIC_RESERVED,
    ContextProviderProfile.OPENAI: (
        *_GENERIC_RESERVED,
        "<|im_start|>",
        "<|im_end|>",
        "<|endoftext|>",
    ),
    ContextProviderProfile.ANTHROPIC: (
        *_GENERIC_RESERVED,
        "\n\nHuman:",
        "\n\nAssistant:",
        "<system>",
        "</system>",
    ),
}
_SYNTHETIC_ROLE_PATTERNS = (
    re.compile(r"(?im)^\s*(?:system|developer|assistant|user|tool)\s*:\s*"),
    re.compile(r"(?i)\[\s*(?:system|developer|assistant|user|tool)\s*\]"),
    re.compile(r"(?i)<\s*/?\s*(?:system|developer|assistant|user|tool)\s*>"),
)
_TEMPLATE_MARKERS = ("{{", "}}", "{%", "%}", "${", "<%", "%>")
_BIDI_CLASSES = {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
_ROLE_RANK = {
    ContextRole.SYSTEM: 0,
    ContextRole.DEVELOPER: 1,
    ContextRole.USER: 2,
    ContextRole.DATA: 3,
}
_EXPECTED_HIERARCHY = {
    ContextOrigin.SYSTEM_POLICY: (
        ContextRole.SYSTEM,
        TrustLevel.TRUSTED,
        InstructionPermission.SYSTEM,
    ),
    ContextOrigin.DEVELOPER: (
        ContextRole.DEVELOPER,
        TrustLevel.TRUSTED,
        InstructionPermission.DEVELOPER,
    ),
    ContextOrigin.USER: (
        ContextRole.USER,
        TrustLevel.UNTRUSTED,
        InstructionPermission.USER,
    ),
}
_DATA_ORIGINS = {
    ContextOrigin.RETRIEVAL,
    ContextOrigin.MEMORY,
    ContextOrigin.TOOL,
    ContextOrigin.EXTERNAL,
    ContextOrigin.MULTIMODAL,
}


def _safe_ref(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value).encode()
    return f"sha256:{hashlib.sha256(normalized).hexdigest()}"


def _contains_unicode_smuggling(value: str) -> bool:
    return any(
        unicodedata.category(character) in {"Cf", "Cs", "Co"}
        or (unicodedata.category(character) == "Cc" and character not in {"\t", "\n", "\r"})
        or unicodedata.bidirectional(character) in _BIDI_CLASSES
        or 0xFE00 <= ord(character) <= 0xFE0F
        or 0xE0000 <= ord(character) <= 0xE007F
        or 0xE0100 <= ord(character) <= 0xE01EF
        for character in value
    )


def _walk(value: object) -> Iterable[object]:
    yield value
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _escape_text(value: str, tokens: tuple[str, ...]) -> str:
    escaped = unicodedata.normalize("NFKC", value)
    for token in sorted(set(tokens), key=len, reverse=True):
        escaped = re.sub(
            re.escape(token),
            lambda match: "".join(f"\\u{ord(character):04x}" for character in match.group()),
            escaped,
            flags=re.IGNORECASE,
        )
    for pattern in _SYNTHETIC_ROLE_PATTERNS:
        escaped = pattern.sub(
            lambda match: "".join(f"\\u{ord(character):04x}" for character in match.group()),
            escaped,
        )
    for marker in _TEMPLATE_MARKERS:
        escaped = escaped.replace(
            marker,
            "".join(f"\\u{ord(character):04x}" for character in marker),
        )
    return escaped


class TrustedContextAssembler:
    """Build and verify provider-neutral context without flattening trust zones.

    Applications protect the HMAC key and manifest, derive all labels from
    authenticated state, and call :meth:`require_provider_request` immediately
    before dispatching its returned request to the provider adapter.
    """

    def __init__(self, signing_key: bytes, policy: ContextAssemblyPolicy | None = None) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        self._key = bytes(signing_key)
        self._policy = (policy or ContextAssemblyPolicy()).model_copy(deep=True)

    @property
    def policy(self) -> ContextAssemblyPolicy:
        """Return a defensive copy of the context assembly policy."""
        return self._policy.model_copy(deep=True)

    def assemble(
        self,
        segments: Iterable[ContextSegment],
        *,
        request_id: str,
        tenant_id: str,
        purpose: str,
        now: datetime | None = None,
    ) -> ContextAssemblyResult:
        """Validate trust zones and produce one exact request plus signed manifest."""
        items = tuple(segments)
        findings = self._structural_findings(
            items,
            request_id=request_id,
            tenant_id=tenant_id,
            purpose=purpose,
        )
        if findings:
            return ContextAssemblyResult(action=GuardAction.BLOCK, findings=tuple(findings))

        tokens = self._reserved_tokens
        transformed = False
        prepared: list[ContextSegment] = []
        syntax_findings: list[ContextAssemblyFinding] = []
        for segment in items:
            content_findings = self._content_findings(segment, tokens)
            unicode_findings = [
                finding
                for finding in content_findings
                if finding.code == ContextAssemblyCode.UNICODE_SMUGGLING
            ]
            if unicode_findings or (
                content_findings and self._policy.reserved_token_mode == ReservedTokenMode.REJECT
            ):
                syntax_findings.extend(content_findings)
                continue
            if content_findings:
                transformed = True
                prepared.append(
                    segment.model_copy(update={"content": _escape_text(segment.content, tokens)})
                )
            else:
                prepared.append(segment)

        if syntax_findings:
            return ContextAssemblyResult(
                action=GuardAction.BLOCK,
                findings=tuple(syntax_findings),
            )

        ordered = tuple(sorted(prepared, key=lambda item: (_ROLE_RANK[item.role], item.ordinal)))
        messages = tuple(self._message(segment) for segment in ordered)
        request = ProviderContextRequest(
            provider_profile=self._policy.provider_profile,
            request_id=request_id,
            tenant_id=tenant_id,
            purpose=purpose,
            messages=messages,
        )
        issued_at = now or datetime.now(tz=UTC)
        manifest = self._manifest(ordered, request, issued_at)
        return ContextAssemblyResult(
            action=GuardAction.TRANSFORM if transformed else GuardAction.ALLOW,
            request=request,
            manifest=manifest,
        )

    def require_assembly(
        self,
        segments: Iterable[ContextSegment],
        *,
        request_id: str,
        tenant_id: str,
        purpose: str,
        now: datetime | None = None,
    ) -> tuple[ProviderContextRequest, ContextManifest]:
        """Return an exact request and manifest or raise without exposing content."""
        result = self.assemble(
            segments,
            request_id=request_id,
            tenant_id=tenant_id,
            purpose=purpose,
            now=now,
        )
        if not result.is_allowed or result.request is None or result.manifest is None:
            raise ContextAssemblyError(result)
        return result.request, result.manifest

    def verify_provider_request(
        self,
        request: ProviderContextRequest,
        manifest: ContextManifest,
        *,
        request_id: str,
        tenant_id: str,
        purpose: str,
        now: datetime | None = None,
    ) -> ContextAssemblyResult:
        """Verify the manifest and exact adapted request immediately before use."""
        current = now or datetime.now(tz=UTC)
        findings: list[ContextAssemblyFinding] = []
        if not self._signature_matches(manifest):
            findings.append(
                self._finding(
                    ContextAssemblyCode.MANIFEST_INVALID,
                    Severity.CRITICAL,
                    "Context manifest signature is invalid",
                )
            )
            return ContextAssemblyResult(action=GuardAction.BLOCK, findings=tuple(findings))

        if manifest.issued_at > current + timedelta(
            seconds=self._policy.max_future_skew_seconds
        ) or current - manifest.issued_at > timedelta(
            seconds=self._policy.max_manifest_age_seconds
        ):
            findings.append(
                self._finding(
                    ContextAssemblyCode.MANIFEST_EXPIRED,
                    Severity.CRITICAL,
                    "Context manifest is expired or issued too far in the future",
                )
            )
        if (
            manifest.request_ref != _safe_ref(request_id)
            or manifest.tenant_ref != _safe_ref(tenant_id)
            or manifest.purpose_ref != _safe_ref(purpose)
            or request.request_id != request_id
            or request.tenant_id != tenant_id
            or request.purpose != purpose
        ):
            findings.append(
                self._finding(
                    ContextAssemblyCode.REQUEST_MISMATCH,
                    Severity.CRITICAL,
                    "Context request does not match its trusted request, tenant, or purpose",
                )
            )
        if (
            request.provider_profile != manifest.provider_profile
            or request.adapter_id != manifest.adapter_id
            or request.adapter_version != manifest.adapter_version
        ):
            findings.append(
                self._finding(
                    ContextAssemblyCode.ADAPTER_TRANSFORMATION,
                    Severity.CRITICAL,
                    "Context provider adapter identity or version changed",
                )
            )
        if manifest.policy_digest != self._policy.policy_digest:
            findings.append(
                self._finding(
                    ContextAssemblyCode.POLICY_MISMATCH,
                    Severity.CRITICAL,
                    "Context manifest was issued under another assembly policy",
                )
            )
        if request.request_digest != manifest.request_digest:
            findings.append(
                self._finding(
                    ContextAssemblyCode.ADAPTER_TRANSFORMATION,
                    Severity.CRITICAL,
                    "Context roles, order, data markers, or content changed after assembly",
                )
            )
        findings.extend(self._request_hierarchy_findings(request))
        return ContextAssemblyResult(
            action=GuardAction.BLOCK if findings else GuardAction.ALLOW,
            findings=tuple(findings),
            request=request if not findings else None,
            manifest=manifest if not findings else None,
        )

    def require_provider_request(
        self,
        request: ProviderContextRequest,
        manifest: ContextManifest,
        *,
        request_id: str,
        tenant_id: str,
        purpose: str,
        now: datetime | None = None,
    ) -> ProviderContextRequest:
        """Return the exact verified request or raise before the provider call."""
        result = self.verify_provider_request(
            request,
            manifest,
            request_id=request_id,
            tenant_id=tenant_id,
            purpose=purpose,
            now=now,
        )
        if not result.is_allowed or result.request is None:
            raise ContextAssemblyError(result)
        return result.request

    @property
    def _reserved_tokens(self) -> tuple[str, ...]:
        return (
            *_PROFILE_RESERVED[self._policy.provider_profile],
            *self._policy.extra_reserved_tokens,
        )

    def _structural_findings(
        self,
        segments: tuple[ContextSegment, ...],
        *,
        request_id: str,
        tenant_id: str,
        purpose: str,
    ) -> list[ContextAssemblyFinding]:
        findings: list[ContextAssemblyFinding] = []
        if not request_id.strip() or not tenant_id.strip() or not purpose.strip():
            findings.append(
                self._finding(
                    ContextAssemblyCode.REQUEST_MISMATCH,
                    Severity.CRITICAL,
                    "Request, tenant, and purpose identities must not be blank",
                )
            )
            return findings
        if not segments or len(segments) > self._policy.max_segments:
            findings.append(
                self._finding(
                    ContextAssemblyCode.CONTEXT_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Context has an invalid segment count",
                )
            )
            return findings

        normalized_ids = [
            unicodedata.normalize("NFKC", item.segment_id).casefold() for item in segments
        ]
        if len(normalized_ids) != len(set(normalized_ids)):
            findings.append(
                self._finding(
                    ContextAssemblyCode.DUPLICATE_SEGMENT,
                    Severity.CRITICAL,
                    "Context segment identities are duplicated or normalization-confusable",
                )
            )
        ordinals = [item.ordinal for item in segments]
        if len(ordinals) != len(set(ordinals)):
            findings.append(
                self._finding(
                    ContextAssemblyCode.DUPLICATE_ORDINAL,
                    Severity.CRITICAL,
                    "Context segment ordinals must be unique",
                )
            )
        system = [item for item in segments if item.role == ContextRole.SYSTEM]
        if len(system) > 1:
            findings.append(
                self._finding(
                    ContextAssemblyCode.DUPLICATE_SYSTEM,
                    Severity.CRITICAL,
                    "Context contains more than one system-policy segment",
                    segment_refs=tuple(item.segment_id for item in system),
                )
            )
        elif self._policy.require_system_policy and not system:
            findings.append(
                self._finding(
                    ContextAssemblyCode.MISSING_SYSTEM,
                    Severity.HIGH,
                    "Context requires exactly one trusted system-policy segment",
                )
            )

        total_chars = 0
        for segment in segments:
            refs = (segment.segment_id,)
            total_chars += len(segment.content)
            if len(segment.content) > self._policy.max_segment_chars:
                findings.append(
                    self._finding(
                        ContextAssemblyCode.CONTEXT_LIMIT_EXCEEDED,
                        Severity.HIGH,
                        "Context segment exceeds its character limit",
                        segment_refs=refs,
                        field_paths=("/content",),
                    )
                )
            if sum(1 for _ in _walk(segment.metadata)) > self._policy.max_metadata_nodes:
                findings.append(
                    self._finding(
                        ContextAssemblyCode.CONTEXT_LIMIT_EXCEEDED,
                        Severity.HIGH,
                        "Context segment metadata exceeds its node limit",
                        segment_refs=refs,
                        field_paths=("/metadata",),
                    )
                )
            if segment.tenant_id != tenant_id:
                findings.append(
                    self._finding(
                        ContextAssemblyCode.TENANT_MISMATCH,
                        Severity.CRITICAL,
                        "Context segment belongs to another tenant",
                        segment_refs=refs,
                    )
                )
            if segment.purpose != purpose:
                findings.append(
                    self._finding(
                        ContextAssemblyCode.PURPOSE_MISMATCH,
                        Severity.CRITICAL,
                        "Context segment is not authorized for this purpose",
                        segment_refs=refs,
                    )
                )
            if not self._hierarchy_valid(segment):
                findings.append(
                    self._finding(
                        ContextAssemblyCode.INVALID_HIERARCHY,
                        Severity.CRITICAL,
                        "Context origin, role, trust, and instruction permission conflict",
                        segment_refs=refs,
                    )
                )
        if total_chars > self._policy.max_total_chars:
            findings.append(
                self._finding(
                    ContextAssemblyCode.CONTEXT_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Context exceeds its total character limit",
                )
            )
        return findings

    @staticmethod
    def _hierarchy_valid(segment: ContextSegment) -> bool:
        expected = _EXPECTED_HIERARCHY.get(segment.origin)
        if expected is not None:
            return (segment.role, segment.trust_level, segment.instruction_permission) == expected
        return (
            segment.origin in _DATA_ORIGINS
            and segment.role == ContextRole.DATA
            and segment.instruction_permission == InstructionPermission.NONE
        )

    def _content_findings(
        self, segment: ContextSegment, tokens: tuple[str, ...]
    ) -> list[ContextAssemblyFinding]:
        findings: list[ContextAssemblyFinding] = []
        folded = unicodedata.normalize("NFKC", segment.content).casefold()
        if _contains_unicode_smuggling(segment.content):
            findings.append(
                self._finding(
                    ContextAssemblyCode.UNICODE_SMUGGLING,
                    Severity.CRITICAL,
                    "Context contains invisible or directional Unicode controls",
                    segment_refs=(segment.segment_id,),
                    field_paths=("/content",),
                )
            )
        if any(unicodedata.normalize("NFKC", token).casefold() in folded for token in tokens):
            findings.append(
                self._finding(
                    ContextAssemblyCode.RESERVED_TOKEN,
                    Severity.CRITICAL,
                    "Context contains a provider-reserved token",
                    segment_refs=(segment.segment_id,),
                    field_paths=("/content",),
                )
            )
        normalized = unicodedata.normalize("NFKC", segment.content)
        if self._policy.reject_synthetic_role_boundaries and any(
            pattern.search(normalized) for pattern in _SYNTHETIC_ROLE_PATTERNS
        ):
            findings.append(
                self._finding(
                    ContextAssemblyCode.SYNTHETIC_ROLE_BOUNDARY,
                    Severity.CRITICAL,
                    "Context contains a synthetic role boundary",
                    segment_refs=(segment.segment_id,),
                    field_paths=("/content",),
                )
            )
        if self._policy.reject_template_syntax and any(
            marker in normalized for marker in _TEMPLATE_MARKERS
        ):
            findings.append(
                self._finding(
                    ContextAssemblyCode.TEMPLATE_INJECTION,
                    Severity.HIGH,
                    "Context contains unresolved template syntax",
                    segment_refs=(segment.segment_id,),
                    field_paths=("/content",),
                )
            )
        return findings

    @staticmethod
    def _message(segment: ContextSegment) -> ContextMessage:
        if segment.role == ContextRole.DATA:
            content = "\n".join(
                (
                    _DATA_BEGIN,
                    f"origin={segment.origin.value}",
                    "instruction_permission=none",
                    f"content_json={json.dumps(segment.content, ensure_ascii=True)}",
                    _DATA_END,
                )
            )
            role: str = "user"
            is_data = True
        else:
            content = segment.content
            role = segment.role.value
            is_data = False
        return ContextMessage(
            role=role,  # type: ignore[arg-type]
            content=content,
            origin=segment.origin,
            trust_level=segment.trust_level,
            instruction_permission=segment.instruction_permission,
            is_data=is_data,
            segment_ref=_safe_ref(segment.segment_id),
        )

    def _manifest(
        self,
        segments: tuple[ContextSegment, ...],
        request: ProviderContextRequest,
        issued_at: datetime,
    ) -> ContextManifest:
        fingerprints = tuple(self._fingerprint(item) for item in segments)
        unsigned = ContextManifest(
            provider_profile=request.provider_profile,
            request_ref=_safe_ref(request.request_id),
            tenant_ref=_safe_ref(request.tenant_id),
            purpose_ref=_safe_ref(request.purpose),
            policy_digest=self._policy.policy_digest,
            segment_fingerprints=fingerprints,
            request_digest=request.request_digest,
            issued_at=issued_at,
            signature="0" * 64,
        )
        return unsigned.model_copy(update={"signature": self._signature(unsigned)})

    @staticmethod
    def _fingerprint(segment: ContextSegment) -> ContextSegmentFingerprint:
        return ContextSegmentFingerprint(
            segment_ref=_safe_ref(segment.segment_id),
            ordinal=segment.ordinal,
            origin=segment.origin,
            role=segment.role,
            trust_level=segment.trust_level,
            instruction_permission=segment.instruction_permission,
            tenant_ref=_safe_ref(segment.tenant_id),
            purpose_ref=_safe_ref(segment.purpose),
            provenance_ref=_safe_ref(segment.provenance_id),
            content_digest=hashlib.sha256(
                unicodedata.normalize("NFC", segment.content).encode()
            ).hexdigest(),
            metadata_digest=context_digest(segment.metadata),
        )

    def _signature(self, manifest: ContextManifest) -> str:
        encoded = canonical_context_json(manifest_signing_payload(manifest)).encode()
        return hmac.new(self._key, encoded, hashlib.sha256).hexdigest()

    def _signature_matches(self, manifest: ContextManifest) -> bool:
        return hmac.compare_digest(manifest.signature, self._signature(manifest))

    def _request_hierarchy_findings(
        self, request: ProviderContextRequest
    ) -> list[ContextAssemblyFinding]:
        findings: list[ContextAssemblyFinding] = []
        previous_rank = -1
        system_count = 0
        seen_refs: set[str] = set()
        for index, message in enumerate(request.messages):
            if message.segment_ref in seen_refs:
                findings.append(
                    self._finding(
                        ContextAssemblyCode.DUPLICATE_SEGMENT,
                        Severity.CRITICAL,
                        "Provider request duplicates a context segment",
                    )
                )
            seen_refs.add(message.segment_ref)
            if message.origin == ContextOrigin.SYSTEM_POLICY:
                rank = 0
                system_count += 1
                valid = (
                    message.role == "system"
                    and not message.is_data
                    and message.trust_level == TrustLevel.TRUSTED
                    and message.instruction_permission == InstructionPermission.SYSTEM
                )
            elif message.origin == ContextOrigin.DEVELOPER:
                rank = 1
                valid = (
                    message.role == "developer"
                    and not message.is_data
                    and message.trust_level == TrustLevel.TRUSTED
                    and message.instruction_permission == InstructionPermission.DEVELOPER
                )
            elif message.origin == ContextOrigin.USER:
                rank = 2
                valid = (
                    message.role == "user"
                    and not message.is_data
                    and message.trust_level == TrustLevel.UNTRUSTED
                    and message.instruction_permission == InstructionPermission.USER
                )
            else:
                rank = 3
                valid = (
                    message.origin in _DATA_ORIGINS
                    and message.role == "user"
                    and message.is_data
                    and message.instruction_permission == InstructionPermission.NONE
                    and message.content.startswith(f"{_DATA_BEGIN}\n")
                    and message.content.endswith(f"\n{_DATA_END}")
                )
            if not valid or rank < previous_rank:
                findings.append(
                    self._finding(
                        ContextAssemblyCode.INVALID_HIERARCHY,
                        Severity.CRITICAL,
                        "Provider request changed a role, trust zone, or hierarchy order",
                        field_paths=(f"/messages/{index}",),
                    )
                )
            previous_rank = rank
        if self._policy.require_system_policy and system_count != 1:
            findings.append(
                self._finding(
                    ContextAssemblyCode.DUPLICATE_SYSTEM,
                    Severity.CRITICAL,
                    "Provider request must contain exactly one system-policy message",
                )
            )
        return findings

    @staticmethod
    def _finding(
        code: ContextAssemblyCode,
        severity: Severity,
        message: str,
        *,
        segment_refs: tuple[str, ...] = (),
        field_paths: tuple[str, ...] = (),
    ) -> ContextAssemblyFinding:
        return ContextAssemblyFinding(
            code=code,
            severity=severity,
            message=message,
            segment_refs=tuple(_safe_ref(item) for item in segment_refs),
            field_paths=field_paths,
        )
