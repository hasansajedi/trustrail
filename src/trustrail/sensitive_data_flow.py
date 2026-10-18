"""Signed sensitive-data flow tracking and sink enforcement."""

from __future__ import annotations

import contextlib
import threading
from collections import deque
from collections.abc import Iterable
from datetime import datetime
from typing import Protocol, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustrail.exceptions import SensitiveDataFlowError
from trustrail.models.data_labels import data_label_digest, data_label_reference, utcnow
from trustrail.models.data_lifecycle import DataClassification
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.sensitive_data_flow import (
    AuthorizedSensitiveDataTransfer,
    DataFlowTransformation,
    DeclassificationGrant,
    SensitiveDataDeclassificationRequest,
    SensitiveDataDerivationRequest,
    SensitiveDataFlowAuditEvent,
    SensitiveDataFlowCode,
    SensitiveDataFlowDecision,
    SensitiveDataFlowEvidence,
    SensitiveDataFlowFinding,
    SensitiveDataFlowLabel,
    SensitiveDataFlowTrustedKey,
    SensitiveDataSink,
    SensitiveDataSurface,
    SensitiveDataTransferRequest,
)

_CLASSIFICATION_RANK = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}


class SensitiveDataFlowAuditSink(Protocol):
    """Persist content-free sensitive-data flow decisions."""

    def emit(self, event: SensitiveDataFlowAuditEvent) -> None: ...


class MemorySensitiveDataFlowAuditSink:
    """Bounded process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[SensitiveDataFlowAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: SensitiveDataFlowAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[SensitiveDataFlowAuditEvent]:
        with self._lock:
            return list(self._events)


class SensitiveDataFlowSigner:
    """Issue signed origin labels or independently authorized declassifications."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        issuer_id: str,
        allowed_tenant_ids: frozenset[str],
        can_declassify: bool = False,
    ) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = SensitiveDataFlowTrustedKey(
            issuer_id=issuer_id,
            public_key=public_key,
            allowed_tenant_ids=allowed_tenant_ids,
            can_declassify=can_declassify,
        )

    @classmethod
    def generate(
        cls,
        *,
        issuer_id: str,
        allowed_tenant_ids: frozenset[str],
        can_declassify: bool = False,
    ) -> SensitiveDataFlowSigner:
        """Create a signer backed by a new Ed25519 key pair."""
        return cls(
            Ed25519PrivateKey.generate(),
            issuer_id=issuer_id,
            allowed_tenant_ids=allowed_tenant_ids,
            can_declassify=can_declassify,
        )

    @property
    def trusted_key(self) -> SensitiveDataFlowTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def issue(
        self,
        *,
        label_id: str,
        artifact_id: str,
        surface: SensitiveDataSurface,
        content_digest: str,
        origin_ids: frozenset[str],
        origin_trust_domains: frozenset[str],
        tenant_id: str,
        user_id: str,
        allowed_purpose_ids: frozenset[str],
        sensitivity: DataClassification,
        allowed_sink_kinds: frozenset[SensitiveDataSink],
        allowed_sink_ids: frozenset[str],
        expires_at: datetime,
        issued_at: datetime | None = None,
    ) -> SensitiveDataFlowLabel:
        """Issue a signed origin label for exact content."""
        if tenant_id not in self._trusted_key.allowed_tenant_ids:
            raise ValueError("flow signer is not authorized for the tenant")
        current_time = issued_at or utcnow()
        unsigned = SensitiveDataFlowLabel(
            label_id=label_id,
            issuer_id=self._trusted_key.issuer_id,
            key_id=self._trusted_key.key_id,
            artifact_ref=data_label_reference(artifact_id),
            surface=surface,
            content_digest=content_digest,
            origin_refs=frozenset(data_label_reference(value) for value in origin_ids),
            origin_trust_domains=origin_trust_domains,
            tenant_id=tenant_id,
            user_ref=data_label_reference(user_id),
            allowed_purpose_ids=allowed_purpose_ids,
            sensitivity=sensitivity,
            allowed_sink_kinds=allowed_sink_kinds,
            allowed_sink_ids=allowed_sink_ids,
            transformations_seen=frozenset({DataFlowTransformation.ORIGIN}),
            last_transformation=DataFlowTransformation.ORIGIN,
            lineage_depth=0,
            issued_at=current_time,
            expires_at=expires_at,
        )
        return self._sign_label(unsigned)

    def issue_declassification(
        self,
        *,
        grant_id: str,
        source_label: SensitiveDataFlowLabel,
        output_content_digest: str,
        target_sensitivity: DataClassification,
        allowed_purpose_ids: frozenset[str],
        allowed_sink_kinds: frozenset[SensitiveDataSink],
        allowed_sink_ids: frozenset[str],
        justification_id: str,
        expires_at: datetime,
        issued_at: datetime | None = None,
    ) -> DeclassificationGrant:
        """Issue a grant bound to one source label and exact transformed output."""
        if not self._trusted_key.can_declassify:
            raise ValueError("signer is not a declassification authority")
        if source_label.tenant_id not in self._trusted_key.allowed_tenant_ids:
            raise ValueError("declassification authority is not authorized for the tenant")
        unsigned = DeclassificationGrant(
            grant_id=grant_id,
            issuer_id=self._trusted_key.issuer_id,
            key_id=self._trusted_key.key_id,
            tenant_id=source_label.tenant_id,
            user_ref=source_label.user_ref,
            source_label_digest=source_label.label_digest,
            output_content_digest=output_content_digest,
            target_sensitivity=target_sensitivity,
            allowed_purpose_ids=allowed_purpose_ids,
            allowed_sink_kinds=allowed_sink_kinds,
            allowed_sink_ids=allowed_sink_ids,
            justification_ref=data_label_reference(justification_id),
            issued_at=issued_at or utcnow(),
            expires_at=expires_at,
        )
        signature = self._private_key.sign(unsigned.signing_bytes).hex()
        return unsigned.model_copy(update={"signature": signature})

    def _sign_label(self, label: SensitiveDataFlowLabel) -> SensitiveDataFlowLabel:
        signature = self._private_key.sign(label.signing_bytes).hex()
        return label.model_copy(update={"signature": signature})


class SensitiveDataFlowVerifier:
    """Verify label and declassification authority independently of producers."""

    def __init__(self, trusted_keys: Iterable[SensitiveDataFlowTrustedKey]) -> None:
        self._keys = {key.key_id: key for key in trusted_keys}

    def label_findings(
        self,
        label: SensitiveDataFlowLabel,
        *,
        now: datetime,
    ) -> list[SensitiveDataFlowFinding]:
        return self._verify_signed(
            key_id=label.key_id,
            issuer_id=label.issuer_id,
            tenant_id=label.tenant_id,
            signature=label.signature,
            signing_bytes=label.signing_bytes,
            issued_at=label.issued_at,
            expires_at=label.expires_at,
            now=now,
            require_declassification=False,
        )

    def grant_findings(
        self,
        grant: DeclassificationGrant,
        *,
        now: datetime,
    ) -> list[SensitiveDataFlowFinding]:
        return self._verify_signed(
            key_id=grant.key_id,
            issuer_id=grant.issuer_id,
            tenant_id=grant.tenant_id,
            signature=grant.signature,
            signing_bytes=grant.signing_bytes,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            now=now,
            require_declassification=True,
        )

    def _verify_signed(
        self,
        *,
        key_id: str,
        issuer_id: str,
        tenant_id: str,
        signature: str | None,
        signing_bytes: bytes,
        issued_at: datetime,
        expires_at: datetime,
        now: datetime,
        require_declassification: bool,
    ) -> list[SensitiveDataFlowFinding]:
        key = self._keys.get(key_id)
        if key is None or key.revoked:
            return [_finding(SensitiveDataFlowCode.LABEL_KEY_UNKNOWN, Severity.CRITICAL)]
        if (
            key.issuer_id != issuer_id
            or tenant_id not in key.allowed_tenant_ids
            or (require_declassification and not key.can_declassify)
        ):
            code = (
                SensitiveDataFlowCode.DECLASSIFICATION_INVALID
                if require_declassification
                else SensitiveDataFlowCode.LABEL_KEY_UNKNOWN
            )
            return [_finding(code, Severity.CRITICAL)]
        if key.active_from is not None and now < key.active_from:
            return [_finding(SensitiveDataFlowCode.LABEL_KEY_UNKNOWN, Severity.CRITICAL)]
        if key.expires_at is not None and now >= key.expires_at:
            return [_finding(SensitiveDataFlowCode.LABEL_KEY_UNKNOWN, Severity.CRITICAL)]
        if now < issued_at:
            return [_finding(SensitiveDataFlowCode.LABEL_NOT_YET_VALID, Severity.HIGH)]
        if now >= expires_at:
            code = (
                SensitiveDataFlowCode.DECLASSIFICATION_EXPIRED
                if require_declassification
                else SensitiveDataFlowCode.LABEL_EXPIRED
            )
            return [_finding(code, Severity.HIGH)]
        if signature is None:
            code = (
                SensitiveDataFlowCode.DECLASSIFICATION_INVALID
                if require_declassification
                else SensitiveDataFlowCode.LABEL_SIGNATURE_INVALID
            )
            return [_finding(code, Severity.CRITICAL)]
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(signature), signing_bytes
            )
        except (InvalidSignature, ValueError):
            code = (
                SensitiveDataFlowCode.DECLASSIFICATION_INVALID
                if require_declassification
                else SensitiveDataFlowCode.LABEL_SIGNATURE_INVALID
            )
            return [_finding(code, Severity.CRITICAL)]
        return []


class SensitiveDataFlowPropagator:
    """Conservatively propagate labels and apply authenticated declassification."""

    def __init__(
        self,
        signer: SensitiveDataFlowSigner,
        trusted_label_keys: Iterable[SensitiveDataFlowTrustedKey],
        *,
        declassification_keys: Iterable[SensitiveDataFlowTrustedKey] = (),
        audit_sink: SensitiveDataFlowAuditSink | None = None,
    ) -> None:
        self._signer = signer
        self._verifier = SensitiveDataFlowVerifier(trusted_label_keys)
        self._declassification_verifier = SensitiveDataFlowVerifier(declassification_keys)
        self._audit_sink = audit_sink

    def propagate(
        self,
        request: SensitiveDataDerivationRequest,
        *,
        now: datetime | None = None,
    ) -> SensitiveDataFlowDecision:
        """Join all source authority without allowing encoding or hop laundering."""
        current_time = now or utcnow()
        findings = self._source_findings(request.source_labels, current_time)
        if not findings:
            findings.extend(_source_conflicts(request.source_labels))
        if request.source_labels and (
            request.source_labels[0].tenant_id not in self._signer.trusted_key.allowed_tenant_ids
            or request.issued_at < max(source.issued_at for source in request.source_labels)
            or request.issued_at > current_time
        ):
            findings.append(_finding(SensitiveDataFlowCode.LINEAGE_MISMATCH))
        label = None
        if not findings:
            label = self._derive(request)
        return self._decision(
            request_id=request.request_id,
            findings=findings,
            label=label,
            source_count=len(request.source_labels),
            now=current_time,
        )

    def require_propagation(
        self,
        request: SensitiveDataDerivationRequest,
        *,
        now: datetime | None = None,
    ) -> SensitiveDataFlowLabel:
        """Return a derived label or raise before transformed data can continue."""
        result = self.propagate(request, now=now)
        if result.derived_label is None:
            raise SensitiveDataFlowError(result)
        return result.derived_label

    def declassify(
        self,
        request: SensitiveDataDeclassificationRequest,
        *,
        now: datetime | None = None,
    ) -> SensitiveDataFlowDecision:
        """Apply a separately signed grant to one exact transformed output."""
        current_time = now or utcnow()
        source = request.source_label
        grant = request.grant
        findings = self._verifier.label_findings(source, now=current_time)
        findings.extend(self._declassification_verifier.grant_findings(grant, now=current_time))
        if (
            grant.source_label_digest != source.label_digest
            or grant.output_content_digest != request.output_content_digest
            or grant.tenant_id != source.tenant_id
            or grant.user_ref != source.user_ref
            or request.issued_at < grant.issued_at
            or request.issued_at < source.issued_at
            or request.issued_at > current_time
            or source.tenant_id not in self._signer.trusted_key.allowed_tenant_ids
        ):
            findings.append(_finding(SensitiveDataFlowCode.DECLASSIFICATION_INVALID))
        label = None
        if not findings:
            lineage = _lineage((source,))
            unsigned = SensitiveDataFlowLabel(
                label_id=request.label_id,
                issuer_id=self._signer.trusted_key.issuer_id,
                key_id=self._signer.trusted_key.key_id,
                artifact_ref=data_label_reference(request.artifact_id),
                surface=request.surface,
                content_digest=request.output_content_digest,
                origin_refs=source.origin_refs,
                origin_trust_domains=source.origin_trust_domains,
                tenant_id=source.tenant_id,
                user_ref=source.user_ref,
                allowed_purpose_ids=grant.allowed_purpose_ids,
                sensitivity=grant.target_sensitivity,
                allowed_sink_kinds=grant.allowed_sink_kinds,
                allowed_sink_ids=grant.allowed_sink_ids,
                source_label_digests=lineage.sources,
                ancestor_label_digests=lineage.ancestors,
                transformations_seen=source.transformations_seen
                | {DataFlowTransformation.DECLASSIFY},
                last_transformation=DataFlowTransformation.DECLASSIFY,
                lineage_depth=source.lineage_depth + 1,
                declassification_grant_digests=tuple(
                    sorted({*source.declassification_grant_digests, grant.grant_digest})
                ),
                issued_at=request.issued_at,
                expires_at=min(source.expires_at, grant.expires_at),
            )
            label = self._signer._sign_label(unsigned)
        return self._decision(
            request_id=request.request_id,
            findings=findings,
            label=label,
            source_count=1,
            now=current_time,
        )

    def require_declassification(
        self,
        request: SensitiveDataDeclassificationRequest,
        *,
        now: datetime | None = None,
    ) -> SensitiveDataFlowLabel:
        """Return an authenticated declassified label or raise."""
        result = self.declassify(request, now=now)
        if result.derived_label is None:
            raise SensitiveDataFlowError(result)
        return result.derived_label

    def _derive(self, request: SensitiveDataDerivationRequest) -> SensitiveDataFlowLabel:
        sources = request.source_labels
        lineage = _lineage(sources)
        unsigned = SensitiveDataFlowLabel(
            label_id=request.label_id,
            issuer_id=self._signer.trusted_key.issuer_id,
            key_id=self._signer.trusted_key.key_id,
            artifact_ref=data_label_reference(request.artifact_id),
            surface=request.surface,
            content_digest=request.content_digest,
            origin_refs=frozenset().union(*(source.origin_refs for source in sources)),
            origin_trust_domains=frozenset().union(
                *(source.origin_trust_domains for source in sources)
            ),
            tenant_id=sources[0].tenant_id,
            user_ref=sources[0].user_ref,
            allowed_purpose_ids=frozenset(_intersection(s.allowed_purpose_ids for s in sources)),
            sensitivity=max(
                (source.sensitivity for source in sources),
                key=_CLASSIFICATION_RANK.__getitem__,
            ),
            allowed_sink_kinds=frozenset(_intersection(s.allowed_sink_kinds for s in sources)),
            allowed_sink_ids=frozenset(_intersection(s.allowed_sink_ids for s in sources)),
            source_label_digests=lineage.sources,
            ancestor_label_digests=lineage.ancestors,
            transformations_seen=frozenset().union(
                *(source.transformations_seen for source in sources), {request.transformation}
            ),
            last_transformation=request.transformation,
            lineage_depth=max(source.lineage_depth for source in sources) + 1,
            declassification_grant_digests=tuple(
                sorted(set().union(*(source.declassification_grant_digests for source in sources)))
            ),
            issued_at=request.issued_at,
            expires_at=min(source.expires_at for source in sources),
        )
        return self._signer._sign_label(unsigned)

    def _source_findings(
        self,
        sources: tuple[SensitiveDataFlowLabel, ...],
        now: datetime,
    ) -> list[SensitiveDataFlowFinding]:
        findings: list[SensitiveDataFlowFinding] = []
        for source in sources:
            findings.extend(self._verifier.label_findings(source, now=now))
        return findings

    def _decision(
        self,
        *,
        request_id: str,
        findings: list[SensitiveDataFlowFinding],
        label: SensitiveDataFlowLabel | None,
        source_count: int,
        now: datetime,
    ) -> SensitiveDataFlowDecision:
        action = GuardAction.ALLOW if label is not None else GuardAction.BLOCK
        code = SensitiveDataFlowCode.ALLOWED if label is not None else findings[0].code
        audit = _audit(code, action, request_id, label, None, now)
        self._publish(audit)
        return SensitiveDataFlowDecision(
            action=action,
            findings=tuple(_deduplicate(findings)),
            derived_label=label,
            evidence=_evidence(label, source_count=source_count),
            audit_event=audit,
        )

    def _publish(self, event: SensitiveDataFlowAuditEvent) -> None:
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)


class SensitiveDataFlowGuard:
    """Fail closed before network, message, file, model, tenant, or MCP sinks."""

    def __init__(
        self,
        trusted_label_keys: Iterable[SensitiveDataFlowTrustedKey],
        *,
        declassification_keys: Iterable[SensitiveDataFlowTrustedKey] = (),
        audit_sink: SensitiveDataFlowAuditSink | None = None,
    ) -> None:
        self._verifier = SensitiveDataFlowVerifier(trusted_label_keys)
        self._declassification_verifier = SensitiveDataFlowVerifier(declassification_keys)
        self._audit_sink = audit_sink

    def authorize(
        self,
        request: SensitiveDataTransferRequest,
        *,
        now: datetime | None = None,
    ) -> SensitiveDataFlowDecision:
        """Authorize one exact labeled transfer at a fully mediated sink."""
        current_time = now or utcnow()
        label = request.label
        findings: list[SensitiveDataFlowFinding] = []
        if label is None:
            findings.append(_finding(SensitiveDataFlowCode.LABEL_MISSING))
        else:
            findings.extend(self._verifier.label_findings(label, now=current_time))
            findings.extend(_binding_findings(request, label))
            findings.extend(self._lineage_findings(request, label, current_time))

        permit = None
        if label is not None and not findings:
            permit = AuthorizedSensitiveDataTransfer(
                authorization_id=data_label_digest(
                    {
                        "request": request.request_digest,
                        "label": label.label_digest,
                        "sink": request.destination.sink_id,
                    }
                ),
                request_digest=request.request_digest,
                label_digest=label.label_digest,
                sink_ref=data_label_reference(request.destination.sink_id),
                sink_kind=request.destination.sink_kind,
            )
        action = GuardAction.ALLOW if permit else GuardAction.BLOCK
        code = SensitiveDataFlowCode.ALLOWED if permit else findings[0].code
        audit = _audit(
            code,
            action,
            request.request_id,
            label,
            request.destination.sink_id,
            current_time,
        )
        self._publish(audit)
        return SensitiveDataFlowDecision(
            action=action,
            findings=tuple(_deduplicate(findings)),
            permit=permit,
            evidence=_evidence(
                label,
                sink_id=request.destination.sink_id,
                source_count=len(request.source_labels),
            ),
            audit_event=audit,
        )

    def require(
        self,
        request: SensitiveDataTransferRequest,
        *,
        now: datetime | None = None,
    ) -> AuthorizedSensitiveDataTransfer:
        """Return an exact sink permit or raise before disclosure."""
        result = self.authorize(request, now=now)
        if result.permit is None:
            raise SensitiveDataFlowError(result)
        return result.permit

    def _lineage_findings(
        self,
        request: SensitiveDataTransferRequest,
        label: SensitiveDataFlowLabel,
        now: datetime,
    ) -> list[SensitiveDataFlowFinding]:
        sources = request.source_labels
        if label.source_label_digests and not sources:
            return [_finding(SensitiveDataFlowCode.LINEAGE_MISSING)]
        if not label.source_label_digests and sources:
            return [_finding(SensitiveDataFlowCode.LINEAGE_MISMATCH)]
        findings: list[SensitiveDataFlowFinding] = []
        for source in sources:
            findings.extend(self._verifier.label_findings(source, now=now))
        if sources:
            lineage = _lineage(sources)
            if (
                lineage.sources != label.source_label_digests
                or lineage.ancestors != label.ancestor_label_digests
                or max(source.lineage_depth for source in sources) + 1 != label.lineage_depth
            ):
                findings.append(_finding(SensitiveDataFlowCode.LINEAGE_MISMATCH))
            findings.extend(self._declassification_lineage_findings(request, label, sources, now))
            if label.last_transformation != DataFlowTransformation.DECLASSIFY:
                findings.extend(_policy_expansion_findings(label, sources))
        elif request.declassification_grants:
            findings.append(_finding(SensitiveDataFlowCode.DECLASSIFICATION_INVALID))
        return findings

    def _declassification_lineage_findings(
        self,
        request: SensitiveDataTransferRequest,
        label: SensitiveDataFlowLabel,
        sources: tuple[SensitiveDataFlowLabel, ...],
        now: datetime,
    ) -> list[SensitiveDataFlowFinding]:
        expected = label.declassification_grant_digests
        supplied = tuple(sorted(grant.grant_digest for grant in request.declassification_grants))
        if expected != supplied:
            code = (
                SensitiveDataFlowCode.DECLASSIFICATION_REQUIRED
                if expected and not supplied
                else SensitiveDataFlowCode.DECLASSIFICATION_INVALID
            )
            return [_finding(code)]
        findings: list[SensitiveDataFlowFinding] = []
        for grant in request.declassification_grants:
            findings.extend(self._declassification_verifier.grant_findings(grant, now=now))
            if (
                grant.source_label_digest not in label.ancestor_label_digests
                or grant.tenant_id != label.tenant_id
                or grant.user_ref != label.user_ref
            ):
                findings.append(_finding(SensitiveDataFlowCode.DECLASSIFICATION_INVALID))
        if label.last_transformation == DataFlowTransformation.DECLASSIFY:
            if len(sources) != 1 or len(request.declassification_grants) < 1:
                findings.append(_finding(SensitiveDataFlowCode.DECLASSIFICATION_REQUIRED))
                return findings
            source = sources[0]
            current_grants = [
                grant
                for grant in request.declassification_grants
                if grant.grant_digest not in source.declassification_grant_digests
            ]
            if len(current_grants) != 1:
                findings.append(_finding(SensitiveDataFlowCode.DECLASSIFICATION_INVALID))
                return findings
            grant = current_grants[0]
            if (
                grant.source_label_digest != source.label_digest
                or grant.output_content_digest != label.content_digest
                or grant.target_sensitivity != label.sensitivity
                or grant.allowed_purpose_ids != label.allowed_purpose_ids
                or grant.allowed_sink_kinds != label.allowed_sink_kinds
                or grant.allowed_sink_ids != label.allowed_sink_ids
            ):
                findings.append(_finding(SensitiveDataFlowCode.DECLASSIFICATION_INVALID))
        return findings

    def _publish(self, event: SensitiveDataFlowAuditEvent) -> None:
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)


def _binding_findings(
    request: SensitiveDataTransferRequest,
    label: SensitiveDataFlowLabel,
) -> list[SensitiveDataFlowFinding]:
    findings: list[SensitiveDataFlowFinding] = []
    if request.content_digest != label.content_digest:
        findings.append(_finding(SensitiveDataFlowCode.CONTENT_BINDING_INVALID))
    if (
        request.authenticated_tenant_id != label.tenant_id
        or request.destination.tenant_id != label.tenant_id
    ):
        findings.append(_finding(SensitiveDataFlowCode.TENANT_CONFLICT))
    if request.authenticated_user_ref != label.user_ref:
        findings.append(_finding(SensitiveDataFlowCode.USER_CONFLICT))
    if request.purpose_id not in label.allowed_purpose_ids:
        findings.append(_finding(SensitiveDataFlowCode.PURPOSE_DENIED))
    if (
        request.destination.sink_kind not in label.allowed_sink_kinds
        or request.destination.sink_id not in label.allowed_sink_ids
    ):
        findings.append(_finding(SensitiveDataFlowCode.SINK_DENIED))
    return findings


def _source_conflicts(
    sources: tuple[SensitiveDataFlowLabel, ...],
) -> list[SensitiveDataFlowFinding]:
    findings: list[SensitiveDataFlowFinding] = []
    if len({source.label_digest for source in sources}) != len(sources):
        findings.append(_finding(SensitiveDataFlowCode.LINEAGE_MISMATCH))
    if len({source.tenant_id for source in sources}) != 1:
        findings.append(_finding(SensitiveDataFlowCode.TENANT_CONFLICT))
    if len({source.user_ref for source in sources}) != 1:
        findings.append(_finding(SensitiveDataFlowCode.USER_CONFLICT))
    if not _intersection(source.allowed_purpose_ids for source in sources):
        findings.append(_finding(SensitiveDataFlowCode.PURPOSE_DENIED))
    if not _intersection(source.allowed_sink_kinds for source in sources) or not _intersection(
        source.allowed_sink_ids for source in sources
    ):
        findings.append(_finding(SensitiveDataFlowCode.SINK_DENIED))
    if max(source.lineage_depth for source in sources) >= 128:
        findings.append(_finding(SensitiveDataFlowCode.LINEAGE_LIMIT_EXCEEDED))
    return findings


def _policy_expansion_findings(
    label: SensitiveDataFlowLabel,
    sources: tuple[SensitiveDataFlowLabel, ...],
) -> list[SensitiveDataFlowFinding]:
    expected_transforms = frozenset().union(
        *(source.transformations_seen for source in sources)
    ) | {label.last_transformation}
    if (
        label.tenant_id != sources[0].tenant_id
        or label.user_ref != sources[0].user_ref
        or label.origin_refs != frozenset().union(*(source.origin_refs for source in sources))
        or label.origin_trust_domains
        != frozenset().union(*(source.origin_trust_domains for source in sources))
        or label.allowed_purpose_ids
        != frozenset(_intersection(source.allowed_purpose_ids for source in sources))
        or label.allowed_sink_kinds
        != frozenset(_intersection(source.allowed_sink_kinds for source in sources))
        or label.allowed_sink_ids
        != frozenset(_intersection(source.allowed_sink_ids for source in sources))
        or label.sensitivity
        != max((source.sensitivity for source in sources), key=_CLASSIFICATION_RANK.__getitem__)
        or label.transformations_seen != expected_transforms
        or label.expires_at != min(source.expires_at for source in sources)
        or label.declassification_grant_digests
        != tuple(
            sorted(set().union(*(source.declassification_grant_digests for source in sources)))
        )
    ):
        return [_finding(SensitiveDataFlowCode.POLICY_EXPANSION)]
    return []


class _Lineage:
    def __init__(self, sources: tuple[str, ...], ancestors: tuple[str, ...]) -> None:
        self.sources = sources
        self.ancestors = ancestors


def _lineage(sources: tuple[SensitiveDataFlowLabel, ...]) -> _Lineage:
    immediate = tuple(sorted(source.label_digest for source in sources))
    ancestors = tuple(
        sorted(
            set(immediate).union(
                *(source.ancestor_label_digests for source in sources),
            )
        )
    )
    return _Lineage(immediate, ancestors)


_T = TypeVar("_T")


def _intersection(values: Iterable[frozenset[_T]]) -> set[_T]:
    iterator = iter(values)
    try:
        result = set(next(iterator))
    except StopIteration:
        return set()
    for value in iterator:
        result.intersection_update(value)
    return result


def _finding(
    code: SensitiveDataFlowCode,
    severity: Severity = Severity.CRITICAL,
) -> SensitiveDataFlowFinding:
    messages = {
        SensitiveDataFlowCode.ALLOWED: "Sensitive-data flow is authorized",
        SensitiveDataFlowCode.LABEL_MISSING: "Sensitive content is missing a flow label",
        SensitiveDataFlowCode.LABEL_KEY_UNKNOWN: "Flow authority is not trusted",
        SensitiveDataFlowCode.LABEL_SIGNATURE_INVALID: "Flow label signature is invalid",
        SensitiveDataFlowCode.LABEL_NOT_YET_VALID: "Flow authority is not yet valid",
        SensitiveDataFlowCode.LABEL_EXPIRED: "Flow label has expired",
        SensitiveDataFlowCode.CONTENT_BINDING_INVALID: "Label is not bound to transferred content",
        SensitiveDataFlowCode.TENANT_CONFLICT: "Flow crosses a tenant boundary",
        SensitiveDataFlowCode.USER_CONFLICT: "Flow changes authenticated user authority",
        SensitiveDataFlowCode.PURPOSE_DENIED: "Purpose is not permitted by every source",
        SensitiveDataFlowCode.SINK_DENIED: "Sink is not permitted by every source",
        SensitiveDataFlowCode.LINEAGE_MISSING: "Required immediate lineage is missing",
        SensitiveDataFlowCode.LINEAGE_MISMATCH: "Supplied lineage does not match the signed label",
        SensitiveDataFlowCode.POLICY_EXPANSION: "Derived flow weakens source restrictions",
        SensitiveDataFlowCode.DECLASSIFICATION_REQUIRED: (
            "Authenticated declassification is required"
        ),
        SensitiveDataFlowCode.DECLASSIFICATION_INVALID: (
            "Declassification grant is invalid or rebound"
        ),
        SensitiveDataFlowCode.DECLASSIFICATION_EXPIRED: "Declassification grant has expired",
        SensitiveDataFlowCode.LINEAGE_LIMIT_EXCEEDED: "Maximum flow lineage depth is exceeded",
    }
    return SensitiveDataFlowFinding(code=code, severity=severity, message=messages[code])


def _deduplicate(
    findings: list[SensitiveDataFlowFinding],
) -> list[SensitiveDataFlowFinding]:
    return list({finding.code: finding for finding in reversed(findings)}.values())[::-1]


def _evidence(
    label: SensitiveDataFlowLabel | None,
    *,
    source_count: int,
    sink_id: str | None = None,
) -> SensitiveDataFlowEvidence:
    return SensitiveDataFlowEvidence(
        label_ref=data_label_reference(label.label_digest) if label else None,
        sink_ref=data_label_reference(sink_id) if sink_id else None,
        lineage_depth=label.lineage_depth if label else 0,
        origin_count=len(label.origin_refs) if label else 0,
        source_count=source_count,
        sensitivity=label.sensitivity if label else None,
        transformation=label.last_transformation if label else None,
    )


def _audit(
    code: SensitiveDataFlowCode,
    action: GuardAction,
    request_id: str,
    label: SensitiveDataFlowLabel | None,
    sink_id: str | None,
    now: datetime,
) -> SensitiveDataFlowAuditEvent:
    return SensitiveDataFlowAuditEvent(
        code=code,
        action=action,
        request_ref=data_label_reference(request_id),
        label_ref=data_label_reference(label.label_digest) if label else None,
        sink_ref=data_label_reference(sink_id) if sink_id else None,
        occurred_at=now,
    )
