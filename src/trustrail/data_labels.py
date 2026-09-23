"""Signed classification propagation and complete data-boundary mediation."""

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

from trustrail.exceptions import DataLabelError
from trustrail.models.data_labels import (
    AuthorizedLabeledTransfer,
    DataBoundaryKind,
    DataBoundaryRequest,
    DataClassificationLabel,
    DataFlowSurface,
    DataHandlingRequirement,
    DataLabelAuditEvent,
    DataLabelCode,
    DataLabelDecision,
    DataLabelFinding,
    DataLabelJoinRequest,
    DataLabelTrustedKey,
    DataLineageEvidence,
    DataTransformationKind,
    data_label_digest,
    data_label_reference,
    utcnow,
)
from trustrail.models.data_lifecycle import DataClassification
from trustrail.models.enums import GuardAction, Severity

_CLASSIFICATION_RANK = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}


class DataLabelAuditSink(Protocol):
    """Persist content-safe label decisions."""

    def emit(self, event: DataLabelAuditEvent) -> None: ...


class MemoryDataLabelAuditSink:
    """Bounded process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[DataLabelAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: DataLabelAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[DataLabelAuditEvent]:
        with self._lock:
            return list(self._events)


class DataLabelSigner:
    """Issue origin labels from an out-of-band classification authority."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        issuer_id: str,
        allowed_tenant_ids: frozenset[str],
    ) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = DataLabelTrustedKey(
            issuer_id=issuer_id,
            public_key=public_key,
            allowed_tenant_ids=allowed_tenant_ids,
        )

    @classmethod
    def generate(
        cls,
        *,
        issuer_id: str,
        allowed_tenant_ids: frozenset[str],
    ) -> DataLabelSigner:
        """Create a signer backed by a new Ed25519 key pair."""
        return cls(
            Ed25519PrivateKey.generate(),
            issuer_id=issuer_id,
            allowed_tenant_ids=allowed_tenant_ids,
        )

    @property
    def trusted_key(self) -> DataLabelTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def issue(
        self,
        *,
        label_id: str,
        artifact_id: str,
        surface: DataFlowSurface,
        content_digest: str,
        tenant_id: str,
        classification: DataClassification,
        allowed_purpose_ids: frozenset[str],
        allowed_residencies: frozenset[str],
        permitted_destination_ids: frozenset[str],
        permitted_boundary_kinds: frozenset[DataBoundaryKind],
        handling_requirements: frozenset[DataHandlingRequirement] = frozenset(),
        retention_until: datetime,
        issued_at: datetime | None = None,
    ) -> DataClassificationLabel:
        """Issue a label for content classified by this trusted authority."""
        if tenant_id not in self._trusted_key.allowed_tenant_ids:
            raise ValueError("label issuer is not authorized for the tenant")
        return self._sign(
            label_id=label_id,
            artifact_id=artifact_id,
            surface=surface,
            content_digest=content_digest,
            tenant_id=tenant_id,
            classification=classification,
            allowed_purpose_ids=allowed_purpose_ids,
            allowed_residencies=allowed_residencies,
            permitted_destination_ids=permitted_destination_ids,
            permitted_boundary_kinds=permitted_boundary_kinds,
            handling_requirements=handling_requirements,
            retention_until=retention_until,
            source_label_digests=(),
            transformation=DataTransformationKind.ORIGIN,
            issued_at=issued_at or utcnow(),
        )

    def _sign(
        self,
        *,
        label_id: str,
        artifact_id: str,
        surface: DataFlowSurface,
        content_digest: str,
        tenant_id: str,
        classification: DataClassification,
        allowed_purpose_ids: frozenset[str],
        allowed_residencies: frozenset[str],
        permitted_destination_ids: frozenset[str],
        permitted_boundary_kinds: frozenset[DataBoundaryKind],
        handling_requirements: frozenset[DataHandlingRequirement],
        retention_until: datetime,
        source_label_digests: tuple[str, ...],
        transformation: DataTransformationKind,
        issued_at: datetime,
    ) -> DataClassificationLabel:
        unsigned = DataClassificationLabel(
            label_id=label_id,
            issuer_id=self._trusted_key.issuer_id,
            key_id=self._trusted_key.key_id,
            artifact_ref=data_label_reference(artifact_id),
            surface=surface,
            content_digest=content_digest,
            tenant_id=tenant_id,
            classification=classification,
            allowed_purpose_ids=allowed_purpose_ids,
            allowed_residencies=allowed_residencies,
            permitted_destination_ids=permitted_destination_ids,
            permitted_boundary_kinds=permitted_boundary_kinds,
            handling_requirements=handling_requirements,
            retention_until=retention_until,
            source_label_digests=source_label_digests,
            transformation=transformation,
            issued_at=issued_at,
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class DataLabelVerifier:
    """Verify issuer, tenant authority, signature, and lifetime."""

    def __init__(self, trusted_keys: tuple[DataLabelTrustedKey, ...]) -> None:
        if len({key.key_id for key in trusted_keys}) != len(trusted_keys):
            raise ValueError("trusted data-label key IDs must be unique")
        self._keys = {key.key_id: key.model_copy(deep=True) for key in trusted_keys}

    def findings(
        self,
        label: DataClassificationLabel,
        *,
        now: datetime,
    ) -> list[DataLabelFinding]:
        if label.signature is None:
            return [
                _finding(
                    DataLabelCode.LABEL_UNSIGNED,
                    Severity.CRITICAL,
                    "Data classification label is unsigned",
                )
            ]
        key = self._keys.get(label.key_id)
        if key is None or key.revoked:
            return [
                _finding(
                    DataLabelCode.LABEL_KEY_UNKNOWN,
                    Severity.CRITICAL,
                    "Data classification issuer key is unavailable",
                )
            ]
        if key.issuer_id != label.issuer_id or label.tenant_id not in key.allowed_tenant_ids:
            return [
                _finding(
                    DataLabelCode.LABEL_ISSUER_MISMATCH,
                    Severity.CRITICAL,
                    "Label issuer is not authorized for the declared tenant",
                )
            ]
        if key.active_from is not None and now < key.active_from:
            return [
                _finding(
                    DataLabelCode.LABEL_KEY_UNKNOWN,
                    Severity.CRITICAL,
                    "Data classification issuer key is not active",
                )
            ]
        if key.expires_at is not None and now >= key.expires_at:
            return [
                _finding(
                    DataLabelCode.LABEL_KEY_UNKNOWN,
                    Severity.CRITICAL,
                    "Data classification issuer key has expired",
                )
            ]
        if now < label.issued_at or now >= label.retention_until:
            return [
                _finding(
                    DataLabelCode.LABEL_EXPIRED,
                    Severity.HIGH,
                    "Data classification label is outside its usable lifetime",
                )
            ]
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(label.signature),
                label.signing_bytes,
            )
        except (InvalidSignature, ValueError):
            return [
                _finding(
                    DataLabelCode.LABEL_SIGNATURE_INVALID,
                    Severity.CRITICAL,
                    "Data classification label signature is invalid",
                )
            ]
        return []


class DataLabelPropagator:
    """Conservatively join trusted source labels and sign the derived label."""

    def __init__(
        self,
        signer: DataLabelSigner,
        trusted_keys: tuple[DataLabelTrustedKey, ...],
        *,
        audit_sink: DataLabelAuditSink | None = None,
    ) -> None:
        self._signer = signer
        self._verifier = DataLabelVerifier(trusted_keys)
        self._audit_sink = audit_sink

    def join(
        self,
        request: DataLabelJoinRequest,
        *,
        now: datetime | None = None,
    ) -> DataLabelDecision:
        """Create the strictest valid label across all supplied source labels."""
        current_time = now or utcnow()
        findings: list[DataLabelFinding] = []
        for label in request.source_labels:
            findings.extend(self._verifier.findings(label, now=current_time))
        if len({label.label_digest for label in request.source_labels}) != len(
            request.source_labels
        ):
            findings.append(
                _finding(
                    DataLabelCode.LABEL_CONFLICT,
                    Severity.HIGH,
                    "A source label was supplied more than once",
                )
            )

        tenants = {label.tenant_id for label in request.source_labels}
        if len(tenants) != 1:
            findings.append(
                _finding(
                    DataLabelCode.TENANT_CONFLICT,
                    Severity.CRITICAL,
                    "Source labels cross tenant boundaries",
                )
            )
        elif next(iter(tenants)) not in self._signer.trusted_key.allowed_tenant_ids:
            findings.append(
                _finding(
                    DataLabelCode.LABEL_ISSUER_MISMATCH,
                    Severity.CRITICAL,
                    "Derivation signer is not authorized for the source tenant",
                )
            )

        purposes = _intersection(label.allowed_purpose_ids for label in request.source_labels)
        residencies = _intersection(label.allowed_residencies for label in request.source_labels)
        destinations = _intersection(
            label.permitted_destination_ids for label in request.source_labels
        )
        boundary_kinds = _intersection(
            label.permitted_boundary_kinds for label in request.source_labels
        )
        if not purposes or not residencies or not destinations or not boundary_kinds:
            findings.append(
                _finding(
                    DataLabelCode.LABEL_CONFLICT,
                    Severity.HIGH,
                    "Source labels have no common purpose, residency, or destination authority",
                )
            )
        earliest_retention = min(label.retention_until for label in request.source_labels)
        if request.issued_at > current_time or request.issued_at >= earliest_retention:
            findings.append(
                _finding(
                    DataLabelCode.RETENTION_DENIED,
                    Severity.HIGH,
                    "Derived label issuance is outside the source lifetime",
                )
            )

        derived: DataClassificationLabel | None = None
        if not findings:
            classification = max(
                (label.classification for label in request.source_labels),
                key=_CLASSIFICATION_RANK.__getitem__,
            )
            handling = frozenset().union(
                *(label.handling_requirements for label in request.source_labels)
            )
            source_digests = tuple(sorted(label.label_digest for label in request.source_labels))
            derived = self._signer._sign(
                label_id=request.label_id,
                artifact_id=request.artifact_id,
                surface=request.surface,
                content_digest=request.content_digest,
                tenant_id=next(iter(tenants)),
                classification=classification,
                allowed_purpose_ids=frozenset(purposes),
                allowed_residencies=frozenset(residencies),
                permitted_destination_ids=frozenset(destinations),
                permitted_boundary_kinds=frozenset(boundary_kinds),
                handling_requirements=handling,
                retention_until=earliest_retention,
                source_label_digests=source_digests,
                transformation=request.transformation,
                issued_at=request.issued_at,
            )

        action = GuardAction.ALLOW if derived is not None else GuardAction.BLOCK
        code = DataLabelCode.ALLOWED if derived is not None else findings[0].code
        audit = _audit_event(
            code=code,
            action=action,
            request_id=request.request_id,
            label=derived,
            source_count=len(request.source_labels),
            now=current_time,
        )
        self._publish(audit)
        evidence = _evidence(derived) if derived is not None else None
        return DataLabelDecision(
            action=action,
            findings=tuple(_deduplicate(findings)),
            derived_label=derived,
            evidence=evidence,
            audit_event=audit,
        )

    def require_join(
        self,
        request: DataLabelJoinRequest,
        *,
        now: datetime | None = None,
    ) -> DataClassificationLabel:
        """Return the joined label or raise before derived content is used."""
        result = self.join(request, now=now)
        if not result.is_allowed or result.derived_label is None:
            raise DataLabelError(result)
        return result.derived_label

    def _publish(self, event: DataLabelAuditEvent) -> None:
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)


class DataLabelGuard:
    """Enforce labels before every provider, retrieval, storage, log, tool, or output use."""

    def __init__(
        self,
        trusted_keys: tuple[DataLabelTrustedKey, ...],
        *,
        audit_sink: DataLabelAuditSink | None = None,
    ) -> None:
        self._verifier = DataLabelVerifier(trusted_keys)
        self._audit_sink = audit_sink

    def authorize(
        self,
        request: DataBoundaryRequest,
        *,
        now: datetime | None = None,
    ) -> DataLabelDecision:
        """Authorize one exact labeled transfer at a completely mediated boundary."""
        current_time = now or utcnow()
        label = request.label
        findings: list[DataLabelFinding] = []
        if label is None:
            findings.append(
                _finding(
                    DataLabelCode.LABEL_MISSING,
                    Severity.CRITICAL,
                    "Data boundary request is missing a classification label",
                )
            )
        else:
            findings.extend(self._verifier.findings(label, now=current_time))
            findings.extend(self._binding_findings(request, label))
            findings.extend(self._lineage_findings(label, request.source_labels, current_time))

        permit: AuthorizedLabeledTransfer | None = None
        if label is not None and not findings:
            permit = AuthorizedLabeledTransfer(
                authorization_id=data_label_digest(
                    {
                        "request": request.request_digest,
                        "label": label.label_digest,
                        "destination": request.destination.destination_id,
                    }
                ),
                request_digest=request.request_digest,
                label_digest=label.label_digest,
                destination_ref=data_label_reference(request.destination.destination_id),
                boundary_kind=request.destination.boundary_kind,
            )

        action = GuardAction.ALLOW if permit is not None else GuardAction.BLOCK
        code = DataLabelCode.ALLOWED if permit is not None else findings[0].code
        audit = _audit_event(
            code=code,
            action=action,
            request_id=request.request_id,
            label=label,
            destination_id=request.destination.destination_id,
            source_count=len(request.source_labels),
            now=current_time,
        )
        self._publish(audit)
        return DataLabelDecision(
            action=action,
            findings=tuple(_deduplicate(findings)),
            permit=permit,
            evidence=(
                _evidence(label, request.destination.destination_id) if label is not None else None
            ),
            audit_event=audit,
        )

    def require(
        self,
        request: DataBoundaryRequest,
        *,
        now: datetime | None = None,
    ) -> AuthorizedLabeledTransfer:
        """Return an exact transfer permit or raise before data crosses the boundary."""
        result = self.authorize(request, now=now)
        if not result.is_allowed or result.permit is None:
            raise DataLabelError(result)
        return result.permit

    def _binding_findings(
        self,
        request: DataBoundaryRequest,
        label: DataClassificationLabel,
    ) -> list[DataLabelFinding]:
        findings: list[DataLabelFinding] = []
        destination = request.destination
        if request.content_digest != label.content_digest:
            findings.append(
                _finding(
                    DataLabelCode.CONTENT_BINDING_INVALID,
                    Severity.CRITICAL,
                    "Label is not bound to the transferred content",
                )
            )
        if (
            request.authenticated_tenant_id != label.tenant_id
            or destination.tenant_id != label.tenant_id
        ):
            findings.append(
                _finding(
                    DataLabelCode.TENANT_CONFLICT,
                    Severity.CRITICAL,
                    "Data transfer crosses a tenant boundary",
                )
            )
        if request.purpose_id not in label.allowed_purpose_ids:
            findings.append(
                _finding(
                    DataLabelCode.PURPOSE_DENIED,
                    Severity.HIGH,
                    "Destination purpose is not permitted by the label",
                )
            )
        if destination.residency not in label.allowed_residencies:
            findings.append(
                _finding(
                    DataLabelCode.RESIDENCY_DENIED,
                    Severity.HIGH,
                    "Destination residency is not permitted by the label",
                )
            )
        if (
            destination.destination_id not in label.permitted_destination_ids
            or destination.boundary_kind not in label.permitted_boundary_kinds
        ):
            findings.append(
                _finding(
                    DataLabelCode.DESTINATION_DENIED,
                    Severity.HIGH,
                    "Destination identity or boundary kind is not permitted by the label",
                )
            )
        if label.classification not in destination.supported_classifications:
            findings.append(
                _finding(
                    DataLabelCode.CLASSIFICATION_UNSUPPORTED,
                    Severity.HIGH,
                    "Destination does not support the label classification",
                )
            )
        if not label.handling_requirements.issubset(destination.enforced_handling):
            findings.append(
                _finding(
                    DataLabelCode.HANDLING_UNSUPPORTED,
                    Severity.HIGH,
                    "Destination cannot enforce every required handling control",
                )
            )
        if (
            request.requested_retention_until is not None
            and request.requested_retention_until > label.retention_until
        ):
            findings.append(
                _finding(
                    DataLabelCode.RETENTION_DENIED,
                    Severity.HIGH,
                    "Destination would retain data beyond the label deadline",
                )
            )
        return findings

    def _lineage_findings(
        self,
        label: DataClassificationLabel,
        sources: tuple[DataClassificationLabel, ...],
        now: datetime,
    ) -> list[DataLabelFinding]:
        if label.source_label_digests and not sources:
            return [
                _finding(
                    DataLabelCode.LINEAGE_MISSING,
                    Severity.CRITICAL,
                    "Derived label source evidence is missing",
                )
            ]
        if not label.source_label_digests and sources:
            return [
                _finding(
                    DataLabelCode.LINEAGE_MISMATCH,
                    Severity.CRITICAL,
                    "Origin label was supplied with undeclared source evidence",
                )
            ]
        findings: list[DataLabelFinding] = []
        for source in sources:
            findings.extend(self._verifier.findings(source, now=now))
        source_digests = tuple(sorted(source.label_digest for source in sources))
        if source_digests != label.source_label_digests:
            findings.append(
                _finding(
                    DataLabelCode.LINEAGE_MISMATCH,
                    Severity.CRITICAL,
                    "Derived label is not bound to the supplied source labels",
                )
            )
        findings.extend(_downgrade_findings(label, sources))
        return findings

    def _publish(self, event: DataLabelAuditEvent) -> None:
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)


def _downgrade_findings(
    proposed: DataClassificationLabel,
    sources: tuple[DataClassificationLabel, ...],
) -> list[DataLabelFinding]:
    if not sources:
        return []
    findings: list[DataLabelFinding] = []
    tenants = {source.tenant_id for source in sources}
    if len(tenants) != 1 or proposed.tenant_id not in tenants:
        findings.append(
            _finding(
                DataLabelCode.TENANT_CONFLICT,
                Severity.CRITICAL,
                "Derived label changes or combines tenant authority",
            )
        )
    maximum_classification = max(
        (source.classification for source in sources),
        key=_CLASSIFICATION_RANK.__getitem__,
    )
    purposes = _intersection(source.allowed_purpose_ids for source in sources)
    residencies = _intersection(source.allowed_residencies for source in sources)
    destinations = _intersection(source.permitted_destination_ids for source in sources)
    boundaries = _intersection(source.permitted_boundary_kinds for source in sources)
    required_handling = frozenset().union(*(source.handling_requirements for source in sources))
    earliest_retention = min(source.retention_until for source in sources)
    if (
        _CLASSIFICATION_RANK[proposed.classification] < _CLASSIFICATION_RANK[maximum_classification]
        or not proposed.allowed_purpose_ids.issubset(purposes)
        or not proposed.allowed_residencies.issubset(residencies)
        or not proposed.permitted_destination_ids.issubset(destinations)
        or not proposed.permitted_boundary_kinds.issubset(boundaries)
        or not required_handling.issubset(proposed.handling_requirements)
        or proposed.retention_until > earliest_retention
    ):
        findings.append(
            _finding(
                DataLabelCode.LABEL_DOWNGRADED,
                Severity.CRITICAL,
                "Derived label weakens one or more source restrictions",
            )
        )
    return findings


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


def _finding(code: DataLabelCode, severity: Severity, message: str) -> DataLabelFinding:
    return DataLabelFinding(code=code, severity=severity, message=message)


def _deduplicate(findings: list[DataLabelFinding]) -> list[DataLabelFinding]:
    unique: dict[DataLabelCode, DataLabelFinding] = {}
    for finding in findings:
        unique.setdefault(finding.code, finding)
    return list(unique.values())


def _evidence(
    label: DataClassificationLabel,
    destination_id: str | None = None,
) -> DataLineageEvidence:
    return DataLineageEvidence(
        label_ref=data_label_reference(label.label_digest),
        source_label_refs=tuple(
            data_label_reference(digest) for digest in label.source_label_digests
        ),
        destination_ref=(
            data_label_reference(destination_id) if destination_id is not None else None
        ),
        classification=label.classification,
        surface=label.surface,
        transformation=label.transformation,
    )


def _audit_event(
    *,
    code: DataLabelCode,
    action: GuardAction,
    request_id: str,
    label: DataClassificationLabel | None,
    source_count: int,
    now: datetime,
    destination_id: str | None = None,
) -> DataLabelAuditEvent:
    return DataLabelAuditEvent(
        code=code,
        action=action,
        request_ref=data_label_reference(request_id),
        label_ref=(data_label_reference(label.label_digest) if label is not None else None),
        destination_ref=(
            data_label_reference(destination_id) if destination_id is not None else None
        ),
        source_count=source_count,
        occurred_at=now,
    )
