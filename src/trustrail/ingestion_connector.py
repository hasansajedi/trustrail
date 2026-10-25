"""Admission, continuous verification, and impact tracing for ingestion connectors."""

from __future__ import annotations

import threading
import uuid
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Protocol, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustrail.models.enums import GuardAction, Severity
from trustrail.models.ingestion_connector import (
    AdmittedIngestionConnector,
    AuthorizedConnectorSync,
    ConnectorAdmissionControl,
    ConnectorAdmissionEvidence,
    ConnectorConfiguration,
    ConnectorDocument,
    ConnectorDocumentProvenance,
    ConnectorSyncReport,
    ConnectorSyncRequest,
    ConnectorSyncStatus,
    ConnectorTrustedKey,
    IngestionConnectorCode,
    IngestionConnectorDecision,
    IngestionConnectorFinding,
    IngestionConnectorKind,
    IngestionConnectorManifest,
    IngestionConnectorPhase,
    IngestionConnectorPolicy,
    IngestionConnectorStatus,
    connector_reference,
)
from trustrail.models.supply_chain import ArtifactDigest

_SignedT = TypeVar(
    "_SignedT",
    IngestionConnectorManifest,
    ConnectorAdmissionEvidence,
    AdmittedIngestionConnector,
    AuthorizedConnectorSync,
    ConnectorDocumentProvenance,
)


class ConnectorLineageStore(Protocol):
    """Bounded lineage and quarantine state used for transitive impact tracing."""

    def record_document(self, provenance: ConnectorDocumentProvenance) -> None:
        """Record one verified connector-produced document."""
        ...

    def record_artifact(
        self, artifact_reference: str, upstream_references: tuple[str, ...]
    ) -> None:
        """Record one downstream artifact derived from known upstream nodes."""
        ...

    def quarantine(
        self,
        *,
        connector_reference_value: str | None = None,
        sync_reference: str | None = None,
        origin_references: tuple[str, ...] = (),
        limit: int = 100_000,
    ) -> tuple[tuple[str, ...], bool]:
        """Quarantine matching origins and transitive dependents."""
        ...

    def is_quarantined(self, artifact_reference: str) -> bool:
        """Return whether an artifact is currently quarantined."""
        ...


class ConnectorLineageCapacityError(RuntimeError):
    """Raised when bounded lineage state cannot safely admit another artifact."""


class MemoryConnectorLineageStore:
    """Thread-safe, capacity-bounded process-local lineage graph."""

    def __init__(self, *, max_artifacts: int = 100_000) -> None:
        if max_artifacts < 1:
            raise ValueError("max_artifacts must be positive")
        self._max_artifacts = max_artifacts
        self._parents: dict[str, tuple[str, ...]] = {}
        self._children: dict[str, set[str]] = defaultdict(set)
        self._connector: dict[str, str] = {}
        self._sync: dict[str, str] = {}
        self._provenance: dict[str, str] = {}
        self._quarantined: set[str] = set()
        self._lock = threading.RLock()

    def record_document(self, provenance: ConnectorDocumentProvenance) -> None:
        reference = provenance.document_reference
        with self._lock:
            self._reserve(reference)
            existing_connector = self._connector.get(reference)
            existing_sync = self._sync.get(reference)
            existing_provenance = self._provenance.get(reference)
            if (
                existing_connector
                not in {
                    None,
                    provenance.connector_reference,
                }
                or existing_sync
                not in {
                    None,
                    provenance.sync_reference,
                }
                or existing_provenance
                not in {
                    None,
                    provenance.provenance_digest,
                }
            ):
                raise ValueError("document lineage reference was rebound")
            self._parents.setdefault(reference, ())
            self._connector[reference] = provenance.connector_reference
            self._sync[reference] = provenance.sync_reference
            self._provenance[reference] = provenance.provenance_digest

    def record_artifact(
        self, artifact_reference: str, upstream_references: tuple[str, ...]
    ) -> None:
        if not upstream_references or len(upstream_references) > 1_000:
            raise ValueError("downstream artifacts require 1 to 1000 upstream references")
        if len(set(upstream_references)) != len(upstream_references):
            raise ValueError("upstream references must be unique")
        with self._lock:
            if artifact_reference in upstream_references:
                raise ValueError("lineage cannot contain a direct cycle")
            if any(reference not in self._parents for reference in upstream_references):
                raise ValueError("all upstream lineage references must already exist")
            self._reserve(artifact_reference)
            existing = self._parents.get(artifact_reference)
            if existing is not None and existing != upstream_references:
                raise ValueError("artifact lineage reference was rebound")
            self._parents[artifact_reference] = upstream_references
            for reference in upstream_references:
                self._children[reference].add(artifact_reference)
            if any(reference in self._quarantined for reference in upstream_references):
                self._quarantined.add(artifact_reference)

    def quarantine(
        self,
        *,
        connector_reference_value: str | None = None,
        sync_reference: str | None = None,
        origin_references: tuple[str, ...] = (),
        limit: int = 100_000,
    ) -> tuple[tuple[str, ...], bool]:
        if limit < 1:
            raise ValueError("quarantine result limit must be positive")
        with self._lock:
            seeds = set(origin_references)
            seeds.update(
                reference
                for reference, value in self._connector.items()
                if connector_reference_value is not None and value == connector_reference_value
            )
            seeds.update(
                reference
                for reference, value in self._sync.items()
                if sync_reference is not None and value == sync_reference
            )
            queue = deque(sorted(seeds))
            affected: set[str] = set()
            while queue:
                reference = queue.popleft()
                if reference in affected:
                    continue
                affected.add(reference)
                queue.extend(sorted(self._children.get(reference, ())))
            self._quarantined.update(affected)
            ordered = tuple(sorted(affected))
            return ordered[:limit], len(ordered) > limit

    def is_quarantined(self, artifact_reference: str) -> bool:
        with self._lock:
            return artifact_reference in self._quarantined

    def _reserve(self, reference: str) -> None:
        if reference not in self._parents and len(self._parents) >= self._max_artifacts:
            raise ConnectorLineageCapacityError("connector lineage capacity exhausted")


class IngestionConnectorSigner:
    """Issue Ed25519-signed manifests, evidence, admissions, and provenance."""

    def __init__(self, private_key: Ed25519PrivateKey, *, authority_id: str) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = ConnectorTrustedKey(
            authority_id=authority_id,
            public_key=public_key,
        )

    @classmethod
    def generate(cls, *, authority_id: str) -> IngestionConnectorSigner:
        return cls(Ed25519PrivateKey.generate(), authority_id=authority_id)

    @property
    def trusted_key(self) -> ConnectorTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def sign_manifest(
        self,
        *,
        manifest_id: str,
        connector_id: str,
        kind: IngestionConnectorKind,
        configuration: ConnectorConfiguration,
        status: IngestionConnectorStatus = IngestionConnectorStatus.ACTIVE,
        max_documents_per_sync: int = 10_000,
        max_document_bytes: int = 10_000_000,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> IngestionConnectorManifest:
        current = issued_at or datetime.now(tz=UTC)
        unsigned = IngestionConnectorManifest(
            manifest_id=manifest_id,
            connector_id=connector_id,
            kind=kind,
            status=status,
            configuration=configuration,
            max_documents_per_sync=max_documents_per_sync,
            max_document_bytes=max_document_bytes,
            authority_id=self._trusted_key.authority_id,
            key_id=self._trusted_key.key_id,
            issued_at=current,
            expires_at=expires_at or current + timedelta(days=1),
        )
        return self._sign(unsigned)

    def sign_evidence(
        self,
        *,
        evidence_id: str,
        connector_id: str,
        manifest_digest: str,
        configuration: ConnectorConfiguration,
        controls: frozenset[ConnectorAdmissionControl] | None = None,
        owned_source_uris: frozenset[str] | None = None,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> ConnectorAdmissionEvidence:
        current = issued_at or datetime.now(tz=UTC)
        unsigned = ConnectorAdmissionEvidence(
            evidence_id=evidence_id,
            connector_id=connector_id,
            manifest_digest=manifest_digest,
            configuration=configuration,
            controls=controls if controls is not None else frozenset(ConnectorAdmissionControl),
            owned_source_uris=(
                owned_source_uris
                if owned_source_uris is not None
                else configuration.allowed_source_uris
            ),
            authority_id=self._trusted_key.authority_id,
            key_id=self._trusted_key.key_id,
            issued_at=current,
            expires_at=expires_at or current + timedelta(hours=1),
        )
        return self._sign(unsigned)

    def sign_admission(self, admission: AdmittedIngestionConnector) -> AdmittedIngestionConnector:
        return self._sign(admission)

    def sign_authorization(self, authorization: AuthorizedConnectorSync) -> AuthorizedConnectorSync:
        return self._sign(authorization)

    def sign_provenance(
        self, provenance: ConnectorDocumentProvenance
    ) -> ConnectorDocumentProvenance:
        return self._sign(provenance)

    def _sign(self, value: _SignedT) -> _SignedT:
        return value.model_copy(
            update={"signature": self._private_key.sign(value.signing_bytes).hex()},
            deep=True,
        )


class IngestionConnectorGuard:
    """Fail-closed connector admission, sync verification, and impact tracing."""

    def __init__(
        self,
        *,
        manifest_keys: tuple[ConnectorTrustedKey, ...],
        evidence_keys: tuple[ConnectorTrustedKey, ...],
        control_signer: IngestionConnectorSigner,
        policy: IngestionConnectorPolicy | None = None,
        lineage_store: ConnectorLineageStore | None = None,
        max_lineage_artifacts: int = 100_000,
    ) -> None:
        self._manifest_keys = {key.key_id: key.model_copy(deep=True) for key in manifest_keys}
        self._evidence_keys = {key.key_id: key.model_copy(deep=True) for key in evidence_keys}
        self._control_signer = control_signer
        self._control_key = control_signer.trusted_key
        self._policy = (policy or IngestionConnectorPolicy()).model_copy(deep=True)
        self._lineage = (
            MemoryConnectorLineageStore(max_artifacts=max_lineage_artifacts)
            if lineage_store is None
            else lineage_store
        )
        self._active: dict[str, str] = {}
        self._document_counts: dict[str, int] = {}
        self._lock = threading.RLock()

    @property
    def policy(self) -> IngestionConnectorPolicy:
        return self._policy.model_copy(deep=True)

    def admit(
        self,
        manifest: IngestionConnectorManifest,
        evidence: ConnectorAdmissionEvidence | None,
        *,
        now: datetime | None = None,
    ) -> IngestionConnectorDecision:
        """Admit only a signed connector with complete independent evidence."""
        current = self._now(now)
        findings = self._manifest_findings(manifest, current)
        if evidence is None:
            findings.append(self._finding(IngestionConnectorCode.EVIDENCE_REQUIRED, manifest))
        else:
            findings.extend(self._evidence_findings(evidence, manifest, current))
        findings = self._deduplicate(findings)
        if findings or evidence is None:
            if not self._connector_disabled(findings):
                return self._decision(IngestionConnectorPhase.ADMISSION, findings)
            affected, truncated, lineage_findings = self._quarantine(
                manifest=manifest,
                connector_wide=True,
            )
            return self._decision(
                IngestionConnectorPhase.ADMISSION,
                [*findings, *lineage_findings],
                affected=affected,
                truncated=truncated,
            )

        unsigned = AdmittedIngestionConnector(
            admission_id=str(uuid.uuid4()),
            connector_id=manifest.connector_id,
            manifest_digest=manifest.manifest_digest,
            evidence_digest=evidence.evidence_digest,
            configuration_digest=manifest.configuration.configuration_digest,
            authority_id=self._control_key.authority_id,
            key_id=self._control_key.key_id,
            issued_at=current,
            expires_at=min(
                manifest.expires_at,
                evidence.expires_at,
                current + timedelta(seconds=self._policy.admission_ttl_seconds),
            ),
        )
        admission = self._control_signer.sign_admission(unsigned)
        return IngestionConnectorDecision(
            phase=IngestionConnectorPhase.ADMISSION,
            action=GuardAction.ALLOW,
            admission=admission,
        )

    def authorize_sync(
        self,
        manifest: IngestionConnectorManifest,
        admission: AdmittedIngestionConnector,
        request: ConnectorSyncRequest,
        *,
        now: datetime | None = None,
    ) -> IngestionConnectorDecision:
        """Continuously recheck the exact connector state before one sync."""
        current = self._now(now)
        findings = self._manifest_findings(manifest, current)
        findings.extend(self._admission_findings(admission, manifest, current))
        findings.extend(self._sync_request_findings(request, admission, manifest, current))
        findings = self._deduplicate(findings)
        if findings:
            affected, truncated, lineage_findings = self._quarantine(
                sync_reference=connector_reference(request.sync_id, domain="sync"),
                manifest=manifest,
                connector_wide=self._connector_disabled(findings),
            )
            return self._decision(
                IngestionConnectorPhase.SYNCHRONIZATION,
                [*findings, *lineage_findings],
                affected=affected,
                truncated=truncated,
            )

        unsigned = AuthorizedConnectorSync(
            authorization_id=str(uuid.uuid4()),
            sync_id=request.sync_id,
            connector_id=manifest.connector_id,
            manifest_digest=manifest.manifest_digest,
            admission_digest=admission.admission_digest,
            evidence_digest=admission.evidence_digest,
            configuration_digest=manifest.configuration.configuration_digest,
            state_digest=request.effective_state.state_digest,
            request_digest=request.request_digest,
            source_uris=request.source_uris,
            max_documents=manifest.max_documents_per_sync,
            max_document_bytes=manifest.max_document_bytes,
            expected_content_types=manifest.configuration.expected_content_types,
            parser=manifest.configuration.parser,
            authority_id=self._control_key.authority_id,
            key_id=self._control_key.key_id,
            issued_at=current,
            expires_at=min(
                manifest.expires_at,
                admission.expires_at,
                current + timedelta(seconds=self._policy.authorization_ttl_seconds),
            ),
        )
        authorization = self._control_signer.sign_authorization(unsigned)
        with self._lock:
            self._active[authorization.authorization_id] = authorization.authorization_digest
            self._document_counts[authorization.authorization_id] = 0
        return IngestionConnectorDecision(
            phase=IngestionConnectorPhase.SYNCHRONIZATION,
            action=GuardAction.ALLOW,
            authorization=authorization,
        )

    def verify_document(
        self,
        manifest: IngestionConnectorManifest,
        authorization: AuthorizedConnectorSync,
        document: ConnectorDocument,
        *,
        now: datetime | None = None,
    ) -> IngestionConnectorDecision:
        """Bind one document to the authorized connector/parser/source state."""
        current = self._now(now)
        with self._lock:
            findings = self._manifest_findings(manifest, current)
            findings.extend(self._authorization_findings(authorization, manifest, current))
            active = self._active.get(authorization.authorization_id)
            if active is None:
                findings.append(
                    self._finding(IngestionConnectorCode.AUTHORIZATION_REPLAYED, manifest)
                )
            elif active != authorization.authorization_digest:
                findings.append(
                    self._finding(IngestionConnectorCode.AUTHORIZATION_INVALID, manifest)
                )
            count = self._document_counts.get(authorization.authorization_id, 0)
            if count >= authorization.max_documents:
                findings.append(
                    self._finding(IngestionConnectorCode.DOCUMENT_LIMIT_EXCEEDED, manifest)
                )
            findings.extend(self._document_findings(document, authorization, manifest))
            findings = self._deduplicate(findings)
            if findings:
                affected, truncated, lineage_findings = self._quarantine(
                    sync_reference=connector_reference(authorization.sync_id, domain="sync"),
                    manifest=manifest,
                    connector_wide=self._connector_disabled(findings),
                )
                return self._decision(
                    IngestionConnectorPhase.DOCUMENT,
                    [*findings, *lineage_findings],
                    affected=affected,
                    truncated=truncated,
                )

            unsigned = ConnectorDocumentProvenance(
                document_reference=connector_reference(document.document_id, domain="document"),
                content_digest=document.observed_digest,
                content_type=document.content_type,
                source_uri=document.source_uri,
                connector_reference=connector_reference(manifest.connector_id, domain="connector"),
                sync_reference=connector_reference(authorization.sync_id, domain="sync"),
                connector_id=manifest.connector_id,
                sync_id=authorization.sync_id,
                manifest_digest=manifest.manifest_digest,
                configuration_digest=authorization.configuration_digest,
                state_digest=authorization.state_digest,
                parser=authorization.parser,
                produced_at=current,
                authority_id=self._control_key.authority_id,
                key_id=self._control_key.key_id,
            )
            provenance = self._control_signer.sign_provenance(unsigned)
            verified = document.model_copy(update={"provenance": provenance}, deep=True)
            try:
                self._lineage.record_document(provenance)
            except Exception:
                return self._decision(
                    IngestionConnectorPhase.DOCUMENT,
                    [self._finding(IngestionConnectorCode.LINEAGE_UNAVAILABLE, manifest)],
                )
            self._document_counts[authorization.authorization_id] = count + 1
            return IngestionConnectorDecision(
                phase=IngestionConnectorPhase.DOCUMENT,
                action=GuardAction.ALLOW,
                document=verified,
            )

    def complete_sync(
        self,
        manifest: IngestionConnectorManifest,
        authorization: AuthorizedConnectorSync,
        report: ConnectorSyncReport,
        *,
        now: datetime | None = None,
    ) -> IngestionConnectorDecision:
        """Consume a sync authorization and quarantine partial or inconsistent output."""
        current = self._now(now)
        with self._lock:
            findings = self._manifest_findings(manifest, current)
            findings.extend(self._authorization_findings(authorization, manifest, current))
            active = self._active.pop(authorization.authorization_id, None)
            accepted = self._document_counts.pop(authorization.authorization_id, 0)
            if active is None:
                findings.append(
                    self._finding(IngestionConnectorCode.AUTHORIZATION_REPLAYED, manifest)
                )
            elif active != authorization.authorization_digest:
                findings.append(
                    self._finding(IngestionConnectorCode.AUTHORIZATION_INVALID, manifest)
                )
            if (
                report.authorization_id != authorization.authorization_id
                or report.sync_id != authorization.sync_id
                or report.manifest_digest != authorization.manifest_digest
                or report.state_digest != authorization.state_digest
                or report.processed_documents != accepted
                or report.expected_documents > authorization.max_documents
            ):
                findings.append(self._finding(IngestionConnectorCode.SYNC_REPORT_INVALID, manifest))
            if (
                report.status != ConnectorSyncStatus.COMPLETE
                or report.failure_count
                or report.processed_documents != report.expected_documents
            ):
                findings.append(self._finding(IngestionConnectorCode.PARTIAL_SYNC, manifest))
            findings = self._deduplicate(findings)
            if findings:
                affected, truncated, lineage_findings = self._quarantine(
                    sync_reference=connector_reference(authorization.sync_id, domain="sync"),
                    manifest=manifest,
                    connector_wide=self._connector_disabled(findings),
                )
                return self._decision(
                    IngestionConnectorPhase.COMPLETION,
                    [*findings, *lineage_findings],
                    affected=affected,
                    truncated=truncated,
                )
            return IngestionConnectorDecision(
                phase=IngestionConnectorPhase.COMPLETION,
                action=GuardAction.ALLOW,
            )

    def verify_downstream(
        self,
        manifest: IngestionConnectorManifest,
        document: ConnectorDocument,
        *,
        now: datetime | None = None,
    ) -> IngestionConnectorDecision:
        """Reverify signed provenance immediately before downstream use."""
        current = self._now(now)
        findings = self._manifest_findings(manifest, current)
        provenance = document.provenance
        if provenance is None:
            findings.append(self._finding(IngestionConnectorCode.PROVENANCE_MISSING, manifest))
        else:
            if not self._control_signature_valid(provenance):
                findings.append(self._finding(IngestionConnectorCode.PROVENANCE_INVALID, manifest))
            payload = (
                document.content.encode() if isinstance(document.content, str) else document.content
            )
            actual = ArtifactDigest.from_bytes(payload, document.observed_digest.algorithm)
            invalid = (
                provenance.document_reference
                != connector_reference(document.document_id, domain="document")
                or not provenance.content_digest.matches(actual)
                or not document.observed_digest.matches(actual)
                or provenance.content_type != document.content_type
                or provenance.source_uri != document.source_uri
                or provenance.connector_id != manifest.connector_id
                or provenance.connector_reference
                != connector_reference(manifest.connector_id, domain="connector")
                or provenance.manifest_digest != manifest.manifest_digest
                or provenance.configuration_digest != manifest.configuration.configuration_digest
                or provenance.parser != manifest.configuration.parser
            )
            if invalid:
                findings.append(self._finding(IngestionConnectorCode.PROVENANCE_INVALID, manifest))
            try:
                quarantined = self._lineage.is_quarantined(provenance.document_reference)
            except Exception:
                findings.append(self._finding(IngestionConnectorCode.LINEAGE_UNAVAILABLE, manifest))
            else:
                if quarantined:
                    findings.append(
                        self._finding(IngestionConnectorCode.ARTIFACT_QUARANTINED, manifest)
                    )
        findings = self._deduplicate(findings)
        if findings:
            if not self._connector_disabled(findings):
                return self._decision(IngestionConnectorPhase.DOWNSTREAM, findings)
            affected, truncated, lineage_findings = self._quarantine(
                manifest=manifest,
                connector_wide=True,
            )
            return self._decision(
                IngestionConnectorPhase.DOWNSTREAM,
                [*findings, *lineage_findings],
                affected=affected,
                truncated=truncated,
            )
        return IngestionConnectorDecision(
            phase=IngestionConnectorPhase.DOWNSTREAM,
            action=GuardAction.ALLOW,
            document=document.model_copy(deep=True),
        )

    def register_downstream_artifact(
        self,
        artifact_id: str,
        upstream_references: tuple[str, ...],
    ) -> str:
        """Register a derived index, chunk, embedding, cache, or other artifact."""
        reference = connector_reference(artifact_id, domain="artifact")
        self._lineage.record_artifact(reference, upstream_references)
        return reference

    def quarantine_connector(self, connector_id: str) -> IngestionConnectorDecision:
        """Trusted incident-response hook for a compromised connector identity."""
        reference = connector_reference(connector_id, domain="connector")
        try:
            affected, truncated = self._lineage.quarantine(connector_reference_value=reference)
            findings = (
                IngestionConnectorFinding(
                    code=IngestionConnectorCode.CONNECTOR_COMPROMISED,
                    severity=Severity.CRITICAL,
                    message="Connector was reported compromised and its lineage was quarantined",
                    connector_reference=reference,
                ),
            )
        except Exception:
            affected, truncated = (), False
            findings = (
                IngestionConnectorFinding(
                    code=IngestionConnectorCode.LINEAGE_UNAVAILABLE,
                    severity=Severity.CRITICAL,
                    message="Connector lineage could not be quarantined safely",
                    connector_reference=reference,
                ),
            )
        return IngestionConnectorDecision(
            phase=IngestionConnectorPhase.INCIDENT,
            action=GuardAction.QUARANTINE,
            findings=findings,
            affected_artifact_references=affected,
            impact_truncated=truncated,
        )

    def _manifest_findings(
        self,
        manifest: IngestionConnectorManifest,
        now: datetime,
    ) -> list[IngestionConnectorFinding]:
        if manifest.signature is None:
            return [self._finding(IngestionConnectorCode.MANIFEST_UNSIGNED, manifest)]
        key = self._manifest_keys.get(manifest.key_id)
        if key is None or key.authority_id != manifest.authority_id:
            return [self._finding(IngestionConnectorCode.MANIFEST_KEY_UNKNOWN, manifest)]
        if not self._key_active(key, now):
            return [self._finding(IngestionConnectorCode.MANIFEST_KEY_INACTIVE, manifest)]
        if not self._signature_valid(key, manifest.signing_bytes, manifest.signature):
            return [self._finding(IngestionConnectorCode.MANIFEST_SIGNATURE_INVALID, manifest)]
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        findings: list[IngestionConnectorFinding] = []
        if manifest.issued_at > now + skew:
            findings.append(self._finding(IngestionConnectorCode.MANIFEST_NOT_YET_VALID, manifest))
        if manifest.expires_at < now - skew or now - manifest.issued_at > timedelta(
            seconds=self._policy.max_manifest_age_seconds
        ):
            findings.append(self._finding(IngestionConnectorCode.MANIFEST_EXPIRED, manifest))
        if manifest.status == IngestionConnectorStatus.COMPROMISED:
            findings.append(self._finding(IngestionConnectorCode.CONNECTOR_COMPROMISED, manifest))
        elif manifest.status == IngestionConnectorStatus.REVOKED:
            findings.append(self._finding(IngestionConnectorCode.CONNECTOR_REVOKED, manifest))
        return findings

    def _evidence_findings(
        self,
        evidence: ConnectorAdmissionEvidence,
        manifest: IngestionConnectorManifest,
        now: datetime,
    ) -> list[IngestionConnectorFinding]:
        key = self._evidence_keys.get(evidence.key_id)
        if key is None or key.authority_id != evidence.authority_id:
            return [self._finding(IngestionConnectorCode.EVIDENCE_KEY_UNKNOWN, manifest)]
        if not self._key_active(key, now):
            return [self._finding(IngestionConnectorCode.EVIDENCE_KEY_INACTIVE, manifest)]
        if evidence.signature is None or not self._signature_valid(
            key, evidence.signing_bytes, evidence.signature
        ):
            return [self._finding(IngestionConnectorCode.EVIDENCE_SIGNATURE_INVALID, manifest)]
        findings: list[IngestionConnectorFinding] = []
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        if (
            evidence.issued_at > now + skew
            or evidence.expires_at < now - skew
            or now - evidence.issued_at > timedelta(seconds=self._policy.max_evidence_age_seconds)
        ):
            findings.append(self._finding(IngestionConnectorCode.EVIDENCE_STALE, manifest))
        if (
            evidence.connector_id != manifest.connector_id
            or evidence.manifest_digest != manifest.manifest_digest
            or evidence.configuration != manifest.configuration
        ):
            findings.append(self._finding(IngestionConnectorCode.EVIDENCE_MISMATCH, manifest))
        if self._policy.required_controls - evidence.controls:
            findings.append(
                self._finding(IngestionConnectorCode.ADMISSION_CONTROL_MISSING, manifest)
            )
        if not manifest.configuration.allowed_source_uris.issubset(evidence.owned_source_uris):
            findings.append(
                self._finding(IngestionConnectorCode.SOURCE_OWNERSHIP_UNVERIFIED, manifest)
            )
        return findings

    def _admission_findings(
        self,
        admission: AdmittedIngestionConnector,
        manifest: IngestionConnectorManifest,
        now: datetime,
    ) -> list[IngestionConnectorFinding]:
        invalid = (
            not self._control_signature_valid(admission)
            or admission.connector_id != manifest.connector_id
            or admission.manifest_digest != manifest.manifest_digest
            or admission.configuration_digest != manifest.configuration.configuration_digest
            or admission.expires_at < now
        )
        return (
            [self._finding(IngestionConnectorCode.ADMISSION_INVALID, manifest)] if invalid else []
        )

    def _sync_request_findings(
        self,
        request: ConnectorSyncRequest,
        admission: AdmittedIngestionConnector,
        manifest: IngestionConnectorManifest,
        now: datetime,
    ) -> list[IngestionConnectorFinding]:
        state = request.effective_state
        findings: list[IngestionConnectorFinding] = []
        if (
            request.connector_id != manifest.connector_id
            or request.manifest_digest != manifest.manifest_digest
            or state.connector_id != manifest.connector_id
            or state.manifest_digest != manifest.manifest_digest
            or state.evidence_digest != admission.evidence_digest
            or state.configuration != manifest.configuration
            or state.configuration.configuration_digest != admission.configuration_digest
            or state.observed_at > now + timedelta(seconds=self._policy.clock_skew_seconds)
            or now - state.observed_at > timedelta(seconds=self._policy.max_evidence_age_seconds)
        ):
            findings.append(self._finding(IngestionConnectorCode.EFFECTIVE_STATE_DRIFT, manifest))
        if not request.source_uris.issubset(manifest.configuration.allowed_source_uris):
            findings.append(self._finding(IngestionConnectorCode.SOURCE_NOT_ALLOWED, manifest))
        if abs((now - request.scheduled_for).total_seconds()) > self._policy.schedule_skew_seconds:
            findings.append(self._finding(IngestionConnectorCode.SCHEDULE_INVALID, manifest))
        return findings

    def _authorization_findings(
        self,
        authorization: AuthorizedConnectorSync,
        manifest: IngestionConnectorManifest,
        now: datetime,
    ) -> list[IngestionConnectorFinding]:
        invalid = (
            not self._control_signature_valid(authorization)
            or authorization.connector_id != manifest.connector_id
            or authorization.manifest_digest != manifest.manifest_digest
            or authorization.configuration_digest != manifest.configuration.configuration_digest
            or authorization.parser != manifest.configuration.parser
        )
        findings = (
            [self._finding(IngestionConnectorCode.AUTHORIZATION_INVALID, manifest)]
            if invalid
            else []
        )
        if authorization.expires_at < now:
            findings.append(self._finding(IngestionConnectorCode.AUTHORIZATION_EXPIRED, manifest))
        return findings

    def _document_findings(
        self,
        document: ConnectorDocument,
        authorization: AuthorizedConnectorSync,
        manifest: IngestionConnectorManifest,
    ) -> list[IngestionConnectorFinding]:
        findings: list[IngestionConnectorFinding] = []
        payload = (
            document.content.encode() if isinstance(document.content, str) else document.content
        )
        if len(payload) > authorization.max_document_bytes:
            findings.append(self._finding(IngestionConnectorCode.DOCUMENT_TOO_LARGE, manifest))
        if document.source_uri not in authorization.source_uris:
            findings.append(self._finding(IngestionConnectorCode.SOURCE_NOT_ALLOWED, manifest))
        if document.content_type not in authorization.expected_content_types:
            findings.append(self._finding(IngestionConnectorCode.CONTENT_TYPE_UNEXPECTED, manifest))
        if len(document.parser_candidates) != 1:
            findings.append(self._finding(IngestionConnectorCode.PARSER_AMBIGUOUS, manifest))
        elif document.parser_candidates[0] != authorization.parser:
            findings.append(self._finding(IngestionConnectorCode.PARSER_MISMATCH, manifest))
        actual = ArtifactDigest.from_bytes(payload, document.observed_digest.algorithm)
        if not document.observed_digest.matches(actual):
            findings.append(
                self._finding(IngestionConnectorCode.CONTENT_INTEGRITY_MISMATCH, manifest)
            )
        return findings

    def _quarantine(
        self,
        *,
        manifest: IngestionConnectorManifest,
        sync_reference: str | None = None,
        connector_wide: bool = False,
    ) -> tuple[tuple[str, ...], bool, tuple[IngestionConnectorFinding, ...]]:
        try:
            affected, truncated = self._lineage.quarantine(
                connector_reference_value=(
                    connector_reference(manifest.connector_id, domain="connector")
                    if connector_wide
                    else None
                ),
                sync_reference=sync_reference,
            )
        except Exception:
            return (
                (),
                False,
                (self._finding(IngestionConnectorCode.LINEAGE_UNAVAILABLE, manifest),),
            )
        return affected, truncated, ()

    @staticmethod
    def _connector_disabled(findings: list[IngestionConnectorFinding]) -> bool:
        return any(
            finding.code
            in {
                IngestionConnectorCode.CONNECTOR_COMPROMISED,
                IngestionConnectorCode.CONNECTOR_REVOKED,
            }
            for finding in findings
        )

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        current = value or datetime.now(tz=UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        return current

    @staticmethod
    def _key_active(key: ConnectorTrustedKey, now: datetime) -> bool:
        return (
            not key.revoked
            and not (key.active_from and now < key.active_from)
            and not (key.expires_at and now >= key.expires_at)
        )

    @staticmethod
    def _signature_valid(key: ConnectorTrustedKey, payload: bytes, signature: str) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(signature), payload
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    def _control_signature_valid(self, value: object) -> bool:
        return (
            getattr(value, "signature", None) is not None
            and getattr(value, "key_id", None) == self._control_key.key_id
            and getattr(value, "authority_id", None) == self._control_key.authority_id
            and self._signature_valid(
                self._control_key,
                value.signing_bytes,  # type: ignore[attr-defined]
                value.signature,  # type: ignore[attr-defined]
            )
        )

    @staticmethod
    def _deduplicate(
        findings: list[IngestionConnectorFinding],
    ) -> list[IngestionConnectorFinding]:
        seen: set[IngestionConnectorCode] = set()
        unique: list[IngestionConnectorFinding] = []
        for finding in findings:
            if finding.code not in seen:
                seen.add(finding.code)
                unique.append(finding)
        return unique

    @staticmethod
    def _finding(
        code: IngestionConnectorCode,
        manifest: IngestionConnectorManifest,
    ) -> IngestionConnectorFinding:
        messages = {
            IngestionConnectorCode.MANIFEST_UNSIGNED: "Connector manifest is unsigned",
            IngestionConnectorCode.MANIFEST_KEY_UNKNOWN: "Connector manifest key is not trusted",
            IngestionConnectorCode.MANIFEST_KEY_INACTIVE: "Connector manifest key is inactive",
            IngestionConnectorCode.MANIFEST_SIGNATURE_INVALID: (
                "Connector manifest signature is invalid"
            ),
            IngestionConnectorCode.MANIFEST_NOT_YET_VALID: "Connector manifest is not yet valid",
            IngestionConnectorCode.MANIFEST_EXPIRED: "Connector manifest is stale or expired",
            IngestionConnectorCode.CONNECTOR_COMPROMISED: "Connector is marked compromised",
            IngestionConnectorCode.CONNECTOR_REVOKED: "Connector is revoked",
            IngestionConnectorCode.EVIDENCE_REQUIRED: "Connector admission evidence is required",
            IngestionConnectorCode.EVIDENCE_KEY_UNKNOWN: "Admission evidence key is not trusted",
            IngestionConnectorCode.EVIDENCE_KEY_INACTIVE: "Admission evidence key is inactive",
            IngestionConnectorCode.EVIDENCE_SIGNATURE_INVALID: (
                "Admission evidence signature is invalid"
            ),
            IngestionConnectorCode.EVIDENCE_STALE: "Admission evidence is stale or expired",
            IngestionConnectorCode.EVIDENCE_MISMATCH: (
                "Admission evidence does not match the manifest"
            ),
            IngestionConnectorCode.ADMISSION_CONTROL_MISSING: (
                "Required admission control evidence is missing"
            ),
            IngestionConnectorCode.SOURCE_OWNERSHIP_UNVERIFIED: "Source ownership is not verified",
            IngestionConnectorCode.ADMISSION_INVALID: "Connector admission is invalid or expired",
            IngestionConnectorCode.EFFECTIVE_STATE_DRIFT: (
                "Effective connector or parser state drifted"
            ),
            IngestionConnectorCode.SOURCE_NOT_ALLOWED: "Observed source is not allowlisted",
            IngestionConnectorCode.SCHEDULE_INVALID: (
                "Synchronization is outside its schedule window"
            ),
            IngestionConnectorCode.AUTHORIZATION_INVALID: (
                "Synchronization authorization is invalid"
            ),
            IngestionConnectorCode.AUTHORIZATION_EXPIRED: "Synchronization authorization expired",
            IngestionConnectorCode.AUTHORIZATION_REPLAYED: (
                "Synchronization authorization is missing or consumed"
            ),
            IngestionConnectorCode.DOCUMENT_LIMIT_EXCEEDED: (
                "Synchronization document limit was exceeded"
            ),
            IngestionConnectorCode.DOCUMENT_TOO_LARGE: "Connector document exceeds its byte limit",
            IngestionConnectorCode.CONTENT_TYPE_UNEXPECTED: (
                "Connector emitted an unexpected content type"
            ),
            IngestionConnectorCode.PARSER_AMBIGUOUS: (
                "Connector document has ambiguous parser provenance"
            ),
            IngestionConnectorCode.PARSER_MISMATCH: (
                "Connector document parser differs from the manifest"
            ),
            IngestionConnectorCode.CONTENT_INTEGRITY_MISMATCH: (
                "Connector document content digest is invalid"
            ),
            IngestionConnectorCode.PROVENANCE_MISSING: "Connector document provenance is missing",
            IngestionConnectorCode.PROVENANCE_INVALID: "Connector document provenance is invalid",
            IngestionConnectorCode.PARTIAL_SYNC: "Connector synchronization was partial or failed",
            IngestionConnectorCode.SYNC_REPORT_INVALID: (
                "Connector synchronization report is inconsistent"
            ),
            IngestionConnectorCode.LINEAGE_UNAVAILABLE: (
                "Connector lineage could not be updated safely"
            ),
            IngestionConnectorCode.ARTIFACT_QUARANTINED: (
                "Connector artifact or an ancestor is quarantined"
            ),
        }
        return IngestionConnectorFinding(
            code=code,
            severity=Severity.CRITICAL,
            message=messages[code],
            connector_reference=connector_reference(manifest.connector_id, domain="connector"),
        )

    @staticmethod
    def _decision(
        phase: IngestionConnectorPhase,
        findings: list[IngestionConnectorFinding],
        *,
        affected: tuple[str, ...] = (),
        truncated: bool = False,
    ) -> IngestionConnectorDecision:
        return IngestionConnectorDecision(
            phase=phase,
            action=GuardAction.QUARANTINE,
            findings=tuple(findings),
            affected_artifact_references=affected,
            impact_truncated=truncated,
        )
